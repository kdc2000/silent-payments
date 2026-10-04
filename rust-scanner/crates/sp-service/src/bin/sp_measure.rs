//! Read-only measurement tool for the CHIP-0057 light-wallet draft.
//!
//! `walk`  — walk a height range of the full node's database and emit one CSV
//!           row per transaction block (tweak list length, filter size, header
//!           block size, ...).
//! `bench` — time the client's per-tweak-point work on tweak points dumped by
//!           `walk --tweaks-out`.
//!
//! The database is opened through `ChiaBlockReader::open` (read-only, one
//! connection). Nothing is written to it. No network or RPC calls are made.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use chia_bls::{PublicKey, SecretKey};
use chia_consensus::conditions::{parse_args, Condition};
use chia_consensus::flags::ConsensusFlags;
use chia_consensus::opcodes::{parse_opcode, ASSERT_CONCURRENT_SPEND};
use chia_consensus::validation_error::{first, next, rest};
use chia_protocol::{Bytes, Bytes32, CoinSpend, FullBlock, HeaderBlock};
use chia_traits::streamable::Streamable;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use sp_common::{
    compute_shared_secret_from_tweak, generate_label, scan_tweak_point, sorted_labels, OutputIndex,
};
use sp_service::block_reader::ChiaBlockReader;
use sp_service::generator::extract_coin_spends;
use sp_service::grouping::group_spends;
use sp_service::pk_extractor::extract_synthetic_pk_from_program;

/// CUT_THROUGH_DEPTH of the light-wallet draft.
const CUT_THROUGH_DEPTH: u32 = 1000;

#[derive(Parser)]
#[command(about = "Read-only mainnet measurements for the SP light-wallet draft")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the main-chain peak height of the database.
    Peak {
        #[arg(long)]
        db: PathBuf,
    },
    /// Walk heights [start, end) and write one CSV row per transaction block.
    Walk {
        #[arg(long)]
        db: PathBuf,
        /// First height (inclusive).
        #[arg(long)]
        start: u32,
        /// Last height (exclusive).
        #[arg(long)]
        end: u32,
        /// CSV output path.
        #[arg(long)]
        out: PathBuf,
        /// Also dump every tweak point as `height,hex48` lines.
        #[arg(long)]
        tweaks_out: Option<PathBuf>,
        /// Evaluate the draft's `omit_spent` rule against coin_record.
        #[arg(long)]
        cut_through: bool,
    },
    /// Time the per-tweak-point client work (single-threaded).
    Bench {
        /// File of `height,hex48` lines written by `walk --tweaks-out`.
        #[arg(long)]
        tweaks: PathBuf,
        /// Number of tweak points to sample (evenly spaced through the file).
        #[arg(long, default_value_t = 4000)]
        n: usize,
        /// Timing passes per configuration (the fastest and the median are reported).
        #[arg(long, default_value_t = 5)]
        passes: usize,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Peak { db } => {
            let reader = ChiaBlockReader::open(&db)?;
            println!("{}", reader.get_peak_height()?.ok_or("empty database")?);
            Ok(())
        }
        Cmd::Walk { db, start, end, out, tweaks_out, cut_through } => {
            walk(&db, start, end, &out, tweaks_out.as_deref(), cut_through)
        }
        Cmd::Bench { tweaks, n, passes } => bench(&tweaks, n, passes),
    }
}

// ---------------------------------------------------------------------------
// BIP-158 filter, as chiabip158 encodes it: GCS with P = 20, M = 2^20,
// SipHash-2-4 under an all-zero key, preceded by CompactSize(N).
// ---------------------------------------------------------------------------

const GCS_P: u32 = 20;
const GCS_M: u64 = 1 << 20;

fn siphash24_zero_key(data: &[u8]) -> u64 {
    let mut v0: u64 = 0x736f6d6570736575;
    let mut v1: u64 = 0x646f72616e646f6d;
    let mut v2: u64 = 0x6c7967656e657261;
    let mut v3: u64 = 0x7465646279746573;
    macro_rules! round {
        () => {
            v0 = v0.wrapping_add(v1);
            v1 = v1.rotate_left(13);
            v1 ^= v0;
            v0 = v0.rotate_left(32);
            v2 = v2.wrapping_add(v3);
            v3 = v3.rotate_left(16);
            v3 ^= v2;
            v0 = v0.wrapping_add(v3);
            v3 = v3.rotate_left(21);
            v3 ^= v0;
            v2 = v2.wrapping_add(v1);
            v1 = v1.rotate_left(17);
            v1 ^= v2;
            v2 = v2.rotate_left(32);
        };
    }
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let m = u64::from_le_bytes(c.try_into().unwrap());
        v3 ^= m;
        round!();
        round!();
        v0 ^= m;
    }
    let rem = chunks.remainder();
    let mut last = [0u8; 8];
    last[..rem.len()].copy_from_slice(rem);
    let m = u64::from_le_bytes(last) | ((data.len() as u64) << 56);
    v3 ^= m;
    round!();
    round!();
    v0 ^= m;
    v2 ^= 0xff;
    round!();
    round!();
    round!();
    round!();
    v0 ^ v1 ^ v2 ^ v3
}

fn hash_to_range(element: &[u8], f: u64) -> u64 {
    ((u128::from(siphash24_zero_key(element)) * u128::from(f)) >> 64) as u64
}

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(253);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(254);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(255);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Returns (N, bytes consumed).
fn read_compact_size(buf: &[u8]) -> Option<(u64, usize)> {
    match *buf.first()? {
        n @ 0..=252 => Some((u64::from(n), 1)),
        253 => Some((u64::from(u16::from_le_bytes(buf.get(1..3)?.try_into().ok()?)), 3)),
        254 => Some((u64::from(u32::from_le_bytes(buf.get(1..5)?.try_into().ok()?)), 5)),
        255 => Some((u64::from_le_bytes(buf.get(1..9)?.try_into().ok()?), 9)),
    }
}

struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    cur: u8,
    used: u32,
}

impl BitWriter<'_> {
    fn write(&mut self, value: u64, nbits: u32) {
        for i in (0..nbits).rev() {
            self.cur = (self.cur << 1) | ((value >> i) & 1) as u8;
            self.used += 1;
            if self.used == 8 {
                self.out.push(self.cur);
                self.cur = 0;
                self.used = 0;
            }
        }
    }
    fn flush(&mut self) {
        if self.used > 0 {
            self.out.push(self.cur << (8 - self.used));
            self.cur = 0;
            self.used = 0;
        }
    }
}

/// Encode the filter over a set of distinct elements.
fn bip158_encode(elements: &HashSet<[u8; 32]>) -> Vec<u8> {
    let n = elements.len() as u64;
    let mut out = Vec::new();
    write_compact_size(&mut out, n);
    if n == 0 {
        return out;
    }
    let f = n * GCS_M;
    let mut hashed: Vec<u64> = elements.iter().map(|e| hash_to_range(e, f)).collect();
    hashed.sort_unstable();
    let mut w = BitWriter { out: &mut out, cur: 0, used: 0 };
    let mut last = 0u64;
    for v in hashed {
        let delta = v - last;
        last = v;
        let mut q = delta >> GCS_P;
        while q > 0 {
            let nbits = q.min(64) as u32;
            w.write(u64::MAX, nbits);
            q -= u64::from(nbits);
        }
        w.write(0, 1);
        w.write(delta, GCS_P);
    }
    w.flush();
    out
}

/// Decode a filter into its sorted hashed values (used by `bench`).
fn bip158_decode(filter: &[u8]) -> Option<Vec<u64>> {
    let (n, mut pos) = read_compact_size(filter)?;
    let mut bit = 0u32;
    let mut read_bit = |pos: &mut usize| -> Option<u64> {
        let byte = *filter.get(*pos)?;
        let b = (byte >> (7 - bit)) & 1;
        bit += 1;
        if bit == 8 {
            bit = 0;
            *pos += 1;
        }
        Some(u64::from(b))
    };
    let mut values = Vec::with_capacity(n as usize);
    let mut last = 0u64;
    for _ in 0..n {
        let mut q = 0u64;
        while read_bit(&mut pos)? == 1 {
            q += 1;
        }
        let mut r = 0u64;
        for _ in 0..GCS_P {
            r = (r << 1) | read_bit(&mut pos)?;
        }
        last += (q << GCS_P) + r;
        values.push(last);
    }
    Some(values)
}

// ---------------------------------------------------------------------------
// Independent count of the concurrent-spend components (cross-check of
// `group_spends`, and the only way to see groups it leaves out).
// ---------------------------------------------------------------------------

/// The ASSERT_CONCURRENT_SPEND coin IDs a spend outputs, decided by the
/// consensus crate's own parser (same rule as grouping.rs).
fn concurrent_spend_assertions(spend: &CoinSpend) -> Vec<Bytes32> {
    let mut a = clvmr::Allocator::new();
    let (Ok(puzzle), Ok(solution)) = (
        clvmr::serde::node_from_bytes(&mut a, spend.puzzle_reveal.as_ref()),
        clvmr::serde::node_from_bytes(&mut a, spend.solution.as_ref()),
    ) else {
        return Vec::new();
    };
    let dialect = clvmr::chia_dialect::ChiaDialect::new(clvmr::chia_dialect::ClvmFlags::empty());
    let Ok(output) = clvmr::run_program::run_program(&mut a, &dialect, puzzle, solution, u64::MAX)
    else {
        return Vec::new();
    };
    let flags = ConsensusFlags::empty();
    let mut asserted = Vec::new();
    let mut iter = output.1;
    while let Ok(Some((condition, tail))) = next(&a, iter) {
        iter = tail;
        let Ok(op_node) = first(&a, condition) else { continue };
        if parse_opcode(&a, op_node, flags) != Some(ASSERT_CONCURRENT_SPEND) {
            continue;
        }
        let Ok(args) = rest(&a, condition) else { continue };
        if let Ok(Condition::AssertConcurrentSpend(id_node)) =
            parse_args(&a, args, ASSERT_CONCURRENT_SPEND, flags)
        {
            if let Ok(id) = Bytes32::try_from(a.atom(id_node).as_ref()) {
                asserted.push(id);
            }
        }
    }
    asserted
}

/// Sizes of the strongly connected components with two or more vertices
/// (Kosaraju, iterative).
fn scc_sizes_ge2(adj: &[Vec<usize>]) -> Vec<usize> {
    let n = adj.len();
    if adj.iter().all(Vec::is_empty) {
        return Vec::new();
    }
    let mut radj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (v, outs) in adj.iter().enumerate() {
        for &w in outs {
            radj[w].push(v);
        }
    }
    // Pass 1: finishing order on the forward graph.
    let mut visited = vec![false; n];
    let mut order = Vec::with_capacity(n);
    for s in 0..n {
        if visited[s] {
            continue;
        }
        visited[s] = true;
        let mut stack = vec![(s, 0usize)];
        while let Some(&mut (v, ref mut i)) = stack.last_mut() {
            if *i < adj[v].len() {
                let w = adj[v][*i];
                *i += 1;
                if !visited[w] {
                    visited[w] = true;
                    stack.push((w, 0));
                }
            } else {
                order.push(v);
                stack.pop();
            }
        }
    }
    // Pass 2: components on the reverse graph, in reverse finishing order.
    let mut assigned = vec![false; n];
    let mut sizes = Vec::new();
    for &s in order.iter().rev() {
        if assigned[s] {
            continue;
        }
        assigned[s] = true;
        let mut size = 0usize;
        let mut stack = vec![s];
        while let Some(v) = stack.pop() {
            size += 1;
            for &w in &radj[v] {
                if !assigned[w] {
                    assigned[w] = true;
                    stack.push(w);
                }
            }
        }
        if size >= 2 {
            sizes.push(size);
        }
    }
    sizes
}

/// (number of eligible spends, sizes of all SCCs of size >= 2 among them).
fn eligible_and_components(coin_spends: &[CoinSpend]) -> (usize, Vec<usize>) {
    let eligible: Vec<usize> = coin_spends
        .iter()
        .enumerate()
        .filter(|(_, s)| extract_synthetic_pk_from_program(&s.puzzle_reveal).is_some())
        .map(|(i, _)| i)
        .collect();
    let local: HashMap<Bytes32, usize> = eligible
        .iter()
        .enumerate()
        .map(|(l, &i)| (coin_spends[i].coin.coin_id(), l))
        .collect();
    let adj: Vec<Vec<usize>> = eligible
        .iter()
        .map(|&i| {
            concurrent_spend_assertions(&coin_spends[i])
                .iter()
                .filter_map(|id| local.get(id).copied())
                .collect()
        })
        .collect();
    (eligible.len(), scc_sizes_ge2(&adj))
}

// ---------------------------------------------------------------------------
// walk
// ---------------------------------------------------------------------------

/// The wallet protocol's HeaderBlock for a full block: every field of the
/// FullBlock except `transactions_generator` and
/// `transactions_generator_ref_list`, plus `transactions_filter`
/// (chia-blockchain `header_block_from_block`).
fn header_block(block: &FullBlock, filter: Vec<u8>) -> HeaderBlock {
    HeaderBlock {
        finished_sub_slots: block.finished_sub_slots.clone(),
        reward_chain_block: block.reward_chain_block.clone(),
        challenge_chain_sp_proof: block.challenge_chain_sp_proof.clone(),
        challenge_chain_ip_proof: block.challenge_chain_ip_proof.clone(),
        reward_chain_sp_proof: block.reward_chain_sp_proof.clone(),
        reward_chain_ip_proof: block.reward_chain_ip_proof.clone(),
        infused_challenge_chain_ip_proof: block.infused_challenge_chain_ip_proof.clone(),
        foliage: block.foliage.clone(),
        foliage_transaction_block: block.foliage_transaction_block.clone(),
        transactions_filter: Bytes::new(filter),
        transactions_info: block.transactions_info.clone(),
    }
}

/// Spent heights of coins, via the existing `check_coins_spent`. That function
/// reads `spent_index` as u32 and fails on the value -1 the node now stores for
/// some unspent coins; on failure the coins are asked for one at a time and a
/// coin that still fails is unspent.
fn spent_heights(
    reader: &ChiaBlockReader,
    ids: &[[u8; 32]],
    fallbacks: &mut u64,
) -> HashMap<[u8; 32], Option<u32>> {
    if let Ok(map) = reader.check_coins_spent(ids) {
        return map;
    }
    let mut map = HashMap::new();
    for id in ids {
        match reader.check_coins_spent(std::slice::from_ref(id)) {
            Ok(m) => map.extend(m),
            Err(_) => {
                *fallbacks += 1;
                map.insert(*id, None);
            }
        }
    }
    map
}

fn walk(
    db: &std::path::Path,
    start: u32,
    end: u32,
    out: &std::path::Path,
    tweaks_out: Option<&std::path::Path>,
    cut_through: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let reader = ChiaBlockReader::open(db)?;
    let peak = reader.get_peak_height()?.ok_or("empty database")?;
    if end > peak {
        return Err(format!("end {end} is above the peak {peak}").into());
    }
    let mut csv = BufWriter::new(File::create(out)?);
    let mut tweaks_file = match tweaks_out {
        Some(p) => Some(BufWriter::new(File::create(p)?)),
        None => None,
    };
    writeln!(
        csv,
        "height,timestamp,cost,removals,eligible,multi_groups,largest_group,groups_emitted,\
         dropped_single,dropped_multi,tweaks,tweaks_from_multi,dup_removed,additions_tx,\
         reward_coins,distinct_ph_all,filter_bytes,filter_n,filter_hash_ok,header_with_filter,\
         header_no_filter,tweak_resp_bytes,ct_omitted,gen_us,group_us"
    )?;

    let t_start = Instant::now();
    let (mut heights_read, mut missing, mut non_tx, mut tx) = (0u64, 0u64, 0u64, 0u64);
    let (mut gen_errors, mut filter_mismatch, mut ct_fallbacks) = (0u64, 0u64, 0u64);
    let mut scc_disagree = 0u64;

    for height in start..end {
        let Some((header_hash, block)) = reader.read_block(height)? else {
            missing += 1;
            continue;
        };
        heights_read += 1;
        let (Some(ftb), Some(tx_info)) = (&block.foliage_transaction_block, &block.transactions_info)
        else {
            non_tx += 1;
            continue;
        };
        tx += 1;

        let t0 = Instant::now();
        let coin_spends = match extract_coin_spends(&reader, &block) {
            Ok(s) => s,
            Err(e) => {
                gen_errors += 1;
                eprintln!("height {height}: generator error: {e}");
                continue;
            }
        };
        let gen_us = t0.elapsed().as_micros();

        let t1 = Instant::now();
        let grouped = group_spends(height, header_hash, &coin_spends);
        let group_us = t1.elapsed().as_micros();

        // Eligible spends and the concurrent-spend components, independently.
        let (eligible, comp_sizes) = eligible_and_components(&coin_spends);
        let multi_groups = comp_sizes.len();
        let largest_group = comp_sizes.iter().copied().max().unwrap_or(0);

        // What group_spends emitted.
        let emitted_single = grouped.groups.iter().filter(|g| g.spend_indices.len() == 1).count();
        let emitted_multi = grouped.groups.len() - emitted_single;
        let dropped_single = eligible - emitted_single;
        let dropped_multi = multi_groups as i64 - emitted_multi as i64;
        if dropped_multi < 0 {
            scc_disagree += 1;
        }

        // Tweak list: 48-byte values, deduplicated and sorted.
        let mut tweak_set: BTreeSet<[u8; 48]> = BTreeSet::new();
        let mut multi_set: BTreeSet<[u8; 48]> = BTreeSet::new();
        for g in &grouped.groups {
            let bytes = g.tweak_point.expect("group_spends sets every tweak point").to_bytes();
            tweak_set.insert(bytes);
            if g.spend_indices.len() >= 2 {
                multi_set.insert(bytes);
            }
        }
        let n = tweak_set.len();
        let dup_removed = grouped.groups.len() - n;
        if let Some(f) = tweaks_file.as_mut() {
            for t in &tweak_set {
                writeln!(f, "{height},{}", hex::encode(t))?;
            }
        }

        // Additions and the filter.
        let mut all_ph: HashSet<[u8; 32]> = HashSet::new();
        let mut elements: HashSet<[u8; 32]> = HashSet::new();
        for o in &grouped.outputs {
            let ph: [u8; 32] = o.puzzle_hash.into();
            all_ph.insert(ph);
        }
        for c in &tx_info.reward_claims_incorporated {
            let ph: [u8; 32] = c.puzzle_hash.into();
            all_ph.insert(ph);
        }
        elements.extend(all_ph.iter().copied());
        for s in &coin_spends {
            let id: [u8; 32] = s.coin.coin_id().into();
            elements.insert(id);
        }
        let filter = bip158_encode(&elements);
        let filter_hash: [u8; 32] = Sha256::digest(&filter).into();
        let expected: [u8; 32] = ftb.filter_hash.into();
        let filter_hash_ok = filter_hash == expected;
        if !filter_hash_ok {
            filter_mismatch += 1;
        }
        let filter_n = read_compact_size(&filter).map(|(n, _)| n).unwrap_or(0);
        let filter_bytes = filter.len();

        let header_with_filter = header_block(&block, filter).to_bytes()?.len();
        // What the node sends when the filter is not requested: the encoding
        // of an empty filter, the single byte 0x00.
        let header_no_filter = header_block(&block, vec![0u8]).to_bytes()?.len();

        let tweak_resp_bytes = if n >= 1 { 40 + 48 * n } else { 0 };

        // Cut-through: a tweak point is omitted when every group that has it
        // is exhausted.
        let ct_omitted: String = if cut_through && n > 0 {
            let ids: Vec<[u8; 32]> = grouped.outputs.iter().map(|o| o.coin_id.into()).collect();
            let spent = spent_heights(&reader, &ids, &mut ct_fallbacks);
            let mut by_parent: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
            for o in &grouped.outputs {
                by_parent.entry(o.parent_coin_id.into()).or_default().push(o.coin_id.into());
            }
            let mut all_exhausted: HashMap<[u8; 48], bool> = HashMap::new();
            for g in &grouped.groups {
                let exhausted = g.coin_ids.iter().all(|cid| {
                    let cid: [u8; 32] = (*cid).into();
                    by_parent.get(&cid).is_none_or(|outs| {
                        outs.iter().all(|o| {
                            matches!(spent.get(o), Some(Some(h)) if h + CUT_THROUGH_DEPTH <= peak)
                        })
                    })
                });
                let e = all_exhausted.entry(g.tweak_point.unwrap().to_bytes()).or_insert(true);
                *e = *e && exhausted;
            }
            all_exhausted.values().filter(|e| **e).count().to_string()
        } else if cut_through {
            "0".to_string()
        } else {
            String::new()
        };

        writeln!(
            csv,
            "{height},{},{},{},{eligible},{multi_groups},{largest_group},{},{dropped_single},\
             {dropped_multi},{n},{},{dup_removed},{},{},{},{filter_bytes},{filter_n},{},\
             {header_with_filter},{header_no_filter},{tweak_resp_bytes},{ct_omitted},{gen_us},{group_us}",
            ftb.timestamp,
            tx_info.cost,
            coin_spends.len(),
            grouped.groups.len(),
            multi_set.len(),
            grouped.outputs.len(),
            tx_info.reward_claims_incorporated.len(),
            all_ph.len(),
            u8::from(filter_hash_ok),
        )?;
        if tx % 200 == 0 {
            csv.flush()?;
        }
        if heights_read % 2000 == 0 {
            let secs = t_start.elapsed().as_secs_f64();
            eprintln!(
                "height {height}: {heights_read} heights in {secs:.0}s ({:.0}/s)",
                heights_read as f64 / secs
            );
        }
    }
    csv.flush()?;
    if let Some(f) = tweaks_file.as_mut() {
        f.flush()?;
    }

    let secs = t_start.elapsed().as_secs_f64();
    let meta = format!(
        "start={start}\nend_exclusive={end}\ndb_peak={peak}\nheights_read={heights_read}\n\
         heights_missing={missing}\nnon_transaction_blocks={non_tx}\ntransaction_blocks={tx}\n\
         generator_errors={gen_errors}\nfilter_hash_mismatches={filter_mismatch}\n\
         scc_disagreements={scc_disagree}\ncut_through={cut_through}\n\
         cut_through_single_coin_fallback_unspent={ct_fallbacks}\nelapsed_seconds={secs:.1}\n\
         heights_per_second={:.1}\n",
        heights_read as f64 / secs
    );
    std::fs::write(out.with_extension("meta.txt"), &meta)?;
    eprint!("{meta}");
    Ok(())
}

// ---------------------------------------------------------------------------
// bench
// ---------------------------------------------------------------------------

fn random_sk() -> Result<SecretKey, Box<dyn std::error::Error>> {
    let mut seed = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;
    Ok(SecretKey::from_seed(&seed))
}

/// (fastest, median) microseconds per item over the passes.
fn per_item_us(mut samples: Vec<f64>) -> (f64, f64) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (samples[0], samples[samples.len() / 2])
}

fn bench(
    tweaks_path: &std::path::Path,
    n: usize,
    passes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut all: Vec<[u8; 48]> = Vec::new();
    for line in BufReader::new(File::open(tweaks_path)?).lines() {
        let line = line?;
        let Some((_, hex48)) = line.split_once(',') else { continue };
        if let Ok(bytes) = <[u8; 48]>::try_from(hex::decode(hex48.trim())?.as_slice()) {
            all.push(bytes);
        }
    }
    if all.is_empty() {
        return Err("no tweak points in file".into());
    }
    let stride = (all.len() / n).max(1);
    let sample: Vec<[u8; 48]> = all.iter().step_by(stride).take(n).copied().collect();
    let count = sample.len() as f64;
    println!("tweak points in file: {}, sampled: {} (stride {stride})", all.len(), sample.len());

    let scan_sk = random_sk()?;
    let spend_pk = random_sk()?.public_key();
    // One output that no candidate matches, so the scan runs k = 0 in full
    // and stops there. The hash-map lookup stands in for the filter test.
    let outputs = OutputIndex::new(&[[0x5au8; 32]]);

    // 1. Subgroup-checked decode only.
    let mut samples = Vec::new();
    let mut decoded: Vec<PublicKey> = Vec::new();
    for _ in 0..passes {
        let t = Instant::now();
        decoded = sample.iter().map(|b| PublicKey::from_bytes(b).expect("valid point")).collect();
        samples.push(t.elapsed().as_secs_f64() * 1e6 / count);
    }
    let (best, med) = per_item_us(samples);
    println!("decode+subgroup check:            {best:9.1} us/point (median {med:.1})");

    // 2. b_scan * T and SHA-256 only.
    let mut samples = Vec::new();
    let mut sink = 0u8;
    for _ in 0..passes {
        let t = Instant::now();
        for p in &decoded {
            sink ^= compute_shared_secret_from_tweak(&scan_sk, p)[0];
        }
        samples.push(t.elapsed().as_secs_f64() * 1e6 / count);
    }
    let (best, med) = per_item_us(samples);
    println!("b_scan*T + SHA-256:               {best:9.1} us/point (median {med:.1})");

    // 3. The whole of ScanEntry step 4 per tweak point: decode, shared secret,
    //    t_0, P_0, and one candidate puzzle hash per (unlabeled + labels).
    for registered in [0usize, 10, 100] {
        let mut label_map: HashMap<[u8; 48], u32> = HashMap::new();
        for m in 0..=registered as u32 {
            let (_, pk) = generate_label(&scan_sk, m).map_err(|e| e.to_string())?;
            label_map.insert(pk.to_bytes(), m); // m = 0 is the change label
        }
        let labels = sorted_labels(Some(&label_map));
        let mut samples = Vec::new();
        let mut hits = 0usize;
        for _ in 0..passes {
            let t = Instant::now();
            for b in &sample {
                let Ok(point) = PublicKey::from_bytes(b) else { continue };
                hits += scan_tweak_point(&scan_sk, &spend_pk, &point, &outputs, &labels).len();
            }
            samples.push(t.elapsed().as_secs_f64() * 1e6 / count);
        }
        let (best, med) = per_item_us(samples);
        println!(
            "full step 4, {registered:3} labels ({:3} candidates): {best:9.1} us/point (median {med:.1}), hits {hits}",
            labels.len() + 1
        );
    }

    // 4. Filter side: SipHash of a candidate, and decoding a filter.
    let reps = 2_000_000u64;
    let mut buf = [0u8; 32];
    let t = Instant::now();
    let mut acc = 0u64;
    for i in 0..reps {
        buf[..8].copy_from_slice(&i.to_le_bytes());
        acc ^= hash_to_range(&buf, 1000 * GCS_M);
    }
    println!(
        "SipHash-2-4 + range of one 32-byte candidate: {:.3} us",
        t.elapsed().as_secs_f64() * 1e6 / reps as f64
    );
    for elems in [100usize, 1000, 5000] {
        let set: HashSet<[u8; 32]> = (0..elems as u64)
            .map(|i| {
                let mut e = [0u8; 32];
                e[..8].copy_from_slice(&i.to_le_bytes());
                Sha256::digest(e).into()
            })
            .collect();
        let filter = bip158_encode(&set);
        let rounds = 200;
        let t = Instant::now();
        let mut total = 0usize;
        for _ in 0..rounds {
            total += bip158_decode(&filter).ok_or("filter does not decode")?.len();
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / f64::from(rounds);
        // Round trip: every element is found in the decoded set.
        let decoded = bip158_decode(&filter).ok_or("filter does not decode")?;
        let f = elems as u64 * GCS_M;
        let ok = set.iter().all(|e| decoded.binary_search(&hash_to_range(e, f)).is_ok());
        println!(
            "filter decode, N = {elems:5}: {} bytes, {us:.1} us per filter ({:.3} us/element), round trip {}",
            filter.len(),
            us / elems as f64,
            if ok && total == elems * rounds as usize { "ok" } else { "FAILED" }
        );
    }
    std::hint::black_box((sink, acc));
    Ok(())
}
