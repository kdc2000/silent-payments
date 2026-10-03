use sp_service::block_reader::ChiaBlockReader;
use sp_service::generator::extract_coin_spends;
use sp_service::grouping::group_spends;
use sp_service::pk_extractor::extract_synthetic_pk_from_program;
use sp_service::tweak_index::TweakIndex;
use std::path::PathBuf;

/// The local Chia full node's mainnet database, if `HOME` is set.
fn chia_db_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".chia/mainnet/db/blockchain_v2_mainnet.sqlite"))
}

/// These tests read blocks from a local Chia full node database. Without one
/// they have nothing to check: each test prints a SKIP line and returns.
fn skip_if_no_db() -> Option<PathBuf> {
    let Some(path) = chia_db_path() else {
        eprintln!("SKIP: HOME is not set, no Chia DB to read");
        return None;
    };
    if path.exists() {
        Some(path)
    } else {
        eprintln!("SKIP: Chia DB not found at {:?}", path);
        None
    }
}

#[test]
fn test_read_blocks() {
    let Some(db_path) = skip_if_no_db() else {
        return;
    };
    let reader = ChiaBlockReader::open(&db_path).expect("should open Chia DB read-only");

    // Verify we can read peak height
    let peak = reader
        .get_peak_height()
        .expect("should query peak height");
    assert!(peak.is_some(), "peak height should exist in synced DB");
    let peak_height = peak.unwrap();
    assert!(
        peak_height > 1_000_000,
        "mainnet should have >1M blocks, got {}",
        peak_height
    );

    // Read a specific block (height 1 -- genesis area, guaranteed to exist)
    let result = reader.read_block(1).expect("should read block 1");
    assert!(result.is_some(), "block 1 should exist");
    let (_header_hash, block) = result.unwrap();

    // Block 1 is a non-transaction block (no generator)
    // Just verify deserialization worked
    eprintln!(
        "Block 1 deserialized OK, has generator: {}",
        block.transactions_generator.is_some()
    );
}

#[test]
fn test_read_transaction_block() {
    let Some(db_path) = skip_if_no_db() else {
        return;
    };
    let reader = ChiaBlockReader::open(&db_path).expect("should open Chia DB");

    // Iterate starting from a height known to have transaction blocks.
    // Mainnet blocks around height 250,000+ regularly have transactions.
    // Find the first transaction block from height 250,000.
    let mut found_tx_block = false;
    let mut blocks_checked = 0u32;
    reader
        .iterate_blocks(250_000, |height, _hash, block| {
            blocks_checked += 1;
            if block.transactions_generator.is_some() {
                eprintln!("Found transaction block at height {}", height);
                found_tx_block = true;
                return Err("done".into()); // Stop iteration
            }
            if blocks_checked > 100 {
                return Err("checked 100 blocks".into());
            }
            Ok(())
        })
        .ok(); // Ignore "done" error

    assert!(
        found_tx_block,
        "should find a transaction block within 100 blocks of height 250,000"
    );
}

#[test]
fn test_run_generator() {
    let Some(db_path) = skip_if_no_db() else {
        return;
    };
    let reader = ChiaBlockReader::open(&db_path).expect("should open Chia DB");

    // Find a transaction block and run its generator
    let mut coin_spend_count = 0usize;
    reader
        .iterate_blocks(250_000, |height, _hash, block| {
            if block.transactions_generator.is_some() {
                let spends =
                    extract_coin_spends(&reader, &block).expect("generator execution should succeed");
                coin_spend_count = spends.len();
                eprintln!(
                    "Block {} generator produced {} coin spends",
                    height, coin_spend_count
                );
                return Err("done".into());
            }
            Ok(())
        })
        .ok();

    assert!(
        coin_spend_count > 0,
        "transaction block should produce at least 1 coin spend"
    );
}

#[test]
fn test_extract_synthetic_pk() {
    // Find a transaction block, extract coin spends, and verify at least one
    // standard p2 spend yields a valid 48-byte synthetic PK.
    let Some(db_path) = skip_if_no_db() else {
        return;
    };
    let reader = ChiaBlockReader::open(&db_path).expect("should open Chia DB");

    let mut found_pk = false;
    reader
        .iterate_blocks(250_000, |height, _hash, block| {
            if block.transactions_generator.is_some() {
                let spends = extract_coin_spends(&reader, &block)?;
                for spend in &spends {
                    if let Some(pk) = extract_synthetic_pk_from_program(&spend.puzzle_reveal) {
                        let pk_bytes = pk.to_bytes();
                        assert_eq!(pk_bytes.len(), 48, "synthetic PK should be 48 bytes");
                        eprintln!(
                            "Block {}: extracted synthetic PK: {}",
                            height,
                            hex::encode(&pk_bytes[..8])
                        );
                        found_pk = true;
                        return Err("done".into());
                    }
                }
                // If no standard spends in this block, still stop after first tx block
                return Err("done".into());
            }
            Ok(())
        })
        .ok();

    assert!(
        found_pk,
        "should extract at least one synthetic PK from a transaction block"
    );
}

#[test]
fn test_group_spends_produces_groups() {
    // Process a real block through the full pipeline: read -> generate -> group.
    // Verify that groups have valid tweak points.
    let Some(db_path) = skip_if_no_db() else {
        return;
    };
    let reader = ChiaBlockReader::open(&db_path).expect("should open Chia DB");

    let mut processed = false;
    reader
        .iterate_blocks(250_000, |height, header_hash, block| {
            if block.transactions_generator.is_some() {
                let spends = extract_coin_spends(&reader, &block)?;
                let grouped = group_spends(height, header_hash, &spends);

                eprintln!(
                    "Block {}: {} coin spends, {} groups, {} outputs",
                    height,
                    spends.len(),
                    grouped.groups.len(),
                    grouped.outputs.len()
                );

                // Every group should have at least one spend and a valid tweak_point
                for (i, group) in grouped.groups.iter().enumerate() {
                    assert!(!group.spend_indices.is_empty(), "group {} has no spends", i);
                    assert!(!group.coin_ids.is_empty(), "group {} has no coin_ids", i);
                    assert!(
                        group.tweak_point.is_some(),
                        "group {} should have tweak_point (non-zero A_sum)",
                        i
                    );
                    let tp = group.tweak_point.as_ref().unwrap();
                    assert_eq!(tp.to_bytes().len(), 48, "tweak_point should be 48 bytes");
                    eprintln!(
                        "  Group {}: {} spends, tweak: {}",
                        i,
                        group.coin_ids.len(),
                        hex::encode(&tp.to_bytes()[..8])
                    );
                }

                processed = true;
                return Err("done".into());
            }
            Ok(())
        })
        .ok();

    assert!(processed, "should process at least one transaction block");
}

#[test]
fn test_end_to_end_pipeline() {
    // Full pipeline: read block -> extract spends -> group -> store -> resume
    let Some(db_path) = skip_if_no_db() else {
        return;
    };
    let reader = ChiaBlockReader::open(&db_path).expect("should open Chia DB");
    let mut index = TweakIndex::open_in_memory().expect("should create in-memory index");

    // Process a few blocks starting at height 250,000
    let mut blocks_stored = 0u32;
    reader
        .iterate_blocks(250_000, |height, header_hash, block| {
            if blocks_stored >= 5 {
                return Err("done".into());
            }

            if block.transactions_generator.is_some() {
                let spends = extract_coin_spends(&reader, &block)?;
                let grouped = group_spends(height, header_hash, &spends);

                eprintln!(
                    "Storing block {}: {} groups, {} outputs",
                    height,
                    grouped.groups.len(),
                    grouped.outputs.len()
                );

                index.store_block(&grouped)?;
                blocks_stored += 1;
            }
            Ok(())
        })
        .ok();

    assert!(blocks_stored > 0, "should store at least one block");

    // Verify resume: last_indexed_height should be set
    let last_height = index.get_last_indexed_height().unwrap();
    assert!(
        last_height >= 250_000,
        "last indexed height should be >= 250,000, got {}",
        last_height
    );

    eprintln!(
        "Pipeline complete: {} blocks stored, last height: {}",
        blocks_stored, last_height
    );
}

/// Queries a running Chia full node over RPC, so it is opt-in: it only runs
/// when the environment variable `SP_TEST_LIVE_NODE` is set to `1`. A plain
/// `cargo test` never contacts a node.
#[tokio::test]
async fn test_live_sync_peak() {
    use sp_service::live_sync::{LiveSync, RpcConfig};

    if std::env::var("SP_TEST_LIVE_NODE").as_deref() != Ok("1") {
        eprintln!("SKIP: set SP_TEST_LIVE_NODE=1 to query the local full node RPC");
        return;
    }

    let config = RpcConfig::default();

    // Skip if cert files don't exist
    if !config.cert_path.exists() || !config.key_path.exists() {
        eprintln!("SKIP: Chia RPC certs not found");
        return;
    }

    let sync = LiveSync::new(config, 0).expect("should create LiveSync");
    let peak = sync.get_peak_height().await;

    match peak {
        Some(height) => {
            eprintln!("Full node peak height: {}", height);
            assert!(height > 0, "peak height should be positive");
        }
        None => {
            eprintln!("SKIP: Could not reach full node RPC (node may be down)");
        }
    }
}
