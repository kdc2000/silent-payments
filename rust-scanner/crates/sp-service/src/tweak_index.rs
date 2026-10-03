use rusqlite::{Connection, params};
use std::io::Cursor;

use golomb_coded_set::{GCSFilterWriter, GCSFilterReader, SipHasher24Builder, M, P};

use crate::block_reader::ChiaBlockReader;
use crate::grouping::GroupedBlock;
use crate::types::OutputCoin;

/// Tweak data for a single block: (tweak_point_blobs, output_coins).
pub type BlockTweakData = (Vec<Vec<u8>>, Vec<OutputCoin>);

pub struct TweakIndex {
    conn: Connection,
}

impl TweakIndex {
    /// Open or create the service index database.
    /// Creates tables if they don't exist.
    pub fn open(db_path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        let index = Self { conn };
        index.create_tables()?;
        Ok(index)
    }

    /// Create an in-memory index (for testing).
    pub fn open_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        let index = Self { conn };
        index.create_tables()?;
        Ok(index)
    }

    fn create_tables(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS indexed_blocks (
                height INTEGER PRIMARY KEY,
                block_hash BLOB NOT NULL,
                num_groups INTEGER NOT NULL,
                timestamp INTEGER
            );

            CREATE TABLE IF NOT EXISTS block_tweaks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                height INTEGER NOT NULL,
                group_index INTEGER NOT NULL,
                tweak_point BLOB NOT NULL,
                coin_ids BLOB NOT NULL,
                FOREIGN KEY (height) REFERENCES indexed_blocks(height)
            );

            CREATE TABLE IF NOT EXISTS block_outputs (
                height INTEGER NOT NULL,
                puzzle_hash BLOB NOT NULL,
                coin_id BLOB NOT NULL,
                amount INTEGER NOT NULL,
                parent_coin_id BLOB NOT NULL,
                PRIMARY KEY (height, coin_id)
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO sync_state (key, value) VALUES ('last_indexed_height', '0');

            CREATE TABLE IF NOT EXISTS block_filters (
                height INTEGER PRIMARY KEY,
                header_hash BLOB NOT NULL,
                filter_data BLOB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_block_tweaks_height ON block_tweaks(height);
            CREATE INDEX IF NOT EXISTS idx_block_outputs_height ON block_outputs(height);
        ")?;
        Ok(())
    }

    /// Get the last indexed block height. Returns 0 if no blocks indexed yet.
    pub fn get_last_indexed_height(&self) -> Result<u32, Box<dyn std::error::Error>> {
        let height: String = self.conn.query_row(
            "SELECT value FROM sync_state WHERE key='last_indexed_height'",
            [],
            |row| row.get(0),
        )?;
        Ok(height.parse::<u32>()?)
    }

    /// Get the minimum indexed block height, or None if no blocks indexed.
    pub fn get_min_indexed_height(&self) -> Result<Option<u32>, Box<dyn std::error::Error>> {
        let height: Option<u32> = self.conn.query_row(
            "SELECT MIN(height) FROM indexed_blocks",
            [],
            |row| row.get(0),
        )?;
        Ok(height)
    }

    /// Set the last indexed height (used for --start-height on first run).
    pub fn set_last_indexed_height(&self, height: u32) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "UPDATE sync_state SET value=? WHERE key='last_indexed_height'",
            [height.to_string()],
        )?;
        Ok(())
    }

    /// Store a processed block's tweak data and outputs.
    /// Updates last_indexed_height atomically.
    pub fn store_block(&mut self, block: &GroupedBlock) -> Result<(), Box<dyn std::error::Error>> {
        let tx = self.conn.transaction()?;

        // Insert indexed_blocks record
        tx.execute(
            "INSERT OR REPLACE INTO indexed_blocks (height, block_hash, num_groups, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![
                block.height,
                block.header_hash.as_ref(),
                block.groups.len() as u32,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            ],
        )?;

        // Insert tweak data for each group
        for (group_idx, group) in block.groups.iter().enumerate() {
            if let Some(ref tweak_point) = group.tweak_point {
                // Serialize coin_ids as concatenated 32-byte blobs
                let coin_ids_blob: Vec<u8> = group.coin_ids.iter()
                    .flat_map(|id| id.as_ref().iter().copied())
                    .collect();

                tx.execute(
                    "INSERT INTO block_tweaks (height, group_index, tweak_point, coin_ids) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        block.height,
                        group_idx as u32,
                        tweak_point.to_bytes().as_ref(),
                        coin_ids_blob,
                    ],
                )?;
            }
        }

        // Insert output coins
        for output in &block.outputs {
            tx.execute(
                "INSERT OR REPLACE INTO block_outputs (height, puzzle_hash, coin_id, amount, parent_coin_id) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    block.height,
                    output.puzzle_hash.as_ref(),
                    output.coin_id.as_ref(),
                    output.amount as i64,
                    output.parent_coin_id.as_ref(),
                ],
            )?;
        }

        // Update sync state
        tx.execute(
            "UPDATE sync_state SET value=?1 WHERE key='last_indexed_height'",
            params![block.height.to_string()],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Read tweak data for a specific block height.
    /// Returns (tweak_points, outputs) where tweak_points are 48-byte G1 blobs.
    pub fn get_block_tweaks(&self, height: u32) -> Result<Option<BlockTweakData>, Box<dyn std::error::Error>> {
        // Check if block is indexed
        let exists: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM indexed_blocks WHERE height=?",
            [height],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(None);
        }

        // Read tweaks
        let mut stmt = self.conn.prepare(
            "SELECT tweak_point FROM block_tweaks WHERE height=? ORDER BY group_index"
        )?;
        let tweaks: Vec<Vec<u8>> = stmt.query_map([height], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })?.collect::<Result<_, _>>()?;

        // Read outputs
        let mut stmt = self.conn.prepare(
            "SELECT puzzle_hash, coin_id, amount, parent_coin_id FROM block_outputs WHERE height=?"
        )?;
        let outputs: Vec<OutputCoin> = stmt.query_map([height], |row| {
            let ph: Vec<u8> = row.get(0)?;
            let cid: Vec<u8> = row.get(1)?;
            let amt: i64 = row.get(2)?;
            let pcid: Vec<u8> = row.get(3)?;
            Ok(OutputCoin {
                puzzle_hash: ph.as_slice().try_into().unwrap(),
                coin_id: cid.as_slice().try_into().unwrap(),
                amount: amt as u64,
                parent_coin_id: pcid.as_slice().try_into().unwrap(),
            })
        })?.collect::<Result<_, _>>()?;

        Ok(Some((tweaks, outputs)))
    }

    /// Store a GCS filter for a block height.
    pub fn store_block_filter(
        &mut self,
        height: u32,
        header_hash: &[u8; 32],
        filter_data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "INSERT OR REPLACE INTO block_filters (height, header_hash, filter_data) VALUES (?1, ?2, ?3)",
            params![height, header_hash.as_slice(), filter_data],
        )?;
        Ok(())
    }

    /// Get the GCS filter for a block height.
    /// Returns Some((header_hash, filter_data)) or None if not found.
    #[allow(clippy::type_complexity)]
    pub fn get_block_filter(
        &self,
        height: u32,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, Box<dyn std::error::Error>> {
        let result = self.conn.query_row(
            "SELECT header_hash, filter_data FROM block_filters WHERE height=?",
            [height],
            |row| {
                let hh: Vec<u8> = row.get(0)?;
                let fd: Vec<u8> = row.get(1)?;
                Ok((hh, fd))
            },
        );
        match result {
            Ok((hh, fd)) => Ok(Some((hh, fd))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get coin_ids for each tweak group at a given height.
    /// Returns a Vec of Vec<[u8; 32]>, one entry per group (ordered by group_index).
    fn get_tweak_coin_ids(
        &self,
        height: u32,
    ) -> Result<Vec<Vec<[u8; 32]>>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT coin_ids FROM block_tweaks WHERE height=? ORDER BY group_index",
        )?;
        let rows = stmt.query_map([height], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })?;

        let mut result = Vec::new();
        for row in rows {
            let blob = row?;
            let mut ids = Vec::new();
            for chunk in blob.chunks_exact(32) {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                ids.push(arr);
            }
            result.push(ids);
        }
        Ok(result)
    }

    /// Get block tweaks with UTXO-awareness ("cut-through"): a group's tweak
    /// point is omitted only when every output coin created by the coins of
    /// that group has itself been spent.
    ///
    /// A tweak point only matters to a scanner through the coins its group
    /// created, so a group whose outputs are all spent can no longer lead to a
    /// spendable coin. A group that created no coin at all is omitted for the
    /// same reason.
    ///
    /// How this is decided, from data the service already holds:
    /// - the group's coins are the `coin_ids` stored with its tweak point;
    /// - its outputs are the block's `block_outputs` rows whose
    ///   `parent_coin_id` is one of those coins;
    /// - an output is spent when the full node's `coin_record` has a non-zero
    ///   `spent_index` for its coin ID.
    ///
    /// Every doubt keeps the tweak point: an output the full node does not
    /// know, or a group stored without coin IDs, counts as unspent. Returning
    /// too much is safe; returning too little loses payments.
    ///
    /// The output list is returned unfiltered.
    pub fn get_block_tweaks_utxo_aware(
        &self,
        height: u32,
        chia_reader: &ChiaBlockReader,
    ) -> Result<Option<BlockTweakData>, Box<dyn std::error::Error>> {
        let data = self.get_block_tweaks(height)?;
        let (tweaks, outputs) = match data {
            Some(d) => d,
            None => return Ok(None),
        };

        if tweaks.is_empty() {
            return Ok(Some((tweaks, outputs)));
        }

        // Coin IDs (the group's input coins) per tweak, in the same order.
        let group_coin_ids = self.get_tweak_coin_ids(height)?;
        if group_coin_ids.len() != tweaks.len() {
            return Ok(Some((tweaks, outputs)));
        }

        // Spend status of every coin created in this block.
        let output_ids: Vec<[u8; 32]> = outputs
            .iter()
            .map(|o| <[u8; 32]>::try_from(o.coin_id.as_ref()).unwrap())
            .collect();
        let spent_map = chia_reader.check_coins_spent(&output_ids)?;
        let is_spent = |coin_id: &[u8; 32]| matches!(spent_map.get(coin_id), Some(Some(_)));

        let mut filtered_tweaks = Vec::new();
        for (tweak, group_ids) in tweaks.into_iter().zip(&group_coin_ids) {
            // No coin IDs recorded for this group: its outputs are unknown.
            let has_unspent_output = group_ids.is_empty()
                || outputs.iter().zip(&output_ids).any(|(output, output_id)| {
                    group_ids
                        .iter()
                        .any(|id| id.as_slice() == output.parent_coin_id.as_ref())
                        && !is_spent(output_id)
                });
            if has_unspent_output {
                filtered_tweaks.push(tweak);
            }
        }

        Ok(Some((filtered_tweaks, outputs)))
    }

    /// Get all indexed block heights, sorted ascending.
    pub fn get_indexed_heights(&self) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT height FROM indexed_blocks ORDER BY height"
        )?;
        let heights: Vec<u32> = stmt.query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        Ok(heights)
    }

    /// Get all coin_ids from block_outputs for a given height.
    pub fn get_block_coin_ids(&self, height: u32) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT coin_id FROM block_outputs WHERE height = ?"
        )?;
        let coin_ids: Vec<[u8; 32]> = stmt.query_map([height], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        })?
        .map(|r| {
            let blob = r?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&blob);
            Ok(arr)
        })
        .collect::<Result<_, rusqlite::Error>>()?;
        Ok(coin_ids)
    }

    /// Delete all data for a single block (tweaks, outputs, filters, indexed_blocks).
    /// Does NOT update sync_state -- pruning doesn't affect sync position.
    pub fn delete_block(&mut self, height: u32) -> Result<(), Box<dyn std::error::Error>> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM block_tweaks WHERE height = ?", [height])?;
        tx.execute("DELETE FROM block_outputs WHERE height = ?", [height])?;
        tx.execute("DELETE FROM block_filters WHERE height = ?", [height])?;
        tx.execute("DELETE FROM indexed_blocks WHERE height = ?", [height])?;
        tx.commit()?;
        Ok(())
    }

    /// Delete the tweak data, outputs and index entries of all blocks above a
    /// given height, and set `last_indexed_height` to it.
    ///
    /// NOT wired into the service: reorg handling is not implemented, and
    /// nothing outside this module's tests calls this. It is a building block
    /// for it. Unlike [`TweakIndex::delete_block`] it leaves the blocks' compact
    /// filters (`block_filters`) in place.
    pub fn rollback_above(&mut self, height: u32) -> Result<(), Box<dyn std::error::Error>> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM block_tweaks WHERE height > ?", [height])?;
        tx.execute("DELETE FROM block_outputs WHERE height > ?", [height])?;
        tx.execute("DELETE FROM indexed_blocks WHERE height > ?", [height])?;
        tx.execute(
            "UPDATE sync_state SET value=?1 WHERE key='last_indexed_height'",
            params![height.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// Build a GCS (Golomb-Coded Set) filter from puzzle hashes using BIP-158 parameters.
///
/// Uses the block header hash to derive SipHash keys (k0, k1 from first 16 bytes).
/// Parameters: P=19, M=784931 (BIP-158 standard).
pub fn build_gcs_filter(header_hash: &[u8; 32], puzzle_hashes: &[[u8; 32]]) -> Vec<u8> {
    let k0 = u64::from_le_bytes(header_hash[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(header_hash[8..16].try_into().unwrap());
    let hasher = SipHasher24Builder::new(k0, k1);

    let mut buf = Vec::new();
    {
        let mut writer = GCSFilterWriter::new(&mut buf, hasher, M, P);
        for ph in puzzle_hashes {
            writer.add_element(ph.as_slice());
        }
        writer.finish().unwrap();
    }
    buf
}

/// Check if any of the candidate puzzle hashes match a GCS filter.
///
/// Returns true if any candidate is likely in the filter (BIP-158 false-positive rate applies).
///
/// Fails closed: a filter that cannot be decoded is treated as "may match"
/// and returns true, never "no match". That covers a filter too short to hold
/// its 8-byte element count, an element count the data cannot possibly hold,
/// and any error while decoding. A caller that skips work on `false` therefore
/// never skips because of a damaged filter.
pub fn check_gcs_filter(
    filter_bytes: &[u8],
    header_hash: &[u8; 32],
    candidates: &[[u8; 32]],
) -> bool {
    if candidates.is_empty() {
        return false; // nothing to look for
    }

    // The filter starts with the element count N as 8 little-endian bytes.
    // (The reader itself would treat a missing count as an empty filter.)
    let Some(count_bytes) = filter_bytes.first_chunk::<8>() else {
        return true;
    };
    let n_elements = u64::from_le_bytes(*count_bytes);
    // Each element takes at least P + 1 bits; N * M must fit the hash range.
    let payload_bits = (filter_bytes.len() as u64 - 8) * 8;
    let min_bits = n_elements.checked_mul(u64::from(P) + 1);
    if n_elements.checked_mul(M).is_none() || min_bits.is_none_or(|bits| bits > payload_bits) {
        return true;
    }

    let k0 = u64::from_le_bytes(header_hash[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(header_hash[8..16].try_into().unwrap());
    let hasher = SipHasher24Builder::new(k0, k1);

    let reader = GCSFilterReader::new(hasher, M, P);
    let mut cursor = Cursor::new(filter_bytes);
    let candidate_slices: Vec<&[u8]> = candidates.iter().map(|c| c.as_slice()).collect();
    reader
        .match_any(&mut cursor, &mut candidate_slices.into_iter())
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Bytes32;

    fn make_test_block(height: u32) -> GroupedBlock {
        let header_hash: Bytes32 = [height as u8; 32].into();
        GroupedBlock {
            height,
            header_hash,
            groups: vec![], // Empty groups for basic persistence test
            outputs: vec![
                OutputCoin {
                    puzzle_hash: [1u8; 32].into(),
                    coin_id: [2u8; 32].into(),
                    amount: 1000,
                    parent_coin_id: [3u8; 32].into(),
                },
            ],
        }
    }

    #[test]
    fn test_create_and_resume() {
        let mut index = TweakIndex::open_in_memory().unwrap();

        // Initial state: last indexed height is 0
        assert_eq!(index.get_last_indexed_height().unwrap(), 0);

        // Store a block
        let block = make_test_block(100);
        index.store_block(&block).unwrap();

        // Last indexed height should update
        assert_eq!(index.get_last_indexed_height().unwrap(), 100);

        // Store another block
        let block2 = make_test_block(101);
        index.store_block(&block2).unwrap();
        assert_eq!(index.get_last_indexed_height().unwrap(), 101);
    }

    #[test]
    fn test_store_and_read_outputs() {
        let mut index = TweakIndex::open_in_memory().unwrap();

        let block = make_test_block(50);
        index.store_block(&block).unwrap();

        let result = index.get_block_tweaks(50).unwrap();
        assert!(result.is_some());
        let (tweaks, outputs) = result.unwrap();
        assert_eq!(tweaks.len(), 0); // No groups in test block
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].amount, 1000);
        assert_eq!(outputs[0].puzzle_hash.as_ref(), &[1u8; 32]);
    }

    #[test]
    fn test_rollback() {
        let mut index = TweakIndex::open_in_memory().unwrap();

        index.store_block(&make_test_block(100)).unwrap();
        index.store_block(&make_test_block(101)).unwrap();
        index.store_block(&make_test_block(102)).unwrap();

        assert_eq!(index.get_last_indexed_height().unwrap(), 102);

        // Rollback above 100
        index.rollback_above(100).unwrap();
        assert_eq!(index.get_last_indexed_height().unwrap(), 100);

        // Block 101 and 102 should be gone
        assert!(index.get_block_tweaks(101).unwrap().is_none());
        assert!(index.get_block_tweaks(102).unwrap().is_none());

        // Block 100 should still exist
        assert!(index.get_block_tweaks(100).unwrap().is_some());
    }

    #[test]
    fn test_nonexistent_block() {
        let index = TweakIndex::open_in_memory().unwrap();
        assert!(index.get_block_tweaks(999).unwrap().is_none());
    }

    // --- GCS filter tests ---

    #[test]
    fn test_gcs_filter_deterministic() {
        let header_hash = [42u8; 32];
        let ph1 = [1u8; 32];
        let ph2 = [2u8; 32];

        let filter1 = build_gcs_filter(&header_hash, &[ph1, ph2]);
        let filter2 = build_gcs_filter(&header_hash, &[ph1, ph2]);
        assert_eq!(filter1, filter2, "GCS filter should be deterministic");
        assert!(!filter1.is_empty());
    }

    #[test]
    fn test_gcs_filter_match_included() {
        let header_hash = [42u8; 32];
        let ph1 = [1u8; 32];
        let ph2 = [2u8; 32];

        let filter = build_gcs_filter(&header_hash, &[ph1, ph2]);
        assert!(check_gcs_filter(&filter, &header_hash, &[ph1]));
        assert!(check_gcs_filter(&filter, &header_hash, &[ph2]));
    }

    #[test]
    fn test_gcs_filter_no_match_excluded() {
        let header_hash = [42u8; 32];
        let ph1 = [1u8; 32];
        let ph2 = [2u8; 32];
        let ph_other = [99u8; 32];

        let filter = build_gcs_filter(&header_hash, &[ph1, ph2]);
        // With P=19, M=784931, false positive rate is ~1/784931, so this should almost never match
        assert!(!check_gcs_filter(&filter, &header_hash, &[ph_other]));
    }

    #[test]
    fn test_gcs_filter_undecodable_fails_closed() {
        let header_hash = [42u8; 32];
        let ph1 = [1u8; 32];
        let ph2 = [2u8; 32];
        let absent = [99u8; 32];
        let filter = build_gcs_filter(&header_hash, &[ph1, ph2]);
        assert!(!check_gcs_filter(&filter, &header_hash, &[absent]), "intact filter: no match");

        // Empty, and too short to hold the 8-byte element count.
        assert!(check_gcs_filter(&[], &header_hash, &[absent]));
        assert!(check_gcs_filter(&filter[..5], &header_hash, &[absent]));

        // Element count present but the encoded elements are cut off.
        assert!(check_gcs_filter(&filter[..8], &header_hash, &[absent]));
        assert!(check_gcs_filter(&filter[..filter.len() - 3], &header_hash, &[absent]));

        // An element count the data cannot hold (and that overflows N * M).
        let mut huge_count = filter.clone();
        huge_count[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(check_gcs_filter(&huge_count, &header_hash, &[absent]));
        let mut too_many = filter.clone();
        too_many[..8].copy_from_slice(&1_000u64.to_le_bytes());
        assert!(check_gcs_filter(&too_many, &header_hash, &[absent]));
    }

    #[test]
    fn test_gcs_filter_decode_error_fails_closed() {
        // 50 elements, last two bytes cut off: the element count and the size
        // look plausible, and decoding only fails when the reader runs off the
        // end. 200 absent candidates force it to read every element.
        let header_hash = [7u8; 32];
        let members: Vec<[u8; 32]> = (0u8..50).map(|i| [i; 32]).collect();
        let absent: Vec<[u8; 32]> = (0u8..200)
            .map(|i| {
                let mut c = [0xF0u8; 32];
                c[0] = i;
                c[1] = 0xAB;
                c
            })
            .collect();
        let filter = build_gcs_filter(&header_hash, &members);
        assert!(!check_gcs_filter(&filter, &header_hash, &absent), "intact filter: no match");

        let truncated = &filter[..filter.len() - 2];
        assert!(
            check_gcs_filter(truncated, &header_hash, &absent),
            "a filter that fails to decode must be treated as a possible match"
        );
    }

    #[test]
    fn test_gcs_filter_valid_empty_filter_and_empty_query_do_not_match() {
        let header_hash = [42u8; 32];
        // A well-formed filter over zero elements is decodable: no match.
        let empty = build_gcs_filter(&header_hash, &[]);
        assert!(!check_gcs_filter(&empty, &header_hash, &[[1u8; 32]]));
        // No candidates: nothing can match, whatever the filter.
        assert!(!check_gcs_filter(&[], &header_hash, &[]));
    }

    // --- block_filters CRUD tests ---

    #[test]
    fn test_block_filters_table_created() {
        let index = TweakIndex::open_in_memory().unwrap();
        // Table should exist -- query should not error
        let count: u32 = index.conn.query_row(
            "SELECT COUNT(*) FROM block_filters",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_store_and_get_block_filter() {
        let mut index = TweakIndex::open_in_memory().unwrap();
        let header_hash = [7u8; 32];
        let filter_data = vec![1, 2, 3, 4, 5];

        index.store_block_filter(100, &header_hash, &filter_data).unwrap();

        let result = index.get_block_filter(100).unwrap();
        assert!(result.is_some());
        let (hh, fd) = result.unwrap();
        assert_eq!(hh, header_hash.to_vec());
        assert_eq!(fd, filter_data);
    }

    #[test]
    fn test_get_block_filter_nonexistent() {
        let index = TweakIndex::open_in_memory().unwrap();
        let result = index.get_block_filter(999).unwrap();
        assert!(result.is_none());
    }

    // --- UTXO-aware query tests ---

    /// A full-node `coin_record` table holding the given (coin id, spent_index)
    /// rows; spent_index 0 means unspent.
    fn mock_chia_reader(coins: &[([u8; 32], u32)]) -> ChiaBlockReader {
        let chia_conn = rusqlite::Connection::open_in_memory().unwrap();
        chia_conn.execute_batch(
            "CREATE TABLE coin_record (
                coin_name BLOB NOT NULL,
                confirmed_index INTEGER,
                spent_index INTEGER,
                coinbase INTEGER,
                puzzle_hash BLOB,
                coin_parent BLOB,
                amount BLOB,
                timestamp INTEGER
            );"
        ).unwrap();
        for (coin_id, spent_index) in coins {
            chia_conn.execute(
                "INSERT INTO coin_record (coin_name, confirmed_index, spent_index, coinbase, puzzle_hash, coin_parent, amount, timestamp)
                 VALUES (?1, 50, ?2, 0, ?3, ?3, X'00', 0)",
                rusqlite::params![coin_id.as_slice(), spent_index, [0u8; 32].as_slice()],
            ).unwrap();
        }
        ChiaBlockReader::from_connection(chia_conn)
    }

    fn tweak_for(seed: u8) -> chia_bls::PublicKey {
        chia_bls::SecretKey::from_seed(&[seed; 32]).public_key()
    }

    fn group(index: usize, tweak: chia_bls::PublicKey, coin_ids: &[[u8; 32]]) -> crate::grouping::SpendGroup {
        crate::grouping::SpendGroup {
            spend_indices: vec![index],
            a_sum: tweak,
            tweak_point: Some(tweak),
            coin_ids: coin_ids.iter().map(|id| Bytes32::from(*id)).collect(),
        }
    }

    fn output(coin_id: [u8; 32], parent: [u8; 32]) -> OutputCoin {
        OutputCoin {
            puzzle_hash: [0x11u8; 32].into(),
            coin_id: coin_id.into(),
            amount: 1000,
            parent_coin_id: parent.into(),
        }
    }

    #[test]
    fn test_utxo_aware_keeps_group_with_unspent_output_and_drops_fully_spent_group() {
        let mut index = TweakIndex::open_in_memory().unwrap();

        // Input coins of the groups. All of them are spent in this block, as
        // input coins always are; that must not decide anything.
        let in_a = [0xA0u8; 32];
        let in_b = [0xB0u8; 32];
        let in_c1 = [0xC1u8; 32];
        let in_c2 = [0xC2u8; 32];
        let in_d = [0xD0u8; 32];
        let in_e = [0xE0u8; 32];

        // Outputs, by the group that created them.
        let out_a1 = [0xA1u8; 32]; // spent
        let out_a2 = [0xA2u8; 32]; // spent
        let out_b1 = [0xB1u8; 32]; // spent
        let out_b2 = [0xB2u8; 32]; // UNSPENT
        let out_c = [0xC3u8; 32]; //  UNSPENT, created by the second coin of a 2-coin group
        let out_d = [0xD1u8; 32]; //  not known to the full node

        let (t_a, t_b, t_c, t_d, t_e) =
            (tweak_for(1), tweak_for(2), tweak_for(3), tweak_for(4), tweak_for(5));

        let block = GroupedBlock {
            height: 100,
            header_hash: [1u8; 32].into(),
            groups: vec![
                group(0, t_a, &[in_a]),         // every output spent        -> dropped
                group(1, t_b, &[in_b]),         // one output still unspent  -> kept
                group(2, t_c, &[in_c1, in_c2]), // multi-input, unspent out  -> kept
                group(3, t_d, &[in_d]),         // output status unknown     -> kept
                group(4, t_e, &[in_e]),         // created no coin           -> dropped
            ],
            outputs: vec![
                output(out_a1, in_a),
                output(out_a2, in_a),
                output(out_b1, in_b),
                output(out_b2, in_b),
                output(out_c, in_c2),
                output(out_d, in_d),
            ],
        };
        index.store_block(&block).unwrap();

        let chia_reader = mock_chia_reader(&[
            (in_a, 100), (in_b, 100), (in_c1, 100), (in_c2, 100), (in_d, 100), (in_e, 100),
            (out_a1, 150), (out_a2, 200),
            (out_b1, 150), (out_b2, 0),
            (out_c, 0),
        ]);

        let (tweaks, outputs) = index.get_block_tweaks_utxo_aware(100, &chia_reader).unwrap().unwrap();

        let expected: Vec<Vec<u8>> =
            [t_b, t_c, t_d].iter().map(|t| t.to_bytes().to_vec()).collect();
        assert_eq!(tweaks, expected, "kept: unspent output (B, C) and unknown output (D)");
        assert_eq!(outputs.len(), 6, "the output list is not filtered");

        // The plain query still returns all five.
        assert_eq!(index.get_block_tweaks(100).unwrap().unwrap().0.len(), 5);
    }

    #[test]
    fn test_utxo_aware_group_is_dropped_once_its_last_output_is_spent() {
        let mut index = TweakIndex::open_in_memory().unwrap();
        let input = [0xA0u8; 32];
        let out1 = [0xA1u8; 32];
        let out2 = [0xA2u8; 32];
        let tweak = tweak_for(9);
        index.store_block(&GroupedBlock {
            height: 7,
            header_hash: [7u8; 32].into(),
            groups: vec![group(0, tweak, &[input])],
            outputs: vec![output(out1, input), output(out2, input)],
        }).unwrap();

        let count = |coins: &[([u8; 32], u32)]| {
            index.get_block_tweaks_utxo_aware(7, &mock_chia_reader(coins)).unwrap().unwrap().0.len()
        };
        // The input coin being spent (it always is) drops nothing.
        assert_eq!(count(&[(input, 7), (out1, 0), (out2, 0)]), 1);
        assert_eq!(count(&[(input, 7), (out1, 9), (out2, 0)]), 1);
        assert_eq!(count(&[(input, 7), (out1, 9), (out2, 12)]), 0);
    }
}
