use crate::block_reader::ChiaBlockReader;
use crate::tweak_index::TweakIndex;

/// Prune blocks from the tweak index whose outputs are ALL spent on-chain.
///
/// Blocks with no outputs (empty blocks) are also pruned since they contain
/// no unspent coins. Returns the count of pruned blocks.
///
/// Batches coin_id lookups per block (not across blocks) since
/// `check_coins_spent` already batches internally in chunks of 500.
pub fn prune_spent_blocks(
    index: &mut TweakIndex,
    chia_reader: &ChiaBlockReader,
) -> Result<u32, Box<dyn std::error::Error>> {
    let heights = index.get_indexed_heights()?;
    let mut pruned = 0u32;

    for height in heights {
        let coin_ids = index.get_block_coin_ids(height)?;

        if coin_ids.is_empty() {
            // No outputs = no reason to keep tweak data
            tracing::debug!("Pruning empty block {}", height);
            index.delete_block(height)?;
            pruned += 1;
            continue;
        }

        // Check if all coins are spent
        let spent_map = chia_reader.check_coins_spent(&coin_ids)?;
        let all_spent = coin_ids.iter().all(|id| {
            matches!(spent_map.get(id), Some(Some(_)))
        });

        if all_spent {
            tracing::debug!("Pruning fully-spent block {}", height);
            index.delete_block(height)?;
            pruned += 1;
        } else {
            tracing::debug!("Keeping block {} (has unspent outputs)", height);
        }
    }

    tracing::info!("Spent-block pruning complete: {} blocks pruned", pruned);
    Ok(pruned)
}

/// Prune all blocks below the given minimum height from the tweak index.
///
/// Returns the count of pruned blocks.
pub fn prune_below_height(
    index: &mut TweakIndex,
    min_height: u32,
) -> Result<u32, Box<dyn std::error::Error>> {
    let heights = index.get_indexed_heights()?;
    let mut pruned = 0u32;

    for height in heights {
        if height >= min_height {
            break; // Heights are sorted, no more below min_height
        }
        tracing::debug!("Pruning block {} (below min height {})", height, min_height);
        index.delete_block(height)?;
        pruned += 1;
    }

    tracing::info!("Below-height pruning complete: {} blocks pruned (min_height={})", pruned, min_height);
    Ok(pruned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grouping::{GroupedBlock, SpendGroup};
    use crate::types::OutputCoin;
    use chia_bls::PublicKey;
    use chia_protocol::Bytes32;
    use rusqlite::Connection;

    /// Helper to create a test block with outputs at specified coin_ids.
    fn make_block_with_outputs(height: u32, coin_ids: &[[u8; 32]]) -> GroupedBlock {
        let header_hash: Bytes32 = [height as u8; 32].into();
        let outputs: Vec<OutputCoin> = coin_ids
            .iter()
            .map(|cid| OutputCoin {
                puzzle_hash: [0x11u8; 32].into(),
                coin_id: (*cid).into(),
                amount: 1000,
                parent_coin_id: [0x33u8; 32].into(),
            })
            .collect();

        // Create a tweak group so tweak data gets stored
        let tweak_group = SpendGroup {
            spend_indices: vec![0],
            a_sum: PublicKey::default(),
            tweak_point: Some(PublicKey::default()),
            coin_ids: coin_ids.iter().map(|c| (*c).into()).collect(),
        };

        GroupedBlock {
            height,
            header_hash,
            groups: vec![tweak_group],
            outputs,
        }
    }

    /// Helper to create a block with no outputs and no tweak groups.
    fn make_empty_block(height: u32) -> GroupedBlock {
        let header_hash: Bytes32 = [height as u8; 32].into();
        GroupedBlock {
            height,
            header_hash,
            groups: vec![],
            outputs: vec![],
        }
    }

    /// Helper to set up a mock Chia DB with coin_record entries.
    /// `coins` is a list of (coin_name, spent_index) where spent_index=0 means unspent.
    fn setup_mock_chia_reader(coins: &[([u8; 32], u32)]) -> ChiaBlockReader {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
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

        for (name, spent_index) in coins {
            conn.execute(
                "INSERT INTO coin_record (coin_name, confirmed_index, spent_index, coinbase, puzzle_hash, coin_parent, amount, timestamp)
                 VALUES (?1, 50, ?2, 0, ?3, ?3, X'00', 0)",
                rusqlite::params![name.as_slice(), *spent_index, [0u8; 32].as_slice()],
            ).unwrap();
        }

        ChiaBlockReader::from_connection(conn)
    }

    // --- TweakIndex helper method tests ---

    #[test]
    fn test_get_indexed_heights_empty_db() {
        let index = TweakIndex::open_in_memory().unwrap();
        let heights = index.get_indexed_heights().unwrap();
        assert!(heights.is_empty());
    }

    #[test]
    fn test_get_indexed_heights_sorted() {
        let mut index = TweakIndex::open_in_memory().unwrap();
        // Store blocks in non-sorted order
        let coin_a = [0xAAu8; 32];
        let coin_b = [0xBBu8; 32];
        let coin_c = [0xCCu8; 32];

        index.store_block(&make_block_with_outputs(300, &[coin_c])).unwrap();
        index.store_block(&make_block_with_outputs(100, &[coin_a])).unwrap();
        index.store_block(&make_block_with_outputs(200, &[coin_b])).unwrap();

        let heights = index.get_indexed_heights().unwrap();
        assert_eq!(heights, vec![100, 200, 300]);
    }

    #[test]
    fn test_get_block_coin_ids_returns_coins() {
        let mut index = TweakIndex::open_in_memory().unwrap();
        let coin_a = [0xAAu8; 32];
        let coin_b = [0xBBu8; 32];

        index.store_block(&make_block_with_outputs(100, &[coin_a, coin_b])).unwrap();

        let coin_ids = index.get_block_coin_ids(100).unwrap();
        assert_eq!(coin_ids.len(), 2);
        assert!(coin_ids.contains(&coin_a));
        assert!(coin_ids.contains(&coin_b));
    }

    #[test]
    fn test_get_block_coin_ids_empty_for_no_outputs() {
        let mut index = TweakIndex::open_in_memory().unwrap();
        index.store_block(&make_empty_block(100)).unwrap();

        let coin_ids = index.get_block_coin_ids(100).unwrap();
        assert!(coin_ids.is_empty());
    }

    #[test]
    fn test_delete_block_removes_all_tables() {
        let mut index = TweakIndex::open_in_memory().unwrap();
        let coin_a = [0xAAu8; 32];

        let block = make_block_with_outputs(100, &[coin_a]);
        index.store_block(&block).unwrap();

        // Also store a filter for this block
        index.store_block_filter(100, &[1u8; 32], &[1, 2, 3]).unwrap();

        // Verify data exists
        assert!(index.get_block_tweaks(100).unwrap().is_some());
        assert!(index.get_block_filter(100).unwrap().is_some());

        // Delete the block
        index.delete_block(100).unwrap();

        // Verify all data is gone
        assert!(index.get_block_tweaks(100).unwrap().is_none());
        assert!(index.get_block_filter(100).unwrap().is_none());
        assert!(index.get_block_coin_ids(100).unwrap().is_empty());
        // indexed_blocks should be gone too
        let heights = index.get_indexed_heights().unwrap();
        assert!(!heights.contains(&100));
    }

    #[test]
    fn test_delete_block_does_not_affect_other_heights() {
        let mut index = TweakIndex::open_in_memory().unwrap();
        let coin_a = [0xAAu8; 32];
        let coin_b = [0xBBu8; 32];

        index.store_block(&make_block_with_outputs(100, &[coin_a])).unwrap();
        index.store_block(&make_block_with_outputs(200, &[coin_b])).unwrap();

        index.delete_block(100).unwrap();

        // Block 100 should be gone
        assert!(index.get_block_tweaks(100).unwrap().is_none());
        // Block 200 should still exist
        assert!(index.get_block_tweaks(200).unwrap().is_some());
        let coin_ids_200 = index.get_block_coin_ids(200).unwrap();
        assert_eq!(coin_ids_200.len(), 1);
        assert!(coin_ids_200.contains(&coin_b));
    }

    // --- prune_spent_blocks tests ---

    #[test]
    fn test_prune_spent_blocks_deletes_fully_spent() {
        let mut index = TweakIndex::open_in_memory().unwrap();

        // Block 100 with all coins spent
        let coin_spent = [0xAAu8; 32];
        index.store_block(&make_block_with_outputs(100, &[coin_spent])).unwrap();

        // Block 200 with an unspent coin
        let coin_unspent = [0xBBu8; 32];
        index.store_block(&make_block_with_outputs(200, &[coin_unspent])).unwrap();

        let chia_reader = setup_mock_chia_reader(&[
            (coin_spent, 500),    // spent at height 500
            (coin_unspent, 0),    // unspent
        ]);

        let pruned = prune_spent_blocks(&mut index, &chia_reader).unwrap();
        assert_eq!(pruned, 1);

        // Block 100 should be gone
        assert!(index.get_block_tweaks(100).unwrap().is_none());
        // Block 200 should remain
        assert!(index.get_block_tweaks(200).unwrap().is_some());
    }

    #[test]
    fn test_prune_spent_blocks_handles_empty_blocks() {
        let mut index = TweakIndex::open_in_memory().unwrap();

        // Empty block (no outputs) -- should be pruned
        index.store_block(&make_empty_block(100)).unwrap();

        // Block with unspent coin -- should remain
        let coin_unspent = [0xBBu8; 32];
        index.store_block(&make_block_with_outputs(200, &[coin_unspent])).unwrap();

        let chia_reader = setup_mock_chia_reader(&[
            (coin_unspent, 0),
        ]);

        let pruned = prune_spent_blocks(&mut index, &chia_reader).unwrap();
        assert_eq!(pruned, 1);

        // Empty block should be gone
        let heights = index.get_indexed_heights().unwrap();
        assert!(!heights.contains(&100));
        // Block 200 should remain
        assert!(heights.contains(&200));
    }

    // --- prune_below_height tests ---

    #[test]
    fn test_prune_below_height_removes_below() {
        let mut index = TweakIndex::open_in_memory().unwrap();

        let coin_a = [0xAAu8; 32];
        let coin_b = [0xBBu8; 32];
        let coin_c = [0xCCu8; 32];

        index.store_block(&make_block_with_outputs(100, &[coin_a])).unwrap();
        index.store_block(&make_block_with_outputs(200, &[coin_b])).unwrap();
        index.store_block(&make_block_with_outputs(300, &[coin_c])).unwrap();

        let pruned = prune_below_height(&mut index, 200).unwrap();
        assert_eq!(pruned, 1); // Only block 100 is below 200

        let heights = index.get_indexed_heights().unwrap();
        assert!(!heights.contains(&100)); // Pruned
        assert!(heights.contains(&200));  // At threshold -- kept
        assert!(heights.contains(&300));  // Above -- kept
    }

    #[test]
    fn test_prune_below_height_zero_deletes_nothing() {
        let mut index = TweakIndex::open_in_memory().unwrap();

        let coin_a = [0xAAu8; 32];
        index.store_block(&make_block_with_outputs(100, &[coin_a])).unwrap();

        let pruned = prune_below_height(&mut index, 0).unwrap();
        assert_eq!(pruned, 0);

        let heights = index.get_indexed_heights().unwrap();
        assert_eq!(heights, vec![100]);
    }
}
