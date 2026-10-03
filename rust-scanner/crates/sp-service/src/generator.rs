use chia_consensus::consensus_constants::TEST_CONSTANTS;
use chia_consensus::flags::ConsensusFlags;
use chia_consensus::run_block_generator::get_coinspends_for_trusted_block;
use chia_protocol::{CoinSpend, FullBlock};

use crate::block_reader::ChiaBlockReader;

/// Execute the block's transaction generator and return all coin spends.
///
/// Resolves reference generators from transactions_generator_ref_list by
/// fetching them from the Chia DB via the block reader.
///
/// Skips non-transaction blocks (transactions_generator is None).
///
/// Uses `get_coinspends_for_trusted_block` which returns `Vec<CoinSpend>`
/// with puzzle_reveal and solution for each spend. This is safe for trusted
/// local DB reads where we don't need full validation.
pub fn extract_coin_spends(
    reader: &ChiaBlockReader,
    block: &FullBlock,
) -> Result<Vec<CoinSpend>, Box<dyn std::error::Error>> {
    let generator = match &block.transactions_generator {
        Some(g) => g,
        None => return Ok(vec![]),
    };

    // Resolve reference generators
    let mut ref_generators: Vec<Vec<u8>> = Vec::new();
    for ref_height in &block.transactions_generator_ref_list {
        let ref_gen = reader
            .get_ref_generator(*ref_height)?
            .ok_or_else(|| format!("missing ref generator at height {}", ref_height))?;
        ref_generators.push(ref_gen);
    }

    let ref_slices: Vec<&[u8]> = ref_generators.iter().map(|r| r.as_slice()).collect();

    // Use get_coinspends_for_trusted_block which returns Vec<CoinSpend>
    // with puzzle_reveal and solution for each spend.
    // DONT_VALIDATE_SIGNATURE since we trust blocks from local DB.
    let coin_spends = get_coinspends_for_trusted_block(
        &TEST_CONSTANTS,
        generator,
        ref_slices,
        ConsensusFlags::DONT_VALIDATE_SIGNATURE,
    )?;

    Ok(coin_spends)
}
