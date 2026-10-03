use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin};

/// Data extracted from a single coin spend with a standard p2 puzzle.
#[derive(Debug, Clone)]
pub struct SpendData {
    /// The coin being spent.
    pub coin: Coin,
    /// Coin ID = SHA256(parent_coin_info || puzzle_hash || amount).
    pub coin_id: Bytes32,
    /// The synthetic public key extracted from the standard p2 puzzle.
    pub synthetic_pk: PublicKey,
    /// Conditions output by running the puzzle with its solution.
    /// Each condition is (opcode, list of argument byte-vecs).
    pub conditions: Vec<(u16, Vec<Vec<u8>>)>,
}

/// All standard p2 spends extracted from a single block.
#[derive(Debug, Clone)]
pub struct BlockSpends {
    /// Block height.
    pub height: u32,
    /// Header hash of this block.
    pub header_hash: Bytes32,
    /// Standard p2 spends with extracted synthetic PKs and conditions.
    pub spends: Vec<SpendData>,
    /// All new coins created in this block (output puzzle_hash, coin_id, amount, parent_coin_id).
    pub outputs: Vec<OutputCoin>,
}

/// A new coin created in a block (for client matching).
#[derive(Debug, Clone)]
pub struct OutputCoin {
    pub puzzle_hash: Bytes32,
    pub coin_id: Bytes32,
    pub amount: u64,
    pub parent_coin_id: Bytes32,
}
