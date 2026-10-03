use chia_bls::PublicKey;
use chia_protocol::Program;
use chia_puzzle_types::standard::StandardArgs;
use chia_puzzles::P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE_HASH;
use clvm_traits::FromClvm;
use clvm_utils::{tree_hash, CurriedProgram};
use clvmr::{serde::node_from_bytes, Allocator, NodePtr};

/// Extract the synthetic public key from a coin spend's puzzle reveal.
///
/// Attempts to uncurry the puzzle as a standard p2_delegated_puzzle_or_hidden_puzzle.
/// Returns None if the puzzle is non-standard (CAT, NFT, singleton, etc).
///
/// Uses CurriedProgram<NodePtr, StandardArgs>::from_clvm() for type-safe uncurry.
/// StandardArgs.synthetic_key is already the synthetic key (includes hidden puzzle offset).
///
/// Additionally verifies the uncurried program hash matches the known
/// P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE_HASH to avoid false positives from
/// non-standard puzzles that happen to have a single 48-byte curried argument.
pub fn extract_synthetic_pk(a: &Allocator, puzzle_node: NodePtr) -> Option<PublicKey> {
    let curried =
        CurriedProgram::<NodePtr, StandardArgs>::from_clvm(a, puzzle_node).ok()?;
    // Verify the uncurried program is the standard p2 puzzle
    let program_hash = tree_hash(a, curried.program);
    if program_hash != P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE_HASH.into() {
        return None;
    }
    Some(curried.args.synthetic_key)
}

/// Extract synthetic PK from a CoinSpend's puzzle_reveal Program.
/// Convenience wrapper that creates an Allocator and deserializes the program.
pub fn extract_synthetic_pk_from_program(puzzle: &Program) -> Option<PublicKey> {
    let mut a = Allocator::new();
    let node = node_from_bytes(&mut a, puzzle.as_ref()).ok()?;
    extract_synthetic_pk(&a, node)
}
