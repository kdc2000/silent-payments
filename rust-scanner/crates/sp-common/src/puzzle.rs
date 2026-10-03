//! Puzzle hash computation from public key via StandardArgs.

use chia_bls::PublicKey;
use chia_puzzle_types::DeriveSynthetic;
use chia_puzzle_types::standard::StandardArgs;
use clvm_utils::TreeHash;

/// Compute the standard puzzle hash for a given public key.
///
/// Derives the synthetic public key and uses StandardArgs::curry_tree_hash
/// to compute the puzzle hash directly from the tree structure (no CLVM
/// serialization needed).
pub fn puzzle_hash_for_pk(pk: &PublicKey) -> [u8; 32] {
    let synthetic_pk = pk.derive_synthetic();
    let tree_hash: TreeHash = StandardArgs::curry_tree_hash(synthetic_pk);
    tree_hash.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_puzzle_hash_tv1() {
        // One-time PK from test vector 1
        let pk_bytes: [u8; 48] = hex::decode(
            "b671487c1d275842f529f7a73a63a32a9a1a49e1dbabcac4058cc48626b6db31f48dc49e769a6f8076a9111ff14e964d"
        ).unwrap().try_into().unwrap();
        let pk = PublicKey::from_bytes(&pk_bytes).unwrap();
        let ph = puzzle_hash_for_pk(&pk);
        assert_eq!(
            hex::encode(ph),
            "23adba149dd9000d65e0f8e21b6975364cbe89a63caf56533df4b7664c21fbf5"
        );
    }
}
