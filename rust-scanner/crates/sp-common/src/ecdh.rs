//! ECDH shared secret computation for silent payments.

use chia_bls::{PublicKey, SecretKey};
use sha2::{Sha256, Digest};

use crate::scalar::ScalarField;
use crate::tagged_hash::tagged_hash;

/// Compute sender-side ECDH shared secret: SHA256((input_hash * sender_sk) * scan_pk).
pub fn compute_shared_secret_sender(
    sender_sk: &ScalarField,
    scan_pk: &PublicKey,
    input_hash: &ScalarField,
) -> [u8; 32] {
    let adjusted = input_hash.mul(sender_sk);
    let mut point = *scan_pk;
    point.scalar_multiply(adjusted.as_bytes());
    Sha256::digest(point.to_bytes()).into()
}

/// Compute scanner-side ECDH shared secret: SHA256(scan_sk * (input_hash * sender_pk)).
pub fn compute_shared_secret_scanner(
    scan_sk: &SecretKey,
    sender_pk: &PublicKey,
    input_hash: &ScalarField,
) -> [u8; 32] {
    let mut point = *sender_pk;
    point.scalar_multiply(input_hash.as_bytes());
    point.scalar_multiply(&scan_sk.to_bytes());
    Sha256::digest(point.to_bytes()).into()
}

/// Compute the shared secret from a spend group's tweak point.
///
/// The tweak point is T = input_hash * A_sum (CHIP-0057 "Tweak Points"), so
/// SHA256(serialize(scan_sk * T)) equals [`compute_shared_secret_scanner`].
///
/// The caller MUST have checked that `tweak_point` is in the prime-order
/// subgroup (`PublicKey::from_bytes` does) and is not the identity.
pub fn compute_shared_secret_from_tweak(scan_sk: &SecretKey, tweak_point: &PublicKey) -> [u8; 32] {
    let mut point = *tweak_point;
    point.scalar_multiply(&scan_sk.to_bytes());
    Sha256::digest(point.to_bytes()).into()
}

/// Compute input hash from coin IDs and sender public key.
///
/// Uses the lexicographically smallest coin ID and the sender's (aggregated)
/// public key: tagged_hash("Chia_SP/Inputs", coin_id_L || sender_pk_bytes).
///
/// The result can be zero (with probability about 1/r); senders must fail and
/// scanners must skip the group in that case.
///
/// # Panics
///
/// Panics if `coin_ids` is empty: a spend group has at least one coin.
pub fn compute_input_hash(coin_ids: &[&[u8; 32]], sender_pk: &PublicKey) -> ScalarField {
    let coin_id_l = coin_ids.iter().min().expect("coin_ids must not be empty");
    let pk_bytes = sender_pk.to_bytes();
    let mut data = Vec::with_capacity(32 + 48);
    data.extend_from_slice(coin_id_l.as_slice());
    data.extend_from_slice(&pk_bytes);
    let hash = tagged_hash("Chia_SP/Inputs", &data);
    ScalarField::from_bytes_unsigned(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test Vector 1 constants
    fn tv1_coin_id() -> [u8; 32] {
        sha2::Sha256::digest(b"test-vector-1-coin").into()
    }

    fn tv1_sender_syn_sk() -> ScalarField {
        let bytes: [u8; 32] = hex::decode(
            "5002eaf015c1c3a9694cc054e96273279732f4f963616ff89b6d4addcd678c7a"
        ).unwrap().try_into().unwrap();
        ScalarField::from_bytes_raw(bytes)
    }

    fn tv1_sender_pk() -> PublicKey {
        let bytes: [u8; 48] = hex::decode(
            "8d9a5ed9c9b1a58476b07262007c636d775f2a33f0533737f3b3b0eaf99a8c0c51b3f2d87dc03a657e07f1828ab760fa"
        ).unwrap().try_into().unwrap();
        PublicKey::from_bytes(&bytes).unwrap()
    }

    fn tv1_scan_pk() -> PublicKey {
        let bytes: [u8; 48] = hex::decode(
            "a04f404bfbfdc9311736899fe32d2275bb007814510c3523529487ad7573607573ade20d31c75107b40331fff79ac896"
        ).unwrap().try_into().unwrap();
        PublicKey::from_bytes(&bytes).unwrap()
    }

    fn tv1_scan_sk() -> SecretKey {
        let bytes: [u8; 32] = hex::decode(
            "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6"
        ).unwrap().try_into().unwrap();
        SecretKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn test_compute_input_hash_tv1() {
        let coin_id = tv1_coin_id();
        assert_eq!(
            hex::encode(coin_id),
            "5d759d2d97c03b1f6fe0657e91d25f6b7dd1311d6023271a1bcd35978a94a175"
        );
        let sender_pk = tv1_sender_pk();
        let input_hash = compute_input_hash(&[&coin_id], &sender_pk);
        let hex_str = hex::encode(input_hash.as_bytes());
        assert!(hex_str.starts_with("38a1c837"), "input_hash should start with 38a1c837, got {}", hex_str);
        assert_eq!(
            hex_str,
            "38a1c8379cceb0fbebfdf3016707e54a1c7e9d21afb9489b9cc58f6055cc9411"
        );
    }

    #[test]
    fn test_shared_secret_sender_tv1() {
        let coin_id = tv1_coin_id();
        let sender_pk = tv1_sender_pk();
        let input_hash = compute_input_hash(&[&coin_id], &sender_pk);
        let sender_sk = tv1_sender_syn_sk();
        let scan_pk = tv1_scan_pk();

        // Verify ECDH point (check the intermediate)
        let adjusted = input_hash.mul(&sender_sk);
        let mut point = scan_pk;
        point.scalar_multiply(adjusted.as_bytes());
        let ecdh_point_hex = hex::encode(point.to_bytes());
        assert!(
            ecdh_point_hex.starts_with("aa15516b"),
            "ECDH point should start with aa15516b, got {}",
            ecdh_point_hex
        );

        let shared_secret = compute_shared_secret_sender(&sender_sk, &tv1_scan_pk(), &input_hash);
        assert_eq!(
            hex::encode(shared_secret),
            "d3ac1e8f651a73d2e20b43cb73fd6997de5504afbc04a2d4546a92d0020ba2c6"
        );
    }

    #[test]
    fn test_shared_secret_scanner_tv1() {
        let coin_id = tv1_coin_id();
        let sender_pk = tv1_sender_pk();
        let input_hash = compute_input_hash(&[&coin_id], &sender_pk);
        let scan_sk = tv1_scan_sk();

        let shared_secret = compute_shared_secret_scanner(&scan_sk, &sender_pk, &input_hash);
        assert!(
            hex::encode(shared_secret).starts_with("d3ac1e8f"),
            "scanner shared secret should start with d3ac1e8f"
        );
        assert_eq!(
            hex::encode(shared_secret),
            "d3ac1e8f651a73d2e20b43cb73fd6997de5504afbc04a2d4546a92d0020ba2c6"
        );
    }

    #[test]
    fn test_sender_scanner_agree() {
        let coin_id = tv1_coin_id();
        let sender_pk = tv1_sender_pk();
        let input_hash = compute_input_hash(&[&coin_id], &sender_pk);
        let sender_sk = tv1_sender_syn_sk();
        let scan_pk = tv1_scan_pk();
        let scan_sk = tv1_scan_sk();

        let sender_secret = compute_shared_secret_sender(&sender_sk, &scan_pk, &input_hash);
        let scanner_secret = compute_shared_secret_scanner(&scan_sk, &sender_pk, &input_hash);
        assert_eq!(sender_secret, scanner_secret);
    }
}
