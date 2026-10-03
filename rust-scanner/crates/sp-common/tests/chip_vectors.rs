//! Integration tests for the CHIP-0057 test vectors (1-4 and 6-8).
//!
//! Each test validates every intermediate cryptographic value from the CHIP
//! specification's test vector tables, proving byte-identical cross-language
//! compatibility between Rust sp-common and the Python implementations.
//!
//! Vectors 1-7 treat the recipient's scan and spend secret keys as GIVEN
//! values; they are not what `master_to_scan_sk` / `master_to_spend_sk` derive
//! (that is Vector 8). The given keys are taken from the hex the CHIP prints
//! ([`tv_given_scan_sk`], [`tv_given_spend_sk`]). Test Vector 2's recipient B
//! is listed in the CHIP by public key only, so its secret keys come from the
//! test-only helper [`tv2_recipient_b_legacy_unhardened_sk`].
//!
//! Vector 5 (address encoding) and the address rows of Vector 8 are not
//! covered here: these crates contain no address codec.

use std::collections::HashMap;

use sha2::{Sha256, Digest};

use chia_bls::DerivableKey;
use chia_puzzle_types::DeriveSynthetic;

use sp_common::{
    mnemonic_to_master_sk, master_to_wallet_sk, master_to_scan_sk, master_to_spend_sk,
    compute_shared_secret_sender, compute_shared_secret_scanner, compute_input_hash,
    puzzle_hash_for_pk,
    derive_output_tweak, derive_onetime_pk, derive_onetime_sk,
    generate_label, create_silent_payment_outputs, scan_for_silent_payments,
    aggregate_sender_sks, spend_tweak,
    PublicKey, ScalarField, SecretKey,
};

const TEST_MNEMONIC_1: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const TEST_MNEMONIC_2: &str =
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

/// "Recipient scan SK (b_scan, given)" of CHIP Test Vector 1, reused by
/// Vectors 2 (recipient A), 3, 4, 6 and 7.
const TV_GIVEN_SCAN_SK_HEX: &str =
    "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6";
/// "Recipient spend SK (b_spend, given)" of CHIP Test Vector 1.
const TV_GIVEN_SPEND_SK_HEX: &str =
    "53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087";
/// "Recipient scan PK (B_scan)" of CHIP Test Vector 1.
const TV_GIVEN_SCAN_PK_HEX: &str =
    "a04f404bfbfdc9311736899fe32d2275bb007814510c3523529487ad7573607573ade20d31c75107b40331fff79ac896";
/// "Recipient spend PK (B_spend)" of CHIP Test Vector 1.
const TV_GIVEN_SPEND_PK_HEX: &str =
    "8afc580192f44fab624f613369f792eff3220ea3ca822eb839ab2c9309e527dbf6f31e22e0831ba5088c952625a75c74";

fn sk_from_hex(hex_str: &str) -> SecretKey {
    let bytes: [u8; 32] = hex::decode(hex_str).unwrap().try_into().unwrap();
    SecretKey::from_bytes(&bytes).unwrap()
}

/// TEST ONLY: the given recipient scan secret key of Test Vectors 1-7.
fn tv_given_scan_sk() -> SecretKey {
    sk_from_hex(TV_GIVEN_SCAN_SK_HEX)
}

/// TEST ONLY: the given recipient spend secret key of Test Vectors 1-7.
fn tv_given_spend_sk() -> SecretKey {
    sk_from_hex(TV_GIVEN_SPEND_SK_HEX)
}

/// TEST ONLY: secret keys of Test Vector 2's recipient B.
///
/// The CHIP gives recipient B's public keys but not its secret keys, and the
/// scanner-B check needs the scan secret key. The keys are the UNHARDENED
/// derivation m/12381/8444/<purpose>/0 (the one silent payment addresses used
/// before the CHIP required hardened derivation) from the "zoo ... wrong"
/// mnemonic (purpose 12 = scan, 13 = spend). Callers assert the resulting
/// public keys against the CHIP's hex. Never use this derivation for a wallet.
fn tv2_recipient_b_legacy_unhardened_sk(purpose: u32) -> SecretKey {
    mnemonic_to_master_sk(TEST_MNEMONIC_2)
        .derive_unhardened(12381)
        .derive_unhardened(8444)
        .derive_unhardened(purpose)
        .derive_unhardened(0)
}

/// Derive the synthetic secret key for a wallet SK (same as Python's
/// `calculate_synthetic_secret_key`).
fn synthetic_sk(sk: &SecretKey) -> SecretKey {
    sk.derive_synthetic()
}

/// SHA256 helper for computing coin IDs from test strings.
fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// -------------------------------------------------------------------------
// Test Vector 1: Single Output Payment
// -------------------------------------------------------------------------

#[test]
fn test_chip_vector_1() {
    // --- Key Derivation ---
    let master = mnemonic_to_master_sk(TEST_MNEMONIC_1);
    let wallet_sk = master_to_wallet_sk(&master, 0);
    assert_eq!(
        hex::encode(wallet_sk.to_bytes()),
        "6c8d1a9f97413f8d8e8c158f5bc875b58b498de05c9109b4dc240280d32e2a31"
    );

    let syn_sk = synthetic_sk(&wallet_sk);
    assert_eq!(
        hex::encode(syn_sk.to_bytes()),
        "5002eaf015c1c3a9694cc054e96273279732f4f963616ff89b6d4addcd678c7a"
    );

    let syn_pk = syn_sk.public_key();
    assert_eq!(
        hex::encode(syn_pk.to_bytes()),
        "8d9a5ed9c9b1a58476b07262007c636d775f2a33f0533737f3b3b0eaf99a8c0c51b3f2d87dc03a657e07f1828ab760fa"
    );

    // Recipient keys are given values (not derived from the mnemonic).
    let scan_sk = tv_given_scan_sk();
    assert_eq!(
        hex::encode(scan_sk.to_bytes()),
        "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6"
    );

    let scan_pk = scan_sk.public_key();
    assert_eq!(
        hex::encode(scan_pk.to_bytes()),
        "a04f404bfbfdc9311736899fe32d2275bb007814510c3523529487ad7573607573ade20d31c75107b40331fff79ac896"
    );

    let spend_sk = tv_given_spend_sk();
    assert_eq!(
        hex::encode(spend_sk.to_bytes()),
        "53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087"
    );

    let spend_pk = spend_sk.public_key();
    assert_eq!(
        hex::encode(spend_pk.to_bytes()),
        "8afc580192f44fab624f613369f792eff3220ea3ca822eb839ab2c9309e527dbf6f31e22e0831ba5088c952625a75c74"
    );

    // --- Coin ID ---
    let coin_id = sha256(b"test-vector-1-coin");
    assert_eq!(
        hex::encode(coin_id),
        "5d759d2d97c03b1f6fe0657e91d25f6b7dd1311d6023271a1bcd35978a94a175"
    );

    // --- Protocol Execution ---
    let sender_sk_scalar = ScalarField::from_bytes_raw(syn_sk.to_bytes());
    let input_hash = compute_input_hash(&[&coin_id], &syn_pk);
    assert_eq!(
        hex::encode(input_hash.as_bytes()),
        "38a1c8379cceb0fbebfdf3016707e54a1c7e9d21afb9489b9cc58f6055cc9411"
    );

    // ECDH point intermediate check
    let adjusted = input_hash.mul(&sender_sk_scalar);
    let mut ecdh_point = scan_pk;
    ecdh_point.scalar_multiply(adjusted.as_bytes());
    assert_eq!(
        hex::encode(ecdh_point.to_bytes()),
        "aa15516b2b572ebedcd3c048c07189485f8374449923389534125e99763845700d6d84d8edaf73b6516874d9a798de09"
    );

    // Shared secret (sender side)
    let shared_secret = compute_shared_secret_sender(&sender_sk_scalar, &scan_pk, &input_hash);
    assert_eq!(
        hex::encode(shared_secret),
        "d3ac1e8f651a73d2e20b43cb73fd6997de5504afbc04a2d4546a92d0020ba2c6"
    );

    // Scanner side agrees
    let scanner_secret = compute_shared_secret_scanner(&scan_sk, &syn_pk, &input_hash);
    assert_eq!(shared_secret, scanner_secret);

    // Output tweak t_0
    let t_0 = derive_output_tweak(&shared_secret, 0);
    assert_eq!(
        hex::encode(t_0.as_bytes()),
        "5c560301c50fa309ad43d0f82cd1af143f6e3769659c80e8c14a072331582ab1"
    );

    // One-time PK
    let onetime_pk = derive_onetime_pk(&spend_pk, &t_0);
    assert_eq!(
        hex::encode(onetime_pk.to_bytes()),
        "b671487c1d275842f529f7a73a63a32a9a1a49e1dbabcac4058cc48626b6db31f48dc49e769a6f8076a9111ff14e964d"
    );

    // Puzzle hash
    let puzzle_hash = puzzle_hash_for_pk(&onetime_pk);
    assert_eq!(
        hex::encode(puzzle_hash),
        "23adba149dd9000d65e0f8e21b6975364cbe89a63caf56533df4b7664c21fbf5"
    );

    // One-time SK and key-pair consistency
    let onetime_sk = derive_onetime_sk(&spend_sk, &t_0);
    assert_eq!(
        hex::encode(onetime_sk.to_bytes()),
        "3c399c61ae130724903b3b650e936ff042b7646764289a33519e17100a89db37"
    );
    assert_eq!(onetime_sk.public_key().to_bytes(), onetime_pk.to_bytes());

    // Scanner detection end-to-end
    let detected = scan_for_silent_payments(
        &scan_sk, &spend_pk, &syn_pk, &[&coin_id], &[puzzle_hash], None,
    );
    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].puzzle_hash, puzzle_hash);
    assert_eq!(detected[0].k, 0);
    assert!(detected[0].label.is_none());
}

// -------------------------------------------------------------------------
// Test Vector 2: Multi-Output Payment
// -------------------------------------------------------------------------

#[test]
fn test_chip_vector_2() {
    // --- Key Derivation (Sender) ---
    let master_a = mnemonic_to_master_sk(TEST_MNEMONIC_1);
    let wallet_sk = master_to_wallet_sk(&master_a, 0);
    let syn_sk = synthetic_sk(&wallet_sk);
    let syn_pk = syn_sk.public_key();
    let sender_sk_scalar = ScalarField::from_bytes_raw(syn_sk.to_bytes());

    // --- Recipient A = the given keys of TV1 ---
    let scan_sk_a = tv_given_scan_sk();
    let scan_pk_a = scan_sk_a.public_key();
    assert_eq!(hex::encode(scan_pk_a.to_bytes()), TV_GIVEN_SCAN_PK_HEX);
    let spend_pk_a = tv_given_spend_sk().public_key();
    assert_eq!(hex::encode(spend_pk_a.to_bytes()), TV_GIVEN_SPEND_PK_HEX);

    // --- Recipient B: given keys, listed in the CHIP by public key only ---
    let scan_sk_b = tv2_recipient_b_legacy_unhardened_sk(12);
    let scan_pk_b = scan_sk_b.public_key();
    assert_eq!(
        hex::encode(scan_pk_b.to_bytes()),
        "904b64222fcc0bcf254bcfadcd579cf0530b4fba7ed454f3e6d85799cc9f54913f048f1fb393e4acf1bbe56d09d73108"
    );

    let spend_pk_b = tv2_recipient_b_legacy_unhardened_sk(13).public_key();
    assert_eq!(
        hex::encode(spend_pk_b.to_bytes()),
        "99c454a391281b0c0c25ca8175d93ba9d6c4ce9dabe5a25e28b38c2e9ce66aabe50a73f64a477b212ce110dac1e79813"
    );

    // --- Coin ID ---
    let coin_id = sha256(b"test-vector-2-coin");
    assert_eq!(
        hex::encode(coin_id),
        "b75c75c4787bade82b417272eff88ed90b3013a14b06c16be66b944856f378a2"
    );

    // --- Protocol Execution ---
    let input_hash = compute_input_hash(&[&coin_id], &syn_pk);
    assert_eq!(
        hex::encode(input_hash.as_bytes()),
        "42b39c642d50849aa93f23c34085d80bb6a236cad4e0edd2841d526838c92b22"
    );

    // Recipient A
    let shared_secret_a = compute_shared_secret_sender(&sender_sk_scalar, &scan_pk_a, &input_hash);
    assert_eq!(
        hex::encode(shared_secret_a),
        "e9b20a7df882357c76abb4b5f87dcfc9a64cda6413c85f61efa1c4e81e1be50d"
    );

    let t_a_0 = derive_output_tweak(&shared_secret_a, 0);
    assert_eq!(
        hex::encode(t_a_0.as_bytes()),
        "13682ff0957fce11761842863c1658c4cfe9dad4b312fb5fcd71f66567d33d9b"
    );

    let onetime_pk_a = derive_onetime_pk(&spend_pk_a, &t_a_0);
    assert_eq!(
        hex::encode(onetime_pk_a.to_bytes()),
        "97b332699dfd7741b3f0c8bf1e1a0edef3b4ad7a092a8f38d74f17216cfb1d0f5abe7d853f8e3223407be827c9c3aaa8"
    );

    let puzzle_hash_a = puzzle_hash_for_pk(&onetime_pk_a);
    assert_eq!(
        hex::encode(puzzle_hash_a),
        "596275d286042c639d97e3765fe89d0e5554ac250e0fb4c594a9165017c0a9e5"
    );

    // Recipient B
    let shared_secret_b = compute_shared_secret_sender(&sender_sk_scalar, &scan_pk_b, &input_hash);
    assert_eq!(
        hex::encode(shared_secret_b),
        "1450c748a04e4925bf34d0ef09e21fd1dab0eb0a3675efcb5b2da66d813c06e9"
    );

    let t_b_0 = derive_output_tweak(&shared_secret_b, 0);
    assert_eq!(
        hex::encode(t_b_0.as_bytes()),
        "21d2901f3189dc8def5c5a29e84933a5543ceabd131653dd2ea1951523045976"
    );

    let onetime_pk_b = derive_onetime_pk(&spend_pk_b, &t_b_0);
    assert_eq!(
        hex::encode(onetime_pk_b.to_bytes()),
        "a2557b2b6029fcc6783e8447588311a06b5d3dcad132a318d40bf0d6114595dd3d14fd58fe6f6c88dfa190aaa6bef873"
    );

    let puzzle_hash_b = puzzle_hash_for_pk(&onetime_pk_b);
    assert_eq!(
        hex::encode(puzzle_hash_b),
        "65249bcb907c9a6fac2e14499f6220cc24ba9359767d680c19405da06b69b263"
    );

    // Different recipients get different values
    assert_ne!(shared_secret_a, shared_secret_b);
    assert_ne!(puzzle_hash_a, puzzle_hash_b);

    // create_silent_payment_outputs end-to-end
    let outputs = create_silent_payment_outputs(
        &sender_sk_scalar,
        &[&coin_id],
        &[(scan_pk_a, spend_pk_a), (scan_pk_b, spend_pk_b)],
    )
    .expect("TV2 outputs");
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].1, puzzle_hash_a);
    assert_eq!(outputs[1].1, puzzle_hash_b);

    // Scanner A detects only their output
    let detected_a = scan_for_silent_payments(
        &scan_sk_a, &spend_pk_a, &syn_pk, &[&coin_id],
        &[puzzle_hash_a, puzzle_hash_b], None,
    );
    assert_eq!(detected_a.len(), 1);
    assert_eq!(detected_a[0].puzzle_hash, puzzle_hash_a);

    // Scanner B detects only their output
    let detected_b = scan_for_silent_payments(
        &scan_sk_b, &spend_pk_b, &syn_pk, &[&coin_id],
        &[puzzle_hash_a, puzzle_hash_b], None,
    );
    assert_eq!(detected_b.len(), 1);
    assert_eq!(detected_b[0].puzzle_hash, puzzle_hash_b);
}

// -------------------------------------------------------------------------
// Test Vector 3: Labeled Payment
// -------------------------------------------------------------------------

#[test]
fn test_chip_vector_3() {
    // --- Key Derivation ---
    let master = mnemonic_to_master_sk(TEST_MNEMONIC_1);
    let wallet_sk = master_to_wallet_sk(&master, 0);
    let syn_sk = synthetic_sk(&wallet_sk);
    let syn_pk = syn_sk.public_key();
    let sender_sk_scalar = ScalarField::from_bytes_raw(syn_sk.to_bytes());

    let scan_sk = tv_given_scan_sk();
    let scan_pk = scan_sk.public_key();
    assert_eq!(hex::encode(scan_pk.to_bytes()), TV_GIVEN_SCAN_PK_HEX);
    let spend_sk = tv_given_spend_sk();
    let spend_pk = spend_sk.public_key();
    assert_eq!(hex::encode(spend_pk.to_bytes()), TV_GIVEN_SPEND_PK_HEX);

    // --- Label Generation ---
    let (label_scalar, label_pk) = generate_label(&scan_sk, 1).unwrap();
    assert_eq!(
        hex::encode(label_scalar.as_bytes()),
        "48fa440acca87f501b9984b5d23327d0b7766a4baa913dfb3001d412c48ce465"
    );
    assert_eq!(
        hex::encode(label_pk.to_bytes()),
        "a6dcff3646739745ef7f3ba8e51808dac13765fa9d5e73386d3fbd7841e0773e02a0f8d91baf57d337954322bd06d80c"
    );

    // Labeled spend PK: B_m = B_spend + label_pk
    let b_m = &spend_pk + &label_pk;
    assert_eq!(
        hex::encode(b_m.to_bytes()),
        "965250fb8503cff4c244f360ab84075bfe2da01091745d0e8ce36024ab12e96277d1f02fbbe01cee412dd2ce1b7414c2"
    );

    // --- Coin ID ---
    let coin_id = sha256(b"test-vector-3-coin");
    assert_eq!(
        hex::encode(coin_id),
        "4504f59ea184be18924f95244649287382ec6cdc13f333a8990f648c803a6dac"
    );

    // --- Protocol Execution ---
    let input_hash = compute_input_hash(&[&coin_id], &syn_pk);
    assert_eq!(
        hex::encode(input_hash.as_bytes()),
        "58a1875602949aa6bfaf9cb4837957e7175ffb0b14422dbc8d371799f98e66f5"
    );

    let shared_secret = compute_shared_secret_sender(&sender_sk_scalar, &scan_pk, &input_hash);
    assert_eq!(
        hex::encode(shared_secret),
        "3d1eabb622c40142d4b2557fc222a22cd93d98550255cecb2b6a84985f49215d"
    );

    let t_0 = derive_output_tweak(&shared_secret, 0);
    assert_eq!(
        hex::encode(t_0.as_bytes()),
        "301e842ace534f7de854dcc5a48a656d7e9a6d8b8f93db9fb8277f4d1889bdf1"
    );

    // Sender sends to B_m (labeled spend PK)
    let onetime_pk = derive_onetime_pk(&b_m, &t_0);
    assert_eq!(
        hex::encode(onetime_pk.to_bytes()),
        "97e7466509081a3ed6e50ba0231a6fa1b48d8c910ac6ec933e26cd5091569c615f299726c91a730dbf51a26cb249f17c"
    );

    let puzzle_hash = puzzle_hash_for_pk(&onetime_pk);
    assert_eq!(
        hex::encode(puzzle_hash),
        "ba271d218d487e8e5dc994a09a8580e1e8a0559a615bd5805cff11b5a343441c"
    );

    // Scanner-side ECDH produces same shared secret
    let scanner_secret = compute_shared_secret_scanner(&scan_sk, &syn_pk, &input_hash);
    assert_eq!(shared_secret, scanner_secret);

    // --- Label Detection via Scanning ---
    let mut labels: HashMap<[u8; 48], u32> = HashMap::new();
    labels.insert(label_pk.to_bytes(), 1);

    let detected = scan_for_silent_payments(
        &scan_sk, &spend_pk, &syn_pk, &[&coin_id],
        &[puzzle_hash], Some(&labels),
    );
    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].label, Some(1));
    assert_eq!(detected[0].k, 0);
    assert_eq!(detected[0].puzzle_hash, puzzle_hash);

    // --- Labeled Spending Key Derivation ---
    // Base one-time SK = (b_spend + t_0) mod r
    let base_onetime_sk = derive_onetime_sk(&spend_sk, &t_0);
    assert_eq!(
        hex::encode(base_onetime_sk.to_bytes()),
        "10021d8ab756b398cb4c4732864c264981e39a898e1ff4ea487b8f39f1bb6e77"
    );

    // Labeled one-time SK = (base_onetime_sk + label_scalar) mod r
    let base_scalar = ScalarField::from_bytes_raw(base_onetime_sk.to_bytes());
    let labeled_sk_scalar = base_scalar.add(&label_scalar);
    let labeled_onetime_sk = SecretKey::from_bytes(labeled_sk_scalar.as_bytes())
        .expect("labeled one-time SK must be valid");
    assert_eq!(
        hex::encode(labeled_onetime_sk.to_bytes()),
        "58fc619583ff32e8e6e5cbe8587f4e1a395a04d538b132e5787d634cb64852dc"
    );

    // Key-pair consistency: labeled one-time SK * G == one-time PK
    assert_eq!(labeled_onetime_sk.public_key().to_bytes(), onetime_pk.to_bytes());

    // The combined tweak (t_0 + label_scalar) handed to a signer that holds
    // only b_spend gives the same labeled one-time SK.
    let combined = spend_tweak(&scan_sk, &detected[0].tweak, detected[0].label);
    assert_eq!(
        hex::encode(derive_onetime_sk(&spend_sk, &combined).to_bytes()),
        "58fc619583ff32e8e6e5cbe8587f4e1a395a04d538b132e5787d634cb64852dc"
    );
}

// -------------------------------------------------------------------------
// Test Vector 4: Multi-Input Payment
// -------------------------------------------------------------------------

#[test]
fn test_chip_vector_4() {
    // --- Key Derivation (Individual Sender Keys) ---
    let master = mnemonic_to_master_sk(TEST_MNEMONIC_1);

    let wallet_sk_0 = master_to_wallet_sk(&master, 0);
    let syn_sk_0 = synthetic_sk(&wallet_sk_0);
    let syn_pk_0 = syn_sk_0.public_key();
    assert_eq!(
        hex::encode(syn_sk_0.to_bytes()),
        "5002eaf015c1c3a9694cc054e96273279732f4f963616ff89b6d4addcd678c7a"
    );
    assert_eq!(
        hex::encode(syn_pk_0.to_bytes()),
        "8d9a5ed9c9b1a58476b07262007c636d775f2a33f0533737f3b3b0eaf99a8c0c51b3f2d87dc03a657e07f1828ab760fa"
    );

    let wallet_sk_1 = master_to_wallet_sk(&master, 1);
    let syn_sk_1 = synthetic_sk(&wallet_sk_1);
    let syn_pk_1 = syn_sk_1.public_key();
    assert_eq!(
        hex::encode(syn_sk_1.to_bytes()),
        "05fded8808216b65d439fc41cb07c7270e37ed743e0745652afe055cfe91cf0f"
    );
    assert_eq!(
        hex::encode(syn_pk_1.to_bytes()),
        "94c5c19f4343bc2655af729469285a392de9048851363b0b1329a4539a46ab4c6e8bfb39d32da25bffe4d9cdbe3e1061"
    );

    // --- Key Aggregation ---
    let a_sum = aggregate_sender_sks(&[&syn_sk_0, &syn_sk_1]);
    assert_eq!(
        hex::encode(a_sum.as_bytes()),
        "5600d8781de32f0f3d86bc96b46a3a4ea56ae26da168b55dc66b503acbf95b89"
    );

    let a_sum_sk = SecretKey::from_bytes(a_sum.as_bytes())
        .expect("a_sum must be valid");
    let a_sum_pk = a_sum_sk.public_key();
    assert_eq!(
        hex::encode(a_sum_pk.to_bytes()),
        "a223ab27f801044cd98c8314014b8073347b0e5aae43c69b78b5ca2a562ee9f799b8efad179b34da1b306ca4d62bad40"
    );

    // PK consistency: A_sum == A_0 + A_1 (point addition)
    let pk_sum = &syn_pk_0 + &syn_pk_1;
    assert_eq!(a_sum_pk.to_bytes(), pk_sum.to_bytes());

    // --- Recipient Keys (same as TV1) ---
    let scan_sk = tv_given_scan_sk();
    let scan_pk = scan_sk.public_key();
    assert_eq!(hex::encode(scan_pk.to_bytes()), TV_GIVEN_SCAN_PK_HEX);
    let spend_sk = tv_given_spend_sk();
    let spend_pk = spend_sk.public_key();
    assert_eq!(hex::encode(spend_pk.to_bytes()), TV_GIVEN_SPEND_PK_HEX);

    // --- Coin IDs ---
    let coin_id_0 = sha256(b"test-vector-4-coin-0");
    let coin_id_1 = sha256(b"test-vector-4-coin-1");
    assert_eq!(
        hex::encode(coin_id_0),
        "2b9857e0307ebfbe51829e3be8c992ae57f6a8debe06a5deab429ddae83a8c1a"
    );
    assert_eq!(
        hex::encode(coin_id_1),
        "209bb03a4cd165785e6149bc6dcb27e35829006f02ec927ab5a20521fd27d21a"
    );

    // Lexicographic minimum is coin_id_1
    assert!(coin_id_1 < coin_id_0);

    // --- Protocol Execution ---
    let input_hash = compute_input_hash(&[&coin_id_0, &coin_id_1], &a_sum_pk);
    assert_eq!(
        hex::encode(input_hash.as_bytes()),
        "3f1071552b7f2f5e49b68166cb204f0a1b6a23b0c30a28bcba59a9c3f766e166"
    );

    // ECDH point intermediate check
    let adjusted = input_hash.mul(&a_sum);
    let mut ecdh_point = scan_pk;
    ecdh_point.scalar_multiply(adjusted.as_bytes());
    assert_eq!(
        hex::encode(ecdh_point.to_bytes()),
        "b99921528f3e0b744040ad552d2209eae9092542f4968ab7a85a5c68098f09241a5d5112916f232fdd0edca5f0045080"
    );

    // Shared secret
    let shared_secret = compute_shared_secret_sender(&a_sum, &scan_pk, &input_hash);
    assert_eq!(
        hex::encode(shared_secret),
        "e729dea8c4732747d0e5e930607c52ddfce01ff7c72eaec9ee7c84131e078494"
    );

    // Scanner-side ECDH with A_sum produces same shared secret
    let scanner_secret = compute_shared_secret_scanner(&scan_sk, &a_sum_pk, &input_hash);
    assert_eq!(shared_secret, scanner_secret);

    // Output tweak t_0
    let t_0 = derive_output_tweak(&shared_secret, 0);
    assert_eq!(
        hex::encode(t_0.as_bytes()),
        "18fafd6001bef3fece078f469731b40a5f362994795f9ff6b9339aa235fee312"
    );

    // One-time PK
    let onetime_pk = derive_onetime_pk(&spend_pk, &t_0);
    assert_eq!(
        hex::encode(onetime_pk.to_bytes()),
        "b71f484e6d90a657b215ad7bff6f96a8d9bff07e0133d74917cc6c3ef6fa273a706aa56e1fd6da19ed5466f16450ccb1"
    );

    // Puzzle hash
    let puzzle_hash = puzzle_hash_for_pk(&onetime_pk);
    assert_eq!(
        hex::encode(puzzle_hash),
        "5d7fc7d7447c746cfb400e801a169fc7bfd1c13e03bc7866e6b743860a53ac6b"
    );

    // One-time SK and key-pair consistency
    let onetime_sk = derive_onetime_sk(&spend_sk, &t_0);
    assert_eq!(
        hex::encode(onetime_sk.to_bytes()),
        "6ccc3e13145fd561e438d1bb82954cebb63cfa9577ea15404987aa8e0f309399"
    );
    assert_eq!(onetime_sk.public_key().to_bytes(), onetime_pk.to_bytes());

    // Scanner detection end-to-end
    let detected = scan_for_silent_payments(
        &scan_sk, &spend_pk, &a_sum_pk,
        &[&coin_id_0, &coin_id_1],
        &[puzzle_hash], None,
    );
    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].puzzle_hash, puzzle_hash);
}

// -------------------------------------------------------------------------
// Shared setup for Vectors 6 and 7: the sender and recipient of Vector 1
// -------------------------------------------------------------------------

/// Sender synthetic key pair of Test Vector 1 (wallet index 0 of mnemonic 1).
fn tv1_sender() -> (SecretKey, PublicKey) {
    let master = mnemonic_to_master_sk(TEST_MNEMONIC_1);
    let syn_sk = synthetic_sk(&master_to_wallet_sk(&master, 0));
    let syn_pk = syn_sk.public_key();
    assert_eq!(
        hex::encode(syn_pk.to_bytes()),
        "8d9a5ed9c9b1a58476b07262007c636d775f2a33f0533737f3b3b0eaf99a8c0c51b3f2d87dc03a657e07f1828ab760fa"
    );
    (syn_sk, syn_pk)
}

fn hex32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

// -------------------------------------------------------------------------
// Test Vector 6: Two Outputs to One Recipient
// -------------------------------------------------------------------------

#[test]
fn test_chip_vector_6() {
    let (syn_sk, syn_pk) = tv1_sender();
    let sender_sk_scalar = ScalarField::from_bytes_raw(syn_sk.to_bytes());
    let scan_sk = tv_given_scan_sk();
    let scan_pk = scan_sk.public_key();
    let spend_sk = tv_given_spend_sk();
    let spend_pk = spend_sk.public_key();
    let coin_id = sha256(b"test-vector-1-coin");

    // input_hash and shared_secret are those of Test Vector 1.
    let input_hash = compute_input_hash(&[&coin_id], &syn_pk);
    assert_eq!(
        hex::encode(input_hash.as_bytes()),
        "38a1c8379cceb0fbebfdf3016707e54a1c7e9d21afb9489b9cc58f6055cc9411"
    );
    let shared_secret = compute_shared_secret_sender(&sender_sk_scalar, &scan_pk, &input_hash);
    assert_eq!(
        hex::encode(shared_secret),
        "d3ac1e8f651a73d2e20b43cb73fd6997de5504afbc04a2d4546a92d0020ba2c6"
    );

    // t_1
    let t_1 = derive_output_tweak(&shared_secret, 1);
    assert_eq!(
        hex::encode(t_1.as_bytes()),
        "5b41459e4302fc14258a5ab9af5ac6b45946e83f5a2dadc031b3cb49e79fd899"
    );

    // One-time PK P_1 = B_spend + t_1 * G
    let p_1 = derive_onetime_pk(&spend_pk, &t_1);
    assert_eq!(
        hex::encode(p_1.to_bytes()),
        "97c5bddfec949ab9d30190a9ba4d64d12b47828ee2226e1556161c4082344fa9dd02849f93aa4cdb613e5522bbd08baf"
    );

    // One-time puzzle hash
    let ph_1 = puzzle_hash_for_pk(&p_1);
    assert_eq!(
        hex::encode(ph_1),
        "0dcde144401307ca3caa58239572e6ab3d0a7f09b4f5d8993d652081c2151f84"
    );

    // One-time SK = (b_spend + t_1) mod r
    let onetime_sk_1 = derive_onetime_sk(&spend_sk, &t_1);
    assert_eq!(
        hex::encode(onetime_sk_1.to_bytes()),
        "3b24defe2c06602f0881c526911c87905c90153d58b9c70ac207db36c0d1891f"
    );
    assert_eq!(onetime_sk_1.public_key().to_bytes(), p_1.to_bytes());

    // Sender: the same recipient listed twice gets k = 0 (the TV1 output) and k = 1.
    let ph_0 = hex32("23adba149dd9000d65e0f8e21b6975364cbe89a63caf56533df4b7664c21fbf5");
    let outputs = create_silent_payment_outputs(
        &sender_sk_scalar,
        &[&coin_id],
        &[(scan_pk, spend_pk), (scan_pk, spend_pk)],
    )
    .expect("TV6 outputs");
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].1, ph_0);
    assert_eq!(outputs[1].1, ph_1);
    assert_eq!(outputs[1].0.to_bytes(), p_1.to_bytes());

    // Scanner finds k = 0, continues, finds k = 1, and stops at k = 2.
    let detected = scan_for_silent_payments(
        &scan_sk, &spend_pk, &syn_pk, &[&coin_id], &[ph_1, ph_0], None,
    );
    assert_eq!(detected.len(), 2);
    assert_eq!((detected[0].k, detected[0].puzzle_hash, detected[0].output_index), (0, ph_0, 1));
    assert_eq!((detected[1].k, detected[1].puzzle_hash, detected[1].output_index), (1, ph_1, 0));
    assert_eq!(detected[1].tweak, t_1);
    assert!(detected.iter().all(|d| d.label.is_none()));

    // If the k = 0 output is left out of the transaction, the scanner finds nothing.
    let detected = scan_for_silent_payments(
        &scan_sk, &spend_pk, &syn_pk, &[&coin_id], &[ph_1], None,
    );
    assert!(detected.is_empty());
}

// -------------------------------------------------------------------------
// Test Vector 7: Change Output (Label m = 0)
// -------------------------------------------------------------------------

#[test]
fn test_chip_vector_7() {
    let (syn_sk, syn_pk) = tv1_sender();
    let sender_sk_scalar = ScalarField::from_bytes_raw(syn_sk.to_bytes());
    let scan_sk = tv_given_scan_sk();
    let scan_pk = scan_sk.public_key();
    let spend_sk = tv_given_spend_sk();
    let spend_pk = spend_sk.public_key();

    let coin_id = sha256(b"test-vector-7-coin");
    assert_eq!(
        hex::encode(coin_id),
        "10f36babd97f3da5027238f336ac15a0f12dfb10bc77191711de7eafba964c9f"
    );

    // --- Change label m = 0 ---
    let (label_scalar, label_pk) = generate_label(&scan_sk, 0).unwrap();
    assert_eq!(
        hex::encode(label_scalar.as_bytes()),
        "3106829938a8b73a652a9a31c6c76a37e32f67f924a50e3649291d6904f22082"
    );
    assert_eq!(
        hex::encode(label_pk.to_bytes()),
        "8314ad1fd7b1dc75d97e025a6d9af28af6ed21e11093a1103ea338c7e496d133d4f2bd863b47b9a2839ef1ff2d0e6a9f"
    );
    let b_0 = &spend_pk + &label_pk;
    assert_eq!(
        hex::encode(b_0.to_bytes()),
        "a2c089434a6abae657b8e3a868f3d1b94299b141f3da6a6788f966b0856d68022bd58459d964b7514111529647ebd7e8"
    );

    // --- Protocol execution ---
    let input_hash = compute_input_hash(&[&coin_id], &syn_pk);
    assert_eq!(
        hex::encode(input_hash.as_bytes()),
        "620c82f4fd9faf8a41d7ed8025dbda3857797c0bc5f31f4c34e460ddc4a89e79"
    );
    let shared_secret = compute_shared_secret_sender(&sender_sk_scalar, &scan_pk, &input_hash);
    assert_eq!(
        hex::encode(shared_secret),
        "6b13c43195ded3d7e7366decb4c744e371b98a8cf757a9f9cbd784c644d079dc"
    );
    assert_eq!(
        compute_shared_secret_scanner(&scan_sk, &syn_pk, &input_hash),
        shared_secret
    );
    let t_0 = derive_output_tweak(&shared_secret, 0);
    assert_eq!(
        hex::encode(t_0.as_bytes()),
        "146540ede99c556f61907c7d0ae1e365aa91f3c116709ef64135a4ccecec0322"
    );

    // One-time PK P_0 = B_0 + t_0 * G
    let p_0 = derive_onetime_pk(&b_0, &t_0);
    assert_eq!(
        hex::encode(p_0.to_bytes()),
        "b51abe5a989379591b02288a376668ef4124f16b2a5629ba47bebcd4b2359af4c31428efa13f4bf4ac35ed0dd4805da0"
    );
    let puzzle_hash = puzzle_hash_for_pk(&p_0);
    assert_eq!(
        hex::encode(puzzle_hash),
        "6e0d9f029ea7e8129bf4839d7e805dac5da5b9af5f51fe0374547ac24f8f5257"
    );

    // Sender flow produces the same output.
    let outputs = create_silent_payment_outputs(&sender_sk_scalar, &[&coin_id], &[(scan_pk, b_0)])
        .expect("TV7 outputs");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].1, puzzle_hash);

    // One-time SK = (b_spend + t_0 + label_scalar) mod r
    let combined = spend_tweak(&scan_sk, &t_0, Some(0));
    assert_eq!(combined, t_0.add(&label_scalar));
    let onetime_sk = derive_onetime_sk(&spend_sk, &combined);
    assert_eq!(
        hex::encode(onetime_sk.to_bytes()),
        "254f5ce70b4870c4a9b2811bb36b0e79910a88b839a1c6771ab2d222cb0fd42a"
    );
    assert_eq!(onetime_sk.public_key().to_bytes(), p_0.to_bytes());

    // A scanner with no labels registered does not find the output: its
    // unlabeled candidate at k = 0 is not on chain.
    let unlabeled_candidate = puzzle_hash_for_pk(&derive_onetime_pk(&spend_pk, &t_0));
    assert_eq!(
        hex::encode(unlabeled_candidate),
        "980d14e591ef9db6d449eae11c7c43b3f753f07c79da105a06f27f75a2384dc1"
    );
    let detected = scan_for_silent_payments(
        &scan_sk, &spend_pk, &syn_pk, &[&coin_id], &[puzzle_hash], None,
    );
    assert!(detected.is_empty());

    // A scanner with label m = 0 registered finds the output and reports label 0.
    let mut labels: HashMap<[u8; 48], u32> = HashMap::new();
    labels.insert(label_pk.to_bytes(), 0);
    let detected = scan_for_silent_payments(
        &scan_sk, &spend_pk, &syn_pk, &[&coin_id], &[puzzle_hash], Some(&labels),
    );
    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].label, Some(0));
    assert_eq!(detected[0].k, 0);
    assert_eq!(detected[0].tweak, t_0);
    assert_eq!(detected[0].puzzle_hash, puzzle_hash);
    assert_eq!(detected[0].onetime_pk.to_bytes(), p_0.to_bytes());
}

// -------------------------------------------------------------------------
// Test Vector 8: Key Derivation (hardened)
// -------------------------------------------------------------------------

#[test]
fn test_chip_vector_8() {
    let master = mnemonic_to_master_sk(TEST_MNEMONIC_1);
    assert_eq!(
        hex::encode(master.to_bytes()),
        "11da8b4a2874a49dc42984b6aa127b68ef73adddc333319c36fd0446705204a9"
    );
    assert_eq!(
        hex::encode(master.public_key().to_bytes()),
        "82ae65efe846b15a92c51b7ad6c32589fd79d38263d3cbefbeeba08be8e90d8bc335a1e2fcc66a10b8c817c06232285a"
    );

    // Scan key at m/12381n/8444n/12n/0n
    let scan_sk = master_to_scan_sk(&master);
    assert_eq!(
        hex::encode(scan_sk.to_bytes()),
        "0c474f92e8945069c200bb09302d1e569a9b52f59cc04a27874b1bca2adeca9f"
    );
    assert_eq!(
        hex::encode(scan_sk.public_key().to_bytes()),
        "8bf2be64f401ccc10d3495503ac9e5b675c2e2b08b073917935beed951b70b8ccd01f60c406c4ee7e79237e2eb5affd9"
    );

    // Spend key at m/12381n/8444n/13n/0n
    let spend_sk = master_to_spend_sk(&master);
    assert_eq!(
        hex::encode(spend_sk.to_bytes()),
        "4f8acf271744cf7050197623569e1603b0193f84b958b5d5f1ce8fd18c908e7b"
    );
    assert_eq!(
        hex::encode(spend_sk.public_key().to_bytes()),
        "ad0c7b65a3392b62782b8c0784b10c64b0f4dc8fc2d46d2d3c7c0e1b899bf183f76996226ddf9145789d6b0bf3499219"
    );

    // "These keys are not the given keys used in Vectors 1 through 7."
    assert_ne!(scan_sk.to_bytes(), tv_given_scan_sk().to_bytes());
    assert_ne!(spend_sk.to_bytes(), tv_given_spend_sk().to_bytes());
}
