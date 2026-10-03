//! Local ECDH detection for silent payment coins.
//!
//! The scanner performs client-side detection using the scan secret key and
//! the spend PUBLIC key only (CHIP-0057 "Scanning a Spend Group": "it never
//! needs the spend secret key"). The server pre-computes one tweak point
//! `T = input_hash * A_sum` per spend group, so the client only needs
//! `SHA256(serialize(scan_sk * T))` to get the shared secret. The scan secret
//! key never leaves the client.
//!
//! A detection carries the combined tweak `(t_k + label_scalar) mod r`. Turning
//! it into a one-time secret key is a separate, explicit step that takes the
//! spend secret key: [`derive_onetime_sk_for_detection`].

use std::collections::{HashMap, HashSet};

use chia_bls::{PublicKey, SecretKey};

use sp_common::{
    derive_onetime_sk, generate_label, puzzle_hash_for_pk, scan_tweak_point, sorted_labels,
    spend_tweak, OutputIndex, ScalarField,
};

pub use sp_common::compute_shared_secret_from_tweak;

/// The reserved change label index (CHIP-0057 "Change Detection (m = 0)").
pub const CHANGE_LABEL: u32 = 0;

/// Metadata for a transaction output to scan against.
#[derive(Debug, Clone)]
pub struct OutputMeta {
    pub puzzle_hash: [u8; 32],
    pub coin_id: [u8; 32],
    pub amount: u64,
    pub parent_coin_id: [u8; 32],
}

/// A detected silent payment coin.
///
/// Holds no secret-key material that can spend: `tweak` together with the
/// spend SECRET key gives the one-time secret key (see
/// [`derive_onetime_sk_for_detection`]). `tweak` is still private data — with
/// the public address it links this coin to the wallet.
#[derive(Debug, Clone)]
pub struct DetectedCoin {
    pub coin_id: [u8; 32],
    pub puzzle_hash: [u8; 32],
    pub amount: u64,
    pub parent_coin_id: [u8; 32],
    /// Output index k within the spend group's shared secret.
    pub k: u32,
    /// None for unlabeled, Some(m) for label index m (0 = change).
    pub label: Option<u32>,
    /// Combined tweak scalar: `t_k` for an unlabeled output,
    /// `(t_k + label_scalar_m) mod r` for a labeled one.
    pub tweak: ScalarField,
}

/// Why a one-time secret key could not be derived for a detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendKeyError {
    /// `(b_spend + tweak) mod r` does not control the detected puzzle hash:
    /// the spend secret key is not the one the coin was detected for.
    PuzzleHashMismatch,
}

impl std::fmt::Display for SpendKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpendKeyError::PuzzleHashMismatch => write!(
                f,
                "spend secret key does not match the detected coin's puzzle hash"
            ),
        }
    }
}

impl std::error::Error for SpendKeyError {}

/// Derive the one-time secret key `(b_spend + tweak) mod r` for a coin with
/// the given combined tweak, and check that it controls `puzzle_hash`.
///
/// This is the only place the spend secret key is needed. The returned key is
/// the one-time key b_onetime; the signing key is its synthetic key (CHIP-0057
/// "Spending").
pub fn derive_onetime_sk_from_tweak(
    spend_sk: &SecretKey,
    tweak: &ScalarField,
    puzzle_hash: &[u8; 32],
) -> Result<SecretKey, SpendKeyError> {
    let onetime_sk = derive_onetime_sk(spend_sk, tweak);
    if puzzle_hash_for_pk(&onetime_sk.public_key()) != *puzzle_hash {
        return Err(SpendKeyError::PuzzleHashMismatch);
    }
    Ok(onetime_sk)
}

/// Turn a detection plus the spend secret key into the one-time secret key.
///
/// Scanning never calls this; a signer calls it when the coin is to be spent.
pub fn derive_onetime_sk_for_detection(
    detection: &DetectedCoin,
    spend_sk: &SecretKey,
) -> Result<SecretKey, SpendKeyError> {
    derive_onetime_sk_from_tweak(spend_sk, &detection.tweak, &detection.puzzle_hash)
}

/// Scan a block's outputs for silent payments addressed to this wallet.
///
/// `tweaks` are the block's tweak points, one per spend group; `outputs` are
/// all non-coinbase additions of the block (a tweak point carries no parent
/// information, so every group is checked against every output).
///
/// For each tweak point the shared secret is computed and k = 0, 1, 2, ... is
/// iterated, deriving candidate puzzle hashes, until the first k with no match
/// or until K_max. Every output coin carrying a matching puzzle hash is
/// reported, also when several coins share one puzzle hash.
///
/// - Needs only `scan_sk` and `spend_pk`; no spend secret key is involved.
/// - Tweak points that are the identity element are skipped. Callers MUST
///   deserialize tweak points with subgroup validation
///   (`PublicKey::from_bytes`).
/// - The change label m = 0 is always checked, in addition to any `labels`
///   supplied by the caller (label public key -> label index). Labels are
///   tried in ascending order of m and the first match wins at each k.
/// - A coin is reported once, even if the server repeats a tweak point or an
///   output.
pub fn scan_block(
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
    tweaks: &[PublicKey],
    outputs: &[OutputMeta],
    labels: Option<&HashMap<[u8; 48], u32>>,
) -> Vec<DetectedCoin> {
    let mut detected = Vec::new();
    if tweaks.is_empty() || outputs.is_empty() {
        return detected;
    }

    let puzzle_hashes: Vec<[u8; 32]> = outputs.iter().map(|o| o.puzzle_hash).collect();
    let output_index = OutputIndex::new(&puzzle_hashes);

    // Caller's labels plus the change label, which is always scanned for.
    let mut label_map: HashMap<[u8; 48], u32> = labels.cloned().unwrap_or_default();
    // (A label whose scalar is zero cannot be generated and is not used.)
    if let Ok((_, change_label_pk)) = generate_label(scan_sk, CHANGE_LABEL) {
        label_map.insert(change_label_pk.to_bytes(), CHANGE_LABEL);
    }
    let label_list = sorted_labels(Some(&label_map));

    let mut seen_coins: HashSet<[u8; 32]> = HashSet::new();

    for tweak_point in tweaks {
        if tweak_point.is_inf() {
            continue;
        }
        for hit in scan_tweak_point(scan_sk, spend_pk, tweak_point, &output_index, &label_list) {
            let output = &outputs[hit.output_index];
            if !seen_coins.insert(output.coin_id) {
                continue;
            }
            detected.push(DetectedCoin {
                coin_id: output.coin_id,
                puzzle_hash: output.puzzle_hash,
                amount: output.amount,
                parent_coin_id: output.parent_coin_id,
                k: hit.k,
                label: hit.label,
                tweak: spend_tweak(scan_sk, &hit.tweak, hit.label),
            });
        }
    }

    detected
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use sp_common::{
        compute_input_hash, create_silent_payment_outputs, derive_onetime_pk, derive_output_tweak,
        K_MAX,
    };

    // Given recipient keys of CHIP Test Vectors 1-7 (hex as printed in the CHIP).
    fn tv1_scan_sk() -> SecretKey {
        let bytes: [u8; 32] = hex::decode(
            "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6"
        ).unwrap().try_into().unwrap();
        SecretKey::from_bytes(&bytes).unwrap()
    }

    fn tv1_spend_sk() -> SecretKey {
        let bytes: [u8; 32] = hex::decode(
            "53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087"
        ).unwrap().try_into().unwrap();
        SecretKey::from_bytes(&bytes).unwrap()
    }

    fn tv1_spend_pk() -> PublicKey {
        let bytes: [u8; 48] = hex::decode(
            "8afc580192f44fab624f613369f792eff3220ea3ca822eb839ab2c9309e527dbf6f31e22e0831ba5088c952625a75c74"
        ).unwrap().try_into().unwrap();
        PublicKey::from_bytes(&bytes).unwrap()
    }

    /// Sender synthetic public key of Test Vector 1.
    fn tv1_sender_pk() -> PublicKey {
        let bytes: [u8; 48] = hex::decode(
            "8d9a5ed9c9b1a58476b07262007c636d775f2a33f0533737f3b3b0eaf99a8c0c51b3f2d87dc03a657e07f1828ab760fa"
        ).unwrap().try_into().unwrap();
        PublicKey::from_bytes(&bytes).unwrap()
    }

    /// Sender synthetic secret key of Test Vector 1.
    fn tv1_sender_sk() -> ScalarField {
        ScalarField::from_bytes_raw(
            hex::decode("5002eaf015c1c3a9694cc054e96273279732f4f963616ff89b6d4addcd678c7a")
                .unwrap().try_into().unwrap(),
        )
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// Tweak point for a single TV1-sender coin: input_hash * sender_syn_pk.
    fn tweak_point_for_coin(coin_id: &[u8; 32]) -> PublicKey {
        let sender_pk = tv1_sender_pk();
        let input_hash = compute_input_hash(&[coin_id], &sender_pk);
        let mut tweak_point = sender_pk;
        tweak_point.scalar_multiply(input_hash.as_bytes());
        tweak_point
    }

    /// Compute the tweak point for TV1: input_hash * sender_syn_pk
    fn tv1_tweak_point() -> PublicKey {
        let input_hash_bytes: [u8; 32] = hex::decode(
            "38a1c8379cceb0fbebfdf3016707e54a1c7e9d21afb9489b9cc58f6055cc9411"
        ).unwrap().try_into().unwrap();
        let mut tweak_point = tv1_sender_pk();
        tweak_point.scalar_multiply(&input_hash_bytes);
        tweak_point
    }

    const TV1_PH: &str = "23adba149dd9000d65e0f8e21b6975364cbe89a63caf56533df4b7664c21fbf5";
    const TV6_PH_K1: &str = "0dcde144401307ca3caa58239572e6ab3d0a7f09b4f5d8993d652081c2151f84";

    fn output(puzzle_hash: [u8; 32], coin_tag: u8, amount: u64) -> OutputMeta {
        OutputMeta {
            puzzle_hash,
            coin_id: [coin_tag; 32],
            amount,
            parent_coin_id: [0u8; 32],
        }
    }

    fn tv1_output() -> OutputMeta {
        OutputMeta {
            puzzle_hash: hex32(TV1_PH),
            coin_id: hex32("5d759d2d97c03b1f6fe0657e91d25f6b7dd1311d6023271a1bcd35978a94a175"),
            amount: 1000,
            parent_coin_id: [0u8; 32],
        }
    }

    #[test]
    fn test_compute_shared_secret_from_tweak_tv1() {
        let scan_sk = tv1_scan_sk();
        let tweak_point = tv1_tweak_point();
        let shared_secret = compute_shared_secret_from_tweak(&scan_sk, &tweak_point);
        assert_eq!(
            hex::encode(shared_secret),
            "d3ac1e8f651a73d2e20b43cb73fd6997de5504afbc04a2d4546a92d0020ba2c6",
            "shared secret should match TV1 expected value"
        );
    }

    #[test]
    fn test_scan_block_detects_tv1_coin() {
        let scan_sk = tv1_scan_sk();
        let spend_pk = tv1_spend_pk();
        let tweak_point = tv1_tweak_point();
        let output = tv1_output();

        // Scanning takes the scan secret key and the spend PUBLIC key only.
        let detections = scan_block(&scan_sk, &spend_pk, &[tweak_point], &[output], None);

        assert_eq!(detections.len(), 1, "should detect exactly one coin");
        assert_eq!(
            hex::encode(detections[0].puzzle_hash),
            TV1_PH,
            "detected puzzle_hash should match TV1"
        );
        assert_eq!(
            hex::encode(detections[0].tweak.as_bytes()),
            "5c560301c50fa309ad43d0f82cd1af143f6e3769659c80e8c14a072331582ab1",
            "unlabeled detection carries t_0 of TV1"
        );
        assert_eq!(detections[0].k, 0, "k should be 0");
        assert_eq!(detections[0].label, None);
        assert_eq!(detections[0].amount, 1000);
        assert_eq!(
            hex::encode(detections[0].coin_id),
            "5d759d2d97c03b1f6fe0657e91d25f6b7dd1311d6023271a1bcd35978a94a175"
        );

        // The separate, explicit step with the spend secret key.
        let onetime_sk = derive_onetime_sk_for_detection(&detections[0], &tv1_spend_sk()).unwrap();
        assert_eq!(
            hex::encode(onetime_sk.to_bytes()),
            "3c399c61ae130724903b3b650e936ff042b7646764289a33519e17100a89db37",
            "onetime_sk should match TV1"
        );
    }

    #[test]
    fn test_scan_block_empty_tweaks() {
        let detections = scan_block(&tv1_scan_sk(), &tv1_spend_pk(), &[], &[tv1_output()], None);
        assert!(detections.is_empty(), "empty tweaks should produce no detections");
    }

    #[test]
    fn test_scan_block_no_matching_outputs() {
        // Output with a random puzzle hash that won't match
        let non_matching_output = OutputMeta {
            puzzle_hash: [0xaa; 32],
            coin_id: [0xbb; 32],
            amount: 500,
            parent_coin_id: [0xcc; 32],
        };

        let detections = scan_block(
            &tv1_scan_sk(),
            &tv1_spend_pk(),
            &[tv1_tweak_point()],
            &[non_matching_output],
            None,
        );

        assert!(detections.is_empty(), "non-matching outputs should produce no detections");
    }

    #[test]
    fn test_detected_coin_sk_matches_pk() {
        // The derived onetime_sk produces a PK whose puzzle hash matches.
        let detections = scan_block(
            &tv1_scan_sk(),
            &tv1_spend_pk(),
            &[tv1_tweak_point()],
            &[tv1_output()],
            None,
        );

        assert_eq!(detections.len(), 1);
        let detected = &detections[0];
        let onetime_sk = derive_onetime_sk_for_detection(detected, &tv1_spend_sk()).unwrap();
        let derived_ph = puzzle_hash_for_pk(&onetime_sk.public_key());
        assert_eq!(
            derived_ph, detected.puzzle_hash,
            "onetime_sk should produce a PK whose puzzle hash matches the detected coin"
        );
    }

    #[test]
    fn test_derive_onetime_sk_rejects_wrong_spend_key() {
        let detections = scan_block(
            &tv1_scan_sk(),
            &tv1_spend_pk(),
            &[tv1_tweak_point()],
            &[tv1_output()],
            None,
        );
        let wrong_spend_sk = SecretKey::from_seed(&[9u8; 32]);
        assert_eq!(
            derive_onetime_sk_for_detection(&detections[0], &wrong_spend_sk).unwrap_err(),
            SpendKeyError::PuzzleHashMismatch
        );
    }

    #[test]
    fn test_scan_block_backward_compat() {
        // Call with labels: None, verify existing TV1 test still works
        let detections = scan_block(
            &tv1_scan_sk(),
            &tv1_spend_pk(),
            &[tv1_tweak_point()],
            &[tv1_output()],
            None,
        );

        assert_eq!(detections.len(), 1, "should detect exactly one coin");
        assert_eq!(detections[0].label, None, "label should be None for unlabeled");
        assert_eq!(detections[0].k, 0);
        assert_eq!(detections[0].amount, 1000);
    }

    // TV3 helpers for labeled detection tests (same given recipient keys as TV1)
    fn tv3_tweak_point() -> PublicKey {
        let coin_id: [u8; 32] = Sha256::digest(b"test-vector-3-coin").into();
        tweak_point_for_coin(&coin_id)
    }

    fn tv3_labeled_output() -> OutputMeta {
        // TV3 labeled puzzle hash
        OutputMeta {
            puzzle_hash: hex32("ba271d218d487e8e5dc994a09a8580e1e8a0559a615bd5805cff11b5a343441c"),
            coin_id: hex32("4504f59ea184be18924f95244649287382ec6cdc13f333a8990f648c803a6dac"),
            amount: 2000,
            parent_coin_id: [0u8; 32],
        }
    }

    fn tv3_label_map() -> HashMap<[u8; 48], u32> {
        let (_scalar, label_pk) = generate_label(&tv1_scan_sk(), 1).unwrap();
        let mut labels = HashMap::new();
        labels.insert(label_pk.to_bytes(), 1);
        labels
    }

    #[test]
    fn test_scan_block_labeled_detection() {
        let labels = tv3_label_map();

        let detections = scan_block(
            &tv1_scan_sk(),
            &tv1_spend_pk(),
            &[tv3_tweak_point()],
            &[tv3_labeled_output()],
            Some(&labels),
        );

        assert_eq!(detections.len(), 1, "should detect labeled coin");
        assert_eq!(detections[0].label, Some(1), "label should be Some(1)");
        assert_eq!(detections[0].k, 0);
        assert_eq!(detections[0].amount, 2000);
    }

    #[test]
    fn test_scan_block_labeled_tweak_includes_label_scalar() {
        let labels = tv3_label_map();

        let detections = scan_block(
            &tv1_scan_sk(),
            &tv1_spend_pk(),
            &[tv3_tweak_point()],
            &[tv3_labeled_output()],
            Some(&labels),
        );

        assert_eq!(detections.len(), 1);
        let detected = &detections[0];

        // The detection carries (t_0 + label_scalar) mod r, from TV3's values.
        let t_0 = ScalarField::from_bytes_raw(hex32(
            "301e842ace534f7de854dcc5a48a656d7e9a6d8b8f93db9fb8277f4d1889bdf1",
        ));
        let label_scalar = ScalarField::from_bytes_raw(hex32(
            "48fa440acca87f501b9984b5d23327d0b7766a4baa913dfb3001d412c48ce465",
        ));
        assert_eq!(detected.tweak, t_0.add(&label_scalar));

        // The signer needs only b_spend to reach TV3's labeled one-time SK.
        let onetime_sk = derive_onetime_sk_for_detection(detected, &tv1_spend_sk()).unwrap();
        assert_eq!(
            hex::encode(onetime_sk.to_bytes()),
            "58fc619583ff32e8e6e5cbe8587f4e1a395a04d538b132e5787d634cb64852dc",
            "labeled onetime_sk should match TV3"
        );
        assert_eq!(
            puzzle_hash_for_pk(&onetime_sk.public_key()),
            detected.puzzle_hash,
            "labeled onetime_sk should produce matching puzzle hash"
        );
    }

    #[test]
    fn test_scan_block_unlabeled_preferred() {
        // When output matches unlabeled, label should be None even if labels provided
        let labels = tv3_label_map(); // provide labels, but TV1 output is unlabeled

        let detections = scan_block(
            &tv1_scan_sk(),
            &tv1_spend_pk(),
            &[tv1_tweak_point()],
            &[tv1_output()],
            Some(&labels),
        );

        assert_eq!(detections.len(), 1, "should detect unlabeled coin");
        assert_eq!(detections[0].label, None, "label should be None for unlabeled detection");
    }

    // --- CHIP Test Vector 6: two outputs to one recipient -------------------

    #[test]
    fn test_scan_block_tv6_k0_and_k1() {
        let outputs = [
            output(hex32(TV6_PH_K1), 0x61, 700),
            output(hex32(TV1_PH), 0x60, 300),
        ];
        let detections =
            scan_block(&tv1_scan_sk(), &tv1_spend_pk(), &[tv1_tweak_point()], &outputs, None);

        let found: Vec<(u32, [u8; 32], u64)> =
            detections.iter().map(|d| (d.k, d.coin_id, d.amount)).collect();
        assert_eq!(found, vec![(0, [0x60; 32], 300), (1, [0x61; 32], 700)]);

        let sk_1 = derive_onetime_sk_for_detection(&detections[1], &tv1_spend_sk()).unwrap();
        assert_eq!(
            hex::encode(sk_1.to_bytes()),
            "3b24defe2c06602f0881c526911c87905c90153d58b9c70ac207db36c0d1891f",
            "one-time SK at k = 1 should match TV6"
        );

        // Without the k = 0 output the scanner finds nothing.
        let detections = scan_block(
            &tv1_scan_sk(),
            &tv1_spend_pk(),
            &[tv1_tweak_point()],
            &outputs[..1],
            None,
        );
        assert!(detections.is_empty());
    }

    // --- CHIP Test Vector 7: change label is always checked ------------------

    #[test]
    fn test_scan_block_tv7_change_label_found_without_caller_labels() {
        let coin_id: [u8; 32] = Sha256::digest(b"test-vector-7-coin").into();
        let change_output = output(
            hex32("6e0d9f029ea7e8129bf4839d7e805dac5da5b9af5f51fe0374547ac24f8f5257"),
            0x70,
            4000,
        );

        // No labels supplied, and labels supplied without m = 0: found either way.
        for labels in [None, Some(tv3_label_map())] {
            let detections = scan_block(
                &tv1_scan_sk(),
                &tv1_spend_pk(),
                &[tweak_point_for_coin(&coin_id)],
                std::slice::from_ref(&change_output),
                labels.as_ref(),
            );
            assert_eq!(detections.len(), 1, "change output must be detected");
            assert_eq!(detections[0].label, Some(CHANGE_LABEL));
            assert_eq!(detections[0].k, 0);

            // tweak = (t_0 + label_scalar_0) mod r, from TV7's values.
            let t_0 = ScalarField::from_bytes_raw(hex32(
                "146540ede99c556f61907c7d0ae1e365aa91f3c116709ef64135a4ccecec0322",
            ));
            let label_scalar = ScalarField::from_bytes_raw(hex32(
                "3106829938a8b73a652a9a31c6c76a37e32f67f924a50e3649291d6904f22082",
            ));
            assert_eq!(detections[0].tweak, t_0.add(&label_scalar));

            let onetime_sk =
                derive_onetime_sk_for_detection(&detections[0], &tv1_spend_sk()).unwrap();
            assert_eq!(
                hex::encode(onetime_sk.to_bytes()),
                "254f5ce70b4870c4a9b2811bb36b0e79910a88b839a1c6771ab2d222cb0fd42a",
                "one-time SK should match TV7"
            );
        }
    }

    // --- Required Behaviors -----------------------------------------------

    #[test]
    fn test_scan_block_reports_every_coin_sharing_a_puzzle_hash() {
        // Two coins with the TV1 one-time puzzle hash (different amounts), plus
        // a third with the k = 1 puzzle hash behind them.
        let outputs = [
            output(hex32(TV1_PH), 0x01, 100),
            output([0xaa; 32], 0x02, 1),
            output(hex32(TV1_PH), 0x03, 250),
            output(hex32(TV6_PH_K1), 0x04, 50),
        ];
        let detections =
            scan_block(&tv1_scan_sk(), &tv1_spend_pk(), &[tv1_tweak_point()], &outputs, None);

        let found: Vec<(u32, [u8; 32], u64)> =
            detections.iter().map(|d| (d.k, d.coin_id, d.amount)).collect();
        assert_eq!(
            found,
            vec![(0, [0x01; 32], 100), (0, [0x03; 32], 250), (1, [0x04; 32], 50)]
        );
        // Both coins at k = 0 are spendable with the same one-time key.
        assert_eq!(detections[0].tweak, detections[1].tweak);
        for d in &detections {
            derive_onetime_sk_for_detection(d, &tv1_spend_sk()).unwrap();
        }
    }

    #[test]
    fn test_scan_block_match_advances_k_whatever_the_coin_looks_like() {
        // The k = 0 output is a zero-value coin a wallet might hide as dust.
        // It is still a match, so k advances and the k = 1 output is found.
        // (The scanner applies no policy; filtering happens on its result.)
        let outputs = [
            output(hex32(TV1_PH), 0x01, 0),
            output(hex32(TV6_PH_K1), 0x02, 5_000),
        ];
        let detections =
            scan_block(&tv1_scan_sk(), &tv1_spend_pk(), &[tv1_tweak_point()], &outputs, None);
        assert_eq!(detections.len(), 2);

        let kept_by_policy: Vec<&DetectedCoin> =
            detections.iter().filter(|d| d.amount > 0).collect();
        assert_eq!(kept_by_policy.len(), 1);
        assert_eq!(kept_by_policy[0].k, 1);
    }

    #[test]
    fn test_scan_block_skips_identity_tweak_point() {
        // b_scan * O = O for every scan key, so the "shared secret" of an
        // identity tweak point is public. Put the output it leads to in the
        // block: it must not be reported, and the real tweak point next to it
        // must still be processed.
        let identity = PublicKey::default();
        let public_secret: [u8; 32] = Sha256::digest(identity.to_bytes()).into();
        let bait_ph = puzzle_hash_for_pk(&derive_onetime_pk(
            &tv1_spend_pk(),
            &derive_output_tweak(&public_secret, 0),
        ));
        let outputs = [output(bait_ph, 0x66, 1), tv1_output()];

        let detections = scan_block(
            &tv1_scan_sk(),
            &tv1_spend_pk(),
            &[identity, tv1_tweak_point()],
            &outputs,
            None,
        );
        assert_eq!(detections.len(), 1);
        assert_eq!(hex::encode(detections[0].puzzle_hash), TV1_PH);
    }

    #[test]
    fn test_scan_block_repeated_tweak_point_reports_coin_once() {
        let tp = tv1_tweak_point();
        let detections =
            scan_block(&tv1_scan_sk(), &tv1_spend_pk(), &[tp, tp], &[tv1_output()], None);
        assert_eq!(detections.len(), 1);
    }

    #[test]
    fn test_scan_block_stops_at_k_max() {
        // K_MAX outputs to one scan key are all found; an output for index
        // K_MAX, which no conforming sender creates, is not looked for.
        let coin_id = [0x42u8; 32];
        let scan_sk = tv1_scan_sk();
        let recipient = (scan_sk.public_key(), tv1_spend_pk());
        let derived = create_silent_payment_outputs(
            &tv1_sender_sk(),
            &[&coin_id],
            &vec![recipient; K_MAX as usize],
        )
        .unwrap();

        let tweak_point = tweak_point_for_coin(&coin_id);
        let ss = compute_shared_secret_from_tweak(&scan_sk, &tweak_point);
        let beyond_ph = puzzle_hash_for_pk(&derive_onetime_pk(
            &tv1_spend_pk(),
            &derive_output_tweak(&ss, K_MAX),
        ));

        let mut outputs: Vec<OutputMeta> = derived
            .iter()
            .enumerate()
            .map(|(i, (_, ph))| {
                let mut coin_id = [0u8; 32];
                coin_id[..4].copy_from_slice(&(i as u32).to_be_bytes());
                OutputMeta { puzzle_hash: *ph, coin_id, amount: 1, parent_coin_id: [0u8; 32] }
            })
            .collect();
        outputs.push(output(beyond_ph, 0xff, 1));

        let detections = scan_block(&scan_sk, &tv1_spend_pk(), &[tweak_point], &outputs, None);
        assert_eq!(detections.len(), K_MAX as usize);
        assert_eq!(detections.last().unwrap().k, K_MAX - 1);
        assert!(detections.iter().all(|d| d.coin_id != [0xff; 32]));
    }
}
