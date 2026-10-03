//! Full silent payment protocol: send, scan, and label operations.

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};

use crate::scalar::ScalarField;
use crate::tagged_hash::tagged_hash;
use crate::ecdh::{
    compute_input_hash, compute_shared_secret_from_tweak, compute_shared_secret_scanner,
    compute_shared_secret_sender,
};
use crate::puzzle::puzzle_hash_for_pk;

/// Derive the output tweak t_k for output index k.
///
/// t_k = tagged_hash("Chia_SP/SharedSecret", shared_secret || ser32(k)) mod r
pub fn derive_output_tweak(shared_secret: &[u8; 32], k: u32) -> ScalarField {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(shared_secret);
    data.extend_from_slice(&k.to_be_bytes());
    let hash = tagged_hash("Chia_SP/SharedSecret", &data);
    ScalarField::from_bytes_unsigned(hash)
}

/// Derive one-time public key: B_spend + tweak * G.
pub fn derive_onetime_pk(spend_pk: &PublicKey, tweak: &ScalarField) -> PublicKey {
    let tweak_sk = SecretKey::from_bytes(tweak.as_bytes())
        .expect("tweak must be a valid scalar");
    let tweak_pk = tweak_sk.public_key();
    spend_pk + &tweak_pk
}

/// Derive one-time secret key: (b_spend + tweak) mod r.
///
/// `tweak` is t_k for an unlabeled output, or the combined value
/// `(t_k + label_scalar) mod r` for a labeled one (see [`spend_tweak`]).
pub fn derive_onetime_sk(spend_sk: &SecretKey, tweak: &ScalarField) -> SecretKey {
    let sk_scalar = ScalarField::from_bytes_raw(spend_sk.to_bytes());
    let result = sk_scalar.add(tweak);
    SecretKey::from_bytes(result.as_bytes()).expect("result must be a valid scalar")
}

/// Why a label could not be generated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelError {
    /// The label scalar for index `m` is zero mod r. Such a label would give
    /// B_m = B_spend, the unlabeled address, so the index must not be used.
    ZeroLabelScalar { m: u32 },
}

impl std::fmt::Display for LabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LabelError::ZeroLabelScalar { m } => {
                write!(f, "label scalar for index {m} is zero; this label index must not be used")
            }
        }
    }
}

impl std::error::Error for LabelError {}

/// label_scalar = tagged_hash("Chia_SP/Label", ser256(b_scan) || ser32(m)) mod r
fn label_scalar(scan_sk: &SecretKey, m: u32) -> ScalarField {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&scan_sk.to_bytes());
    data.extend_from_slice(&m.to_be_bytes());
    let hash = tagged_hash("Chia_SP/Label", &data);
    ScalarField::from_bytes_unsigned(hash)
}

/// Generate a label for index m. Returns (label_scalar, label_pk).
///
/// label_scalar = tagged_hash("Chia_SP/Label", b_scan || ser32(m)) mod r
/// label_pk = label_scalar * G
///
/// Fails if the label scalar is zero: that label index must not be used.
pub fn generate_label(scan_sk: &SecretKey, m: u32) -> Result<(ScalarField, PublicKey), LabelError> {
    label_from_scalar(m, label_scalar(scan_sk, m))
}

/// Second half of [`generate_label`]: reject a zero scalar, else derive the key.
fn label_from_scalar(
    m: u32,
    label_scalar: ScalarField,
) -> Result<(ScalarField, PublicKey), LabelError> {
    if label_scalar.is_zero() {
        return Err(LabelError::ZeroLabelScalar { m });
    }
    let label_sk = SecretKey::from_bytes(label_scalar.as_bytes())
        .expect("label scalar is reduced mod r");
    Ok((label_scalar, label_sk.public_key()))
}

/// K_max: the maximum number of outputs for one scan key in one spend group.
///
/// A sender MUST NOT create more than `K_MAX` outputs for a single `B_scan` in
/// one spend group, and a scanner stops iterating `k` for a spend group when
/// `k` reaches `K_MAX` (CHIP-0057 "K_max").
pub const K_MAX: u32 = 2400;

/// Why [`create_silent_payment_outputs`] refused to derive outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The spend group has no coins (`coin_ids` is empty).
    NoInputs,
    /// More than [`K_MAX`] recipient entries share one scan key.
    TooManyOutputs { count: usize },
    /// The recipient at `index` has a scan or spend key that is the identity.
    InvalidRecipientKey { index: usize },
    /// The sender's secret keys sum to zero mod r.
    ZeroKeySum,
    /// `input_hash` reduced to zero mod r.
    ZeroInputHash,
    /// The output tweak `t_k` reduced to zero mod r.
    ZeroOutputTweak { k: u32 },
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::NoInputs => write!(f, "spend group has no input coins"),
            SendError::TooManyOutputs { count } => write!(
                f,
                "{count} outputs for one scan key exceeds K_max = {K_MAX}"
            ),
            SendError::InvalidRecipientKey { index } => write!(
                f,
                "recipient {index} has an identity scan or spend key"
            ),
            SendError::ZeroKeySum => write!(
                f,
                "aggregated sender key sum is zero — invalid for ECDH"
            ),
            SendError::ZeroInputHash => write!(f, "input_hash is zero"),
            SendError::ZeroOutputTweak { k } => write!(f, "output tweak t_{k} is zero"),
        }
    }
}

impl std::error::Error for SendError {}

/// A detected silent payment output.
#[derive(Debug, Clone)]
pub struct DetectedOutput {
    /// Output index k within the shared secret derivation.
    pub k: u32,
    /// The output tweak t_k (without any label scalar; see [`spend_tweak`]).
    pub tweak: ScalarField,
    /// Label index m if detected via label, None for unlabeled.
    pub label: Option<u32>,
    /// The matching puzzle hash.
    pub puzzle_hash: [u8; 32],
    /// The one-time public key.
    pub onetime_pk: PublicKey,
    /// Position of the matching output coin in the list that was scanned.
    ///
    /// Several output coins can carry the same puzzle hash; each of them gets
    /// its own `DetectedOutput` with the same `k` and a different
    /// `output_index`.
    pub output_index: usize,
}

/// The output coins of a scan, indexed by puzzle hash.
///
/// Candidate puzzle hashes are matched by lookup, so the work for a spend
/// group does not depend on the number of outputs in the block. Every position
/// that carries a puzzle hash is kept, so that all coins sharing a one-time
/// puzzle hash are reported.
#[derive(Debug, Clone, Default)]
pub struct OutputIndex {
    by_puzzle_hash: HashMap<[u8; 32], Vec<usize>>,
}

impl OutputIndex {
    /// Index a list of output puzzle hashes, one entry per output coin.
    pub fn new(output_puzzle_hashes: &[[u8; 32]]) -> Self {
        let mut by_puzzle_hash: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
        for (i, ph) in output_puzzle_hashes.iter().enumerate() {
            by_puzzle_hash.entry(*ph).or_default().push(i);
        }
        Self { by_puzzle_hash }
    }

    /// True if there are no outputs at all.
    pub fn is_empty(&self) -> bool {
        self.by_puzzle_hash.is_empty()
    }

    /// Positions of every output coin carrying `puzzle_hash`.
    pub fn positions(&self, puzzle_hash: &[u8; 32]) -> &[usize] {
        self.by_puzzle_hash
            .get(puzzle_hash)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Turn a `label_pk -> m` map into a list sorted by ascending label index m.
///
/// Scanning tries labels in this order and the first match wins at each k, so
/// the result does not depend on hash-map iteration order. Entries whose key
/// bytes are not a valid G1 element are dropped.
pub fn sorted_labels(labels: Option<&HashMap<[u8; 48], u32>>) -> Vec<(u32, PublicKey)> {
    let mut out: Vec<(u32, [u8; 48], PublicKey)> = labels
        .into_iter()
        .flatten()
        .filter_map(|(bytes, m)| PublicKey::from_bytes(bytes).ok().map(|pk| (*m, *bytes, pk)))
        .collect();
    out.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    out.into_iter().map(|(m, _, pk)| (m, pk)).collect()
}

/// The single scalar a signer needs to spend a detected output:
/// `t_k` for an unlabeled output, `(t_k + label_scalar_m) mod r` for a
/// labeled one (CHIP-0057 "Spending", closing note).
///
/// With this value the signer needs only `b_spend`:
/// `b_onetime = (b_spend + spend_tweak) mod r` (see [`derive_onetime_sk`]).
pub fn spend_tweak(scan_sk: &SecretKey, t_k: &ScalarField, label: Option<u32>) -> ScalarField {
    match label {
        None => t_k.clone(),
        Some(m) => t_k.add(&label_scalar(scan_sk, m)),
    }
}

/// One scan key with its recipient entries: (original index, B_m).
type RecipientGroup<'a> = (PublicKey, Vec<(usize, &'a PublicKey)>);

/// Group recipient entries by scan key, keeping each entry's original index.
///
/// Groups are returned in order of first appearance and entries keep their
/// list order, so `k` counts entries of one scan key in the order given.
fn group_recipients(recipients: &[(PublicKey, PublicKey)]) -> Vec<RecipientGroup<'_>> {
    let mut slot: HashMap<[u8; 48], usize> = HashMap::new();
    let mut groups: Vec<RecipientGroup<'_>> = Vec::new();
    for (idx, (scan_pk, spend_pk)) in recipients.iter().enumerate() {
        let g = *slot.entry(scan_pk.to_bytes()).or_insert_with(|| {
            groups.push((*scan_pk, Vec::new()));
            groups.len() - 1
        });
        groups[g].1.push((idx, spend_pk));
    }
    groups
}

/// Create silent payment outputs (sender flow, CHIP-0057 `SendSilentPayment`).
///
/// `sender_sk` is a_sum, the sum mod r of the synthetic secret keys of every
/// coin in the spend group (see [`aggregate_sender_sks`]); `coin_ids` are the
/// coin IDs of those same coins. Each recipient is a `(B_scan, B_m)` pair; the
/// same pair may appear more than once. The counter `k` runs over all entries
/// that share a scan key, in list order.
///
/// Returns one `(one-time PK, puzzle hash)` per recipient entry, in the order
/// given. All of them MUST be created in the transaction.
///
/// Fails, deriving nothing, if
/// - more than [`K_MAX`] entries share one scan key,
/// - the key sum is zero mod r,
/// - `input_hash` is zero, or any `t_k` is zero,
/// - `coin_ids` is empty or a recipient key is the identity element.
pub fn create_silent_payment_outputs(
    sender_sk: &ScalarField,
    coin_ids: &[&[u8; 32]],
    recipients: &[(PublicKey, PublicKey)],
) -> Result<Vec<(PublicKey, [u8; 32])>, SendError> {
    if coin_ids.is_empty() {
        return Err(SendError::NoInputs);
    }

    // a_sum mod r. Reducing here makes the zero check hold for any encoding.
    let a_sum = ScalarField::from_bytes_unsigned(sender_sk.to_bytes());
    if a_sum.is_zero() {
        return Err(SendError::ZeroKeySum);
    }

    let a_sum_pk = SecretKey::from_bytes(a_sum.as_bytes())
        .expect("a_sum is reduced mod r")
        .public_key();
    let input_hash = compute_input_hash(coin_ids, &a_sum_pk);

    create_outputs_with(&a_sum, &input_hash, recipients, derive_output_tweak)
}

/// Sender flow after `a_sum` (already checked to be non-zero) and
/// `input_hash` are known.
///
/// `derive_tweak` is [`derive_output_tweak`] in production; tests substitute it
/// to reach the zero-scalar branches, which no real hash input is known to hit.
fn create_outputs_with(
    a_sum: &ScalarField,
    input_hash: &ScalarField,
    recipients: &[(PublicKey, PublicKey)],
    derive_tweak: impl Fn(&[u8; 32], u32) -> ScalarField,
) -> Result<Vec<(PublicKey, [u8; 32])>, SendError> {
    for (index, (scan_pk, spend_pk)) in recipients.iter().enumerate() {
        if scan_pk.is_inf() || spend_pk.is_inf() {
            return Err(SendError::InvalidRecipientKey { index });
        }
    }

    let groups = group_recipients(recipients);
    for (_, entries) in &groups {
        if entries.len() > K_MAX as usize {
            return Err(SendError::TooManyOutputs { count: entries.len() });
        }
    }

    if input_hash.is_zero() {
        return Err(SendError::ZeroInputHash);
    }

    let mut outputs = vec![(PublicKey::default(), [0u8; 32]); recipients.len()];
    for (scan_pk, entries) in &groups {
        let shared_secret = compute_shared_secret_sender(a_sum, scan_pk, input_hash);
        for (k, (orig_idx, spend_pk)) in entries.iter().enumerate() {
            let k = k as u32;
            let tweak = derive_tweak(&shared_secret, k);
            if tweak.is_zero() {
                return Err(SendError::ZeroOutputTweak { k });
            }
            let onetime_pk = derive_onetime_pk(spend_pk, &tweak);
            let ph = puzzle_hash_for_pk(&onetime_pk);
            outputs[*orig_idx] = (onetime_pk, ph);
        }
    }

    Ok(outputs)
}

/// Scan one spend group for silent payments (CHIP-0057 `ScanForSilentPayment`).
///
/// `sender_pk` is A_sum, the sum of the synthetic public keys of every coin in
/// the group, and `coin_ids` are their coin IDs. `output_puzzle_hashes` holds
/// one entry per output coin to check; every coin whose puzzle hash matches is
/// reported, identified by its position in that slice
/// ([`DetectedOutput::output_index`]).
///
/// The group is skipped (nothing is returned) if A_sum is the identity element
/// or `input_hash` is zero. `k` runs from 0 and stops at the first index with
/// no match, at a zero `t_k`, or at [`K_MAX`].
///
/// `labels` maps label public keys to label indices. Wallets SHOULD always
/// include the change label m = 0; this function scans for exactly the labels
/// it is given.
pub fn scan_for_silent_payments(
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
    sender_pk: &PublicKey,
    coin_ids: &[&[u8; 32]],
    output_puzzle_hashes: &[[u8; 32]],
    labels: Option<&HashMap<[u8; 48], u32>>,
) -> Vec<DetectedOutput> {
    // Zero-sum guard: never hash, and never multiply by, the identity.
    if sender_pk.is_inf() || coin_ids.is_empty() {
        return Vec::new();
    }
    let input_hash = compute_input_hash(coin_ids, sender_pk);
    scan_group_with_input_hash(
        scan_sk,
        spend_pk,
        sender_pk,
        &input_hash,
        &OutputIndex::new(output_puzzle_hashes),
        &sorted_labels(labels),
    )
}

/// Scan a spend group once its `input_hash` is known.
fn scan_group_with_input_hash(
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
    sender_pk: &PublicKey,
    input_hash: &ScalarField,
    outputs: &OutputIndex,
    labels: &[(u32, PublicKey)],
) -> Vec<DetectedOutput> {
    if sender_pk.is_inf() || input_hash.is_zero() || outputs.is_empty() {
        return Vec::new();
    }
    let shared_secret = compute_shared_secret_scanner(scan_sk, sender_pk, input_hash);
    scan_shared_secret(&shared_secret, spend_pk, outputs, labels)
}

/// Scan one spend group given its tweak point `T = input_hash · A_sum`
/// (CHIP-0057 "Tweak Points").
///
/// An identity tweak point is skipped. `tweak_point` MUST have been
/// deserialized with subgroup validation (`PublicKey::from_bytes` does this)
/// when it comes from another party. `outputs` should cover all non-coinbase
/// additions of the block, since a tweak point carries no parent information.
pub fn scan_tweak_point(
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
    tweak_point: &PublicKey,
    outputs: &OutputIndex,
    labels: &[(u32, PublicKey)],
) -> Vec<DetectedOutput> {
    if tweak_point.is_inf() || outputs.is_empty() {
        return Vec::new();
    }
    let shared_secret = compute_shared_secret_from_tweak(scan_sk, tweak_point);
    scan_shared_secret(&shared_secret, spend_pk, outputs, labels)
}

/// The `k` loop of `ScanForSilentPayment`, starting from the shared secret.
///
/// For each k: an unlabeled match records every coin with that puzzle hash and
/// moves on to k+1. Otherwise the labels are tried in ascending order of the
/// label index m (`labels` must be sorted that way, see [`sorted_labels`]) and
/// the first label that matches wins: every coin with that labeled puzzle hash
/// is recorded and scanning moves on to k+1. If nothing matched at k, scanning
/// of this group stops.
///
/// Whether to continue depends only on whether a match was found; callers that
/// filter detections by wallet policy must do so after this returns.
pub fn scan_shared_secret(
    shared_secret: &[u8; 32],
    spend_pk: &PublicKey,
    outputs: &OutputIndex,
    labels: &[(u32, PublicKey)],
) -> Vec<DetectedOutput> {
    scan_shared_secret_with(shared_secret, spend_pk, outputs, labels, derive_output_tweak)
}

fn scan_shared_secret_with(
    shared_secret: &[u8; 32],
    spend_pk: &PublicKey,
    outputs: &OutputIndex,
    labels: &[(u32, PublicKey)],
    derive_tweak: impl Fn(&[u8; 32], u32) -> ScalarField,
) -> Vec<DetectedOutput> {
    let mut detected = Vec::new();
    if outputs.is_empty() {
        return detected;
    }

    for k in 0..K_MAX {
        let tweak = derive_tweak(shared_secret, k);
        if tweak.is_zero() {
            break;
        }
        let base_pk = derive_onetime_pk(spend_pk, &tweak);
        let base_ph = puzzle_hash_for_pk(&base_pk);

        let hits = outputs.positions(&base_ph);
        if !hits.is_empty() {
            detected.extend(hits.iter().map(|&output_index| DetectedOutput {
                k,
                tweak: tweak.clone(),
                label: None,
                puzzle_hash: base_ph,
                onetime_pk: base_pk,
                output_index,
            }));
            continue;
        }

        // Labels are detected by forward computation, in ascending order of
        // m. The first label that matches wins at this k.
        let mut found = false;
        for (m, label_pk) in labels {
            let labeled_pk = base_pk + label_pk;
            let labeled_ph = puzzle_hash_for_pk(&labeled_pk);
            let hits = outputs.positions(&labeled_ph);
            if hits.is_empty() {
                continue;
            }
            found = true;
            detected.extend(hits.iter().map(|&output_index| DetectedOutput {
                k,
                tweak: tweak.clone(),
                label: Some(*m),
                puzzle_hash: labeled_ph,
                onetime_pk: labeled_pk,
                output_index,
            }));
            break;
        }

        if !found {
            break;
        }
    }

    detected
}

/// Aggregate multiple sender secret keys into a single scalar.
///
/// a_sum = (a_1 + a_2 + ... + a_n) mod r
pub fn aggregate_sender_sks(sks: &[&SecretKey]) -> ScalarField {
    let mut sum = ScalarField::from_bytes_raw([0u8; 32]);
    for sk in sks {
        let sk_scalar = ScalarField::from_bytes_raw(sk.to_bytes());
        sum = sum.add(&sk_scalar);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tv1_shared_secret() -> [u8; 32] {
        hex::decode("d3ac1e8f651a73d2e20b43cb73fd6997de5504afbc04a2d4546a92d0020ba2c6")
            .unwrap().try_into().unwrap()
    }

    fn tv1_spend_pk() -> PublicKey {
        let bytes: [u8; 48] = hex::decode(
            "8afc580192f44fab624f613369f792eff3220ea3ca822eb839ab2c9309e527dbf6f31e22e0831ba5088c952625a75c74"
        ).unwrap().try_into().unwrap();
        PublicKey::from_bytes(&bytes).unwrap()
    }

    fn tv1_spend_sk() -> SecretKey {
        let bytes: [u8; 32] = hex::decode(
            "53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087"
        ).unwrap().try_into().unwrap();
        SecretKey::from_bytes(&bytes).unwrap()
    }

    fn tv1_scan_sk() -> SecretKey {
        let bytes: [u8; 32] = hex::decode(
            "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6"
        ).unwrap().try_into().unwrap();
        SecretKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn test_derive_output_tweak_tv1() {
        let shared_secret = tv1_shared_secret();
        let tweak = derive_output_tweak(&shared_secret, 0);
        assert_eq!(
            hex::encode(tweak.as_bytes()),
            "5c560301c50fa309ad43d0f82cd1af143f6e3769659c80e8c14a072331582ab1"
        );
    }

    #[test]
    fn test_derive_onetime_pk_tv1() {
        let shared_secret = tv1_shared_secret();
        let tweak = derive_output_tweak(&shared_secret, 0);
        let spend_pk = tv1_spend_pk();
        let onetime_pk = derive_onetime_pk(&spend_pk, &tweak);
        assert_eq!(
            hex::encode(onetime_pk.to_bytes()),
            "b671487c1d275842f529f7a73a63a32a9a1a49e1dbabcac4058cc48626b6db31f48dc49e769a6f8076a9111ff14e964d"
        );
    }

    #[test]
    fn test_derive_onetime_sk_tv1() {
        let shared_secret = tv1_shared_secret();
        let tweak = derive_output_tweak(&shared_secret, 0);
        let spend_sk = tv1_spend_sk();
        let onetime_sk = derive_onetime_sk(&spend_sk, &tweak);
        assert_eq!(
            hex::encode(onetime_sk.to_bytes()),
            "3c399c61ae130724903b3b650e936ff042b7646764289a33519e17100a89db37"
        );
    }

    #[test]
    fn test_generate_label_tv3() {
        let scan_sk = tv1_scan_sk(); // Same scan SK as TV1 (same mnemonic)
        let (label_scalar, label_pk) = generate_label(&scan_sk, 1).unwrap();
        assert_eq!(
            hex::encode(label_scalar.as_bytes()),
            "48fa440acca87f501b9984b5d23327d0b7766a4baa913dfb3001d412c48ce465"
        );
        assert_eq!(
            hex::encode(label_pk.to_bytes()),
            "a6dcff3646739745ef7f3ba8e51808dac13765fa9d5e73386d3fbd7841e0773e02a0f8d91baf57d337954322bd06d80c"
        );
    }

    #[test]
    fn test_labeled_spending_key_tv3() {
        // From TV3: (b_spend + t_0 + label_scalar) mod r
        // t_0 for TV3 is different from TV1 (different coin_id -> different input_hash -> different shared_secret)
        // TV3 base one-time SK = (b_spend + t_0) mod r = 10021d8ab756b398cb4c4732864c264981e39a898e1ff4ea487b8f39f1bb6e77
        // TV3 labeled one-time SK = (base + label_scalar) mod r = 58fc619583ff32e8e6e5cbe8587f4e1a395a04d538b132e5787d634cb64852dc
        let base_onetime_sk_bytes: [u8; 32] = hex::decode(
            "10021d8ab756b398cb4c4732864c264981e39a898e1ff4ea487b8f39f1bb6e77"
        ).unwrap().try_into().unwrap();
        let label_scalar_bytes: [u8; 32] = hex::decode(
            "48fa440acca87f501b9984b5d23327d0b7766a4baa913dfb3001d412c48ce465"
        ).unwrap().try_into().unwrap();

        let base_scalar = ScalarField::from_bytes_raw(base_onetime_sk_bytes);
        let label_scalar = ScalarField::from_bytes_raw(label_scalar_bytes);
        let labeled = base_scalar.add(&label_scalar);
        assert_eq!(
            hex::encode(labeled.as_bytes()),
            "58fc619583ff32e8e6e5cbe8587f4e1a395a04d538b132e5787d634cb64852dc"
        );
    }

    #[test]
    fn test_aggregate_sks_tv4() {
        // TV4: a_syn_0 + a_syn_1 = a_sum
        let a_syn_0_bytes: [u8; 32] = hex::decode(
            "5002eaf015c1c3a9694cc054e96273279732f4f963616ff89b6d4addcd678c7a"
        ).unwrap().try_into().unwrap();
        let a_syn_1_bytes: [u8; 32] = hex::decode(
            "05fded8808216b65d439fc41cb07c7270e37ed743e0745652afe055cfe91cf0f"
        ).unwrap().try_into().unwrap();

        let sk0 = SecretKey::from_bytes(&a_syn_0_bytes).unwrap();
        let sk1 = SecretKey::from_bytes(&a_syn_1_bytes).unwrap();
        let a_sum = aggregate_sender_sks(&[&sk0, &sk1]);
        assert_eq!(
            hex::encode(a_sum.as_bytes()),
            "5600d8781de32f0f3d86bc96b46a3a4ea56ae26da168b55dc66b503acbf95b89"
        );
    }

    #[test]
    fn test_onetime_sk_matches_pk_tv1() {
        // Verify that one-time SK * G == one-time PK
        let shared_secret = tv1_shared_secret();
        let tweak = derive_output_tweak(&shared_secret, 0);
        let spend_pk = tv1_spend_pk();
        let spend_sk = tv1_spend_sk();

        let onetime_pk = derive_onetime_pk(&spend_pk, &tweak);
        let onetime_sk = derive_onetime_sk(&spend_sk, &tweak);
        let derived_pk = onetime_sk.public_key();
        assert_eq!(onetime_pk.to_bytes(), derived_pk.to_bytes());
    }

    // ---------------------------------------------------------------------
    // Sender failure cases (CHIP "Sending", "Edge Cases", "Required Behaviors")
    // ---------------------------------------------------------------------

    fn scalar(n: u8) -> ScalarField {
        let mut b = [0u8; 32];
        b[31] = n;
        ScalarField::from_bytes_raw(b)
    }

    fn zero() -> ScalarField {
        ScalarField::from_bytes_raw([0u8; 32])
    }

    fn test_sk(seed: u8) -> SecretKey {
        SecretKey::from_seed(&[seed; 32])
    }

    fn tv1_recipient() -> (PublicKey, PublicKey) {
        (tv1_scan_sk().public_key(), tv1_spend_pk())
    }

    /// r - x, as a secret key: the additive inverse of `sk` mod r.
    fn negated_sk(sk: &SecretKey) -> SecretKey {
        use num_bigint::BigUint;
        let r = BigUint::from_bytes_be(&crate::scalar::GROUP_ORDER);
        let x = BigUint::from_bytes_be(&sk.to_bytes());
        let be = (r - x).to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be);
        SecretKey::from_bytes(&out).unwrap()
    }

    #[test]
    fn test_send_fails_when_key_sum_is_zero() {
        let a = test_sk(1);
        let b = negated_sk(&a);
        let a_sum = aggregate_sender_sks(&[&a, &b]);
        assert!(a_sum.is_zero(), "a + (r - a) must be zero mod r");

        let coin_id = [7u8; 32];
        let result = create_silent_payment_outputs(&a_sum, &[&coin_id], &[tv1_recipient()]);
        assert_eq!(result.unwrap_err(), SendError::ZeroKeySum);
    }

    #[test]
    fn test_send_fails_when_key_sum_is_unreduced_group_order() {
        // r itself is zero mod r, however it is encoded.
        let a_sum = ScalarField::from_bytes_raw(crate::scalar::GROUP_ORDER);
        let coin_id = [7u8; 32];
        let result = create_silent_payment_outputs(&a_sum, &[&coin_id], &[tv1_recipient()]);
        assert_eq!(result.unwrap_err(), SendError::ZeroKeySum);
    }

    #[test]
    fn test_send_fails_without_inputs() {
        let result = create_silent_payment_outputs(&scalar(5), &[], &[tv1_recipient()]);
        assert_eq!(result.unwrap_err(), SendError::NoInputs);
    }

    #[test]
    fn test_send_fails_when_input_hash_is_zero() {
        let result =
            create_outputs_with(&scalar(5), &zero(), &[tv1_recipient()], derive_output_tweak);
        assert_eq!(result.unwrap_err(), SendError::ZeroInputHash);
    }

    #[test]
    fn test_send_fails_when_output_tweak_is_zero() {
        // t_0 is fine, t_1 is zero: the whole send fails, not just one output.
        let tweak_fn = |ss: &[u8; 32], k: u32| {
            if k == 1 { zero() } else { derive_output_tweak(ss, k) }
        };
        let result = create_outputs_with(
            &scalar(5),
            &scalar(9),
            &[tv1_recipient(), tv1_recipient()],
            tweak_fn,
        );
        assert_eq!(result.unwrap_err(), SendError::ZeroOutputTweak { k: 1 });
    }

    #[test]
    fn test_send_fails_above_k_max_for_one_scan_key() {
        let coin_id = [7u8; 32];
        let recipients = vec![tv1_recipient(); K_MAX as usize + 1];
        let result = create_silent_payment_outputs(&scalar(5), &[&coin_id], &recipients);
        assert_eq!(
            result.unwrap_err(),
            SendError::TooManyOutputs { count: K_MAX as usize + 1 }
        );
    }

    #[test]
    fn test_k_max_counts_per_scan_key_across_labels() {
        // K_MAX entries for one scan key plus one more under a different label
        // of the SAME scan key is over the limit...
        let (scan_pk, spend_pk) = tv1_recipient();
        let (_, label_pk) = generate_label(&tv1_scan_sk(), 1).unwrap();
        let labeled = (scan_pk, &spend_pk + &label_pk);
        let mut recipients = vec![(scan_pk, spend_pk); K_MAX as usize];
        recipients.push(labeled);
        let coin_id = [7u8; 32];
        assert_eq!(
            create_silent_payment_outputs(&scalar(5), &[&coin_id], &recipients).unwrap_err(),
            SendError::TooManyOutputs { count: K_MAX as usize + 1 }
        );

        // ...while one entry for a different scan key does not count towards it.
        // (Checked with the zero-input-hash exit so no outputs need deriving.)
        let other = (test_sk(42).public_key(), test_sk(43).public_key());
        let mut recipients = vec![(scan_pk, spend_pk); K_MAX as usize];
        recipients.push(other);
        assert_eq!(
            create_outputs_with(&scalar(5), &zero(), &recipients, derive_output_tweak)
                .unwrap_err(),
            SendError::ZeroInputHash,
            "K_MAX entries for one key and 1 for another passes the K_max check"
        );
    }

    #[test]
    fn test_send_rejects_identity_recipient_keys() {
        let coin_id = [7u8; 32];
        let (scan_pk, spend_pk) = tv1_recipient();
        let identity = PublicKey::default();
        assert_eq!(
            create_silent_payment_outputs(&scalar(5), &[&coin_id], &[(identity, spend_pk)])
                .unwrap_err(),
            SendError::InvalidRecipientKey { index: 0 }
        );
        assert_eq!(
            create_silent_payment_outputs(
                &scalar(5),
                &[&coin_id],
                &[(scan_pk, spend_pk), (scan_pk, identity)]
            )
            .unwrap_err(),
            SendError::InvalidRecipientKey { index: 1 }
        );
    }

    #[test]
    fn test_k_counts_entries_in_list_order_across_scan_keys() {
        // Recipients interleaved: A, B, A. A's entries get k = 0 and 1, B's k = 0,
        // and each output lands at its original position.
        let sender = test_sk(9);
        let a_sum = ScalarField::from_bytes_raw(sender.to_bytes());
        let coin_id = [3u8; 32];
        let rec_a = tv1_recipient();
        let scan_b = test_sk(50);
        let rec_b = (scan_b.public_key(), test_sk(51).public_key());

        let outputs =
            create_silent_payment_outputs(&a_sum, &[&coin_id], &[rec_a, rec_b, rec_a]).unwrap();

        let input_hash = compute_input_hash(&[&coin_id], &sender.public_key());
        let ss_a = compute_shared_secret_sender(&a_sum, &rec_a.0, &input_hash);
        let ss_b = compute_shared_secret_sender(&a_sum, &rec_b.0, &input_hash);
        let expect = |ss: &[u8; 32], spend: &PublicKey, k: u32| {
            puzzle_hash_for_pk(&derive_onetime_pk(spend, &derive_output_tweak(ss, k)))
        };
        assert_eq!(outputs[0].1, expect(&ss_a, &rec_a.1, 0));
        assert_eq!(outputs[1].1, expect(&ss_b, &rec_b.1, 0));
        assert_eq!(outputs[2].1, expect(&ss_a, &rec_a.1, 1));
    }

    // ---------------------------------------------------------------------
    // Scanner edge cases (CHIP "Scanning a Spend Group", "Edge Cases")
    // ---------------------------------------------------------------------

    /// Sender side of a payment from `sender` (one coin) to the TV1 recipient,
    /// `n` outputs. Returns (sender pk, coin id, output puzzle hashes).
    fn pay_tv1_recipient(n: usize) -> (PublicKey, [u8; 32], Vec<[u8; 32]>) {
        let sender = test_sk(77);
        let coin_id = [0x5au8; 32];
        let a_sum = ScalarField::from_bytes_raw(sender.to_bytes());
        let outputs =
            create_silent_payment_outputs(&a_sum, &[&coin_id], &vec![tv1_recipient(); n]).unwrap();
        (
            sender.public_key(),
            coin_id,
            outputs.into_iter().map(|(_, ph)| ph).collect(),
        )
    }

    #[test]
    fn test_scan_skips_group_with_identity_a_sum() {
        // With A_sum = O the shared secret would be SHA256(serialize(O)) for
        // everyone. Put the output that secret leads to on chain and check that
        // the scanner still reports nothing.
        let identity = PublicKey::default();
        let coin_id = [1u8; 32];
        let predictable_secret: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(identity.to_bytes()).into()
        };
        let t_0 = derive_output_tweak(&predictable_secret, 0);
        let bait = puzzle_hash_for_pk(&derive_onetime_pk(&tv1_spend_pk(), &t_0));

        let detected = scan_for_silent_payments(
            &tv1_scan_sk(), &tv1_spend_pk(), &identity, &[&coin_id], &[bait], None,
        );
        assert!(detected.is_empty(), "identity A_sum must be skipped");

        // The inner procedure skips it too.
        let detected = scan_group_with_input_hash(
            &tv1_scan_sk(), &tv1_spend_pk(), &identity, &scalar(3),
            &OutputIndex::new(&[bait]), &[],
        );
        assert!(detected.is_empty());
    }

    #[test]
    fn test_scan_skips_group_with_zero_input_hash() {
        // With input_hash = 0 the ECDH point is the identity for every sender.
        // The output that leads to must not be reported.
        let sender_pk = test_sk(77).public_key();
        let predictable_secret = compute_shared_secret_scanner(&tv1_scan_sk(), &sender_pk, &zero());
        let t_0 = derive_output_tweak(&predictable_secret, 0);
        let bait = puzzle_hash_for_pk(&derive_onetime_pk(&tv1_spend_pk(), &t_0));

        let detected = scan_group_with_input_hash(
            &tv1_scan_sk(), &tv1_spend_pk(), &sender_pk, &zero(),
            &OutputIndex::new(&[bait]), &[],
        );
        assert!(detected.is_empty(), "zero input_hash must be skipped");
    }

    #[test]
    fn test_scan_empty_coin_ids_is_skipped_not_a_panic() {
        let sender_pk = test_sk(77).public_key();
        let detected = scan_for_silent_payments(
            &tv1_scan_sk(), &tv1_spend_pk(), &sender_pk, &[], &[[1u8; 32]], None,
        );
        assert!(detected.is_empty());
    }

    #[test]
    fn test_scan_stops_at_zero_tweak() {
        // Three real outputs at k = 0, 1, 2. If t_1 were zero the scanner must
        // stop there: k = 0 is reported, k = 2 is never reached. A zero tweak
        // would make the one-time key equal to B_spend itself, so the puzzle
        // hash of B_spend is put on chain too: it must not count as a match.
        let (sender_pk, coin_id, mut phs) = pay_tv1_recipient(3);
        let input_hash = compute_input_hash(&[&coin_id], &sender_pk);
        let ss = compute_shared_secret_scanner(&tv1_scan_sk(), &sender_pk, &input_hash);

        let all = scan_shared_secret(&ss, &tv1_spend_pk(), &OutputIndex::new(&phs), &[]);
        assert_eq!(all.iter().map(|d| d.k).collect::<Vec<_>>(), vec![0, 1, 2]);

        phs.push(puzzle_hash_for_pk(&tv1_spend_pk()));
        let outputs = OutputIndex::new(&phs);
        let tweak_fn = |ss: &[u8; 32], k: u32| {
            if k == 1 { zero() } else { derive_output_tweak(ss, k) }
        };
        let stopped = scan_shared_secret_with(&ss, &tv1_spend_pk(), &outputs, &[], tweak_fn);
        assert_eq!(stopped.iter().map(|d| d.k).collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn test_scan_records_every_coin_with_a_matching_puzzle_hash() {
        // Required Behaviors: two output coins with the same one-time puzzle
        // hash are both reported.
        let (sender_pk, coin_id, phs) = pay_tv1_recipient(2);
        let unrelated = [0xeeu8; 32];
        // positions:     0        1          2       3
        let on_chain = [phs[0], unrelated, phs[0], phs[1]];

        let detected = scan_for_silent_payments(
            &tv1_scan_sk(), &tv1_spend_pk(), &sender_pk, &[&coin_id], &on_chain, None,
        );
        let found: Vec<(u32, usize)> = detected.iter().map(|d| (d.k, d.output_index)).collect();
        assert_eq!(found, vec![(0, 0), (0, 2), (1, 3)]);
        assert!(detected.iter().all(|d| d.label.is_none()));
        assert_eq!(detected[0].tweak, detected[1].tweak, "same k, same one-time key");
        assert_eq!(detected[0].puzzle_hash, phs[0]);
        assert_eq!(detected[2].puzzle_hash, phs[1]);
    }

    #[test]
    fn test_scan_records_every_coin_with_a_matching_labeled_puzzle_hash() {
        let scan_sk = tv1_scan_sk();
        let (_, label_pk) = generate_label(&scan_sk, 1).unwrap();
        let labeled = (scan_sk.public_key(), &tv1_spend_pk() + &label_pk);

        let sender = test_sk(78);
        let coin_id = [0x5bu8; 32];
        let a_sum = ScalarField::from_bytes_raw(sender.to_bytes());
        let ph = create_silent_payment_outputs(&a_sum, &[&coin_id], &[labeled]).unwrap()[0].1;

        let mut labels = HashMap::new();
        labels.insert(label_pk.to_bytes(), 1u32);
        let detected = scan_for_silent_payments(
            &scan_sk, &tv1_spend_pk(), &sender.public_key(), &[&coin_id],
            &[ph, ph], Some(&labels),
        );
        let found: Vec<(u32, Option<u32>, usize)> =
            detected.iter().map(|d| (d.k, d.label, d.output_index)).collect();
        assert_eq!(found, vec![(0, Some(1), 0), (0, Some(1), 1)]);
    }

    #[test]
    fn test_scan_k_runs_across_labels_of_one_scan_key() {
        // Sender pays (B_scan, B_spend), (B_scan, B_1), (B_scan, B_2): k = 0, 1, 2.
        let scan_sk = tv1_scan_sk();
        let spend_pk = tv1_spend_pk();
        let (_, l1) = generate_label(&scan_sk, 1).unwrap();
        let (_, l2) = generate_label(&scan_sk, 2).unwrap();
        let recipients = [
            (scan_sk.public_key(), spend_pk),
            (scan_sk.public_key(), &spend_pk + &l1),
            (scan_sk.public_key(), &spend_pk + &l2),
        ];
        let sender = test_sk(79);
        let coin_id = [0x5cu8; 32];
        let a_sum = ScalarField::from_bytes_raw(sender.to_bytes());
        let phs: Vec<[u8; 32]> = create_silent_payment_outputs(&a_sum, &[&coin_id], &recipients)
            .unwrap()
            .into_iter()
            .map(|(_, ph)| ph)
            .collect();

        let mut labels = HashMap::new();
        labels.insert(l1.to_bytes(), 1u32);
        labels.insert(l2.to_bytes(), 2u32);
        let detected = scan_for_silent_payments(
            &scan_sk, &spend_pk, &sender.public_key(), &[&coin_id], &phs, Some(&labels),
        );
        let found: Vec<(u32, Option<u32>)> = detected.iter().map(|d| (d.k, d.label)).collect();
        assert_eq!(found, vec![(0, None), (1, Some(1)), (2, Some(2))]);
    }

    #[test]
    fn test_scan_first_label_in_ascending_m_wins_at_each_k() {
        // A sender that (against the CHIP) reuses t_0 for labels 1 and 2. At
        // k = 0 the labels are tried in ascending m and the first match wins:
        // label 1 is reported, label 2 is not looked at, whatever order the
        // label map iterates in. k = 1 has no match, so scanning stops.
        let scan_sk = tv1_scan_sk();
        let spend_pk = tv1_spend_pk();
        let (_, l1) = generate_label(&scan_sk, 1).unwrap();
        let (_, l2) = generate_label(&scan_sk, 2).unwrap();
        let (_, l3) = generate_label(&scan_sk, 3).unwrap();
        let ss = [0x11u8; 32];
        let t_0 = derive_output_tweak(&ss, 0);
        let base = derive_onetime_pk(&spend_pk, &t_0);
        let ph1 = puzzle_hash_for_pk(&(&base + &l1));
        let ph2 = puzzle_hash_for_pk(&(&base + &l2));

        // Insert in several orders: the outcome must not depend on it.
        for order in [[3u32, 2, 1], [1, 2, 3], [2, 3, 1]] {
            let mut labels = HashMap::new();
            for m in order {
                let pk = match m { 1 => l1, 2 => l2, _ => l3 };
                labels.insert(pk.to_bytes(), m);
            }
            let detected = scan_shared_secret(
                &ss, &spend_pk, &OutputIndex::new(&[ph2, ph1]), &sorted_labels(Some(&labels)),
            );
            let found: Vec<(u32, Option<u32>, usize)> =
                detected.iter().map(|d| (d.k, d.label, d.output_index)).collect();
            assert_eq!(found, vec![(0, Some(1), 1)]);
        }

        // With only label 2's output on chain, label 2 is the first match.
        let mut labels = HashMap::new();
        labels.insert(l1.to_bytes(), 1u32);
        labels.insert(l2.to_bytes(), 2u32);
        let detected = scan_shared_secret(
            &ss, &spend_pk, &OutputIndex::new(&[ph2]), &sorted_labels(Some(&labels)),
        );
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].label, Some(2));
    }

    #[test]
    fn test_sorted_labels_is_ascending_in_m() {
        let scan_sk = tv1_scan_sk();
        let mut labels = HashMap::new();
        for m in [7u32, 0, 3, 12, 1] {
            labels.insert(generate_label(&scan_sk, m).unwrap().1.to_bytes(), m);
        }
        let order: Vec<u32> = sorted_labels(Some(&labels)).iter().map(|(m, _)| *m).collect();
        assert_eq!(order, vec![0, 1, 3, 7, 12]);
        assert!(sorted_labels(None).is_empty());
    }

    #[test]
    fn test_label_with_zero_scalar_cannot_be_generated() {
        assert_eq!(
            label_from_scalar(5, zero()).unwrap_err(),
            LabelError::ZeroLabelScalar { m: 5 }
        );
        // A non-zero scalar gives label_pk = label_scalar * G.
        let (s, pk) = label_from_scalar(5, scalar(1)).unwrap();
        assert_eq!(s, scalar(1));
        assert_eq!(pk.to_bytes(), PublicKey::generator().to_bytes());
    }

    #[test]
    fn test_k_max_outputs_all_found_and_scan_stops_at_k_max() {
        // The sender may create exactly K_MAX outputs for one scan key, the
        // scanner finds every one of them, and it does not look at index K_MAX
        // even when an output for that index is on chain.
        let (sender_pk, coin_id, mut phs) = pay_tv1_recipient(K_MAX as usize);
        assert_eq!(phs.len(), K_MAX as usize);

        let input_hash = compute_input_hash(&[&coin_id], &sender_pk);
        let ss = compute_shared_secret_scanner(&tv1_scan_sk(), &sender_pk, &input_hash);
        let beyond = derive_output_tweak(&ss, K_MAX);
        phs.push(puzzle_hash_for_pk(&derive_onetime_pk(&tv1_spend_pk(), &beyond)));

        let detected = scan_for_silent_payments(
            &tv1_scan_sk(), &tv1_spend_pk(), &sender_pk, &[&coin_id], &phs, None,
        );
        assert_eq!(detected.len(), K_MAX as usize);
        assert_eq!(detected.first().unwrap().k, 0);
        assert_eq!(detected.last().unwrap().k, K_MAX - 1);
        assert!(detected.iter().all(|d| d.output_index < K_MAX as usize));
    }

    #[test]
    fn test_scan_tweak_point_matches_group_scan_and_skips_identity() {
        let (sender_pk, coin_id, phs) = pay_tv1_recipient(2);
        let input_hash = compute_input_hash(&[&coin_id], &sender_pk);
        let mut tweak_point = sender_pk;
        tweak_point.scalar_multiply(input_hash.as_bytes());
        let outputs = OutputIndex::new(&phs);

        let detected =
            scan_tweak_point(&tv1_scan_sk(), &tv1_spend_pk(), &tweak_point, &outputs, &[]);
        assert_eq!(detected.iter().map(|d| d.k).collect::<Vec<_>>(), vec![0, 1]);

        // Identity tweak point: the predictable secret's output is not reported.
        let identity = PublicKey::default();
        let predictable = compute_shared_secret_from_tweak(&tv1_scan_sk(), &identity);
        let bait = puzzle_hash_for_pk(&derive_onetime_pk(
            &tv1_spend_pk(),
            &derive_output_tweak(&predictable, 0),
        ));
        let detected = scan_tweak_point(
            &tv1_scan_sk(), &tv1_spend_pk(), &identity, &OutputIndex::new(&[bait]), &[],
        );
        assert!(detected.is_empty(), "identity tweak point must be skipped");
    }

    #[test]
    fn test_spend_tweak_unlabeled_and_labeled() {
        let scan_sk = tv1_scan_sk();
        let t = scalar(100);
        assert_eq!(spend_tweak(&scan_sk, &t, None), t);
        let (label_scalar, _) = generate_label(&scan_sk, 1).unwrap();
        assert_eq!(spend_tweak(&scan_sk, &t, Some(1)), t.add(&label_scalar));
    }
}
