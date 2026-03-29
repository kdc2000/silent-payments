"""
Tests for BIP-352 protocol extensions adapted for Chia BLS12-381.

Covers: PROTO-01 (multi-output), PROTO-02 (input hash), PROTO-03 (scan/spend separation),
PROTO-04 (labeled sub-addresses), PROTO-05 (label unlinkability), PROTO-06 (change detection),
plus foundational crypto primitives (tagged hash, G1 negation/subtraction).
"""

import hashlib

import pytest
from chia_rs import G1Element, PrivateKey

from shared import (
    GROUP_ORDER,
    aggregate_sender_pks,
    aggregate_sender_sks,
    calculate_synthetic_secret_key,
    compute_input_hash,
    compute_shared_secret_full,
    create_silent_payment_outputs,
    decode_silent_payment_address,
    derive_onetime_pk_full,
    derive_onetime_sk_full,
    derive_output_tweak,
    encode_silent_payment_address,
    generate_label,
    generate_labeled_spend_pk,
    master_sk_to_scan_sk,
    master_sk_to_spend_sk,
    master_sk_to_wallet_sk,
    mnemonic_to_master_sk,
    negate_g1,
    puzzle_hash_for_pk,
    scalar_mult_g1,
    scan_for_silent_payment,
    subtract_g1,
    tagged_hash,
)


# Fixed test mnemonic (BIP-39 "abandon" x 11 + "about")
TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


# --- Tagged Hash Tests ---


def test_tagged_hash_deterministic():
    """tagged_hash with same inputs produces identical 32-byte output."""
    result1 = tagged_hash("Chia_SP/test", b"\x00")
    result2 = tagged_hash("Chia_SP/test", b"\x00")
    assert result1 == result2
    assert len(result1) == 32


def test_tagged_hash_domain_separation():
    """tagged_hash with different tags produces different outputs for same data."""
    result_a = tagged_hash("Chia_SP/A", b"\x01")
    result_b = tagged_hash("Chia_SP/B", b"\x01")
    assert result_a != result_b


# --- G1 Negation/Subtraction Tests ---


def test_negate_g1_inverse():
    """P + negate(P) == identity for a generated key."""
    seed = bytes(32)  # deterministic seed
    sk = PrivateKey.from_seed(seed)
    pk = sk.get_g1()
    negated = negate_g1(pk)
    result = pk + negated
    assert result == G1Element()


def test_subtract_g1_roundtrip():
    """subtract_g1(A + B, B) == A for two generated keys."""
    seed_a = bytes([0] * 32)
    seed_b = bytes([1] * 32)
    sk_a = PrivateKey.from_seed(seed_a)
    sk_b = PrivateKey.from_seed(seed_b)
    a = sk_a.get_g1()
    b = sk_b.get_g1()
    result = subtract_g1(a + b, b)
    assert result == a


def test_negate_g1_identity():
    """negate_g1(identity) returns identity unchanged."""
    identity = G1Element()
    assert negate_g1(identity) == identity


# --- Scan/Spend Key Separation Tests ---


def test_scan_spend_key_separation():
    """Scan, spend, and wallet keys are all distinct from the same mnemonic."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_sk = master_sk_to_scan_sk(master)
    spend_sk = master_sk_to_spend_sk(master)
    wallet_sk = master_sk_to_wallet_sk(master)

    scan_pk = scan_sk.get_g1()
    spend_pk = spend_sk.get_g1()
    wallet_pk = wallet_sk.get_g1()

    # All three public keys must be distinct
    assert scan_pk != spend_pk
    assert scan_pk != wallet_pk
    assert spend_pk != wallet_pk

    # Secret keys must also be distinct
    assert bytes(scan_sk) != bytes(spend_sk)


# --- Input Hash Tests (PROTO-02) ---


def test_input_hash_prevents_reuse():
    """PROTO-02: Same sender+recipient with different coin IDs produce different shared secrets."""
    sender_sk = PrivateKey.from_seed(bytes([2] * 32))
    sender_pk = sender_sk.get_g1()

    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk = master_sk_to_scan_sk(master).get_g1()

    coin_ids_a = [bytes(32)]  # all zeros
    coin_ids_b = [bytes.fromhex("01" * 32)]  # all ones

    input_hash_a = compute_input_hash(coin_ids_a, sender_pk)
    input_hash_b = compute_input_hash(coin_ids_b, sender_pk)

    ss_a = compute_shared_secret_full(sender_sk, scan_pk, input_hash_a)
    ss_b = compute_shared_secret_full(sender_sk, scan_pk, input_hash_b)

    assert ss_a != ss_b


def test_input_hash_range():
    """compute_input_hash returns int in range [0, GROUP_ORDER)."""
    pk = PrivateKey.from_seed(bytes(32)).get_g1()
    result = compute_input_hash([b"\x00" * 32], pk)
    assert 0 <= result < GROUP_ORDER


def test_output_tweak_range():
    """derive_output_tweak returns int in range [0, GROUP_ORDER)."""
    result = derive_output_tweak(b"\x00" * 32, 0)
    assert 0 <= result < GROUP_ORDER


# --- Scan/Spend Separation Tests (PROTO-03) ---


def test_scan_spend_separation():
    """PROTO-03: Scan key detects, spend key derives spending secret."""
    # Recipient keys
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_sk = master_sk_to_scan_sk(master)
    scan_pk = scan_sk.get_g1()
    spend_sk = master_sk_to_spend_sk(master)
    spend_pk = spend_sk.get_g1()

    # Sender keys (different identity)
    sender_sk = PrivateKey.from_seed(bytes([3] * 32))
    sender_pk = sender_sk.get_g1()

    # Fixed coin ID
    coin_ids = [bytes.fromhex("ab" * 32)]
    input_hash = compute_input_hash(coin_ids, sender_pk)

    # Sender side: compute shared secret
    ss_sender = compute_shared_secret_full(sender_sk, scan_pk, input_hash)

    # Scanner side: manual ECDH computation
    input_hash_times_A = scalar_mult_g1(input_hash, sender_pk)
    scan_scalar = int.from_bytes(bytes(scan_sk), "big")
    ecdh_point = scalar_mult_g1(scan_scalar, input_hash_times_A)
    ss_scanner = hashlib.sha256(bytes(ecdh_point)).digest()

    # ECDH commutativity: sender and scanner produce same shared secret
    assert ss_sender == ss_scanner

    # Derive output tweak and one-time keys
    tweak = derive_output_tweak(ss_sender, 0)
    onetime_pk = derive_onetime_pk_full(spend_pk, tweak)
    onetime_sk = derive_onetime_sk_full(spend_sk, tweak)

    # Key pair consistency: derived SK matches derived PK
    assert onetime_sk.get_g1() == onetime_pk


def test_ecdh_commutativity():
    """Independent test: sender and scanner ECDH produce identical results."""
    # Two independent key pairs
    sk_a = PrivateKey.from_seed(bytes([10] * 32))
    pk_a = sk_a.get_g1()
    sk_b = PrivateKey.from_seed(bytes([20] * 32))
    pk_b = sk_b.get_g1()

    coin_ids = [bytes([0xFF] * 32)]
    input_hash = compute_input_hash(coin_ids, pk_a)

    # Sender side: (input_hash * a) * B
    ss_sender = compute_shared_secret_full(sk_a, pk_b, input_hash)

    # Scanner side: b * (input_hash * A)
    input_hash_times_A = scalar_mult_g1(input_hash, pk_a)
    b_scalar = int.from_bytes(bytes(sk_b), "big")
    ecdh_point = scalar_mult_g1(b_scalar, input_hash_times_A)
    ss_scanner = hashlib.sha256(bytes(ecdh_point)).digest()

    assert ss_sender == ss_scanner


# --- Multi-Output Tests (PROTO-01) ---


def test_multi_output_different_recipients():
    """PROTO-01: Two recipients get distinct one-time puzzle hashes from single sender."""
    # Sender
    sender_sk = PrivateKey.from_seed(bytes([2] * 32))

    # Recipient 1
    master_1 = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk_1 = master_sk_to_scan_sk(master_1).get_g1()
    spend_pk_1 = master_sk_to_spend_sk(master_1).get_g1()

    # Recipient 2 (different seed)
    master_2 = PrivateKey.from_seed(bytes([99] * 32))
    scan_pk_2 = master_sk_to_scan_sk(
        mnemonic_to_master_sk("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
    ).get_g1()
    spend_pk_2 = master_sk_to_spend_sk(
        mnemonic_to_master_sk("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
    ).get_g1()

    coin_ids = [b"\xaa" * 32]

    outputs = create_silent_payment_outputs(
        sender_sk, coin_ids, [(scan_pk_1, spend_pk_1), (scan_pk_2, spend_pk_2)]
    )

    assert len(outputs) == 2
    # Different recipients get different puzzle hashes
    assert outputs[0][1] != outputs[1][1]
    # Puzzle hashes differ from the recipients' static spend key puzzle hashes
    assert outputs[0][1] != puzzle_hash_for_pk(spend_pk_1)
    assert outputs[1][1] != puzzle_hash_for_pk(spend_pk_2)


def test_multi_output_same_recipient():
    """PROTO-01: Two outputs to same recipient get different puzzle hashes (counter k)."""
    sender_sk = PrivateKey.from_seed(bytes([2] * 32))

    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk = master_sk_to_scan_sk(master).get_g1()
    spend_pk = master_sk_to_spend_sk(master).get_g1()

    coin_ids = [b"\xbb" * 32]

    outputs = create_silent_payment_outputs(
        sender_sk, coin_ids, [(scan_pk, spend_pk), (scan_pk, spend_pk)]
    )

    assert len(outputs) == 2
    # Same recipient, counter k=0 and k=1 produce different puzzle hashes
    assert outputs[0][1] != outputs[1][1]


# --- Labeled Sub-Address Tests (PROTO-04) ---


def test_labeled_subaddress():
    """PROTO-04: Labeled sub-address generation and detection."""
    # Recipient keys
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_sk = master_sk_to_scan_sk(master)
    scan_pk = scan_sk.get_g1()
    spend_pk = master_sk_to_spend_sk(master).get_g1()

    # Generate label m=1
    label_scalar, label_pk = generate_label(scan_sk, 1)
    labeled_spend_pk = generate_labeled_spend_pk(spend_pk, label_pk)

    # Sender creates output to labeled address
    sender_sk = PrivateKey.from_seed(bytes([5] * 32))
    sender_pk = sender_sk.get_g1()
    coin_ids = [b"\xcc" * 32]

    outputs = create_silent_payment_outputs(
        sender_sk, coin_ids, [(scan_pk, labeled_spend_pk)]
    )
    assert len(outputs) == 1

    # Build labels dict for scanning
    labels_dict = {bytes(label_pk): 1}

    # Scan for the payment
    detected = scan_for_silent_payment(
        scan_sk, spend_pk, sender_pk, coin_ids, [outputs[0][1]], labels=labels_dict
    )

    assert len(detected) == 1
    assert detected[0]["label"] == 1
    assert detected[0]["k"] == 0
    assert detected[0]["puzzle_hash"] == outputs[0][1]


# --- Label Unlinkability Tests (PROTO-05) ---


def test_label_unlinkability():
    """PROTO-05: Observer cannot distinguish labeled from unlabeled outputs."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_sk = master_sk_to_scan_sk(master)
    scan_pk = scan_sk.get_g1()
    spend_pk = master_sk_to_spend_sk(master).get_g1()

    # Generate labeled spend PK
    _, label_pk = generate_label(scan_sk, 1)
    labeled_spend_pk = generate_labeled_spend_pk(spend_pk, label_pk)

    # Sender creates one labeled and one unlabeled output
    sender_sk = PrivateKey.from_seed(bytes([6] * 32))
    coin_ids = [b"\xdd" * 32]

    # Unlabeled output
    outputs_unlabeled = create_silent_payment_outputs(
        sender_sk, coin_ids, [(scan_pk, spend_pk)]
    )
    unlabeled_ph = outputs_unlabeled[0][1]

    # Labeled output (different sender to get different shared secret)
    sender_sk_2 = PrivateKey.from_seed(bytes([7] * 32))
    outputs_labeled = create_silent_payment_outputs(
        sender_sk_2, coin_ids, [(scan_pk, labeled_spend_pk)]
    )
    labeled_ph = outputs_labeled[0][1]

    # Both are standard 32-byte puzzle hashes
    assert isinstance(unlabeled_ph, bytes) and len(unlabeled_ph) == 32
    assert isinstance(labeled_ph, bytes) and len(labeled_ph) == 32

    # Both are produced by puzzle_hash_for_pk (standard format)
    # An observer sees only opaque 32-byte hashes with no structural difference
    assert unlabeled_ph != labeled_ph  # different values but same format


# --- Change Detection Tests (PROTO-06) ---


def test_change_detection():
    """PROTO-06: Sender identifies change output via label m=0."""
    # Recipient keys (sender is also recipient for change)
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_sk = master_sk_to_scan_sk(master)
    scan_pk = scan_sk.get_g1()
    spend_pk = master_sk_to_spend_sk(master).get_g1()

    # Generate change label (m=0, reserved for change)
    change_scalar, change_pk = generate_label(scan_sk, 0)
    change_spend_pk = generate_labeled_spend_pk(spend_pk, change_pk)

    # Sender creates change output
    sender_sk = PrivateKey.from_seed(bytes([8] * 32))
    sender_pk = sender_sk.get_g1()
    coin_ids = [b"\xee" * 32]

    outputs = create_silent_payment_outputs(
        sender_sk, coin_ids, [(scan_pk, change_spend_pk)]
    )
    assert len(outputs) == 1

    # Build labels dict with change label m=0
    labels_dict = {bytes(change_pk): 0}

    # Scan for change output
    detected = scan_for_silent_payment(
        scan_sk, spend_pk, sender_pk, coin_ids, [outputs[0][1]], labels=labels_dict
    )

    assert len(detected) == 1
    assert detected[0]["label"] == 0
    assert detected[0]["k"] == 0


# --- End-to-End Integration Tests ---


def test_end_to_end_send_scan_spend():
    """Full protocol flow: sender derives output, scanner detects it, recipient can spend."""
    # Setup: two parties with deterministic keys
    sender_seed = b"sender-test-seed-32-bytes-long!!"
    sender_master = PrivateKey.from_seed(sender_seed)
    sender_sk = master_sk_to_wallet_sk(sender_master, 0)
    sender_pk = sender_sk.get_g1()

    recipient_seed = b"recipient-seed-32-bytes-long!!!!"
    recipient_master = PrivateKey.from_seed(recipient_seed)
    scan_sk = master_sk_to_scan_sk(recipient_master)
    scan_pk = scan_sk.get_g1()
    spend_sk = master_sk_to_spend_sk(recipient_master)
    spend_pk = spend_sk.get_g1()

    # Sender creates payment
    coin_ids = [b"\xbb" * 32]
    outputs = create_silent_payment_outputs(
        sender_sk, coin_ids, [(scan_pk, spend_pk)]
    )
    assert len(outputs) == 1
    onetime_pk_sender, puzzle_hash = outputs[0]

    # Scanner detects payment (using scan_sk, not spend_sk)
    detected = scan_for_silent_payment(
        scan_sk, spend_pk, sender_pk, coin_ids, [puzzle_hash]
    )
    assert len(detected) == 1
    assert detected[0]["puzzle_hash"] == puzzle_hash
    assert detected[0]["label"] is None

    # Recipient derives spending key (requires spend_sk)
    tweak = detected[0]["tweak"]
    onetime_sk = derive_onetime_sk_full(spend_sk, tweak)

    # Verify key pair consistency
    assert onetime_sk.get_g1() == onetime_pk_sender
    assert puzzle_hash_for_pk(onetime_sk.get_g1()) == puzzle_hash


def test_end_to_end_labeled_payment():
    """Full flow with labeled sub-address."""
    sender_seed = b"sender-test-seed-32-bytes-long!!"
    sender_master = PrivateKey.from_seed(sender_seed)
    sender_sk = master_sk_to_wallet_sk(sender_master, 0)
    sender_pk = sender_sk.get_g1()

    recipient_seed = b"recipient-seed-32-bytes-long!!!!"
    recipient_master = PrivateKey.from_seed(recipient_seed)
    scan_sk = master_sk_to_scan_sk(recipient_master)
    scan_pk = scan_sk.get_g1()
    spend_sk = master_sk_to_spend_sk(recipient_master)
    spend_pk = spend_sk.get_g1()

    # Recipient generates labeled sub-address (m=5)
    label_scalar, label_pk = generate_label(scan_sk, 5)
    labeled_spend_pk = generate_labeled_spend_pk(spend_pk, label_pk)

    # Sender sends to labeled address
    coin_ids = [b"\xcc" * 32]
    outputs = create_silent_payment_outputs(
        sender_sk, coin_ids, [(scan_pk, labeled_spend_pk)]
    )
    puzzle_hash = outputs[0][1]

    # Scanner detects with labels
    labels_dict = {bytes(label_pk): 5}
    detected = scan_for_silent_payment(
        scan_sk, spend_pk, sender_pk, coin_ids, [puzzle_hash],
        labels=labels_dict,
    )
    assert len(detected) == 1
    assert detected[0]["label"] == 5

    # Recipient derives spending key for labeled output
    tweak = detected[0]["tweak"]
    onetime_sk_base = derive_onetime_sk_full(spend_sk, tweak)
    # For labeled output: onetime_sk = base_sk + label_scalar
    labeled_onetime_scalar = (
        int.from_bytes(bytes(onetime_sk_base), "big") + label_scalar
    ) % GROUP_ORDER
    labeled_onetime_sk = PrivateKey.from_bytes(
        labeled_onetime_scalar.to_bytes(32, "big")
    )

    # Verify key pair consistency
    assert labeled_onetime_sk.get_g1() == detected[0]["onetime_pk"]


# --- Silent Payment Address Encoding Tests ---


def test_silent_payment_address_roundtrip():
    """Test 1: encode then decode produces identical 48-byte key pairs."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk = master_sk_to_scan_sk(master).get_g1()
    spend_pk = master_sk_to_spend_sk(master).get_g1()

    scan_pk_bytes = bytes(scan_pk)
    spend_pk_bytes = bytes(spend_pk)

    addr = encode_silent_payment_address(scan_pk_bytes, spend_pk_bytes)
    recovered_scan, recovered_spend = decode_silent_payment_address(addr)

    assert recovered_scan == scan_pk_bytes
    assert recovered_spend == spend_pk_bytes


def test_silent_payment_address_prefix():
    """Test 2: encoded address starts with 'tspxch1'."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk_bytes = bytes(master_sk_to_scan_sk(master).get_g1())
    spend_pk_bytes = bytes(master_sk_to_spend_sk(master).get_g1())

    addr = encode_silent_payment_address(scan_pk_bytes, spend_pk_bytes)
    assert addr.startswith("tspxch1")


def test_silent_payment_address_mainnet_prefix():
    """Test 3: encode with prefix='spxch' produces string starting with 'spxch1'."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk_bytes = bytes(master_sk_to_scan_sk(master).get_g1())
    spend_pk_bytes = bytes(master_sk_to_spend_sk(master).get_g1())

    addr = encode_silent_payment_address(scan_pk_bytes, spend_pk_bytes, prefix="spxch")
    assert addr.startswith("spxch1")

    # Round-trip with mainnet prefix
    recovered_scan, recovered_spend = decode_silent_payment_address(addr)
    assert recovered_scan == scan_pk_bytes
    assert recovered_spend == spend_pk_bytes


def test_silent_payment_address_decode_invalid():
    """Test 4: decode with wrong prefix or corrupted data raises ValueError."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk_bytes = bytes(master_sk_to_scan_sk(master).get_g1())
    spend_pk_bytes = bytes(master_sk_to_spend_sk(master).get_g1())

    addr = encode_silent_payment_address(scan_pk_bytes, spend_pk_bytes)

    # Wrong prefix
    with pytest.raises(ValueError):
        decode_silent_payment_address("txch1" + addr[7:])

    # Corrupted data (flip a character)
    corrupted = addr[:-2] + ("q" if addr[-2] != "q" else "p") + addr[-1]
    with pytest.raises(ValueError):
        decode_silent_payment_address(corrupted)

    # Too short (truncated)
    with pytest.raises((ValueError, IndexError)):
        decode_silent_payment_address("tspxch1qqqqq")


def test_silent_payment_address_deterministic():
    """Test 5: same inputs always produce the same address string."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk_bytes = bytes(master_sk_to_scan_sk(master).get_g1())
    spend_pk_bytes = bytes(master_sk_to_spend_sk(master).get_g1())

    addr1 = encode_silent_payment_address(scan_pk_bytes, spend_pk_bytes)
    addr2 = encode_silent_payment_address(scan_pk_bytes, spend_pk_bytes)
    assert addr1 == addr2


def test_silent_payment_address_payload_length():
    """Test 6: the payload is exactly 96 bytes (two 48-byte compressed BLS G1 keys)."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk_bytes = bytes(master_sk_to_scan_sk(master).get_g1())
    spend_pk_bytes = bytes(master_sk_to_spend_sk(master).get_g1())

    # Each key should be exactly 48 bytes
    assert len(scan_pk_bytes) == 48
    assert len(spend_pk_bytes) == 48

    # Encode and decode, verify full 96-byte payload is preserved
    addr = encode_silent_payment_address(scan_pk_bytes, spend_pk_bytes)
    recovered_scan, recovered_spend = decode_silent_payment_address(addr)
    assert len(recovered_scan) == 48
    assert len(recovered_spend) == 48


# --- Multi-Input Key Aggregation Tests (INPUT-01, INPUT-02) ---


def test_multi_input_sender_aggregation():
    """INPUT-01: aggregate_sender_sks sums synthetic SKs mod GROUP_ORDER."""
    sk1 = PrivateKey.from_seed(bytes([10] * 32))
    sk2 = PrivateKey.from_seed(bytes([20] * 32))
    syn_sk1 = calculate_synthetic_secret_key(sk1)
    syn_sk2 = calculate_synthetic_secret_key(sk2)

    agg_sk = aggregate_sender_sks([syn_sk1, syn_sk2])
    expected_scalar = (
        int.from_bytes(bytes(syn_sk1), "big") + int.from_bytes(bytes(syn_sk2), "big")
    ) % GROUP_ORDER
    assert int.from_bytes(bytes(agg_sk), "big") == expected_scalar


def test_multi_input_key_consistency():
    """INPUT-01: scalar sum's PK == point sum of individual PKs."""
    sk1 = PrivateKey.from_seed(bytes([10] * 32))
    sk2 = PrivateKey.from_seed(bytes([20] * 32))
    syn_sk1 = calculate_synthetic_secret_key(sk1)
    syn_sk2 = calculate_synthetic_secret_key(sk2)

    agg_sk = aggregate_sender_sks([syn_sk1, syn_sk2])
    pk_from_scalar = agg_sk.get_g1()
    pk_from_points = aggregate_sender_pks([syn_sk1.get_g1(), syn_sk2.get_g1()])
    assert pk_from_scalar == pk_from_points


def test_multi_input_zero_sum_sender():
    """INPUT-01: aggregate_sender_sks raises ValueError when sum == 0."""
    # Construct two keys that sum to zero mod GROUP_ORDER.
    # sk1 = 1, sk2 = GROUP_ORDER - 1 (so sum = GROUP_ORDER = 0 mod r)
    sk1 = PrivateKey.from_bytes((1).to_bytes(32, "big"))
    sk2 = PrivateKey.from_bytes((GROUP_ORDER - 1).to_bytes(32, "big"))
    with pytest.raises(ValueError, match="aggregated sender key sum is zero"):
        aggregate_sender_sks([sk1, sk2])


def test_multi_input_zero_sum_scanner():
    """INPUT-02: aggregate_sender_pks returns identity when PKs cancel out."""
    sk = PrivateKey.from_seed(bytes([30] * 32))
    pk = sk.get_g1()
    neg_pk = negate_g1(pk)
    result = aggregate_sender_pks([pk, neg_pk])
    assert result == G1Element()


def test_multi_input_scanner_aggregation():
    """INPUT-02: aggregate_sender_pks sums G1 points correctly."""
    sk1 = PrivateKey.from_seed(bytes([10] * 32))
    sk2 = PrivateKey.from_seed(bytes([20] * 32))
    pk1 = sk1.get_g1()
    pk2 = sk2.get_g1()
    assert aggregate_sender_pks([pk1, pk2]) == pk1 + pk2


def test_multi_input_ecdh_commutativity():
    """INPUT-01 + INPUT-02: sender ECDH with agg_sk matches scanner ECDH with agg_pk."""
    # Two sender wallet keys -> synthetic keys
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    wallet_sk_0 = master_sk_to_wallet_sk(master, 0)
    wallet_sk_1 = master_sk_to_wallet_sk(master, 1)
    syn_sk_0 = calculate_synthetic_secret_key(wallet_sk_0)
    syn_sk_1 = calculate_synthetic_secret_key(wallet_sk_1)

    # Recipient keys
    recip_master = PrivateKey.from_seed(b"recipient-seed-32-bytes-long!!!!")
    scan_sk = master_sk_to_scan_sk(recip_master)
    scan_pk = scan_sk.get_g1()
    spend_pk = master_sk_to_spend_sk(recip_master).get_g1()

    # Aggregate sender keys
    agg_sk = aggregate_sender_sks([syn_sk_0, syn_sk_1])
    agg_pk = aggregate_sender_pks([syn_sk_0.get_g1(), syn_sk_1.get_g1()])
    assert agg_sk.get_g1() == agg_pk

    # Coin IDs
    coin_id_0 = hashlib.sha256(b"multi-input-coin-0").digest()
    coin_id_1 = hashlib.sha256(b"multi-input-coin-1").digest()

    # Sender side: ECDH with agg_sk
    input_hash = compute_input_hash([coin_id_0, coin_id_1], agg_pk)
    ss_sender = compute_shared_secret_full(agg_sk, scan_pk, input_hash)

    # Scanner side: ECDH with agg_pk
    input_hash_times_A = scalar_mult_g1(input_hash, agg_pk)
    scan_scalar = int.from_bytes(bytes(scan_sk), "big")
    ecdh_point = scalar_mult_g1(scan_scalar, input_hash_times_A)
    ss_scanner = hashlib.sha256(bytes(ecdh_point)).digest()

    assert ss_sender == ss_scanner

    # Full detection roundtrip
    tweak = derive_output_tweak(ss_sender, 0)
    onetime_pk = derive_onetime_pk_full(spend_pk, tweak)
    puzzle_hash = puzzle_hash_for_pk(onetime_pk)

    detected = scan_for_silent_payment(
        scan_sk, spend_pk, agg_pk, [coin_id_0, coin_id_1], [puzzle_hash]
    )
    assert len(detected) == 1
    assert detected[0]["puzzle_hash"] == puzzle_hash


def test_multi_input_backward_compat():
    """INPUT-01: create_silent_payment_outputs with single PrivateKey still works."""
    # This test verifies backward compatibility -- single SK still accepted
    sender_sk = PrivateKey.from_seed(bytes([2] * 32))
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    scan_pk = master_sk_to_scan_sk(master).get_g1()
    spend_pk = master_sk_to_spend_sk(master).get_g1()

    coin_ids = [b"\xaa" * 32]
    outputs = create_silent_payment_outputs(
        sender_sk, coin_ids, [(scan_pk, spend_pk)]
    )
    assert len(outputs) == 1
    assert len(outputs[0][1]) == 32  # valid puzzle hash


def test_multi_input_create_outputs_list():
    """INPUT-01: create_silent_payment_outputs with list[PrivateKey] matches manual aggregation."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC)
    wallet_sk_0 = master_sk_to_wallet_sk(master, 0)
    wallet_sk_1 = master_sk_to_wallet_sk(master, 1)
    syn_sk_0 = calculate_synthetic_secret_key(wallet_sk_0)
    syn_sk_1 = calculate_synthetic_secret_key(wallet_sk_1)

    recip_master = PrivateKey.from_seed(b"recipient-seed-32-bytes-long!!!!")
    scan_pk = master_sk_to_scan_sk(recip_master).get_g1()
    spend_pk = master_sk_to_spend_sk(recip_master).get_g1()

    coin_id_0 = hashlib.sha256(b"multi-input-coin-0").digest()
    coin_id_1 = hashlib.sha256(b"multi-input-coin-1").digest()

    # Method 1: pass list of SKs
    outputs_list = create_silent_payment_outputs(
        [syn_sk_0, syn_sk_1],
        [coin_id_0, coin_id_1],
        [(scan_pk, spend_pk)],
    )

    # Method 2: manually aggregate and pass single SK
    agg_sk = aggregate_sender_sks([syn_sk_0, syn_sk_1])
    outputs_single = create_silent_payment_outputs(
        agg_sk,
        [coin_id_0, coin_id_1],
        [(scan_pk, spend_pk)],
    )

    assert outputs_list[0][1] == outputs_single[0][1]  # same puzzle hash
