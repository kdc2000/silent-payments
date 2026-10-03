"""Test vectors for the CHIP Silent Payments specification.

These tests verify the intermediate + end-product cryptographic values published
in the CHIP's Test Cases section are reproducible from the stated inputs by the
SDK (chia_wallet_sdk) + the shared.py glue.

Each value is driven through the SDK / glue and asserted ``==
golden_vectors.GOLDEN_*`` (tests/golden_vectors.py).

The recipient goldens are LEGACY keys: the unhardened derivation that addresses
generated before the CHIP's hardened-derivation revision used. The recipient keys
are therefore derived explicitly with
``sdk_adapter.legacy_unhardened_keys_from_mnemonic``; ``SilentPaymentKeys.
from_mnemonic`` is hardened and yields different keys. The CHIP's own vectors
(which use the same key values as "given" keys) are checked from the JSON file in
tests/test_chip0057_vectors.py.
"""

# Golden values.
from tests import golden_vectors

# chia_rs: canonical-byte bridging on the SDK side only (G1 add for the labeled
# spend pk; PrivateKey for the agg-pk derivation).
from chia_rs import G1Element, PrivateKey

# shared.py glue (format/constants helpers — bech32m address encoding).
from shared import puzzle_hash_to_address

# SDK side.
from chia_wallet_sdk import (
    LabelRegistry,
    Mnemonic,
    PublicKey,
    SecretKey,
    SilentPaymentNetwork,
    SilentPayments,
)

import sdk_adapter

TEST_MNEMONIC_1 = golden_vectors.TV1
TEST_MNEMONIC_2 = golden_vectors.TV2


# --- SDK helpers ----------------------------------------------------------

def _sdk_recipient_keys(mnemonic: str):
    """SDK scan/spend SecretKey + PublicKey for a recipient mnemonic — the LEGACY
    (unhardened) keys the goldens were generated from."""
    keys = sdk_adapter.legacy_unhardened_keys_from_mnemonic(mnemonic)
    scan_sk = SecretKey.from_bytes(keys.scan_sk().to_bytes())
    spend_sk = SecretKey.from_bytes(keys.spend_sk().to_bytes())
    return dict(
        keys=keys,
        scan_sk=scan_sk,
        scan_pk=scan_sk.public_key(),
        spend_sk=spend_sk,
        spend_pk=spend_sk.public_key(),
    )


def _sdk_sender_syn_sk(mnemonic: str, index: int) -> SecretKey:
    """SDK sender synthetic SecretKey at the standard wallet path + index."""
    sk = SecretKey.from_seed(Mnemonic(mnemonic).to_seed(""))
    for step in (12381, 8444, 2):
        sk = sk.derive_unhardened(step)
    sk = sk.derive_unhardened(index)
    return sk.derive_synthetic()


def _sdk_one_time_ph(scan_pk, spend_pk, syn_sks, coin_ids, agg_pk_bytes, k=0):
    """SDK derive_one_time_puzzle_hash from SDK keys + the frozen agg-pk bytes."""
    agg_sk = SilentPayments.aggregate_sender_sks(syn_sks)
    ih = SilentPayments.compute_input_hash(coin_ids, PublicKey.from_bytes(agg_pk_bytes))
    return SilentPayments.derive_one_time_puzzle_hash(scan_pk, spend_pk, agg_sk, ih, k)


def test_vector_1_single_output():
    """Test Vector 1: Single output payment.

    SDK key derivation + one-time puzzle hash + address == the goldens. Sender
    and recipient both use TEST_MNEMONIC_1.
    """
    # --- Key Derivation (SDK) ---
    syn_sk = _sdk_sender_syn_sk(TEST_MNEMONIC_1, 0)
    assert syn_sk.to_bytes() == golden_vectors.GOLDEN_SYN_SK_TV1_IDX0
    assert syn_sk.public_key().to_bytes() == golden_vectors.GOLDEN_SYN_PK_TV1_IDX0

    r = _sdk_recipient_keys(TEST_MNEMONIC_1)
    assert r["scan_sk"].to_bytes() == golden_vectors.GOLDEN_SCAN_SK_TV1
    assert r["scan_pk"].to_bytes() == golden_vectors.GOLDEN_SCAN_PK_TV1
    assert r["spend_sk"].to_bytes() == golden_vectors.GOLDEN_SPEND_SK_TV1
    assert r["spend_pk"].to_bytes() == golden_vectors.GOLDEN_SPEND_PK_TV1

    # Silent payment address (SDK encode).
    sp_address = r["keys"].unlabeled_address(SilentPaymentNetwork.Testnet).encode()
    assert sp_address.startswith("tspxch1")

    # --- Protocol Execution: one-time puzzle hash + address ---
    ph = _sdk_one_time_ph(
        r["scan_pk"], r["spend_pk"], [syn_sk],
        [golden_vectors.COIN_ID_TV1], golden_vectors.GOLDEN_SYN_PK_TV1_IDX0, 0
    )
    assert ph == golden_vectors.GOLDEN_ONETIME_PH_TV1
    assert puzzle_hash_to_address(ph) == golden_vectors.GOLDEN_ADDRESS_TV1


def test_vector_2_multi_output():
    """Test Vector 2: Multi-output payment to two different recipients.

    Sender uses TEST_MNEMONIC_1. Recipient A uses TEST_MNEMONIC_1, Recipient B
    uses TEST_MNEMONIC_2. SDK one-time puzzle hashes == the frozen goldens.
    """
    syn_sk = _sdk_sender_syn_sk(TEST_MNEMONIC_1, 0)

    a = _sdk_recipient_keys(TEST_MNEMONIC_1)
    b = _sdk_recipient_keys(TEST_MNEMONIC_2)
    assert b["scan_pk"].to_bytes() == golden_vectors.GOLDEN_SCAN_PK_TV2
    assert b["spend_pk"].to_bytes() == golden_vectors.GOLDEN_SPEND_PK_TV2

    ph_a = _sdk_one_time_ph(
        a["scan_pk"], a["spend_pk"], [syn_sk],
        [golden_vectors.COIN_ID_TV2], golden_vectors.GOLDEN_SYN_PK_TV1_IDX0, 0
    )
    ph_b = _sdk_one_time_ph(
        b["scan_pk"], b["spend_pk"], [syn_sk],
        [golden_vectors.COIN_ID_TV2], golden_vectors.GOLDEN_SYN_PK_TV1_IDX0, 0
    )

    assert ph_a == golden_vectors.GOLDEN_ONETIME_PH_TV2_A
    assert ph_b == golden_vectors.GOLDEN_ONETIME_PH_TV2_B
    assert puzzle_hash_to_address(ph_a) == golden_vectors.GOLDEN_ADDRESS_TV2_A
    assert puzzle_hash_to_address(ph_b) == golden_vectors.GOLDEN_ADDRESS_TV2_B

    # Different recipients get different puzzle hashes.
    assert ph_a != ph_b


def test_vector_3_labeled_payment():
    """Test Vector 3: Labeled payment with label m=1.

    Sender and recipient both use TEST_MNEMONIC_1. SDK label point + labeled
    spend pk + one-time puzzle hash == the frozen goldens.
    """
    syn_sk = _sdk_sender_syn_sk(TEST_MNEMONIC_1, 0)
    r = _sdk_recipient_keys(TEST_MNEMONIC_1)

    # SDK label point (m=1).
    reg = LabelRegistry()
    reg.register(r["scan_sk"], 1)
    label_pk = reg.forward(1)
    assert label_pk is not None
    assert label_pk.to_bytes() == golden_vectors.GOLDEN_LABEL_PK_TV3

    # Labeled spend pk = B_spend + label_point.
    labeled_spend_pk_g1 = (
        G1Element.from_bytes(golden_vectors.GOLDEN_SPEND_PK_TV1)
        + G1Element.from_bytes(label_pk.to_bytes())
    )
    assert bytes(labeled_spend_pk_g1) == golden_vectors.GOLDEN_LABELED_SPEND_PK_TV3

    # Labeled silent payment address (SDK).
    labeled_sp_address = r["keys"].labeled_address(SilentPaymentNetwork.Testnet, 1).encode()
    assert labeled_sp_address.startswith("tspxch1")

    # One-time puzzle hash against the labeled spend pk.
    labeled_spend_pk = PublicKey.from_bytes(bytes(labeled_spend_pk_g1))
    ph = _sdk_one_time_ph(
        r["scan_pk"], labeled_spend_pk, [syn_sk],
        [golden_vectors.COIN_ID_TV3], golden_vectors.GOLDEN_SYN_PK_TV1_IDX0, 0
    )
    assert ph == golden_vectors.GOLDEN_ONETIME_PH_TV3
    assert puzzle_hash_to_address(ph) == golden_vectors.GOLDEN_ADDRESS_TV3


def test_vector_4_multi_input():
    """Test Vector 4: Multi-input payment with 2 sender coins.

    Sender uses TEST_MNEMONIC_1 at derivation indices 0 and 1. SDK aggregated
    sk/pk, input hash, and one-time puzzle hash == the frozen goldens.
    """
    syn_sk_0 = _sdk_sender_syn_sk(TEST_MNEMONIC_1, 0)
    syn_sk_1 = _sdk_sender_syn_sk(TEST_MNEMONIC_1, 1)

    # Individual synthetic keys == frozen goldens.
    assert syn_sk_0.to_bytes() == golden_vectors.GOLDEN_SYN_SK_TV1_IDX0
    assert syn_sk_0.public_key().to_bytes() == golden_vectors.GOLDEN_SYN_PK_TV1_IDX0
    assert syn_sk_1.to_bytes() == golden_vectors.GOLDEN_SYN_SK_TV1_IDX1
    assert syn_sk_1.public_key().to_bytes() == golden_vectors.GOLDEN_SYN_PK_TV1_IDX1

    # SDK aggregated sk (a SecretKey) -> agg pk.
    agg_sk = SilentPayments.aggregate_sender_sks([syn_sk_0, syn_sk_1])
    assert agg_sk.to_bytes() == golden_vectors.GOLDEN_AGG_SK_TV4
    assert agg_sk.public_key().to_bytes() == golden_vectors.GOLDEN_AGG_PK_TV4
    agg_pk = PrivateKey.from_bytes(agg_sk.to_bytes()).get_g1()
    assert bytes(agg_pk) == golden_vectors.GOLDEN_AGG_PK_TV4

    coin_ids = [golden_vectors.COIN_ID_TV4_0, golden_vectors.COIN_ID_TV4_1]

    # Lexicographic minimum coin ID (coin_id_1 < coin_id_0).
    assert min(golden_vectors.COIN_ID_TV4_0, golden_vectors.COIN_ID_TV4_1) == golden_vectors.COIN_ID_TV4_1

    # SDK input hash + one-time puzzle hash.
    ih = SilentPayments.compute_input_hash(coin_ids, PublicKey.from_bytes(bytes(agg_pk)))
    assert ih.to_bytes() == golden_vectors.GOLDEN_INPUT_HASH_TV4.to_bytes(32, "big")

    r = _sdk_recipient_keys(TEST_MNEMONIC_1)
    ph = SilentPayments.derive_one_time_puzzle_hash(
        r["scan_pk"], r["spend_pk"], agg_sk, ih, 0
    )
    assert ph == golden_vectors.GOLDEN_ONETIME_PH_TV4
    assert puzzle_hash_to_address(ph) == golden_vectors.GOLDEN_ADDRESS_TV4
