"""
Tests for the CHIP's "Required Behaviors" and for the rules of the
Specification that have no intermediate values to compare.

The first three sections follow the bullets of "Required Behaviors" one by
one (Addresses, Sending, Scanning). The remaining sections cover the other
MUST-level rules: zero scalars, K_max, label handling, tweak points, and the
command-line scripts (watch-only operation, no secret keys in the output).

Blocks are assembled in memory from coin spends; nothing here talks to a node.
"""

import hashlib
import sys
from unittest.mock import patch

import pytest
from chia_rs import AugSchemeMPL, Coin, CoinSpend, G1Element, PrivateKey, Program, SpendBundle

import shared
from shared import (
    GROUP_ORDER,
    K_MAX,
    MOD,
    TESTNET11_GENESIS,
    aggregate_sender_pks,
    aggregate_sender_sks,
    bech32m_encode,
    build_label_map,
    calculate_synthetic_public_key,
    calculate_synthetic_secret_key,
    compute_input_hash,
    compute_tweak_point,
    create_silent_payment_outputs,
    curry,
    decode_silent_payment_address,
    derive_onetime_pk_full,
    derive_onetime_sk_full,
    derive_output_tweak,
    derive_silent_payment_outputs,
    encode_silent_payment_address,
    extract_synthetic_pk,
    generate_label,
    generate_labeled_address,
    generate_labeled_spend_pk,
    master_sk_to_scan_sk,
    master_sk_to_spend_sk,
    master_sk_to_wallet_sk,
    mnemonic_to_master_sk,
    negate_g1,
    own_change_recipient,
    parse_g1_point,
    parse_watch_only_keys,
    puzzle_for_pk,
    puzzle_hash_for_pk,
    scalar_mult_g1,
    scan_for_silent_payment,
    scan_tweak_point,
)
from scanner import (
    asserted_concurrent_spends,
    block_tweak_points,
    form_spend_groups,
    process_block,
    scan_block,
    scan_block_tweak_points,
)
from send_payment import build_silent_payment_spend
from tests.common import (
    RECIPIENT_A_SCAN_SK,
    RECIPIENT_A_SPEND_SK,
    RECIPIENT_B_SCAN_SK,
    RECIPIENT_B_SPEND_SK,
    TEST_MNEMONIC,
    conditions_puzzle_spend,
    created_coins,
    mock_coinset,
    output_coin,
    solution_for_conditions,
    standard_coin,
    standard_spend,
)

# --- Fixtures ---

SCAN_SK = RECIPIENT_A_SCAN_SK
SCAN_PK = SCAN_SK.get_g1()
SPEND_SK = RECIPIENT_A_SPEND_SK
SPEND_PK = SPEND_SK.get_g1()
RECIPIENT = (SCAN_PK, SPEND_PK)
PAYLOAD = bytes(SCAN_PK) + bytes(SPEND_PK)

IDENTITY = bytes([0xC0]) + bytes(47)
# x = 1 is not the x coordinate of any curve point
NOT_ON_CURVE = bytes([0x80]) + bytes(46) + b"\x01"
# x = 4 is on the curve, but the point is outside the prime-order subgroup
NOT_IN_SUBGROUP = bytes([0x80]) + bytes(46) + b"\x04"

_SENDER_MASTER = PrivateKey.from_seed(bytes([7] * 32))
WALLET_SKS = [master_sk_to_wallet_sk(_SENDER_MASTER, i) for i in range(5)]
SYNTHETIC_SKS = [calculate_synthetic_secret_key(sk) for sk in WALLET_SKS]


def sender_coin(index: int, tag: int, amount: int = 1_000_000) -> Coin:
    """A standard-puzzle coin of sender wallet key `index`."""
    return standard_coin(WALLET_SKS[index], bytes([tag]) * 32, amount)


def raw_address(prefix: str, version: int, payload: bytes) -> str:
    """Encode any version and payload, valid or not."""
    return bech32m_encode(prefix, [version] + shared._convertbits(payload, 8, 5))


def coin_ids_of(group) -> set[bytes]:
    return {bytes(coin_spend.coin.name()) for coin_spend, _ in group}


# =====================================================================
# Required Behaviors: Addresses
# =====================================================================

def test_address_version_31_is_rejected():
    """A version 31 address is rejected."""
    with pytest.raises(ValueError, match="version 31"):
        decode_silent_payment_address(raw_address("spxch", 31, PAYLOAD))
    # also with extra payload, as a future format might have
    with pytest.raises(ValueError, match="version 31"):
        decode_silent_payment_address(raw_address("tspxch", 31, PAYLOAD + bytes(10)))


@pytest.mark.parametrize("payload", [
    PAYLOAD[:95], PAYLOAD + b"\x00", PAYLOAD + bytes(4), PAYLOAD + PAYLOAD, b"",
], ids=["95", "97", "100", "192", "0"])
def test_address_version_0_requires_exactly_96_bytes(payload):
    """A version 0 address whose payload is not exactly 96 bytes is rejected."""
    with pytest.raises(ValueError):
        decode_silent_payment_address(raw_address("spxch", 0, payload))


@pytest.mark.parametrize("version", range(1, 31))
def test_address_versions_1_to_30_use_first_96_bytes(version):
    """A version 1 through 30 address with extra payload bytes is accepted,
    using the first 96 bytes."""
    keys = (bytes(SCAN_PK), bytes(SPEND_PK))
    assert decode_silent_payment_address(raw_address("spxch", version, PAYLOAD + bytes([1, 2, 3, 4]))) == keys
    assert decode_silent_payment_address(raw_address("tspxch", version, PAYLOAD + bytes(range(200)))) == keys
    assert decode_silent_payment_address(raw_address("spxch", version, PAYLOAD)) == keys
    # shorter than 96 bytes: invalid
    with pytest.raises(ValueError):
        decode_silent_payment_address(raw_address("spxch", version, PAYLOAD[:95]))


@pytest.mark.parametrize("payload", [
    IDENTITY + bytes(SPEND_PK),
    bytes(SCAN_PK) + IDENTITY,
    NOT_ON_CURVE + bytes(SPEND_PK),
    bytes(SCAN_PK) + NOT_ON_CURVE,
    NOT_IN_SUBGROUP + bytes(SPEND_PK),
    bytes(SCAN_PK) + NOT_IN_SUBGROUP,
    bytes(48) + bytes(SPEND_PK),
], ids=[
    "scan_identity", "spend_identity", "scan_not_on_curve", "spend_not_on_curve",
    "scan_not_in_subgroup", "spend_not_in_subgroup", "scan_bad_encoding",
])
def test_address_with_identity_or_invalid_key_is_rejected(payload):
    """An address in which either key is the identity element, or is not a
    valid G1 element, is rejected - for version 0 and for versions 1-30."""
    with pytest.raises(ValueError):
        decode_silent_payment_address(raw_address("spxch", 0, payload))
    with pytest.raises(ValueError):
        decode_silent_payment_address(raw_address("spxch", 7, payload + b"\x00\x00"))


def test_point_validation_rejects_points_outside_the_subgroup():
    """The x = 4 point really is on the curve (so only the subgroup check can
    reject it), and parse_g1_point rejects it."""
    on_curve = G1Element.from_bytes_unchecked(NOT_IN_SUBGROUP)
    assert bytes(on_curve) == NOT_IN_SUBGROUP
    for bad in (NOT_IN_SUBGROUP, NOT_ON_CURVE, IDENTITY, bytes(47), bytes(49)):
        with pytest.raises(ValueError):
            parse_g1_point(bad)
    assert parse_g1_point(bytes(SCAN_PK)) == SCAN_PK


def test_address_padding_bits_must_be_zero():
    """Leftover padding bits of the 5-to-8-bit conversion must be zero."""
    address = encode_silent_payment_address(bytes(SCAN_PK), bytes(SPEND_PK), "spxch")
    assert decode_silent_payment_address(address) == (bytes(SCAN_PK), bytes(SPEND_PK))

    # 96 bytes are 153 full groups and 3 bits: the last group has 2 padding bits.
    groups = [0] + shared._convertbits(PAYLOAD, 8, 5)
    assert groups[-1] & 0b11 == 0
    for padding in (1, 2, 3):
        tampered = groups[:-1] + [groups[-1] | padding]
        with pytest.raises(ValueError, match="padding"):
            decode_silent_payment_address(bech32m_encode("spxch", tampered))

    # A whole surplus 5-bit group is not padding either, even when it is zero.
    with pytest.raises(ValueError):
        decode_silent_payment_address(bech32m_encode("spxch", groups + [0]))


def test_address_length_limit():
    """Addresses up to 1,023 characters are accepted; longer ones are not.
    The 90-character bech32 limit is not enforced."""
    v0 = encode_silent_payment_address(bytes(SCAN_PK), bytes(SPEND_PK), "spxch")
    assert len(v0) == 167 > 90

    # version 1, 634 payload bytes: "spxch" + "1" + 1 + 1015 + 6 = 1,028 > 1,023
    too_long = raw_address("spxch", 1, PAYLOAD + bytes(634 - 96))
    assert len(too_long) > 1023
    with pytest.raises(ValueError, match="too long"):
        decode_silent_payment_address(too_long)

    # 630 payload bytes: 1,008 data characters, 1,021 in total
    longest = raw_address("spxch", 1, PAYLOAD + bytes(630 - 96))
    assert 1016 <= len(longest) <= 1023
    assert decode_silent_payment_address(longest) == (bytes(SCAN_PK), bytes(SPEND_PK))


def test_address_network_and_format_checks():
    """Wrong network, mixed case and pre-versioning addresses are rejected."""
    mainnet = encode_silent_payment_address(bytes(SCAN_PK), bytes(SPEND_PK), "spxch")
    testnet = encode_silent_payment_address(bytes(SCAN_PK), bytes(SPEND_PK), "tspxch")

    # A sender rejects an address for another network
    assert decode_silent_payment_address(testnet, expected_prefix="tspxch")
    with pytest.raises(ValueError, match="another network"):
        decode_silent_payment_address(mainnet, expected_prefix="tspxch")
    with pytest.raises(ValueError, match="another network"):
        decode_silent_payment_address(testnet, expected_prefix="spxch")

    # bech32m: all upper case is the same address, mixed case is invalid
    assert decode_silent_payment_address(mainnet.upper()) == (bytes(SCAN_PK), bytes(SPEND_PK))
    with pytest.raises(ValueError, match="mixed case"):
        decode_silent_payment_address(mainnet[:20] + mainnet[20:].upper())

    # An address without the version character (payload directly after "1")
    legacy = bech32m_encode("tspxch", shared._convertbits(PAYLOAD, 8, 5))
    with pytest.raises(ValueError):
        decode_silent_payment_address(legacy)


def test_encoder_refuses_invalid_keys():
    """No address is produced that a decoder would have to reject."""
    for scan, spend in (
        (IDENTITY, bytes(SPEND_PK)), (bytes(SCAN_PK), IDENTITY),
        (NOT_IN_SUBGROUP, bytes(SPEND_PK)), (bytes(SCAN_PK), NOT_ON_CURVE),
        (bytes(SCAN_PK)[:47], bytes(SPEND_PK)),
    ):
        with pytest.raises(ValueError):
            encode_silent_payment_address(scan, spend)
    with pytest.raises(ValueError):
        encode_silent_payment_address(bytes(SCAN_PK), bytes(SPEND_PK), prefix="xch")


# =====================================================================
# Required Behaviors: Sending
# =====================================================================

def test_sender_fails_on_zero_key_sum():
    """A spend group whose secret keys sum to zero mod r makes the sender fail."""
    sk1 = PrivateKey.from_bytes((5).to_bytes(32, "big"))
    sk2 = PrivateKey.from_bytes((GROUP_ORDER - 5).to_bytes(32, "big"))
    coin_ids = [b"\x01" * 32, b"\x02" * 32]
    with pytest.raises(ValueError, match="aggregated sender key sum is zero"):
        create_silent_payment_outputs([sk1, sk2], coin_ids, [RECIPIENT])
    with pytest.raises(ValueError, match="aggregated sender key sum is zero"):
        derive_silent_payment_outputs([sk1, sk2], coin_ids, [RECIPIENT])
    # a single zero key is a zero sum as well
    zero = PrivateKey.from_bytes(bytes(32))
    with pytest.raises(ValueError, match="aggregated sender key sum is zero"):
        create_silent_payment_outputs(zero, [b"\x01" * 32], [RECIPIENT])
    with pytest.raises(ValueError, match="aggregated sender key sum is zero"):
        create_silent_payment_outputs([zero], [b"\x01" * 32], [RECIPIENT])


def test_sender_fails_above_k_max_outputs_for_one_scan_key():
    """More than K_max outputs for one scan key in one spend group makes the
    sender fail."""
    assert K_MAX == 2400
    with pytest.raises(ValueError, match="K_max"):
        create_silent_payment_outputs(
            SYNTHETIC_SKS[0], [b"\x01" * 32], [RECIPIENT] * (K_MAX + 1)
        )
    # The limit is per scan key and counts entries with different labels too.
    _, label_pk = generate_label(SCAN_SK, 1)
    labeled = (SCAN_PK, generate_labeled_spend_pk(SPEND_PK, label_pk))
    with pytest.raises(ValueError, match="K_max"):
        create_silent_payment_outputs(
            SYNTHETIC_SKS[0], [b"\x01" * 32], [RECIPIENT] * K_MAX + [labeled]
        )


def test_k_max_is_per_scan_key(monkeypatch):
    """Exactly K_max outputs for one scan key are allowed, and outputs for
    another scan key do not count towards it (checked with a small K_max)."""
    monkeypatch.setattr(shared, "K_MAX", 3)
    other = (RECIPIENT_B_SCAN_SK.get_g1(), RECIPIENT_B_SPEND_SK.get_g1())
    outputs = derive_silent_payment_outputs(
        SYNTHETIC_SKS[0], [b"\x01" * 32], [RECIPIENT] * 3 + [other] * 3
    )
    assert [o["k"] for o in outputs] == [0, 1, 2, 0, 1, 2]
    with pytest.raises(ValueError, match="K_max"):
        derive_silent_payment_outputs(SYNTHETIC_SKS[0], [b"\x01" * 32], [RECIPIENT] * 4)


def test_sender_cycle_with_intermediate_coin():
    """When the sender's cycle includes an intermediate coin created inside
    the transaction, that coin's key and coin ID are included in a_sum and
    coin_id_L, and the recipient detects the payment."""
    # Coin A exists before the transaction. A creates the intermediate coin E
    # (a different key of the sender), and E is spent in the same block.
    # Search parents until the intermediate coin has the smallest coin ID, so
    # that leaving it out would change coin_id_L.
    for tag in range(1, 200):
        coin_a = sender_coin(0, tag)
        coin_e = Coin(coin_a.name(), puzzle_hash_for_pk(WALLET_SKS[1].get_g1()), 600_000)
        if coin_e.name() < coin_a.name():
            break
    assert coin_e.name() < coin_a.name()
    group_ids = [bytes(coin_a.name()), bytes(coin_e.name())]

    # The sender derives the output from BOTH coins: the group as it stands
    # once the whole transaction has been laid out.
    (output,) = derive_silent_payment_outputs(
        [SYNTHETIC_SKS[0], SYNTHETIC_SKS[1]], group_ids, [RECIPIENT]
    )
    pk_sum = aggregate_sender_pks([SYNTHETIC_SKS[0].get_g1(), SYNTHETIC_SKS[1].get_g1()])
    # coin_id_L is the intermediate coin's ID, and a_sum includes its key.
    assert min(group_ids) == bytes(coin_e.name())
    input_hash = int.from_bytes(
        shared.tagged_hash("Chia_SP/Inputs", bytes(coin_e.name()) + bytes(pk_sum)), "big"
    ) % GROUP_ORDER
    assert input_hash == compute_input_hash(group_ids, pk_sum)
    a_sum = aggregate_sender_sks(SYNTHETIC_SKS[:2])
    assert a_sum.get_g1() == pk_sum
    assert output["shared_secret"] == shared.compute_shared_secret_full(a_sum, SCAN_PK, input_hash)

    # A -> E -> A is the cycle; the intermediate coin creates the payment.
    spends = [
        standard_spend(coin_a, WALLET_SKS[0], [
            [51, coin_e.puzzle_hash, coin_e.amount], [64, coin_e.name()],
        ]),
        standard_spend(coin_e, WALLET_SKS[1], [
            [51, output["puzzle_hash"], 500_000], [64, coin_a.name()],
        ]),
    ]
    additions = created_coins(spends)
    assert coin_e in additions

    groups = form_spend_groups(spends)
    assert [coin_ids_of(g) for g in groups] == [
        {group_ids[0]}, {group_ids[1]}, set(group_ids),
    ]

    detected = scan_block(SCAN_SK, SPEND_PK, spends, additions)
    assert len(detected) == 1
    assert detected[0]["puzzle_hash"] == output["puzzle_hash"]
    assert detected[0]["t_k"] == output["t_k"]
    assert set(detected[0]["group_coin_ids"]) == set(group_ids)
    assert detected[0]["coin"].amount == 500_000

    # An output derived without the intermediate coin is NOT what the
    # scanner finds: it differs from the correct one.
    (stale,) = derive_silent_payment_outputs([SYNTHETIC_SKS[0]], group_ids[:1], [RECIPIENT])
    assert stale["puzzle_hash"] != output["puzzle_hash"]


# =====================================================================
# Required Behaviors: Scanning
# =====================================================================

def _identity_sum_block():
    """Two eligible spends bound in a cycle whose public keys cancel."""
    pk = SYNTHETIC_SKS[0].get_g1()
    neg_puzzle = curry(MOD, bytes(negate_g1(pk)))
    assert extract_synthetic_pk(neg_puzzle) == negate_g1(pk)
    coin_a = sender_coin(0, 0x21)
    coin_n = Coin(b"\x22" * 32, neg_puzzle.get_tree_hash(), 1_000_000)

    # What a scanner WITHOUT the guard would derive: with A_sum = O the
    # shared secret is SHA256(serialize(O)), the same for every recipient.
    shared_secret = hashlib.sha256(bytes(G1Element())).digest()
    predictable_ph = puzzle_hash_for_pk(
        derive_onetime_pk_full(SPEND_PK, derive_output_tweak(shared_secret, 0))
    )
    spends = [
        standard_spend(coin_a, WALLET_SKS[0], [[51, predictable_ph, 1000], [64, coin_n.name()]]),
        CoinSpend(coin_n, neg_puzzle, solution_for_conditions([[64, coin_a.name()]])),
    ]
    return spends, predictable_ph


def test_scanner_skips_group_with_identity_key_sum():
    """A spend group whose public keys sum to the identity element is skipped."""
    spends, predictable_ph = _identity_sum_block()
    additions = created_coins(spends)
    assert [c.puzzle_hash for c in additions] == [predictable_ph]

    # The two spends do form a multi-input group...
    groups = form_spend_groups(spends)
    assert len(groups) == 3 and len(groups[2]) == 2
    assert aggregate_sender_pks([pk for _, pk in groups[2]]) == G1Element()

    # ...which is skipped: no detection, and no tweak point for it.
    assert scan_block(SCAN_SK, SPEND_PK, spends, additions) == []
    assert len(block_tweak_points(spends)) == 2
    coin_ids = [bytes(cs.coin.name()) for cs, _ in groups[2]]
    assert compute_tweak_point(coin_ids, G1Element()) is None
    assert scan_for_silent_payment(SCAN_SK, SPEND_PK, G1Element(), coin_ids, additions) == []


def test_one_way_asserter_is_not_part_of_the_group():
    """A spend that asserts a group member's coin ID without being asserted
    back is not part of that group, and the payment is still detected."""
    coin_0, coin_1, coin_m = sender_coin(0, 0x31), sender_coin(1, 0x32), sender_coin(3, 0x3D)
    group_ids = [bytes(coin_0.name()), bytes(coin_1.name())]
    (output,) = derive_silent_payment_outputs(SYNTHETIC_SKS[:2], group_ids, [RECIPIENT])

    spends = [
        standard_spend(coin_0, WALLET_SKS[0], [[51, output["puzzle_hash"], 700], [64, coin_1.name()]]),
        standard_spend(coin_1, WALLET_SKS[1], [[64, coin_0.name()]]),
        # third party: asserts both members, nobody asserts it back
        standard_spend(coin_m, WALLET_SKS[3], [[64, coin_0.name()], [64, coin_1.name()]]),
    ]

    groups = form_spend_groups(spends)
    assert [coin_ids_of(g) for g in groups] == [
        {group_ids[0]}, {group_ids[1]}, {bytes(coin_m.name())}, set(group_ids),
    ]

    detected = scan_block(SCAN_SK, SPEND_PK, spends, created_coins(spends))
    assert len(detected) == 1
    assert detected[0]["puzzle_hash"] == output["puzzle_hash"]
    assert set(detected[0]["group_coin_ids"]) == set(group_ids)


def test_non_eligible_spend_contributes_nothing():
    """A spend that is not an eligible spend contributes no key, no coin ID,
    and no edge, even when it outputs ASSERT_CONCURRENT_SPEND conditions."""
    coin_a, coin_b = sender_coin(0, 0x41), sender_coin(1, 0x42)

    # N is not a standard-puzzle spend. The assertions run A -> N -> B -> A:
    # a cycle only if N counted as a vertex.
    spend_n = conditions_puzzle_spend(b"\x4e" * 32, 5, [[64, coin_b.name()]])
    assert extract_synthetic_pk(spend_n.puzzle_reveal) is None
    assert asserted_concurrent_spends(spend_n) == [bytes(coin_b.name())]

    # A is therefore a single-input group, and its payment is derived from A alone.
    (output,) = derive_silent_payment_outputs([SYNTHETIC_SKS[0]], [bytes(coin_a.name())], [RECIPIENT])
    # What a scanner that let N join the graph would look for instead:
    (wrong,) = derive_silent_payment_outputs(
        SYNTHETIC_SKS[:2], [bytes(coin_a.name()), bytes(coin_b.name())], [RECIPIENT]
    )

    spends = [
        standard_spend(coin_a, WALLET_SKS[0], [
            [51, output["puzzle_hash"], 100], [51, wrong["puzzle_hash"], 200],
            [64, spend_n.coin.name()],
        ]),
        spend_n,
        standard_spend(coin_b, WALLET_SKS[1], [[64, coin_a.name()]]),
    ]

    # Only single-input groups, and only of the eligible spends.
    groups = form_spend_groups(spends)
    assert [coin_ids_of(g) for g in groups] == [{bytes(coin_a.name())}, {bytes(coin_b.name())}]
    assert len(block_tweak_points(spends)) == 2

    detected = scan_block(SCAN_SK, SPEND_PK, spends, created_coins(spends))
    assert [d["puzzle_hash"] for d in detected] == [output["puzzle_hash"]]
    assert detected[0]["group_coin_ids"] == [bytes(coin_a.name())]


def test_wrapped_or_altered_standard_puzzle_is_not_eligible():
    """Only the bare standard puzzle is eligible: no outer layer, no other
    module, no extra curried argument, no invalid key."""
    synthetic_pk = calculate_synthetic_public_key(WALLET_SKS[0].get_g1())
    standard = puzzle_for_pk(WALLET_SKS[0].get_g1())
    assert extract_synthetic_pk(standard) == synthetic_pk
    assert extract_synthetic_pk(Program.from_bytes(bytes(standard))) == synthetic_pk

    # another module with a public key as its first curried argument
    other_mod = Program.to([2, 2, 5])
    assert extract_synthetic_pk(curry(other_mod, bytes(synthetic_pk))) is None
    # the standard module with a second curried argument
    assert extract_synthetic_pk(curry(MOD, bytes(synthetic_pk), b"\x01" * 32)) is None
    # the standard puzzle as the inner puzzle of an outer layer
    wrapped = Program.from_bytes_unchecked(
        b"\xff\x02\xff\xff\x01" + bytes(other_mod)
        + b"\xff\xff\x04\xff\xff\x01" + bytes(standard) + b"\xff\x01\x80\x80"
    )
    assert extract_synthetic_pk(wrapped) is None
    # the standard module curried with bytes that are not a valid key
    assert extract_synthetic_pk(curry(MOD, NOT_IN_SUBGROUP)) is None
    assert extract_synthetic_pk(curry(MOD, b"\x01" * 32)) is None
    # not curried at all
    assert extract_synthetic_pk(MOD) is None
    assert extract_synthetic_pk(Program.to(1)) is None


def test_only_consensus_encoding_of_condition_64_counts():
    """A two-byte 0x0040 atom is not condition code 64, and the first argument
    must be a 32-byte atom."""
    coin_a, coin_b = sender_coin(0, 0x51), sender_coin(1, 0x52)
    b_asserts_a = standard_spend(coin_b, WALLET_SKS[1], [[64, coin_a.name()]])
    singles = [{bytes(coin_a.name())}, {bytes(coin_b.name())}]

    for bad_condition in (
        [b"\x00\x40", coin_a.name()],              # two-byte encoding of 64
        [b"\x00\x00\x40", coin_a.name()],
        [64, coin_b.name()[:31]],                  # argument is not 32 bytes
        [64, coin_b.name() + b"\x00"],
        [64, [coin_b.name()]],                     # argument is not an atom
        [64],
    ):
        if bad_condition[0] != 64:
            bad_condition = [bad_condition[0], coin_b.name()]
        a_spend = standard_spend(coin_a, WALLET_SKS[0], [bad_condition])
        assert asserted_concurrent_spends(a_spend) == []
        assert [coin_ids_of(g) for g in form_spend_groups([a_spend, b_asserts_a])] == singles

    # The one-byte code with a 32-byte first argument is the condition; extra
    # arguments do not change that.
    for good_condition in ([64, coin_b.name()], [b"\x40", coin_b.name(), b"extra"]):
        a_spend = standard_spend(coin_a, WALLET_SKS[0], [good_condition])
        assert asserted_concurrent_spends(a_spend) == [bytes(coin_b.name())]
        assert [coin_ids_of(g) for g in form_spend_groups([a_spend, b_asserts_a])] == singles + [
            {bytes(coin_a.name()), bytes(coin_b.name())}
        ]


def test_assertion_of_coin_outside_the_block_adds_no_edge():
    """Conditions naming coins that are not eligible spends in the block add
    no edge and no coin ID."""
    coin_a, coin_b = sender_coin(0, 0x61), sender_coin(1, 0x62)
    elsewhere = b"\x00" * 32  # smaller than any real coin ID, not spent here
    group_ids = [bytes(coin_a.name()), bytes(coin_b.name())]
    (output,) = derive_silent_payment_outputs(SYNTHETIC_SKS[:2], group_ids, [RECIPIENT])
    spends = [
        standard_spend(coin_a, WALLET_SKS[0], [
            [51, output["puzzle_hash"], 100], [64, coin_b.name()], [64, elsewhere],
        ]),
        standard_spend(coin_b, WALLET_SKS[1], [[64, coin_a.name()], [64, elsewhere]]),
    ]
    assert coin_ids_of(form_spend_groups(spends)[2]) == set(group_ids)
    detected = scan_block(SCAN_SK, SPEND_PK, spends, created_coins(spends))
    assert [d["puzzle_hash"] for d in detected] == [output["puzzle_hash"]]


def test_two_coins_with_the_same_one_time_puzzle_hash_are_both_reported():
    """Two output coins with the same one-time puzzle hash are both reported."""
    # One coin creating two coins of different amounts for the same puzzle hash
    coin_a = sender_coin(0, 0x71)
    (output,) = derive_silent_payment_outputs([SYNTHETIC_SKS[0]], [bytes(coin_a.name())], [RECIPIENT])
    spends = [standard_spend(coin_a, WALLET_SKS[0], [
        [51, output["puzzle_hash"], 100], [51, output["puzzle_hash"], 250],
    ])]
    detected = scan_block(SCAN_SK, SPEND_PK, spends, created_coins(spends))
    assert sorted(d["coin"].amount for d in detected) == [100, 250]
    assert {d["k"] for d in detected} == {0}
    assert len({d["coin_id"] for d in detected}) == 2
    # one key spends both
    assert len({d["spend_tweak"] for d in detected}) == 1
    onetime_sk = derive_onetime_sk_full(SPEND_SK, detected[0]["spend_tweak"])
    assert puzzle_hash_for_pk(onetime_sk.get_g1()) == output["puzzle_hash"]

    # Two coins of a multi-input group each creating a coin for it
    coin_b, coin_c = sender_coin(1, 0x72), sender_coin(2, 0x73)
    group_ids = [bytes(coin_b.name()), bytes(coin_c.name())]
    (output,) = derive_silent_payment_outputs(SYNTHETIC_SKS[1:3], group_ids, [RECIPIENT])
    spends = [
        standard_spend(coin_b, WALLET_SKS[1], [[51, output["puzzle_hash"], 100], [64, coin_c.name()]]),
        standard_spend(coin_c, WALLET_SKS[2], [[51, output["puzzle_hash"], 100], [64, coin_b.name()]]),
    ]
    detected = scan_block(SCAN_SK, SPEND_PK, spends, created_coins(spends))
    assert len(detected) == 2
    assert {bytes(d["coin"].parent_coin_info) for d in detected} == set(group_ids)

    # The same through the spend-group procedure itself
    coins = [output_coin(output["puzzle_hash"], amount=1), output_coin(output["puzzle_hash"], amount=2)]
    pk_sum = aggregate_sender_pks([sk.get_g1() for sk in SYNTHETIC_SKS[1:3]])
    assert len(scan_for_silent_payment(SCAN_SK, SPEND_PK, pk_sum, group_ids, coins)) == 2


def test_filtered_match_still_advances_k():
    """A matching output that wallet policy filters out still advances k."""
    coin_a = sender_coin(0, 0x81)
    outputs = derive_silent_payment_outputs(
        [SYNTHETIC_SKS[0]], [bytes(coin_a.name())], [RECIPIENT] * 3
    )
    # k = 0 and k = 1 are dust; k = 2 is a real payment.
    spends = [standard_spend(coin_a, WALLET_SKS[0], [
        [51, outputs[0]["puzzle_hash"], 1],
        [51, outputs[1]["puzzle_hash"], 0],
        [51, outputs[2]["puzzle_hash"], 50_000],
    ])]
    additions = created_coins(spends)

    def not_dust(coin):
        return coin.amount >= 1000

    detected = scan_block(SCAN_SK, SPEND_PK, spends, additions, output_filter=not_dust)
    assert [(d["k"], d["coin"].amount) for d in detected] == [(2, 50_000)]
    assert detected[0]["puzzle_hash"] == outputs[2]["puzzle_hash"]

    # Without a policy all three are reported.
    assert [d["k"] for d in scan_block(SCAN_SK, SPEND_PK, spends, additions)] == [0, 1, 2]

    # The scanner script's --min-amount policy behaves the same way.
    with patch("scanner.subprocess.run", side_effect=mock_coinset({9: spends})):
        reported = process_block(9, SCAN_SK, SPEND_PK, min_amount=1000)
    assert [(d["k"], d["amount"]) for d in reported] == [(2, 50_000)]


# =====================================================================
# Sending: other rules of SendSilentPayment
# =====================================================================

def test_sender_fails_on_identity_recipient_keys():
    for recipient in ((G1Element(), SPEND_PK), (SCAN_PK, G1Element())):
        with pytest.raises(ValueError, match="identity"):
            create_silent_payment_outputs(SYNTHETIC_SKS[0], [b"\x01" * 32], [RECIPIENT, recipient])


def test_sender_fails_on_zero_input_hash(monkeypatch):
    monkeypatch.setattr(shared, "compute_input_hash", lambda coin_ids, pk: 0)
    with pytest.raises(ValueError, match="input_hash is zero"):
        create_silent_payment_outputs(SYNTHETIC_SKS[0], [b"\x01" * 32], [RECIPIENT])


def test_sender_fails_on_zero_output_tweak(monkeypatch):
    real = shared.derive_output_tweak
    monkeypatch.setattr(shared, "derive_output_tweak", lambda ss, k: 0 if k == 1 else real(ss, k))
    assert len(create_silent_payment_outputs(SYNTHETIC_SKS[0], [b"\x01" * 32], [RECIPIENT])) == 1
    with pytest.raises(ValueError, match="t_1 is zero"):
        create_silent_payment_outputs(SYNTHETIC_SKS[0], [b"\x01" * 32], [RECIPIENT] * 2)


def test_sender_needs_one_key_per_coin():
    """a_sum and coin_id_L are computed over exactly the coins of the group."""
    with pytest.raises(ValueError, match="one secret key per coin"):
        create_silent_payment_outputs(SYNTHETIC_SKS[:2], [b"\x01" * 32], [RECIPIENT])
    with pytest.raises(ValueError, match="one secret key per coin"):
        create_silent_payment_outputs(SYNTHETIC_SKS[:1], [b"\x01" * 32, b"\x02" * 32], [RECIPIENT])
    with pytest.raises(ValueError, match="duplicate"):
        create_silent_payment_outputs(SYNTHETIC_SKS[:2], [b"\x01" * 32, b"\x01" * 32], [RECIPIENT])
    with pytest.raises(ValueError):
        create_silent_payment_outputs([], [], [RECIPIENT])


def test_k_increments_across_labels_sharing_a_scan_key():
    """The counter k runs over all entries with the same scan key, whatever
    their label, and restarts for another scan key."""
    labeled = {
        m: (SCAN_PK, generate_labeled_spend_pk(SPEND_PK, generate_label(SCAN_SK, m)[1]))
        for m in (1, 2)
    }
    other = (RECIPIENT_B_SCAN_SK.get_g1(), RECIPIENT_B_SPEND_SK.get_g1())
    coin_ids = [b"\x0c" * 32]
    recipients = [RECIPIENT, labeled[1], other, labeled[2], labeled[1]]
    outputs = derive_silent_payment_outputs(SYNTHETIC_SKS[0], coin_ids, recipients)
    assert [o["k"] for o in outputs] == [0, 1, 0, 2, 3]
    assert len({o["t_k"] for o in outputs}) == 5  # no tweak is reused

    coins = [output_coin(o["puzzle_hash"]) for o in outputs]
    detected = scan_for_silent_payment(
        SCAN_SK, SPEND_PK, SYNTHETIC_SKS[0].get_g1(), coin_ids, coins,
        labels=build_label_map(SCAN_SK, [1, 2]),
    )
    assert [(d["k"], d["label"]) for d in detected] == [(0, None), (1, 1), (2, 2), (3, 1)]
    for d in detected:
        onetime_sk = derive_onetime_sk_full(SPEND_SK, d["spend_tweak"])
        assert puzzle_hash_for_pk(onetime_sk.get_g1()) == d["puzzle_hash"]


def _wallet_coins(indices, first_tag):
    coins = []
    for n, index in enumerate(indices):
        coin = sender_coin(index, first_tag + n, amount=1000 * (n + 1))
        coins.append({
            "coin_id": bytes(coin.name()),
            "parent_coin_info": bytes(coin.parent_coin_info),
            "puzzle_hash": bytes(coin.puzzle_hash),
            "amount": coin.amount,
        })
    return coins


def _verify_bundle(bundle: SpendBundle, wallet_sks) -> None:
    """Every coin's conditions are committed to by that coin's signature."""
    pks, msgs = [], []
    for coin_spend, wallet_sk in zip(bundle.coin_spends, wallet_sks):
        delegated_puzzle_hash = None
        _, node = coin_spend.puzzle_reveal.run_rust(11_000_000_000, 0, coin_spend.solution)
        while node.pair:
            cond, node = node.pair
            op, args = cond.pair
            if op.atom == b"\x32":  # AGG_SIG_ME
                pk_node, rest = args.pair
                assert pk_node.atom == bytes(calculate_synthetic_public_key(wallet_sk.get_g1()))
                delegated_puzzle_hash = rest.pair[0].atom
        assert delegated_puzzle_hash is not None
        pks.append(calculate_synthetic_public_key(wallet_sk.get_g1()))
        msgs.append(delegated_puzzle_hash + coin_spend.coin.name() + TESTNET11_GENESIS)
    assert AugSchemeMPL.aggregate_verify(pks, msgs, bundle.aggregated_signature)


def test_built_single_input_payment_has_no_binding_and_is_detected():
    """A payment funded by a single coin needs no ASSERT_CONCURRENT_SPEND."""
    coins = _wallet_coins([0], 0x91)
    change_ph = puzzle_hash_for_pk(WALLET_SKS[0].get_g1())
    bundle, outputs = build_silent_payment_spend(
        coins, WALLET_SKS[:1], [(SCAN_PK, SPEND_PK, 400)], change_ph, fee=10
    )
    spends = list(bundle.coin_spends)
    assert asserted_concurrent_spends(spends[0]) == []
    _verify_bundle(bundle, WALLET_SKS[:1])

    additions = created_coins(spends)
    assert sorted(c.amount for c in additions) == [400, 590]
    detected = scan_block(SCAN_SK, SPEND_PK, spends, additions)
    assert [(d["puzzle_hash"], d["coin"].amount) for d in detected] == [(outputs[0]["puzzle_hash"], 400)]


def test_built_multi_input_payment_binds_exactly_the_summed_coins():
    """Every silent payment output is created by a coin in the spend group,
    and the cycle is built over exactly the coins whose keys are summed."""
    indices = [2, 0, 4]
    coins = _wallet_coins(indices, 0xA1)
    wallet_sks = [WALLET_SKS[i] for i in indices]
    group_ids = [c["coin_id"] for c in coins]
    _, label_pk = generate_label(SCAN_SK, 1)
    recipients = [
        (SCAN_PK, SPEND_PK, 1500),
        (SCAN_PK, generate_labeled_spend_pk(SPEND_PK, label_pk), 2500),
    ]
    bundle, outputs = build_silent_payment_spend(
        coins, wallet_sks, recipients, puzzle_hash_for_pk(wallet_sks[0].get_g1()), fee=100
    )
    spends = list(bundle.coin_spends)
    _verify_bundle(bundle, wallet_sks)

    # The outputs are those of SendSilentPayment over exactly these coins.
    expected = derive_silent_payment_outputs(
        [calculate_synthetic_secret_key(sk) for sk in wallet_sks], group_ids,
        [(scan, spend) for scan, spend, _ in recipients],
    )
    assert [o["puzzle_hash"] for o in outputs] == [o["puzzle_hash"] for o in expected]
    assert [o["k"] for o in outputs] == [0, 1]

    # One cycle: coin i asserts coin (i-1) mod n, and nothing else.
    for i, spend in enumerate(spends):
        assert asserted_concurrent_spends(spend) == [group_ids[(i - 1) % 3]]

    # The scanner recovers exactly that group...
    groups = form_spend_groups(spends)
    assert len(groups) == 4 and coin_ids_of(groups[3]) == set(group_ids)

    # ...every silent payment output has a coin of the group as its parent...
    additions = created_coins(spends)
    sp_coins = [c for c in additions if c.puzzle_hash in {o["puzzle_hash"] for o in outputs}]
    assert len(sp_coins) == 2
    assert all(bytes(c.parent_coin_info) in group_ids for c in sp_coins)

    # ...and the recipient detects both outputs.
    detected = scan_block(SCAN_SK, SPEND_PK, spends, additions, labels=build_label_map(SCAN_SK, [1]))
    assert [(d["k"], d["label"], d["coin"].amount) for d in detected] == [(0, None, 1500), (1, 1, 2500)]
    assert all(set(d["group_coin_ids"]) == set(group_ids) for d in detected)

    # The same detections from the block's tweak points alone.
    tweak_points = [bytes(t) for t in block_tweak_points(spends)]
    from_points = scan_block_tweak_points(
        SCAN_SK, SPEND_PK, tweak_points, additions, labels=build_label_map(SCAN_SK, [1])
    )
    assert [d["coin_id"] for d in from_points] == [d["coin_id"] for d in detected]


def test_build_spend_rejects_bad_input():
    coins = _wallet_coins([0], 0xB1)
    change_ph = puzzle_hash_for_pk(WALLET_SKS[0].get_g1())
    # the key does not belong to the coin: not a coin we can put in a spend group
    with pytest.raises(ValueError, match="standard-puzzle coin"):
        build_silent_payment_spend(coins, [WALLET_SKS[1]], [(SCAN_PK, SPEND_PK, 10)], change_ph)
    with pytest.raises(ValueError, match="Insufficient funds"):
        build_silent_payment_spend(coins, WALLET_SKS[:1], [(SCAN_PK, SPEND_PK, 5000)], change_ph)
    with pytest.raises(ValueError, match="identity"):
        build_silent_payment_spend(coins, WALLET_SKS[:1], [(G1Element(), SPEND_PK, 10)], change_ph)


def test_send_script_rejects_address_of_another_network(monkeypatch, capsys):
    """The sender rejects an address whose prefix is not its network's,
    before it looks at the wallet."""
    import send_payment
    mainnet = encode_silent_payment_address(bytes(SCAN_PK), bytes(SPEND_PK), "spxch")
    monkeypatch.setattr(sys, "argv", ["send_payment.py", mainnet] + TEST_MNEMONIC.split())
    with patch("send_payment.subprocess.run", side_effect=AssertionError("no chain access expected")):
        with pytest.raises(SystemExit) as exc:
            send_payment.main()
    assert exc.value.code == 1
    assert "another network" in capsys.readouterr().err


# =====================================================================
# Scanning: other rules of ScanForSilentPayment
# =====================================================================

def test_scanner_stops_at_k_max(monkeypatch):
    """The scanner never looks at index K_max or beyond."""
    coin_ids = [b"\x0d" * 32]
    sender_pk = SYNTHETIC_SKS[0].get_g1()
    outputs = derive_silent_payment_outputs(SYNTHETIC_SKS[0], coin_ids, [RECIPIENT] * 4)
    coins = [output_coin(o["puzzle_hash"]) for o in outputs]
    assert len(scan_for_silent_payment(SCAN_SK, SPEND_PK, sender_pk, coin_ids, coins)) == 4

    monkeypatch.setattr(shared, "K_MAX", 3)
    detected = scan_for_silent_payment(SCAN_SK, SPEND_PK, sender_pk, coin_ids, coins)
    assert [d["k"] for d in detected] == [0, 1, 2]


def test_scanner_skips_group_with_zero_input_hash(monkeypatch):
    coin_ids = [b"\x0e" * 32]
    sender_pk = SYNTHETIC_SKS[0].get_g1()
    (output,) = derive_silent_payment_outputs(SYNTHETIC_SKS[0], coin_ids, [RECIPIENT])
    coins = [output_coin(output["puzzle_hash"])]
    assert len(scan_for_silent_payment(SCAN_SK, SPEND_PK, sender_pk, coin_ids, coins)) == 1

    monkeypatch.setattr(shared, "compute_input_hash", lambda coin_ids, pk: 0)
    assert compute_tweak_point(coin_ids, sender_pk) is None
    assert scan_for_silent_payment(SCAN_SK, SPEND_PK, sender_pk, coin_ids, coins) == []


def test_scanner_stops_on_zero_output_tweak(monkeypatch):
    coin_ids = [b"\x0f" * 32]
    sender_pk = SYNTHETIC_SKS[0].get_g1()
    outputs = derive_silent_payment_outputs(SYNTHETIC_SKS[0], coin_ids, [RECIPIENT] * 3)
    coins = [output_coin(o["puzzle_hash"]) for o in outputs]

    real = shared.derive_output_tweak
    monkeypatch.setattr(shared, "derive_output_tweak", lambda ss, k: 0 if k == 1 else real(ss, k))
    detected = scan_for_silent_payment(SCAN_SK, SPEND_PK, sender_pk, coin_ids, coins)
    assert [d["k"] for d in detected] == [0]


def test_change_label_is_always_checked():
    """m = 0 is scanned for whether or not the caller registered it."""
    coin_ids = [b"\x10" * 32]
    sender_pk = SYNTHETIC_SKS[0].get_g1()
    change_recipient = own_change_recipient(SCAN_SK, SPEND_PK)
    (output,) = derive_silent_payment_outputs(SYNTHETIC_SKS[0], coin_ids, [change_recipient])
    coins = [output_coin(output["puzzle_hash"])]

    _, label_pk_1 = generate_label(SCAN_SK, 1)
    for labels in (None, {}, {bytes(label_pk_1): 1}, build_label_map(SCAN_SK), build_label_map(SCAN_SK, [3, 1])):
        detected = scan_for_silent_payment(SCAN_SK, SPEND_PK, sender_pk, coin_ids, coins, labels=labels)
        assert [(d["k"], d["label"]) for d in detected] == [(0, 0)]

    assert sorted(build_label_map(SCAN_SK).values()) == [0]
    assert sorted(build_label_map(SCAN_SK, [3, 1]).values()) == [0, 1, 3]


def test_unlabeled_first_then_labels_in_ascending_order():
    """At each k the unlabeled candidate is tried first, then the labels in
    ascending order of m; the first candidate that matches is the only one
    recorded for that k."""
    coin_ids = [b"\x11" * 32]
    sender_pk = SYNTHETIC_SKS[0].get_g1()
    labeled = {
        m: (SCAN_PK, generate_labeled_spend_pk(SPEND_PK, generate_label(SCAN_SK, m)[1]))
        for m in (0, 1, 2)
    }

    def k0_coin(recipient):
        # Each call derives the k = 0 output for that address on its own.
        (o,) = derive_silent_payment_outputs(SYNTHETIC_SKS[0], coin_ids, [recipient])
        return output_coin(o["puzzle_hash"])

    unlabeled, change, one, two = k0_coin(RECIPIENT), k0_coin(labeled[0]), k0_coin(labeled[1]), k0_coin(labeled[2])
    # Label map in an order that is neither ascending nor the insertion order of m
    label_map = {}
    for m in (2, 0, 1):
        label_map[bytes(generate_label(SCAN_SK, m)[1])] = m

    def scan(coins):
        found = scan_for_silent_payment(SCAN_SK, SPEND_PK, sender_pk, coin_ids, coins, labels=label_map)
        return [(d["k"], d["label"]) for d in found]

    # (A sender following the CHIP never produces two matches at one index.)
    assert scan([two, one, change, unlabeled]) == [(0, None)]
    assert scan([two, one, change]) == [(0, 0)]
    assert scan([two, one]) == [(0, 1)]
    assert scan([two]) == [(0, 2)]
    assert scan([]) == []


def test_scan_rejects_label_map_of_another_scan_key():
    """A detection is never reported with a spend tweak that cannot be right."""
    coin_ids = [b"\x12" * 32]
    _, label_pk = generate_label(SCAN_SK, 1)
    (output,) = derive_silent_payment_outputs(
        SYNTHETIC_SKS[0], coin_ids, [(SCAN_PK, generate_labeled_spend_pk(SPEND_PK, label_pk))]
    )
    with pytest.raises(ValueError, match="does not belong"):
        scan_for_silent_payment(
            SCAN_SK, SPEND_PK, SYNTHETIC_SKS[0].get_g1(), coin_ids,
            [output_coin(output["puzzle_hash"])], labels={bytes(label_pk): 5},
        )


def test_scanner_needs_no_spend_secret_key_and_returns_no_secret_key():
    """Detection works from b_scan and B_spend alone; the one-time key is
    derived separately, from b_spend and the recorded tweak."""
    coin_ids = [b"\x13" * 32]
    (output,) = derive_silent_payment_outputs(SYNTHETIC_SKS[0], coin_ids, [RECIPIENT])
    scan_sk, spend_pk = parse_watch_only_keys(bytes(SCAN_SK).hex(), "0x" + bytes(SPEND_PK).hex())
    (d,) = scan_for_silent_payment(
        scan_sk, spend_pk, SYNTHETIC_SKS[0].get_g1(), coin_ids, [output_coin(output["puzzle_hash"])]
    )
    assert set(d) == {"coin", "coin_id", "k", "label", "t_k", "spend_tweak", "puzzle_hash", "onetime_pk"}
    assert not any(isinstance(v, PrivateKey) for v in d.values())
    assert derive_onetime_sk_full(SPEND_SK, d["spend_tweak"]).get_g1() == d["onetime_pk"]

    with pytest.raises(ValueError):
        parse_watch_only_keys(bytes(SCAN_SK).hex(), IDENTITY.hex())
    with pytest.raises(ValueError):
        parse_watch_only_keys(bytes(SCAN_SK).hex(), NOT_IN_SUBGROUP.hex())
    with pytest.raises(ValueError):
        parse_watch_only_keys(bytes(32).hex(), bytes(SPEND_PK).hex())


# =====================================================================
# Tweak points
# =====================================================================

def _mixed_block():
    """A block with a single-input payment, a multi-input payment and noise."""
    coin_s = sender_coin(0, 0xC1)
    coin_0, coin_1, coin_2 = sender_coin(1, 0xC2), sender_coin(2, 0xC3), sender_coin(3, 0xC4)
    coin_x = sender_coin(4, 0xC5)
    group_ids = [bytes(c.name()) for c in (coin_0, coin_1, coin_2)]
    (single,) = derive_silent_payment_outputs([SYNTHETIC_SKS[0]], [bytes(coin_s.name())], [RECIPIENT])
    multi = derive_silent_payment_outputs(SYNTHETIC_SKS[1:4], group_ids, [RECIPIENT] * 2)
    spends = [
        standard_spend(coin_s, WALLET_SKS[0], [[51, single["puzzle_hash"], 111]]),
        standard_spend(coin_0, WALLET_SKS[1], [[51, multi[0]["puzzle_hash"], 222], [64, coin_2.name()]]),
        standard_spend(coin_1, WALLET_SKS[2], [[51, multi[1]["puzzle_hash"], 333], [64, coin_0.name()]]),
        standard_spend(coin_2, WALLET_SKS[3], [[64, coin_1.name()]]),
        standard_spend(coin_x, WALLET_SKS[4], [[51, b"\x99" * 32, 444]]),
        conditions_puzzle_spend(b"\xc6" * 32, 9, [[51, b"\x98" * 32, 9]]),
    ]
    return spends, group_ids


def test_tweak_point_definition():
    """T = input_hash * A_sum, and b_scan * T gives the sender's shared secret."""
    coin_ids = [b"\x21" * 32, b"\x20" * 32]
    a_sum = aggregate_sender_sks(SYNTHETIC_SKS[:2])
    pk_sum = aggregate_sender_pks([sk.get_g1() for sk in SYNTHETIC_SKS[:2]])
    input_hash = compute_input_hash(coin_ids, pk_sum)
    tweak_point = compute_tweak_point(coin_ids, pk_sum)
    assert tweak_point == scalar_mult_g1(input_hash, pk_sum)
    assert shared.compute_shared_secret_from_tweak_point(SCAN_SK, tweak_point) \
        == shared.compute_shared_secret_full(a_sum, SCAN_PK, input_hash)


def test_block_tweak_points_one_per_spend_group():
    spends, group_ids = _mixed_block()
    groups = form_spend_groups(spends)
    # five eligible spends on their own, plus the 3-cycle
    assert [len(g) for g in groups] == [1, 1, 1, 1, 1, 3]
    assert coin_ids_of(groups[5]) == set(group_ids)

    tweak_points = block_tweak_points(spends)
    assert len(tweak_points) == 6
    expected = [
        compute_tweak_point(
            [bytes(cs.coin.name()) for cs, _ in g], aggregate_sender_pks([pk for _, pk in g])
        )
        for g in groups
    ]
    assert tweak_points == expected


def test_scan_from_tweak_points_finds_the_same_payments():
    """Scanning from tweak points matches against all additions of the block
    and finds what ScanBlock finds."""
    spends, _ = _mixed_block()
    additions = created_coins(spends)
    assert len(additions) == 5

    from_block = scan_block(SCAN_SK, SPEND_PK, spends, additions)
    assert sorted(d["coin"].amount for d in from_block) == [111, 222, 333]

    tweak_points = [bytes(t) for t in block_tweak_points(spends)]
    from_points = scan_block_tweak_points(SCAN_SK, SPEND_PK, tweak_points, additions)
    assert {d["coin_id"] for d in from_points} == {d["coin_id"] for d in from_block}
    for d in from_points:
        (same,) = [b for b in from_block if b["coin_id"] == d["coin_id"]]
        assert (d["k"], d["label"], d["t_k"], d["spend_tweak"]) == \
            (same["k"], same["label"], same["t_k"], same["spend_tweak"])

    # Another recipient finds nothing in either mode.
    other_scan, other_spend = RECIPIENT_B_SCAN_SK, RECIPIENT_B_SPEND_SK.get_g1()
    assert scan_block(other_scan, other_spend, spends, additions) == []
    assert scan_block_tweak_points(other_scan, other_spend, tweak_points, additions) == []


@pytest.mark.parametrize("bad_point", [
    IDENTITY, NOT_ON_CURVE, NOT_IN_SUBGROUP, bytes(48), bytes(47), bytes(SCAN_PK) + b"\x00",
], ids=["identity", "not_on_curve", "not_in_subgroup", "bad_encoding", "short", "long"])
def test_supplied_tweak_point_is_validated_before_use(bad_point, monkeypatch):
    """A tweak point from another party is checked (valid, in the subgroup,
    not the identity) BEFORE it is multiplied by the scan secret key."""
    spends, _ = _mixed_block()
    additions = created_coins(spends)

    def no_multiplication(scalar, point):
        raise AssertionError("an unvalidated point reached scalar multiplication")

    monkeypatch.setattr(shared, "scalar_mult_g1", no_multiplication)
    with pytest.raises(ValueError):
        scan_tweak_point(SCAN_SK, SPEND_PK, bad_point, additions)
    with pytest.raises(ValueError):
        scan_block_tweak_points(SCAN_SK, SPEND_PK, [bad_point], additions)


# =====================================================================
# Labels
# =====================================================================

def test_label_zero_is_never_handed_out_as_an_address(monkeypatch, capsys):
    """m = 0 is reserved for the wallet's own change."""
    for m in (0, -1):
        with pytest.raises(ValueError, match="reserved for change"):
            generate_labeled_address(SCAN_SK, SPEND_PK, m)

    # Label 1 and up are fine.
    address = generate_labeled_address(SCAN_SK, SPEND_PK, 1, "spxch")
    _, label_pk = generate_label(SCAN_SK, 1)
    assert decode_silent_payment_address(address) == (
        bytes(SCAN_PK), bytes(generate_labeled_spend_pk(SPEND_PK, label_pk))
    )

    # The change label is available as recipient keys for the wallet's own
    # transactions only - not as an address string.
    scan_pk, change_pk = own_change_recipient(SCAN_SK, SPEND_PK)
    assert scan_pk == SCAN_PK
    assert change_pk == generate_labeled_spend_pk(SPEND_PK, generate_label(SCAN_SK, 0)[1])

    # The address generator script refuses --label 0.
    import generate_address
    monkeypatch.setattr(sys, "argv", ["generate_address.py", "--label", "0"] + TEST_MNEMONIC.split())
    with pytest.raises(SystemExit) as exc:
        generate_address.main()
    assert exc.value.code != 0
    captured = capsys.readouterr()
    assert "spxch1" not in captured.out
    assert "reserved for change" in captured.err


def test_label_with_zero_scalar_is_not_used(monkeypatch):
    """A label index whose label_scalar is zero must not be used."""
    monkeypatch.setattr(shared, "compute_label_scalar", lambda scan_sk, m: 0 if m in (0, 4) else 12345 + m)
    with pytest.raises(ValueError, match="zero label scalar"):
        generate_label(SCAN_SK, 4)
    with pytest.raises(ValueError, match="zero label scalar"):
        generate_labeled_address(SCAN_SK, SPEND_PK, 4)
    with pytest.raises(ValueError, match="zero label scalar"):
        build_label_map(SCAN_SK, [3, 4])
    with pytest.raises(ValueError, match="zero label scalar"):
        own_change_recipient(SCAN_SK, SPEND_PK)
    # An unusable change label is simply not scanned for.
    assert sorted(build_label_map(SCAN_SK, [3]).values()) == [3]
    assert generate_label(SCAN_SK, 3)[0] == 12348


def test_label_index_must_fit_32_bits():
    for m in (-1, 2**32):
        with pytest.raises(ValueError):
            generate_label(SCAN_SK, m)
    assert generate_label(SCAN_SK, 2**32 - 1)[0] != 0


# =====================================================================
# Scripts
# =====================================================================

_RECIPIENT_MASTER = mnemonic_to_master_sk(TEST_MNEMONIC)
_MNEMONIC_SCAN_SK = master_sk_to_scan_sk(_RECIPIENT_MASTER)
_MNEMONIC_SPEND_SK = master_sk_to_spend_sk(_RECIPIENT_MASTER)


def _paid_block(label: int | None = None):
    """Block 77: a sender coin pays the recipient whose keys are derived from
    TEST_MNEMONIC (hardened). Returns (blocks, coin, output, secrets)."""
    scan_sk, spend_sk = _MNEMONIC_SCAN_SK, _MNEMONIC_SPEND_SK
    spend_pk, label_scalar = spend_sk.get_g1(), 0
    address_spend_pk = spend_pk
    if label is not None:
        label_scalar, label_pk = generate_label(scan_sk, label)
        address_spend_pk = generate_labeled_spend_pk(spend_pk, label_pk)
    coin_a = sender_coin(0, 0xD1)
    (output,) = derive_silent_payment_outputs(
        [SYNTHETIC_SKS[0]], [bytes(coin_a.name())], [(scan_sk.get_g1(), address_spend_pk)]
    )
    spends = [standard_spend(coin_a, WALLET_SKS[0], [[51, output["puzzle_hash"], 12345]])]
    (coin,) = created_coins(spends)

    spend_tweak = (output["t_k"] + label_scalar) % GROUP_ORDER
    onetime_sk = derive_onetime_sk_full(spend_sk, spend_tweak)
    secrets = [
        bytes(scan_sk).hex(), bytes(spend_sk).hex(), bytes(onetime_sk).hex(),
        bytes(calculate_synthetic_secret_key(onetime_sk)).hex(), bytes(_RECIPIENT_MASTER).hex(),
    ]
    return {77: spends}, coin, spend_tweak, secrets


@pytest.mark.parametrize("mode", ["mnemonic", "watch_only"])
def test_scan_coin_script(mode, monkeypatch, capsys):
    """scan_coin.py runs from a mnemonic and watch-only (scan secret key +
    spend public key), and prints no secret key."""
    import scan_coin
    blocks, coin, spend_tweak, secrets = _paid_block()
    argv = ["scan_coin.py", coin.name().hex()]
    if mode == "mnemonic":
        argv += TEST_MNEMONIC.split()
    else:
        argv += ["--scan-key", bytes(_MNEMONIC_SCAN_SK).hex(),
                 "--spend-pubkey", bytes(_MNEMONIC_SPEND_SK.get_g1()).hex()]
    monkeypatch.setattr(sys, "argv", argv)
    with patch("scanner.subprocess.run", side_effect=mock_coinset(blocks)):
        scan_coin.main()
    out = capsys.readouterr().out

    assert "MATCH! This coin belongs to you." in out
    assert f"{spend_tweak:064x}" in out
    for secret in secrets:
        assert secret not in out


def test_scan_coin_script_no_match_and_label(monkeypatch, capsys):
    import scan_coin
    # Another recipient's keys: no match
    blocks, coin, _, _ = _paid_block()
    monkeypatch.setattr(sys, "argv", [
        "scan_coin.py", "0x" + coin.name().hex(),
        "--scan-key", bytes(SCAN_SK).hex(), "--spend-pubkey", bytes(SPEND_PK).hex(),
    ])
    with patch("scanner.subprocess.run", side_effect=mock_coinset(blocks)):
        scan_coin.main()
    assert "NO MATCH" in capsys.readouterr().out

    # A labeled payment is found when the label is scanned for
    blocks, coin, spend_tweak, _ = _paid_block(label=2)
    base = ["scan_coin.py", coin.name().hex()] + TEST_MNEMONIC.split()
    for extra, expect in (([], "NO MATCH"), (["--labels", "1,2"], f"{spend_tweak:064x}")):
        monkeypatch.setattr(sys, "argv", base + extra)
        with patch("scanner.subprocess.run", side_effect=mock_coinset(blocks)):
            scan_coin.main()
        assert expect in capsys.readouterr().out

    # Watch-only mode needs both keys
    monkeypatch.setattr(sys, "argv", ["scan_coin.py", coin.name().hex(), "--scan-key", bytes(SCAN_SK).hex()])
    with pytest.raises(SystemExit):
        scan_coin.main()


@pytest.mark.parametrize("mode", ["mnemonic", "watch_only"])
def test_scanner_script(mode, monkeypatch, capsys):
    """scanner.py runs from a mnemonic and watch-only, reports the coin with
    its spend tweak, and prints no secret key."""
    import scanner
    blocks, coin, spend_tweak, secrets = _paid_block()
    argv = ["scanner.py", "-s", "70", "-e", "80"]
    if mode == "mnemonic":
        address = encode_silent_payment_address(
            bytes(_MNEMONIC_SCAN_SK.get_g1()), bytes(_MNEMONIC_SPEND_SK.get_g1())
        )
        argv += [address] + TEST_MNEMONIC.split()
    else:
        argv += ["--scan-key", bytes(_MNEMONIC_SCAN_SK).hex(),
                 "--spend-pubkey", bytes(_MNEMONIC_SPEND_SK.get_g1()).hex()]
    monkeypatch.setattr(sys, "argv", argv)
    with patch("scanner.subprocess.run", side_effect=mock_coinset(blocks)):
        scanner.main()
    captured = capsys.readouterr()

    assert coin.name().hex() in captured.out
    assert f"{spend_tweak:064x}" in captured.out
    assert "12345 mojos" in captured.out
    assert "Found 1 silent payment(s)" in captured.err
    assert "Warning" not in captured.err
    for secret in secrets:
        assert secret not in captured.out + captured.err


def test_generate_address_script_prints_hardened_address(monkeypatch, capsys):
    """generate_address.py prints the address of the hardened-derived keys
    (Test Vector 8), and no secret key."""
    import generate_address
    monkeypatch.setattr(sys, "argv", ["generate_address.py"] + TEST_MNEMONIC.split())
    generate_address.main()
    out = capsys.readouterr().out
    assert "tspxch1q30etue85q8xvzrf5j4gr4j09ke6u9c4s3vrnj9unt0hdj5dhpwxv6q0kp3qxcnh8u7fr0chtttlantgv0dj6xwftvfuzhrq8sjcsce9s7nwglsk5d5knclqwrwyehuvr7a5evgndm7g527yadv9lxjvjrycwanlf" in out
    assert bytes(_MNEMONIC_SCAN_SK).hex() not in out
    assert bytes(_MNEMONIC_SPEND_SK).hex() not in out

    monkeypatch.setattr(sys, "argv", ["generate_address.py", "--mainnet", "--label", "1"] + TEST_MNEMONIC.split())
    generate_address.main()
    out = capsys.readouterr().out
    assert generate_labeled_address(_MNEMONIC_SCAN_SK, _MNEMONIC_SPEND_SK.get_g1(), 1, "spxch") in out


@pytest.mark.parametrize("mode", ["scan", "tweak"])
def test_spend_coin_script(mode, monkeypatch, capsys):
    """spend_coin.py derives the one-time key from the spend secret key and
    the spend tweak (found by scanning, or supplied by a watch-only scanner),
    signs a valid spend, and prints no secret key."""
    import spend_coin
    blocks, coin, spend_tweak, secrets = _paid_block(label=1)
    argv = ["spend_coin.py", coin.name().hex()] + TEST_MNEMONIC.split()
    argv += ["--labels", "1"] if mode == "scan" else ["--tweak", f"{spend_tweak:064x}"]
    monkeypatch.setattr(sys, "argv", argv)
    pushed = []
    with patch("scanner.subprocess.run", side_effect=mock_coinset(blocks, pushed)):
        spend_coin.main()
    out = capsys.readouterr().out
    assert "SUCCESS" in out
    for secret in secrets:
        assert secret not in out

    # The pushed bundle spends the coin to the standard wallet address, with
    # a signature made by the one-time key.
    (bundle_json,) = pushed
    bundle = SpendBundle.from_json_dict(bundle_json)
    (coin_spend,) = bundle.coin_spends
    assert coin_spend.coin == coin
    dest_ph = puzzle_hash_for_pk(master_sk_to_wallet_sk(_RECIPIENT_MASTER, 0).get_g1())
    assert [(c.puzzle_hash, c.amount) for c in created_coins([coin_spend])] == [(dest_ph, 12345)]

    onetime_sk = derive_onetime_sk_full(_MNEMONIC_SPEND_SK, spend_tweak)
    synthetic_pk = calculate_synthetic_public_key(onetime_sk.get_g1())
    assert extract_synthetic_pk(coin_spend.puzzle_reveal) == synthetic_pk
    delegated = Program.to((1, [[51, dest_ph, 12345]]))
    msg = delegated.get_tree_hash() + coin.name() + TESTNET11_GENESIS
    assert AugSchemeMPL.verify(synthetic_pk, msg, bundle.aggregated_signature)


def test_spend_coin_rejects_wrong_tweak_or_foreign_coin(monkeypatch, capsys):
    import spend_coin
    blocks, coin, spend_tweak, _ = _paid_block()
    pushed = []

    # A tweak that does not belong to the coin
    monkeypatch.setattr(sys, "argv", ["spend_coin.py", coin.name().hex()] + TEST_MNEMONIC.split()
                        + ["--tweak", f"{spend_tweak + 1:064x}"])
    with patch("scanner.subprocess.run", side_effect=mock_coinset(blocks, pushed)):
        with pytest.raises(SystemExit):
            spend_coin.main()
    assert "does not match" in capsys.readouterr().out

    # A coin that is not ours
    monkeypatch.setattr(sys, "argv", ["spend_coin.py", coin.name().hex(), "zoo"] + ["zoo"] * 10 + ["wrong"])
    with patch("scanner.subprocess.run", side_effect=mock_coinset(blocks, pushed)):
        with pytest.raises(SystemExit):
            spend_coin.main()
    assert "NO MATCH" in capsys.readouterr().out
    assert pushed == []

    with pytest.raises(ValueError, match="does not match"):
        spend_coin.build_spend_bundle(coin, SPEND_SK, b"\x00" * 32)
