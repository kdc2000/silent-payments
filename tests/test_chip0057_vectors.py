"""CHIP-0057 machine-readable test vectors, through the adapter/SDK.

SOURCE OF THE VECTORS: ``tests/data/chip-0057-test_vectors.json`` is a verbatim
COPY of the vectors file that accompanies the CHIP
(``assets/chip-0057/test_vectors.json`` in the Chia-Network/chips repository),
kept here so the suite is self-contained. The CHIP's file is the source of truth:
when the CHIP's vectors change, re-copy the file — do not edit the copy.
``test_vectors_copy_matches_pure_python_copy`` compares it with the copy the
pure-Python implementation tests against
(``pure-python/tests/data/chip-0057-test_vectors.json``, the output of
``pure-python/gen_test_vectors.py``), so the two copies in this repository cannot
drift apart; it is skipped when that directory is not present.

What is checked, every value against the JSON:

* every payment vector: the inputs' synthetic keys, the key sum, coin_id_L, the
  input hash, the tweak point, every output's one-time puzzle hash (sender side),
  and — scanning the vector's tweak point with the recipient's scan secret key and
  spend PUBLIC key — every output's k, label, combined spend tweak, one-time
  secret/public key and puzzle hash (recipient side);
* the label vectors (label scalar + label public key, incl. the change label);
* every address vector (encode, decode, network) and every address case (valid
  ones decode to the listed keys, invalid ones raise);
* hardened key derivation from the mnemonic (Test Vector 8);
* required behaviours: scanning without the spend secret key and spending with
  it, the change label detected with no label registered, two coins that share a
  one-time puzzle hash both reported, a zero key sum raising.

NOT observable through the SDK's Python API, so not asserted on their own: an
output's ``shared_secret`` and bare ``t_k`` (the API exposes neither). ``t_k`` is
covered through ``spend_tweak == (t_k + label_scalar) mod r``, both sides of
which come from the JSON / the SDK.

Offline: no chain I/O. The SDK may be imported here (tests/ is not scanned by
``test_sole_sdk_importer``).
"""

import json
from pathlib import Path

import pytest

import chia_wallet_sdk as sdk

import sdk_adapter
import shared

VECTORS_PATH = Path(__file__).resolve().parent / "data" / "chip-0057-test_vectors.json"
PURE_PYTHON_VECTORS = (
    Path(__file__).resolve().parent.parent
    / "pure-python" / "tests" / "data" / "chip-0057-test_vectors.json"
)

VECTORS = json.loads(VECTORS_PATH.read_text())
PAYMENTS = VECTORS["payments"]

# The order r of the BLS12-381 G1 group (CHIP-0057 "Definitions").
GROUP_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _h(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


def _sk(hex_str: str) -> "sdk.SecretKey":
    return sdk.SecretKey.from_bytes(_h(hex_str))


def _pk(hex_str: str) -> "sdk.PublicKey":
    return sdk.PublicKey.from_bytes(_h(hex_str))


def _int(hex_str: str) -> int:
    return int(hex_str, 16)


def _recipient_keys(recipient: dict):
    """The vector's GIVEN recipient keys, as SilentPaymentKeys (no derivation)."""
    return sdk.SilentPaymentKeys.from_secret_keys(
        _sk(recipient["scan_sk"]), _sk(recipient["spend_sk"])
    )


def _puzzle_hash_of_onetime_sk(onetime_sk) -> bytes:
    """Standard puzzle hash of a one-time key (the synthetic key is curried)."""
    return bytes(sdk.standard_puzzle_hash(onetime_sk.derive_synthetic().public_key()))


def _output_coin(payment: dict, index: int) -> "sdk.Coin":
    """A coin for output ``index`` of a payment vector.

    The vectors give coin IDs of the inputs and puzzle hashes of the outputs, not
    whole coins, so the parent is the first input's coin id and the amount is
    arbitrary (distinct per output).
    """
    return sdk.Coin(
        _h(payment["inputs"][0]["coin_id"]),
        _h(payment["outputs"][index]["puzzle_hash"]),
        1_000 + index,
    )


def _tweak_data(payment: dict) -> "sdk.TweakData":
    """TweakData holding the vector's tweak point and all of its outputs."""
    outputs = []
    for index in range(len(payment["outputs"])):
        coin = _output_coin(payment, index)
        outputs.append(
            sdk.OutputMeta(coin.puzzle_hash, coin.coin_id(), coin.amount, coin.parent_coin_info)
        )
    return sdk.TweakData([_pk(payment["tweak_point"])], outputs)


def _payment(name: str) -> dict:
    return next(p for p in PAYMENTS if p["name"] == name)


# --------------------------------------------------------------------------
# the copy
# --------------------------------------------------------------------------

def test_vectors_copy_matches_pure_python_copy():
    """The copy in tests/data is byte-identical to the pure-python copy."""
    if not PURE_PYTHON_VECTORS.is_file():
        pytest.skip("pure-python/tests/data/chip-0057-test_vectors.json not present")
    assert VECTORS_PATH.read_bytes() == PURE_PYTHON_VECTORS.read_bytes(), (
        "tests/data/chip-0057-test_vectors.json differs from "
        "pure-python/tests/data/chip-0057-test_vectors.json — re-copy both from "
        "the CHIP's vectors file (the source)"
    )


def test_vectors_file_shape():
    """The file is the CHIP-0057 v0 vector set this module knows how to read."""
    assert VECTORS["chip"] == "CHIP-0057"
    assert VECTORS["address_version"] == shared.SP_ADDRESS_VERSION == 0
    assert [p["name"] for p in PAYMENTS] == [
        "vector_1_single_output",
        "vector_2_two_recipients",
        "vector_3_labeled",
        "vector_4_multi_input",
        "vector_6_two_outputs_one_recipient",
        "vector_7_change_label",
    ]
    assert len(VECTORS["labels"]) == 2
    assert len(VECTORS["addresses"]) == 4
    assert len(VECTORS["address_cases"]) == 16


# --------------------------------------------------------------------------
# payment vectors — sender side
# --------------------------------------------------------------------------

@pytest.mark.parametrize("payment", PAYMENTS, ids=[p["name"] for p in PAYMENTS])
def test_payment_vector_sender_side(payment):
    """Key sum, coin_id_L, input hash, tweak point and every one-time puzzle hash."""
    sender_sks = [_sk(i["synthetic_sk"]) for i in payment["inputs"]]
    coin_ids = [_h(i["coin_id"]) for i in payment["inputs"]]

    for inp, sk in zip(payment["inputs"], sender_sks):
        assert sk.public_key().to_bytes().hex() == inp["synthetic_pk"]

    # a_sum (a SecretKey) and A_sum, by both routes.
    a_sum = sdk_adapter.aggregate_sender_sks(sender_sks)
    assert a_sum.public_key().to_bytes().hex() == payment["a_sum_pk"]
    a_sum_pk = sdk_adapter.aggregate_sender_pks([sk.public_key() for sk in sender_sks])
    assert a_sum_pk.to_bytes().hex() == payment["a_sum_pk"]
    assert _int(a_sum.to_bytes().hex()) == sum(
        _int(i["synthetic_sk"]) for i in payment["inputs"]
    ) % GROUP_ORDER

    # coin_id_L is the lexicographic minimum of the group's coin ids.
    assert min(coin_ids).hex() == payment["coin_id_l"]

    # input_hash.
    input_hash = sdk_adapter.compute_input_hash(coin_ids, a_sum_pk)
    assert input_hash.to_bytes().hex() == payment["input_hash"]

    # Tweak point T = input_hash * A_sum = (input_hash * a_sum mod r) * G. The
    # scalar product is done in Python (the SDK's Python API has no scalar-times-
    # point primitive); the point comes from the SDK. The scanning test below
    # checks the same tweak point through the SDK's scanner.
    t_scalar = (_int(payment["input_hash"]) * _int(a_sum.to_bytes().hex())) % GROUP_ORDER
    tweak_point = sdk.SecretKey.from_bytes(t_scalar.to_bytes(32, "big")).public_key()
    assert tweak_point.to_bytes().hex() == payment["tweak_point"]

    # Every output's one-time puzzle hash.
    for output in payment["outputs"]:
        recipient = output["recipient"]
        puzzle_hash = sdk_adapter.derive_one_time_puzzle_hash(
            _pk(recipient["scan_pk"]),
            _pk(recipient["address_spend_pk"]),
            a_sum,
            input_hash,
            output["k"],
        )
        assert bytes(puzzle_hash).hex() == output["puzzle_hash"]


@pytest.mark.parametrize("payment", PAYMENTS, ids=[p["name"] for p in PAYMENTS])
def test_payment_vector_recipient_keys_and_addresses(payment):
    """The given recipient keys are consistent and the address key is B_spend,
    B_m (labeled) or B_0 (change), as built by the SDK."""
    for output in payment["outputs"]:
        recipient = output["recipient"]
        keys = _recipient_keys(recipient)
        assert keys.scan_pk().to_bytes().hex() == recipient["scan_pk"]
        assert keys.spend_pk().to_bytes().hex() == recipient["spend_pk"]

        label = recipient["label"]
        if label is None:
            address = sdk_adapter.encode_silent_payment_address(keys)
        elif label == 0:
            address = sdk_adapter.change_address(keys)
        else:
            address = sdk_adapter.labeled_address(keys, label)
        scan_pk, address_spend_pk = sdk_adapter.decode_silent_payment_address(address)
        assert scan_pk.to_bytes().hex() == recipient["scan_pk"]
        assert address_spend_pk.to_bytes().hex() == recipient["address_spend_pk"]


# --------------------------------------------------------------------------
# payment vectors — recipient side (scan with scan_sk + spend PUBLIC key)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("payment", PAYMENTS, ids=[p["name"] for p in PAYMENTS])
def test_payment_vector_scan_and_spend_tweaks(payment):
    """Scanning the vector's tweak point finds every output of each recipient with
    the listed k, label and combined spend tweak; the spend secret key then gives
    the listed one-time key."""
    tweak_data = _tweak_data(payment)

    # Group the outputs by recipient (scan key).
    by_recipient = {}
    for index, output in enumerate(payment["outputs"]):
        by_recipient.setdefault(output["recipient"]["scan_sk"], []).append((index, output))

    for scan_sk_hex, outputs in by_recipient.items():
        recipient = outputs[0][1]["recipient"]
        scan_sk = _sk(scan_sk_hex)
        spend_pk = _pk(recipient["spend_pk"])  # the PUBLIC key: all a scanner holds
        spend_sk = _sk(recipient["spend_sk"])  # only used after the scan, to spend

        # Register the labels m >= 1 this recipient is paid on. The change label
        # m = 0 is never registered: the scanner checks it by itself.
        label_indices = sorted(
            {o["recipient"]["label"] for _, o in outputs if o["recipient"]["label"]}
        )
        labels = sdk_adapter.label_registry(scan_sk, label_indices)

        detections = sdk_adapter.scan_from_tweaks(
            scan_sk, spend_pk, tweak_data, labels, shared.K_MAX
        )
        assert len(detections) == len(outputs), (
            f"{payment['name']}: expected {len(outputs)} detections for scan key "
            f"{scan_sk_hex[:8]}…, got {len(detections)}"
        )

        by_coin_id = {bytes(d.coin_id): d for d in detections}
        for index, output in outputs:
            coin = _output_coin(payment, index)
            detection = by_coin_id[bytes(coin.coin_id())]
            assert bytes(detection.puzzle_hash).hex() == output["puzzle_hash"]
            assert detection.amount == coin.amount
            assert bytes(detection.parent_coin_id) == bytes(coin.parent_coin_info)
            assert bytes(detection.coin().coin_id()) == bytes(coin.coin_id())
            assert detection.k == output["k"]
            assert detection.label == output["recipient"]["label"]

            # The combined spend tweak (t_k + label_scalar) mod r.
            assert detection.tweak.to_bytes().hex() == output["spend_tweak"]
            label = output["recipient"]["label"]
            label_scalar = 0
            if label is not None:
                scalar, _label_pk = sdk_adapter.generate_label(scan_sk, label)
                label_scalar = _int(scalar.to_bytes().hex())
            assert (_int(output["t_k"]) + label_scalar) % GROUP_ORDER == _int(
                output["spend_tweak"]
            )

            # Spending: one-time key = (spend_sk + spend_tweak) mod r, three ways.
            onetime_sk = sdk_adapter.derive_onetime_sk(spend_sk, detection.tweak)
            for same_key in (
                onetime_sk,
                detection.onetime_sk(spend_sk),
                sdk_adapter.derive_onetime_sk(spend_sk, output["spend_tweak"]),
                sdk_adapter.derive_onetime_sk(spend_sk, _h(output["spend_tweak"])),
            ):
                assert same_key.to_bytes().hex() == output["onetime_sk"]
            assert onetime_sk.public_key().to_bytes().hex() == output["onetime_pk"]
            assert _puzzle_hash_of_onetime_sk(onetime_sk).hex() == output["puzzle_hash"]

            # The plain-dict record carries k, label and the tweak — and no key.
            record = sdk_adapter.detections_to_records([detection], block_height=7)[0]
            assert record == {
                "coin_id": bytes(coin.coin_id()).hex(),
                "parent_coin_id": bytes(coin.parent_coin_info).hex(),
                "puzzle_hash": output["puzzle_hash"],
                "amount": coin.amount,
                "block_height": 7,
                "k": output["k"],
                "label": output["recipient"]["label"],
                "tweak": output["spend_tweak"],
            }
            assert output["onetime_sk"] not in json.dumps(record)


def test_vector_6_omitted_k0_output_hides_k1():
    """Test Vector 6 verification: with the k = 0 output left out of the
    transaction the scanner finds nothing (it stops at the first index with no
    match), and with both present it finds k = 0 and k = 1."""
    payment = _payment("vector_6_two_outputs_one_recipient")
    recipient = payment["outputs"][0]["recipient"]
    scan_sk, spend_pk = _sk(recipient["scan_sk"]), _pk(recipient["spend_pk"])

    full = _tweak_data(payment)
    detections = sdk_adapter.scan_from_tweaks(
        scan_sk, spend_pk, full, sdk_adapter.label_registry(scan_sk, [])
    )
    assert sorted(d.k for d in detections) == [0, 1]

    only_k1 = sdk.TweakData(full.tweak_points, [full.outputs[1]])
    assert (
        sdk_adapter.scan_from_tweaks(
            scan_sk, spend_pk, only_k1, sdk_adapter.label_registry(scan_sk, [])
        )
        == []
    )


# --------------------------------------------------------------------------
# labels
# --------------------------------------------------------------------------

@pytest.mark.parametrize("vector", VECTORS["labels"], ids=lambda v: f"m{v['m']}")
def test_label_vectors(vector):
    """Label scalar and label public key (m = 0 is the change label)."""
    scan_sk = _sk(vector["scan_sk"])
    scalar, label_pk = sdk_adapter.generate_label(scan_sk, vector["m"])
    assert scalar.to_bytes().hex() == vector["label_scalar"]
    assert label_pk.to_bytes().hex() == vector["label_pk"]
    # label_pk == label_scalar * G.
    assert _sk(vector["label_scalar"]).public_key().to_bytes().hex() == vector["label_pk"]

    if vector["m"] >= 1:
        registry = sdk_adapter.label_registry(scan_sk, [vector["m"]])
        assert registry.forward(vector["m"]).to_bytes().hex() == vector["label_pk"]


def test_change_label_is_only_available_as_the_change_address():
    """m = 0 cannot be handed out as a labeled address; change_address builds
    (B_scan, B_0) — Test Vector 7's address key."""
    recipient = _payment("vector_7_change_label")["outputs"][0]["recipient"]
    keys = _recipient_keys(recipient)
    with pytest.raises(ValueError, match="reserved for change"):
        sdk_adapter.labeled_address(keys, 0)

    scan_pk, b0 = sdk_adapter.decode_silent_payment_address(sdk_adapter.change_address(keys))
    assert scan_pk.to_bytes().hex() == recipient["scan_pk"]
    assert b0.to_bytes().hex() == recipient["address_spend_pk"]
    assert recipient["address_spend_pk"] != recipient["spend_pk"]


# --------------------------------------------------------------------------
# addresses
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "vector", VECTORS["addresses"], ids=lambda v: f"{v['network']}-{v['spend_pk'][:8]}"
)
def test_address_vectors_round_trip(vector):
    """Every address vector encodes to the listed string and decodes back to the
    listed keys and network — through the adapter and through the shared.py glue."""
    testnet = vector["network"] == "testnet"
    assert vector["network"] in ("mainnet", "testnet")
    scan_pk, spend_pk = _h(vector["scan_pk"]), _h(vector["spend_pk"])
    address = vector["address"]

    # encode
    assert (
        sdk_adapter.encode_silent_payment_address_from_bytes(scan_pk, spend_pk, testnet=testnet)
        == address
    )
    prefix = "tspxch" if testnet else "spxch"
    assert shared.encode_silent_payment_address(scan_pk, spend_pk, prefix) == address
    assert address.startswith(prefix + "1q"), "version 0 character is 'q'"
    assert len(address) == (168 if testnet else 167)

    # decode
    dec_scan, dec_spend = sdk_adapter.decode_silent_payment_address(address)
    assert (dec_scan.to_bytes(), dec_spend.to_bytes()) == (scan_pk, spend_pk)
    assert shared.decode_silent_payment_address(address) == (scan_pk, spend_pk)
    assert sdk_adapter.silent_payment_address_is_testnet(address) is testnet


@pytest.mark.parametrize(
    "case", VECTORS["address_cases"], ids=lambda c: c["description"].split(":")[0]
)
def test_address_cases(case):
    """Valid cases decode to the listed keys; invalid cases raise — through the
    adapter and through the shared.py glue."""
    address = case["address"]
    if case["valid"]:
        scan_pk, spend_pk = sdk_adapter.decode_silent_payment_address(address)
        assert scan_pk.to_bytes().hex() == case["scan_pk"]
        assert spend_pk.to_bytes().hex() == case["spend_pk"]
        assert shared.decode_silent_payment_address(address) == (
            _h(case["scan_pk"]),
            _h(case["spend_pk"]),
        )
    else:
        with pytest.raises(ValueError):
            sdk_adapter.decode_silent_payment_address(address)
        with pytest.raises(ValueError):
            shared.decode_silent_payment_address(address)
        with pytest.raises(ValueError):
            sdk_adapter.silent_payment_address_is_testnet(address)


def test_every_invalid_case_category_is_present():
    """The cases cover each rejection rule of CHIP-0057 "Required Behaviors"."""
    invalid = [c["description"] for c in VECTORS["address_cases"] if not c["valid"]]
    for needle in ("version 31", "version 0 with a 95-byte", "version 0 with a 97-byte",
                   "version 1 with a 95-byte", "scan key is the identity",
                   "spend key is the identity", "outside the prime-order subgroup",
                   "not on the curve", "non-zero padding", "mixed case",
                   "wrong checksum", "longer than 1,023", "not a silent payment prefix"):
        assert any(needle in d for d in invalid), needle
    assert sum(c["valid"] for c in VECTORS["address_cases"]) == 3


def test_encoder_rejects_invalid_keys():
    """Encoding an address with an identity key, or a key that is not a valid G1
    point, raises — in the adapter and in the shared.py glue."""
    good = _h(VECTORS["addresses"][0]["scan_pk"])
    identity = bytes([0xC0]) + bytes(47)
    not_a_point = bytes([0xFF]) * 48

    for scan_pk, spend_pk in ((identity, good), (good, identity)):
        with pytest.raises(ValueError, match="identity"):
            sdk_adapter.encode_silent_payment_address_from_bytes(scan_pk, spend_pk)
        with pytest.raises(ValueError, match="identity"):
            shared.encode_silent_payment_address(scan_pk, spend_pk)
    for scan_pk, spend_pk in ((not_a_point, good), (good, not_a_point)):
        with pytest.raises(ValueError):
            sdk_adapter.encode_silent_payment_address_from_bytes(scan_pk, spend_pk)
        with pytest.raises(ValueError):
            shared.encode_silent_payment_address(scan_pk, spend_pk)


def test_decoder_rejects_nonzero_padding_bits():
    """CHIP-0057 "Silent Payment Address": leftover padding bits MUST be zero. A
    96-byte payload fills 154 five-bit groups with 2 padding bits."""
    vector = VECTORS["addresses"][1]  # testnet
    payload = _h(vector["scan_pk"]) + _h(vector["spend_pk"])

    def encode(groups):
        data = list(groups)
        checksum = shared._bech32m_polymod(
            shared._bech32m_hrp_expand("tspxch") + data + [0] * 6
        ) ^ shared.BECH32M_CONST
        data += [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
        return "tspxch1" + "".join(shared.BECH32_CHARSET[d] for d in data)

    groups = [0] + shared._convertbits(payload, 8, 5)
    assert encode(groups) == vector["address"]  # the helper reproduces the vector
    for padding in (1, 2, 3):
        bad = list(groups)
        bad[-1] |= padding
        with pytest.raises(ValueError):
            sdk_adapter.decode_silent_payment_address(encode(bad))


# --------------------------------------------------------------------------
# key derivation (Test Vector 8)
# --------------------------------------------------------------------------

def test_hardened_key_derivation():
    """keys_from_mnemonic derives the CHIP-0057 hardened keys and addresses."""
    kd = VECTORS["key_derivation"]
    assert kd["scan_path"] == "m/12381n/8444n/12n/0n"
    assert kd["spend_path"] == "m/12381n/8444n/13n/0n"

    master = sdk.SecretKey.from_seed(sdk.Mnemonic(kd["mnemonic"]).to_seed(kd["passphrase"]))
    assert master.to_bytes().hex() == kd["master_sk"]
    assert master.public_key().to_bytes().hex() == kd["master_pk"]

    keys = sdk_adapter.keys_from_mnemonic(kd["mnemonic"])
    assert keys.scan_sk().to_bytes().hex() == kd["scan_sk"]
    assert keys.scan_pk().to_bytes().hex() == kd["scan_pk"]
    assert keys.spend_sk().to_bytes().hex() == kd["spend_sk"]
    assert keys.spend_pk().to_bytes().hex() == kd["spend_pk"]

    # The paths, spelled out: hardened at every level.
    assert master.derive_hardened_path([12381, 8444, 12, 0]).to_bytes().hex() == kd["scan_sk"]
    assert master.derive_hardened_path([12381, 8444, 13, 0]).to_bytes().hex() == kd["spend_sk"]

    assert (
        sdk_adapter.encode_silent_payment_address(keys, sdk.SilentPaymentNetwork.Mainnet)
        == kd["mainnet_address"]
    )
    assert sdk_adapter.encode_silent_payment_address(keys) == kd["testnet_address"]


def test_legacy_derivation_is_separate_and_explicit():
    """The legacy function derives the unhardened keys (the "given" keys of
    vectors 1-7, i.e. the keys of an address generated before the CHIP's
    hardened-derivation revision) — different from the hardened keys of the same
    mnemonic."""
    kd = VECTORS["key_derivation"]
    given = PAYMENTS[0]["outputs"][0]["recipient"]

    legacy = sdk_adapter.legacy_unhardened_keys_from_mnemonic(kd["mnemonic"])
    assert legacy.scan_sk().to_bytes().hex() == given["scan_sk"]
    assert legacy.spend_sk().to_bytes().hex() == given["spend_sk"]
    assert legacy.scan_pk().to_bytes().hex() == given["scan_pk"]
    assert legacy.spend_pk().to_bytes().hex() == given["spend_pk"]

    master = sdk.SecretKey.from_seed(sdk.Mnemonic(kd["mnemonic"]).to_seed(""))
    assert (
        master.derive_unhardened_path([12381, 8444, 12, 0]).to_bytes().hex()
        == given["scan_sk"]
    )
    assert (
        master.derive_unhardened_path([12381, 8444, 13, 0]).to_bytes().hex()
        == given["spend_sk"]
    )

    assert given["scan_sk"] != kd["scan_sk"] and given["spend_sk"] != kd["spend_sk"]
    assert "unsafe for new addresses" in sdk_adapter.LEGACY_KEYS_WARNING
    assert "\n" not in sdk_adapter.LEGACY_KEYS_WARNING  # one line


# --------------------------------------------------------------------------
# required behaviours
# --------------------------------------------------------------------------

def test_change_label_detected_with_no_labels_registered():
    """Test Vector 7: with an EMPTY label registry the unlabeled candidate at k = 0
    is not on chain, the change label m = 0 is still checked, and the output is
    reported as label 0."""
    payment = _payment("vector_7_change_label")
    output = payment["outputs"][0]
    recipient = output["recipient"]
    scan_sk, spend_pk = _sk(recipient["scan_sk"]), _pk(recipient["spend_pk"])

    # The unlabeled candidate the CHIP lists is a different puzzle hash.
    a_sum = sdk_adapter.aggregate_sender_sks([_sk(i["synthetic_sk"]) for i in payment["inputs"]])
    input_hash = sdk_adapter.compute_input_hash(
        [_h(i["coin_id"]) for i in payment["inputs"]], a_sum.public_key()
    )
    unlabeled = sdk_adapter.derive_one_time_puzzle_hash(
        _pk(recipient["scan_pk"]), spend_pk, a_sum, input_hash, 0
    )
    assert bytes(unlabeled).hex() == (
        "980d14e591ef9db6d449eae11c7c43b3f753f07c79da105a06f27f75a2384dc1"
    )
    assert bytes(unlabeled).hex() != output["puzzle_hash"]

    labels = sdk_adapter.label_registry(scan_sk, [])
    assert labels.is_empty()
    detections = sdk_adapter.scan_from_tweaks(scan_sk, spend_pk, _tweak_data(payment), labels)
    assert len(detections) == 1
    assert detections[0].label == 0
    assert detections[0].k == 0
    assert bytes(detections[0].puzzle_hash).hex() == output["puzzle_hash"]
    assert detections[0].tweak.to_bytes().hex() == output["spend_tweak"]


def test_two_coins_sharing_a_one_time_puzzle_hash_are_both_reported():
    """CHIP-0057 "Outputs Sharing a Puzzle Hash": two coins with the same one-time
    puzzle hash (different amounts) are both reported, with the same k and tweak."""
    payment = _payment("vector_1_single_output")
    output = payment["outputs"][0]
    recipient = output["recipient"]
    scan_sk, spend_pk = _sk(recipient["scan_sk"]), _pk(recipient["spend_pk"])

    parent = _h(payment["inputs"][0]["coin_id"])
    puzzle_hash = _h(output["puzzle_hash"])
    coins = [sdk.Coin(parent, puzzle_hash, amount) for amount in (111, 222)]
    assert coins[0].coin_id() != coins[1].coin_id()
    tweak_data = sdk.TweakData(
        [_pk(payment["tweak_point"])],
        [sdk.OutputMeta(c.puzzle_hash, c.coin_id(), c.amount, c.parent_coin_info) for c in coins],
    )

    detections = sdk_adapter.scan_from_tweaks(
        scan_sk, spend_pk, tweak_data, sdk_adapter.label_registry(scan_sk, [])
    )
    assert len(detections) == 2
    assert {bytes(d.coin_id) for d in detections} == {bytes(c.coin_id()) for c in coins}
    assert {d.amount for d in detections} == {111, 222}
    for detection in detections:
        assert bytes(detection.puzzle_hash) == puzzle_hash
        assert detection.k == 0 and detection.label is None
        assert detection.tweak.to_bytes().hex() == output["spend_tweak"]

    records = sdk_adapter.detections_to_records(detections)
    assert len(records) == 2 and len({r["coin_id"] for r in records}) == 2
    assert {r["tweak"] for r in records} == {output["spend_tweak"]}


def test_zero_key_sum_raises():
    """A spend group whose secret keys sum to zero mod r makes the sender fail
    (keys 1 and r - 1), with the CHIP's message from the adapter."""
    one = sdk.SecretKey.from_bytes((1).to_bytes(32, "big"))
    r_minus_one = sdk.SecretKey.from_bytes((GROUP_ORDER - 1).to_bytes(32, "big"))

    with pytest.raises(ValueError) as exc:
        sdk_adapter.aggregate_sender_sks([one, r_minus_one])
    assert str(exc.value) == "aggregated sender key sum is zero — invalid for ECDH"
    assert str(exc.value) == sdk_adapter.ZERO_KEY_SUM_MESSAGE

    # The SDK primitive raises by itself.
    with pytest.raises(ValueError, match="key sum is zero"):
        sdk.SilentPayments.aggregate_sender_sks([one, r_minus_one])

    # The scanner-side counterpart: public keys that sum to the identity.
    with pytest.raises(ValueError, match="identity"):
        sdk_adapter.aggregate_sender_pks([one.public_key(), r_minus_one.public_key()])

    # A non-zero sum is returned as a SecretKey.
    two = sdk_adapter.aggregate_sender_sks([one, one])
    assert isinstance(two, sdk.SecretKey)
    assert two.to_bytes() == (2).to_bytes(32, "big")


def test_k_max_is_the_iteration_cap():
    """k_max bounds the output index: 1 stops after k = 0, 2 reaches k = 1."""
    payment = _payment("vector_6_two_outputs_one_recipient")
    recipient = payment["outputs"][0]["recipient"]
    scan_sk, spend_pk = _sk(recipient["scan_sk"]), _pk(recipient["spend_pk"])
    tweak_data = _tweak_data(payment)

    def scan(k_max):
        return sorted(
            d.k
            for d in sdk_adapter.scan_from_tweaks(
                scan_sk, spend_pk, tweak_data, sdk_adapter.label_registry(scan_sk, []), k_max
            )
        )

    assert scan(1) == [0]
    assert scan(2) == [0, 1]


def test_k_max_is_capped_at_the_chip_value():
    """shared.K_MAX is the CHIP's K_max (2400), and the SDK caps a larger request
    at it: with 2,402 consecutive outputs (k = 0 .. 2401) on chain, the scanner
    reports exactly k = 0 .. 2399 — by default and when asked for far more — so
    this scanner never finds what another conforming scanner would not."""
    assert shared.K_MAX == 2400

    payment = _payment("vector_1_single_output")
    recipient = payment["outputs"][0]["recipient"]
    scan_sk, spend_pk = _sk(recipient["scan_sk"]), _pk(recipient["spend_pk"])
    parent = _h(payment["inputs"][0]["coin_id"])
    a_sum = sdk_adapter.aggregate_sender_sks([_sk(payment["inputs"][0]["synthetic_sk"])])
    input_hash = sdk_adapter.compute_input_hash([parent], a_sum.public_key())

    outputs = []
    for k in range(shared.K_MAX + 2):
        puzzle_hash = sdk_adapter.derive_one_time_puzzle_hash(
            _pk(recipient["scan_pk"]), spend_pk, a_sum, input_hash, k
        )
        coin = sdk.Coin(parent, puzzle_hash, 1 + k)
        outputs.append(sdk.OutputMeta(coin.puzzle_hash, coin.coin_id(), coin.amount, parent))
    assert bytes(outputs[0].puzzle_hash).hex() == payment["outputs"][0]["puzzle_hash"]
    tweak_data = sdk.TweakData([_pk(payment["tweak_point"])], outputs)

    for k_max in (None, 10**6):
        args = () if k_max is None else (k_max,)
        detections = sdk_adapter.scan_from_tweaks(
            scan_sk, spend_pk, tweak_data, sdk_adapter.label_registry(scan_sk, []), *args
        )
        assert sorted(d.k for d in detections) == list(range(shared.K_MAX))
