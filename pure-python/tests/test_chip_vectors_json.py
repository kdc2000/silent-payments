"""
JSON-driven tests: the CHIP's machine-readable test vectors.

tests/data/chip-0057-test_vectors.json is a copy of the vectors file that
accompanies the CHIP. Every value in it is recomputed here by this
implementation: each payment (input_hash, tweak point, and each output's
shared secret, t_k, one-time public key, puzzle hash, spend tweak and
one-time secret key), the labels, every address and address case, and the
key derivation. The file itself is reproduced byte for byte by
gen_test_vectors.py.
"""

import json
import os
import sys

import pytest
from chia_rs import G1Element, PrivateKey

import gen_test_vectors
from shared import (
    GROUP_ORDER,
    SP_ADDRESS_VERSION,
    aggregate_sender_pks,
    build_label_map,
    combine_spend_tweak,
    compute_input_hash,
    compute_label_scalar,
    compute_tweak_point,
    decode_silent_payment_address,
    derive_onetime_sk_full,
    derive_silent_payment_outputs,
    encode_silent_payment_address,
    generate_label,
    generate_labeled_spend_pk,
    master_sk_to_scan_sk,
    master_sk_to_spend_sk,
    mnemonic_to_master_sk,
    scan_for_silent_payment,
    scan_tweak_point,
)
from tests.common import output_coin

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "data", "chip-0057-test_vectors.json")

with open(VECTORS_PATH) as _f:
    VECTORS_TEXT = _f.read()
VECTORS = json.loads(VECTORS_TEXT)

PREFIXES = {"mainnet": "spxch", "testnet": "tspxch"}


def sk(hex_str: str) -> PrivateKey:
    return PrivateKey.from_bytes(bytes.fromhex(hex_str))


def pk(hex_str: str) -> G1Element:
    return G1Element.from_bytes(bytes.fromhex(hex_str))


def int_hex(value: int) -> str:
    return f"{value:064x}"


def test_vectors_file_shape():
    """The file has the expected sections and nothing is silently skipped."""
    assert VECTORS["chip"] == "CHIP-0057"
    assert VECTORS["address_version"] == SP_ADDRESS_VERSION == 0
    assert [p["name"] for p in VECTORS["payments"]] == [
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


@pytest.mark.parametrize("payment", VECTORS["payments"], ids=lambda p: p["name"])
def test_payment_inputs(payment):
    """Key sum, smallest coin ID, input_hash and tweak point of each payment."""
    sender_sks = [sk(i["synthetic_sk"]) for i in payment["inputs"]]
    coin_ids = [bytes.fromhex(i["coin_id"]) for i in payment["inputs"]]

    for sender_sk, i in zip(sender_sks, payment["inputs"]):
        assert bytes(sender_sk.get_g1()).hex() == i["synthetic_pk"]

    pk_sum = aggregate_sender_pks([s.get_g1() for s in sender_sks])
    assert bytes(pk_sum).hex() == payment["a_sum_pk"]
    assert min(coin_ids).hex() == payment["coin_id_l"]

    input_hash = compute_input_hash(coin_ids, pk_sum)
    assert int_hex(input_hash) == payment["input_hash"]
    assert bytes(compute_tweak_point(coin_ids, pk_sum)).hex() == payment["tweak_point"]


@pytest.mark.parametrize("payment", VECTORS["payments"], ids=lambda p: p["name"])
def test_payment_sender(payment):
    """The sender derives every output of each payment."""
    sender_sks = [sk(i["synthetic_sk"]) for i in payment["inputs"]]
    coin_ids = [bytes.fromhex(i["coin_id"]) for i in payment["inputs"]]

    recipients = []
    for out in payment["outputs"]:
        r = out["recipient"]
        scan_sk, spend_sk = sk(r["scan_sk"]), sk(r["spend_sk"])
        assert bytes(scan_sk.get_g1()).hex() == r["scan_pk"]
        assert bytes(spend_sk.get_g1()).hex() == r["spend_pk"]

        # Second key of the recipient's address: B_spend, or B_m for a label
        address_spend_pk = spend_sk.get_g1()
        if r["label"] is not None:
            _, label_pk = generate_label(scan_sk, r["label"])
            address_spend_pk = generate_labeled_spend_pk(address_spend_pk, label_pk)
        assert bytes(address_spend_pk).hex() == r["address_spend_pk"]
        recipients.append((scan_sk.get_g1(), address_spend_pk))

    derived = derive_silent_payment_outputs(sender_sks, coin_ids, recipients)
    assert len(derived) == len(payment["outputs"])
    for got, out in zip(derived, payment["outputs"]):
        assert got["k"] == out["k"]
        assert got["shared_secret"].hex() == out["shared_secret"]
        assert int_hex(got["t_k"]) == out["t_k"]
        assert bytes(got["onetime_pk"]).hex() == out["onetime_pk"]
        assert got["puzzle_hash"].hex() == out["puzzle_hash"]


@pytest.mark.parametrize("from_tweak_point", [False, True], ids=["from_keys", "from_tweak_point"])
@pytest.mark.parametrize("payment", VECTORS["payments"], ids=lambda p: p["name"])
def test_payment_recipient(payment, from_tweak_point):
    """Each recipient detects exactly its outputs, with the recorded k, label,
    t_k and spend tweak, and derives the one-time secret key from the spend
    tweak. Checked both from the group's keys and from its tweak point."""
    coin_ids = [bytes.fromhex(i["coin_id"]) for i in payment["inputs"]]
    pk_sum = pk(payment["a_sum_pk"])
    all_coins = [
        output_coin(bytes.fromhex(out["puzzle_hash"]), amount=n + 1)
        for n, out in enumerate(payment["outputs"])
    ]

    recipients = {out["recipient"]["scan_sk"]: out["recipient"] for out in payment["outputs"]}
    for scan_sk_hex, r in recipients.items():
        scan_sk, spend_sk = sk(scan_sk_hex), sk(r["spend_sk"])
        expected = [o for o in payment["outputs"] if o["recipient"]["scan_sk"] == scan_sk_hex]
        used_labels = [o["recipient"]["label"] for o in expected if o["recipient"]["label"] is not None]
        labels = build_label_map(scan_sk, used_labels)

        if from_tweak_point:
            detected = scan_tweak_point(
                scan_sk, spend_sk.get_g1(), bytes.fromhex(payment["tweak_point"]),
                all_coins, labels=labels,
            )
        else:
            detected = scan_for_silent_payment(
                scan_sk, spend_sk.get_g1(), pk_sum, coin_ids, all_coins, labels=labels,
            )

        assert len(detected) == len(expected)
        for d, out in zip(detected, expected):
            assert d["k"] == out["k"]
            assert d["label"] == out["recipient"]["label"]
            assert d["puzzle_hash"].hex() == out["puzzle_hash"]
            assert bytes(d["onetime_pk"]).hex() == out["onetime_pk"]
            assert int_hex(d["t_k"]) == out["t_k"]
            assert int_hex(d["spend_tweak"]) == out["spend_tweak"]

            # spend_tweak is (t_k + label_scalar) mod r
            label_scalar = 0
            if out["recipient"]["label"] is not None:
                label_scalar = compute_label_scalar(scan_sk, out["recipient"]["label"])
            assert d["spend_tweak"] == combine_spend_tweak(d["t_k"], label_scalar)
            assert d["spend_tweak"] == (int(out["t_k"], 16) + label_scalar) % GROUP_ORDER

            # The signer needs only b_spend and the spend tweak
            onetime_sk = derive_onetime_sk_full(spend_sk, d["spend_tweak"])
            assert bytes(onetime_sk).hex() == out["onetime_sk"]
            assert bytes(onetime_sk.get_g1()).hex() == out["onetime_pk"]


@pytest.mark.parametrize("label", VECTORS["labels"], ids=lambda entry: f"m={entry['m']}")
def test_labels(label):
    label_scalar, label_pk = generate_label(sk(label["scan_sk"]), label["m"])
    assert int_hex(label_scalar) == label["label_scalar"]
    assert bytes(label_pk).hex() == label["label_pk"]


@pytest.mark.parametrize("entry", VECTORS["addresses"], ids=lambda e: e["address"][:12] + e["spend_pk"][:6])
def test_addresses(entry):
    scan_pk, spend_pk = bytes.fromhex(entry["scan_pk"]), bytes.fromhex(entry["spend_pk"])
    prefix = PREFIXES[entry["network"]]
    assert encode_silent_payment_address(scan_pk, spend_pk, prefix) == entry["address"]
    assert decode_silent_payment_address(entry["address"]) == (scan_pk, spend_pk)
    assert decode_silent_payment_address(entry["address"], expected_prefix=prefix) == (scan_pk, spend_pk)


@pytest.mark.parametrize("case", VECTORS["address_cases"], ids=lambda c: c["description"])
def test_address_cases(case):
    if case["valid"]:
        assert decode_silent_payment_address(case["address"]) == (
            bytes.fromhex(case["scan_pk"]), bytes.fromhex(case["spend_pk"])
        )
    else:
        with pytest.raises(ValueError):
            decode_silent_payment_address(case["address"])


def test_key_derivation():
    kd = VECTORS["key_derivation"]
    assert kd["passphrase"] == ""
    assert kd["scan_path"] == "m/12381n/8444n/12n/0n"
    assert kd["spend_path"] == "m/12381n/8444n/13n/0n"

    master = mnemonic_to_master_sk(kd["mnemonic"])
    assert bytes(master).hex() == kd["master_sk"]
    assert bytes(master.get_g1()).hex() == kd["master_pk"]

    scan_sk, spend_sk = master_sk_to_scan_sk(master), master_sk_to_spend_sk(master)
    assert bytes(scan_sk).hex() == kd["scan_sk"]
    assert bytes(scan_sk.get_g1()).hex() == kd["scan_pk"]
    assert bytes(spend_sk).hex() == kd["spend_sk"]
    assert bytes(spend_sk.get_g1()).hex() == kd["spend_pk"]

    scan_pk, spend_pk = bytes(scan_sk.get_g1()), bytes(spend_sk.get_g1())
    assert encode_silent_payment_address(scan_pk, spend_pk, "spxch") == kd["mainnet_address"]
    assert encode_silent_payment_address(scan_pk, spend_pk, "tspxch") == kd["testnet_address"]


# --- The generator ---

def test_generator_reproduces_file_byte_for_byte(tmp_path, monkeypatch, capsys):
    """gen_test_vectors.py regenerates the vectors file exactly."""
    assert gen_test_vectors.serialize(gen_test_vectors.build_vectors()) == VECTORS_TEXT

    out = tmp_path / "vectors.json"
    monkeypatch.setattr(sys, "argv", ["gen_test_vectors.py", str(out)])
    gen_test_vectors.main()
    assert out.read_bytes() == VECTORS_TEXT.encode()


def test_generator_check_mode(tmp_path, monkeypatch, capsys):
    """--check passes when the CHIP text prints only reproducible values, and
    fails when it prints a value this implementation does not produce."""
    printed = sorted(
        set(gen_test_vectors._protocol_values(VECTORS)) | gen_test_vectors.chip_only_values(VECTORS)
    )
    body = "\n".join(f"| value | `{v}` |" for v in printed)
    good = f"# CHIP\n\n## Test Cases\n\n{body}\n\n## Reference Implementation\n"
    assert gen_test_vectors.check_against_chip(VECTORS, good) == ([], [])

    bogus = "ab" * 32
    bad = good.replace("## Reference Implementation", f"`{bogus}`\n\n## Reference Implementation")
    assert gen_test_vectors.check_against_chip(VECTORS, bad) == ([], [bogus])

    chip = tmp_path / "chip.md"
    out = tmp_path / "vectors.json"
    monkeypatch.setattr(sys, "argv", ["gen_test_vectors.py", str(out), "--check", str(chip)])

    chip.write_text(good)
    gen_test_vectors.main()

    chip.write_text(bad)
    with pytest.raises(SystemExit) as exc:
        gen_test_vectors.main()
    assert exc.value.code == 1
    assert bogus in capsys.readouterr().out
