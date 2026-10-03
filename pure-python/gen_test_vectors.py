#!/usr/bin/env python3
"""
Generate the CHIP-0057 machine-readable test vectors (test_vectors.json).

Every value is computed by this directory's implementation (shared.py):
the payments of the CHIP's Test Vectors 1-4, 6 and 7 with all intermediate
values, the labels, the addresses of Test Vector 5, examples of addresses
that must be accepted or rejected, and the key derivation of Test Vector 8.

Usage:
    python gen_test_vectors.py <output.json>
    python gen_test_vectors.py <output.json> --check <chip-0057.md>

With --check, the generated values are also compared with the text of the
CHIP: every key, scalar, point, hash and address printed in its "Test Cases"
section must be reproduced by this implementation (exit status 1 otherwise),
and the number of generated values that the CHIP does not print is reported.
"""

import argparse
import hashlib
import json
import re
import sys

from chia_rs import PrivateKey

import shared

# The BLS12-381 base field modulus, used only to build an off-curve address case
FIELD_MODULUS = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Recipient keys of Test Vectors 1-7. The CHIP treats them as given values.
RECIPIENT_A_SCAN_SK = "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6"
RECIPIENT_A_SPEND_SK = "53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087"
RECIPIENT_B_SCAN_SK = "56a3762ba1200ab5a796d3a2af85261f745ee9620e927d0232c18b710cbf22d2"
RECIPIENT_B_SPEND_SK = "70fbad8c37b92e585f890bcef5730727d4100584fc9df4bbc9f5e533691d20bf"


def hx(value) -> str:
    """Hex of a key, point or byte string."""
    return bytes(value).hex()


def int_hex(value: int) -> str:
    """A scalar as 32-byte big-endian hex."""
    return f"{value:064x}"


def secret_key(hex_str: str) -> PrivateKey:
    return PrivateKey.from_bytes(bytes.fromhex(hex_str))


def test_coin_id(name: str) -> bytes:
    """The coin IDs of the vectors are SHA256 of a name."""
    return hashlib.sha256(name.encode()).digest()


def payment(name, description, sender_sks, coin_ids, recipients) -> dict:
    """One payment with all intermediate values.

    recipients: list of (scan_sk, spend_sk, label m or None), in sender order.
    """
    entries = []
    for scan_sk, spend_sk, m in recipients:
        label_scalar, address_spend_pk = 0, spend_sk.get_g1()
        if m is not None:
            label_scalar, label_pk = shared.generate_label(scan_sk, m)
            address_spend_pk = shared.generate_labeled_spend_pk(address_spend_pk, label_pk)
        entries.append((scan_sk, spend_sk, m, label_scalar, address_spend_pk))

    derived = shared.derive_silent_payment_outputs(
        sender_sks, coin_ids, [(e[0].get_g1(), e[4]) for e in entries]
    )

    pk_sum = shared.aggregate_sender_pks([sk.get_g1() for sk in sender_sks])
    outputs = []
    for (scan_sk, spend_sk, m, label_scalar, address_spend_pk), out in zip(entries, derived):
        spend_tweak = shared.combine_spend_tweak(out["t_k"], label_scalar)
        onetime_sk = shared.derive_onetime_sk_full(spend_sk, spend_tweak)
        assert onetime_sk.get_g1() == out["onetime_pk"]
        outputs.append({
            "recipient": {
                "scan_sk": hx(scan_sk), "scan_pk": hx(scan_sk.get_g1()),
                "spend_sk": hx(spend_sk), "spend_pk": hx(spend_sk.get_g1()),
                "label": m, "address_spend_pk": hx(address_spend_pk),
            },
            "k": out["k"],
            "shared_secret": hx(out["shared_secret"]),
            "t_k": int_hex(out["t_k"]),
            "onetime_pk": hx(out["onetime_pk"]),
            "puzzle_hash": hx(out["puzzle_hash"]),
            "spend_tweak": int_hex(spend_tweak),
            "onetime_sk": hx(onetime_sk),
        })

    return {
        "name": name,
        "description": description,
        "inputs": [
            {"synthetic_sk": hx(sk), "synthetic_pk": hx(sk.get_g1()), "coin_id": hx(coin_id)}
            for sk, coin_id in zip(sender_sks, coin_ids)
        ],
        "a_sum_pk": hx(pk_sum),
        "coin_id_l": hx(min(coin_ids)),
        "input_hash": int_hex(shared.compute_input_hash(coin_ids, pk_sum)),
        "tweak_point": hx(shared.compute_tweak_point(coin_ids, pk_sum)),
        "outputs": outputs,
    }


def raw_address(prefix: str, version: int, payload: bytes) -> str:
    """Encode any version and payload, valid or not, for the address cases."""
    return shared.bech32m_encode(prefix, [version] + shared._convertbits(payload, 8, 5))


def build_vectors() -> dict:
    master = shared.mnemonic_to_master_sk(MNEMONIC)
    # Sender keys: the mnemonic's standard wallet keys at indices 0 and 1
    sender = [
        shared.calculate_synthetic_secret_key(shared.master_sk_to_wallet_sk(master, i))
        for i in (0, 1)
    ]
    a_scan, a_spend = secret_key(RECIPIENT_A_SCAN_SK), secret_key(RECIPIENT_A_SPEND_SK)
    b_scan, b_spend = secret_key(RECIPIENT_B_SCAN_SK), secret_key(RECIPIENT_B_SPEND_SK)

    payments = [
        payment(
            "vector_1_single_output", "One input, one unlabeled output.",
            [sender[0]], [test_coin_id("test-vector-1-coin")],
            [(a_scan, a_spend, None)],
        ),
        payment(
            "vector_2_two_recipients", "One input, two recipients with different scan keys.",
            [sender[0]], [test_coin_id("test-vector-2-coin")],
            [(a_scan, a_spend, None), (b_scan, b_spend, None)],
        ),
        payment(
            "vector_3_labeled", "One input, one output to a labeled address (m = 1).",
            [sender[0]], [test_coin_id("test-vector-3-coin")],
            [(a_scan, a_spend, 1)],
        ),
        payment(
            "vector_4_multi_input",
            "Two inputs bound by a 2-cycle of ASSERT_CONCURRENT_SPEND conditions.",
            [sender[0], sender[1]],
            [test_coin_id("test-vector-4-coin-0"), test_coin_id("test-vector-4-coin-1")],
            [(a_scan, a_spend, None)],
        ),
        payment(
            "vector_6_two_outputs_one_recipient",
            "The transaction of vector 1 with the same recipient listed twice (k = 0, 1).",
            [sender[0]], [test_coin_id("test-vector-1-coin")],
            [(a_scan, a_spend, None), (a_scan, a_spend, None)],
        ),
        payment(
            "vector_7_change_label",
            "One input, one change output to the recipient's own label m = 0.",
            [sender[0]], [test_coin_id("test-vector-7-coin")],
            [(a_scan, a_spend, 0)],
        ),
    ]

    labels = []
    for m in (0, 1):
        label_scalar, label_pk = shared.generate_label(a_scan, m)
        labels.append({
            "scan_sk": hx(a_scan), "m": m,
            "label_scalar": int_hex(label_scalar), "label_pk": hx(label_pk),
        })

    # Addresses (Test Vector 5): the unlabeled address and the label m = 1 address
    scan_pk, spend_pk = bytes(a_scan.get_g1()), bytes(a_spend.get_g1())
    _, label_pk_1 = shared.generate_label(a_scan, 1)
    labeled_pk = bytes(shared.generate_labeled_spend_pk(a_spend.get_g1(), label_pk_1))
    addresses = [
        {
            "scan_pk": hx(scan_pk), "spend_pk": hx(second_key), "network": network,
            "address": shared.encode_silent_payment_address(scan_pk, second_key, prefix),
        }
        for second_key in (spend_pk, labeled_pk)
        for network, prefix in (("mainnet", "spxch"), ("testnet", "tspxch"))
    ]

    # Addresses that exercise the versioning and point validation rules
    payload = scan_pk + spend_pk
    identity = bytes([0xC0]) + bytes(47)
    # x = 4 is on the curve but outside the prime-order subgroup
    outside_subgroup = bytes([0x80]) + bytes(46) + b"\x04"
    # the smallest x for which x^3 + 4 is not a square mod p, so no point has it
    off_curve_x = next(
        x for x in range(1, 100)
        if pow((x ** 3 + 4) % FIELD_MODULUS, (FIELD_MODULUS - 1) // 2, FIELD_MODULUS) != 1
    )
    off_curve = bytes([0x80]) + off_curve_x.to_bytes(48, "big")[1:]
    valid_mainnet = shared.encode_silent_payment_address(scan_pk, spend_pk, "spxch")
    # version 0 data with the two padding bits of the last payload group set
    nonzero_padding = [0] + shared._convertbits(payload, 8, 5)
    nonzero_padding[-1] |= 0b11
    address_cases = [
        {
            "description": "version 1 with 4 extra payload bytes: valid, the first 96 bytes are the keys",
            "address": raw_address("spxch", 1, payload + bytes([1, 2, 3, 4])),
            "valid": True, "scan_pk": hx(scan_pk), "spend_pk": hx(spend_pk),
        },
        {
            "description": "version 31: invalid",
            "address": raw_address("spxch", 31, payload), "valid": False,
        },
        {
            "description": "version 0 with a 95-byte payload: invalid",
            "address": raw_address("spxch", 0, payload[:95]), "valid": False,
        },
        {
            "description": "version 0 with a 97-byte payload: invalid",
            "address": raw_address("spxch", 0, payload + b"\x00"), "valid": False,
        },
        {
            "description": "version 1 with a 95-byte payload: invalid",
            "address": raw_address("spxch", 1, payload[:95]), "valid": False,
        },
        {
            "description": "scan key is the identity element: invalid",
            "address": raw_address("spxch", 0, identity + spend_pk), "valid": False,
        },
        {
            "description": "spend key is the identity element: invalid",
            "address": raw_address("spxch", 0, scan_pk + identity), "valid": False,
        },
        {
            "description": "scan key is on the curve but outside the prime-order subgroup: invalid",
            "address": raw_address("spxch", 0, outside_subgroup + spend_pk), "valid": False,
        },
        {
            "description": "scan key is not on the curve: invalid",
            "address": raw_address("spxch", 0, off_curve + spend_pk), "valid": False,
        },
        {
            "description": "non-zero padding bits after the payload: invalid",
            "address": shared.bech32m_encode("spxch", nonzero_padding), "valid": False,
        },
        {
            "description": "all upper case: valid",
            "address": valid_mainnet.upper(),
            "valid": True, "scan_pk": hx(scan_pk), "spend_pk": hx(spend_pk),
        },
        {
            "description": "mixed case: invalid",
            "address": valid_mainnet[:10] + valid_mainnet[10:20].upper() + valid_mainnet[20:],
            "valid": False,
        },
        {
            "description": "wrong checksum: invalid",
            "address": valid_mainnet[:-1] + ("q" if valid_mainnet[-1] != "q" else "p"), "valid": False,
        },
        {
            "description": "longer than 1,023 characters: invalid",
            "address": raw_address("spxch", 1, payload + bytes(550)), "valid": False,
        },
        {
            "description": "version 1 at exactly 1,023 characters: valid, the first 96 bytes are the keys",
            "address": raw_address("spxch", 1, payload + bytes(535)),
            "valid": True, "scan_pk": hx(scan_pk), "spend_pk": hx(spend_pk),
        },
        {
            "description": "not a silent payment prefix: invalid",
            "address": raw_address("xch", 0, payload), "valid": False,
        },
    ]

    # Key derivation (Test Vector 8): hardened at every level
    scan_sk = shared.master_sk_to_scan_sk(master)
    spend_sk = shared.master_sk_to_spend_sk(master)
    derived_scan_pk, derived_spend_pk = bytes(scan_sk.get_g1()), bytes(spend_sk.get_g1())
    key_derivation = {
        "mnemonic": MNEMONIC, "passphrase": "",
        "master_sk": hx(master), "master_pk": hx(master.get_g1()),
        "scan_path": "m/12381n/8444n/12n/0n",
        "scan_sk": hx(scan_sk), "scan_pk": hx(derived_scan_pk),
        "spend_path": "m/12381n/8444n/13n/0n",
        "spend_sk": hx(spend_sk), "spend_pk": hx(derived_spend_pk),
        "mainnet_address": shared.encode_silent_payment_address(derived_scan_pk, derived_spend_pk, "spxch"),
        "testnet_address": shared.encode_silent_payment_address(derived_scan_pk, derived_spend_pk, "tspxch"),
    }

    return {
        "chip": "CHIP-0057",
        "address_version": shared.SP_ADDRESS_VERSION,
        "notes": "All integers are 32-byte big-endian hex. Points are 48-byte compressed G1. "
                 "spend_tweak is (t_k + label_scalar) mod r.",
        "payments": payments,
        "labels": labels,
        "addresses": addresses,
        "address_cases": address_cases,
        "key_derivation": key_derivation,
    }


def serialize(vectors: dict) -> str:
    """The exact text of the vectors file."""
    return json.dumps(vectors, indent=2) + "\n"


def _protocol_values(node):
    """Yield every hex value (32 bytes or longer) and every address in the vectors."""
    if isinstance(node, dict):
        for value in node.values():
            yield from _protocol_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from _protocol_values(value)
    elif isinstance(node, str):
        is_hex = len(node) >= 64 and all(ch in "0123456789abcdef" for ch in node)
        if is_hex or "spxch1" in node:
            yield node


def chip_only_values(vectors: dict) -> set[str]:
    """Values the CHIP prints in its Test Cases that the vectors file does not
    carry: intermediate values of single steps, and the one-time addresses."""
    master = shared.mnemonic_to_master_sk(MNEMONIC)
    wallet_sks = [shared.master_sk_to_wallet_sk(master, i) for i in (0, 1)]
    sender = [shared.calculate_synthetic_secret_key(sk) for sk in wallet_sks]
    a_scan, a_spend = secret_key(RECIPIENT_A_SCAN_SK), secret_key(RECIPIENT_A_SPEND_SK)
    by_name = {p["name"]: p for p in vectors["payments"]}

    values = {hx(wallet_sks[0])}  # sender wallet SK (vector 1)

    # Aggregated secret key and ECDH point S = (input_hash * a_sum) * B_scan (vectors 1 and 4)
    for name, sender_sks in (("vector_1_single_output", sender[:1]), ("vector_4_multi_input", sender)):
        a_sum = shared.aggregate_sender_sks(sender_sks)
        scalar = int(by_name[name]["input_hash"], 16) * int.from_bytes(bytes(a_sum), "big")
        values.add(hx(a_sum))
        values.add(hx(shared.scalar_mult_g1(scalar % shared.GROUP_ORDER, a_scan.get_g1())))

    # Base one-time SK (b_spend + t_0) of the labeled payment (vector 3)
    t_0 = int(by_name["vector_3_labeled"]["outputs"][0]["t_k"], 16)
    values.add(hx(shared.derive_onetime_sk_full(a_spend, t_0)))

    # Unlabeled candidate puzzle hash of the change payment (vector 7)
    t_0 = int(by_name["vector_7_change_label"]["outputs"][0]["t_k"], 16)
    values.add(hx(shared.puzzle_hash_for_pk(shared.derive_onetime_pk_full(a_spend.get_g1(), t_0))))

    # One-time addresses of all outputs
    for p in vectors["payments"]:
        for out in p["outputs"]:
            values.add(shared.puzzle_hash_to_address(bytes.fromhex(out["puzzle_hash"]), "txch"))
    return values


def check_against_chip(vectors: dict, chip_text: str) -> tuple[list[str], list[str]]:
    """Compare the vectors with the text of the CHIP.

    Returns (not_printed, not_reproduced):
      not_printed    - values of the file that the CHIP does not print.
                       Expected to be non-empty: the file holds more than the
                       CHIP shows (tweak points, spend tweaks, address cases).
      not_reproduced - 32-byte and 48-byte hex values and addresses printed
                       in the CHIP's "Test Cases" section that are neither in
                       the file nor among chip_only_values. Must be empty.
    """
    values = set(_protocol_values(vectors))
    not_printed = sorted(v for v in values if v not in chip_text)

    start = chip_text.index("## Test Cases")
    end = chip_text.index("## Reference Implementation")
    printed = set(re.findall(
        r"`([0-9a-f]{64}|[0-9a-f]{96}|t?spxch1[a-z0-9]+|t?xch1[a-z0-9]+)`",
        chip_text[start:end],
    ))
    file_text = json.dumps(vectors)
    extra = chip_only_values(vectors)
    not_reproduced = sorted(v for v in printed if v not in file_text and v not in extra)
    return not_printed, not_reproduced


def main():
    parser = argparse.ArgumentParser(description="Generate the CHIP-0057 test vectors")
    parser.add_argument("output", help="Path of the JSON file to write")
    parser.add_argument("--check", metavar="CHIP_MD",
                        help="Also compare the values with the text of the CHIP")
    args = parser.parse_args()

    vectors = build_vectors()
    with open(args.output, "w") as f:
        f.write(serialize(vectors))
    print(f"wrote {args.output}")

    if args.check:
        with open(args.check) as f:
            chip_text = f.read()
        not_printed, not_reproduced = check_against_chip(vectors, chip_text)
        total = len(set(_protocol_values(vectors)))
        print(f"values in the file: {total}; printed in the CHIP: {total - len(not_printed)}; "
              f"not printed in the CHIP: {len(not_printed)}")
        print(f"values in the CHIP's Test Cases not reproduced: {len(not_reproduced)}")
        for value in not_reproduced:
            print("  ", value)
        if not_reproduced:
            sys.exit(1)


if __name__ == "__main__":
    main()
