#!/usr/bin/env python3
"""
Spend a silent payment coin back to the recipient's standard wallet address.

Takes the coin ID and the recipient's mnemonic. Detects the coin using
scan/spend key separation, derives the one-time secret key, builds a
spend bundle sending the full amount to the recipient's spend-key-derived
standard address, and pushes it via coinset.

Usage:
    python spend_coin.py <coin_id_hex> -f keyfile.txt
    python spend_coin.py <coin_id_hex> [recipient_mnemonic]
    python spend_coin.py <coin_id_hex> --sage
"""

import sys
import json
import hashlib
import argparse
import subprocess

from chia_rs import (
    G1Element, Program, Coin, CoinSpend, SpendBundle, AugSchemeMPL,
)
from shared import (
    mnemonic_to_master_sk, master_sk_to_scan_sk, master_sk_to_spend_sk,
    compute_input_hash, derive_output_tweak,
    derive_onetime_pk_full, derive_onetime_sk_full,
    puzzle_for_pk, puzzle_hash_for_pk,
    calculate_synthetic_secret_key,
    extract_synthetic_pk, scalar_mult_g1,
    aggregate_sender_pks, compute_coin_id,
    TESTNET11_GENESIS,
    load_mnemonic,
)

parser = argparse.ArgumentParser(description="Spend a silent payment coin")
parser.add_argument("coin_id", help="Coin ID hex to spend")
parser.add_argument("mnemonic_words", nargs="*", help="Recipient mnemonic words")
parser.add_argument("-f", "--mnemonic-file", help="File containing recipient mnemonic")
parser.add_argument("--sage", action="store_true", help="Submit transaction via Sage RPC")
parser.add_argument("--sage-url", help="Sage RPC URL (default: https://127.0.0.1:9257)")
parser.add_argument("--sage-cert", help="Path to Sage TLS client certificate")
parser.add_argument("--sage-key", help="Path to Sage TLS client key")


def coinset_call(command: str, arg: str) -> dict:
    coin_id = arg if arg.startswith("0x") else "0x" + arg
    result = subprocess.run(
        ["coinset", "-t", "-r", command, coin_id],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"coinset error: {result.stderr.strip()}")
    return json.loads(result.stdout)


def get_coin_record(coin_id: str) -> dict:
    result = coinset_call("get_coin_record_by_name", coin_id)
    if not result.get("success"):
        raise RuntimeError(f"Could not find coin: {result}")
    return result["coin_record"]


def get_puzzle_and_solution(coin_id: str) -> dict:
    result = coinset_call("get_puzzle_and_solution", coin_id)
    if not result.get("success"):
        raise RuntimeError(f"Could not get puzzle/solution: {result}")
    return result["coin_solution"]


def extract_sender_synthetic_pk(coin_record: dict) -> G1Element | None:
    parent_id = coin_record["coin"]["parent_coin_info"]
    if parent_id.startswith("0x"):
        parent_id = parent_id[2:]

    parent_record = get_coin_record(parent_id)
    if not parent_record.get("spent"):
        raise RuntimeError("Parent coin is not spent — cannot extract puzzle")

    parent_spend = get_puzzle_and_solution(parent_id)
    puzzle = Program.from_bytes(bytes.fromhex(parent_spend["puzzle_reveal"][2:]))
    return extract_synthetic_pk(puzzle)


def strip_0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


def _detection_attempts(parent_coin_id, sender_pk, coin_record):
    """Yield (coin_ids, sender_pk, mode) for single then multi-input detection."""
    # Pass 1: single-input
    yield [parent_coin_id], sender_pk, "single-input"

    # Pass 2: multi-input -- find sibling spends with same puzzle hash in same block
    spent_height = coin_record.get("spent_block_index")
    if spent_height is None:
        return

    # The parent coin created our output. Look up the parent to find its puzzle hash.
    parent_hex = strip_0x(coin_record["coin"]["parent_coin_info"])
    try:
        parent_record = get_coin_record(parent_hex)
    except RuntimeError:
        return
    parent_ph = strip_0x(parent_record["coin"]["puzzle_hash"])

    # Find other coins with the same puzzle hash spent in the same block
    try:
        result = subprocess.run(
            ["coinset", "-t", "-r", "get_coin_records_by_puzzle_hash",
             "0x" + parent_ph],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return
        records = json.loads(result.stdout).get("coin_records", [])
    except (RuntimeError, json.JSONDecodeError):
        return

    # Filter to coins spent at the same height as the parent
    parent_spent_height = parent_record.get("spent_block_index")
    if parent_spent_height is None:
        return

    siblings = [
        r for r in records
        if r.get("spent", False)
        and r.get("spent_block_index") == parent_spent_height
    ]

    if len(siblings) < 2:
        return

    # Extract PKs and coin IDs from all siblings
    pks = []
    group_coin_ids = []
    for sib in siblings:
        sib_coin = sib["coin"]
        sib_parent = bytes.fromhex(strip_0x(sib_coin["parent_coin_info"]))
        sib_ph = bytes.fromhex(strip_0x(sib_coin["puzzle_hash"]))
        sib_amount = sib_coin["amount"]
        sib_coin_id = compute_coin_id(sib_parent, sib_ph, sib_amount)

        try:
            spend_data = get_puzzle_and_solution(sib_coin_id.hex())
            puzzle_hex = strip_0x(spend_data["puzzle_reveal"])
            puzzle = Program.from_bytes(bytes.fromhex(puzzle_hex))
            pk = extract_synthetic_pk(puzzle)
            if pk is None:
                continue
            pks.append(pk)
            group_coin_ids.append(sib_coin_id)
        except RuntimeError:
            continue

    if len(pks) < 2:
        return

    pk_sum = aggregate_sender_pks(pks)
    if pk_sum == G1Element():
        return

    yield group_coin_ids, pk_sum, f"multi-input ({len(pks)} coins)"


def main():
    args = parser.parse_args()
    coin_id = args.coin_id
    if coin_id.startswith("0x"):
        coin_id = coin_id[2:]

    if args.mnemonic_file:
        mnemonic = load_mnemonic(["-f", args.mnemonic_file], prompt="Enter recipient mnemonic: ")
    elif args.mnemonic_words:
        mnemonic = " ".join(args.mnemonic_words)
    else:
        mnemonic = load_mnemonic([], prompt="Enter recipient mnemonic: ")

    # Derive recipient scan and spend keys
    master_sk = mnemonic_to_master_sk(mnemonic)
    scan_sk = master_sk_to_scan_sk(master_sk)
    scan_pk = scan_sk.get_g1()
    spend_sk = master_sk_to_spend_sk(master_sk)
    spend_pk = spend_sk.get_g1()

    # Destination: recipient's spend-key-derived standard address
    dest_puzzle_hash = puzzle_hash_for_pk(spend_pk)

    print(f"Scan pubkey:  {bytes(scan_pk).hex()}")
    print(f"Spend pubkey: {bytes(spend_pk).hex()}")
    print(f"Destination PH: {dest_puzzle_hash.hex()}")
    print(f"Checking coin:  {coin_id}")
    print()

    # Look up the coin
    coin_record = get_coin_record(coin_id)
    coin_data = coin_record["coin"]
    coin_ph = coin_data["puzzle_hash"]
    if coin_ph.startswith("0x"):
        coin_ph = coin_ph[2:]
    amount = coin_data["amount"]

    if coin_record.get("spent"):
        print("ERROR: This coin has already been spent.")
        sys.exit(1)

    print(f"Coin puzzle hash: {coin_ph}")
    print(f"Coin amount:      {amount} mojos")
    print()

    # Extract sender's synthetic public key from parent puzzle
    print("Extracting sender synthetic public key from parent puzzle...")
    sender_synthetic_pk = extract_sender_synthetic_pk(coin_record)

    if sender_synthetic_pk is None:
        print("Could not extract synthetic public key.")
        sys.exit(1)

    print(f"Sender synthetic pk: {bytes(sender_synthetic_pk).hex()}")

    # Try single-input detection first (Pass 1)
    parent_coin_info = coin_data["parent_coin_info"]
    if parent_coin_info.startswith("0x"):
        parent_coin_info = parent_coin_info[2:]
    parent_coin_id = bytes.fromhex(parent_coin_info)

    tweak = None
    for try_coin_ids, try_pk, mode in _detection_attempts(
        parent_coin_id, sender_synthetic_pk, coin_record
    ):
        input_hash = compute_input_hash(try_coin_ids, try_pk)
        input_hash_times_A = scalar_mult_g1(input_hash, try_pk)
        scan_scalar = int.from_bytes(bytes(scan_sk), "big")
        ecdh_point = scalar_mult_g1(scan_scalar, input_hash_times_A)
        shared_secret = hashlib.sha256(bytes(ecdh_point)).digest()

        t = derive_output_tweak(shared_secret, 0)
        candidate_pk = derive_onetime_pk_full(spend_pk, t)
        expected_ph = puzzle_hash_for_pk(candidate_pk)

        if expected_ph.hex() == coin_ph:
            tweak = t
            onetime_pk = candidate_pk
            print(f"MATCH ({mode}) -- coin belongs to you. Building spend...")
            print()
            break

    if tweak is None:
        print("NO MATCH. This coin does not belong to you.")
        sys.exit(1)

    # Derive the one-time secret key and synthetic secret key for signing
    onetime_sk = derive_onetime_sk_full(spend_sk, tweak)
    synthetic_sk = calculate_synthetic_secret_key(onetime_sk)

    # Build the coin object
    parent_id = coin_data["parent_coin_info"]
    if parent_id.startswith("0x"):
        parent_id = parent_id[2:]
    coin = Coin(
        bytes.fromhex(parent_id),
        bytes.fromhex(coin_ph),
        amount,
    )

    # Build the puzzle and solution
    onetime_puzzle = puzzle_for_pk(onetime_pk)

    # Conditions: send full amount to recipient's standard address
    conditions = [
        [51, dest_puzzle_hash, amount],  # CREATE_COIN
    ]
    # The delegated puzzle must be quoted -- (q . conditions)
    delegated_puzzle = Program.to((1, conditions))

    # Build solution manually to preserve delegated_puzzle as a tree.
    # Solution structure: (nil delegated_puzzle nil)
    # Program.to() would flatten the delegated puzzle into an atom blob.
    dp_bytes = bytes(delegated_puzzle)
    solution = Program.from_bytes_unchecked(
        b'\xff\x80\xff' + dp_bytes + b'\xff\x80\x80'
    )

    # Sign
    msg = delegated_puzzle.get_tree_hash() + coin.name() + TESTNET11_GENESIS
    sig = AugSchemeMPL.sign(synthetic_sk, msg)

    # Build spend bundle
    coin_spend = CoinSpend(coin, onetime_puzzle, solution)
    spend_bundle = SpendBundle([coin_spend], sig)

    print(f"Sending {amount} mojos to your wallet address...")

    if args.sage:
        from sage_rpc import SageRPC
        sage = SageRPC(
            url=args.sage_url,
            cert_path=args.sage_cert,
            key_path=args.sage_key,
        )
        sage.submit_transaction(spend_bundle.to_json_dict())
        print("SUCCESS! Transaction submitted via Sage.")
        print(f"Funds sent to your wallet address (spend key derivation).")
    else:
        result = subprocess.run(
            ["coinset", "-t", "-r", "push_tx", json.dumps(spend_bundle.to_json_dict())],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"coinset push_tx error: {result.stderr.strip()}")
            try:
                err = json.loads(result.stdout)
                print(f"Response: {err}")
            except Exception:
                print(f"stdout: {result.stdout}")
            sys.exit(1)

        response = json.loads(result.stdout)
        if response.get("success"):
            print("SUCCESS! Transaction submitted.")
            print(f"Funds sent to your wallet address (spend key derivation).")
        else:
            print(f"FAILED: {response}")


if __name__ == "__main__":
    main()
