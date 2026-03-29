#!/usr/bin/env python3
"""
Check if a coin belongs to a silent payment recipient.

Given the recipient's mnemonic and a coin ID, this program:
1. Looks up the coin on-chain via coinset
2. Extracts the sender's synthetic public key from the parent coin's puzzle
3. Performs scanner-side ECDH: b_scan * (input_hash * A)
4. Derives the expected one-time puzzle hash using spend key separation
5. Compares it to the coin's actual puzzle hash

If they match, the coin belongs to the recipient and can be spent with
the derived one-time secret key.

Usage:
    python scan_coin.py <coin_id_hex> -f keyfile.txt
    python scan_coin.py <coin_id_hex> [recipient_mnemonic]
"""

import sys
import json
import hashlib
import argparse
import subprocess

from chia_rs import G1Element, Program
from shared import (
    mnemonic_to_master_sk, master_sk_to_scan_sk, master_sk_to_spend_sk,
    compute_input_hash, derive_output_tweak,
    derive_onetime_pk_full, derive_onetime_sk_full,
    puzzle_hash_for_pk, calculate_synthetic_secret_key,
    extract_synthetic_pk, scalar_mult_g1,
    load_mnemonic,
)

parser = argparse.ArgumentParser(description="Check if a coin belongs to a silent payment recipient")
parser.add_argument("coin_id", help="Coin ID hex to check")
parser.add_argument("mnemonic_words", nargs="*", help="Recipient mnemonic words")
parser.add_argument("-f", "--mnemonic-file", help="File containing recipient mnemonic")


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
    """Extract the sender's synthetic PK from the parent coin's puzzle reveal."""
    parent_id = coin_record["coin"]["parent_coin_info"]
    if parent_id.startswith("0x"):
        parent_id = parent_id[2:]

    parent_record = get_coin_record(parent_id)
    if not parent_record.get("spent"):
        raise RuntimeError("Parent coin is not spent — cannot extract puzzle")

    parent_spend = get_puzzle_and_solution(parent_id)

    puzzle = Program.from_bytes(bytes.fromhex(parent_spend["puzzle_reveal"][2:]))
    return extract_synthetic_pk(puzzle)


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

    print(f"Scan pubkey:  {bytes(scan_pk).hex()}")
    print(f"Spend pubkey: {bytes(spend_pk).hex()}")
    print(f"Checking coin: {coin_id}")
    print()

    # Look up the coin
    coin_record = get_coin_record(coin_id)
    coin_ph = coin_record["coin"]["puzzle_hash"]
    if coin_ph.startswith("0x"):
        coin_ph = coin_ph[2:]

    print(f"Coin puzzle hash: {coin_ph}")
    print(f"Coin amount:      {coin_record['coin']['amount']} mojos")
    print()

    # Extract sender's synthetic public key from the parent coin's puzzle
    print("Extracting sender synthetic public key from parent puzzle...")
    sender_synthetic_pk = extract_sender_synthetic_pk(coin_record)

    if sender_synthetic_pk is None:
        print("Could not extract synthetic public key. Parent coin may not use a standard puzzle.")
        sys.exit(1)

    print(f"Sender synthetic pk: {bytes(sender_synthetic_pk).hex()}")

    # Scanner-side ECDH: b_scan * (input_hash * A)
    # Use the PARENT coin's ID as the coin_ids list for input_hash,
    # because the sender used their spent coin's ID (the parent) when
    # computing the ECDH. The output coin didn't exist yet at send time.
    parent_id = coin_record["coin"]["parent_coin_info"]
    if parent_id.startswith("0x"):
        parent_id = parent_id[2:]
    coin_ids = [bytes.fromhex(parent_id)]
    input_hash = compute_input_hash(coin_ids, sender_synthetic_pk)

    input_hash_times_A = scalar_mult_g1(input_hash, sender_synthetic_pk)
    scan_scalar = int.from_bytes(bytes(scan_sk), "big")
    ecdh_point = scalar_mult_g1(scan_scalar, input_hash_times_A)
    shared_secret = hashlib.sha256(bytes(ecdh_point)).digest()

    tweak = derive_output_tweak(shared_secret, 0)
    onetime_pk = derive_onetime_pk_full(spend_pk, tweak)
    expected_ph = puzzle_hash_for_pk(onetime_pk)

    print(f"Expected PH:         {expected_ph.hex()}")
    print()

    if expected_ph.hex() == coin_ph:
        print("MATCH! This coin belongs to you.")
        print()

        # Derive the one-time secret key for spending (uses spend key)
        onetime_sk = derive_onetime_sk_full(spend_sk, tweak)
        synthetic_sk = calculate_synthetic_secret_key(onetime_sk)
        print(f"One-time secret key (for spending): {bytes(onetime_sk).hex()}")
        print(f"One-time public key:                {bytes(onetime_pk).hex()}")
        print(f"Synthetic secret key:               {bytes(synthetic_sk).hex()}")
    else:
        print("NO MATCH. This coin does not belong to you.")


if __name__ == "__main__":
    main()
