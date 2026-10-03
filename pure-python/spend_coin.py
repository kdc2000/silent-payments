#!/usr/bin/env python3
"""
Spend a silent payment coin back to the recipient's standard wallet address.

Takes the coin ID and the recipient's mnemonic. The coin is detected with
the scan key and spend public key, exactly as scanner.py does it, which
yields the coin's spend tweak. The one-time secret key is then derived from
the spend secret key and that tweak — the only step that needs the spend
secret key — and used to sign a spend bundle that sends the full amount to
the recipient's standard wallet address (m/12381/8444/2/0).

A spend tweak reported by a watch-only scanner (scanner.py, scan_coin.py)
can be passed with --tweak; the scan is then skipped.

Usage:
    python spend_coin.py <coin_id_hex> -f keyfile.txt
    python spend_coin.py <coin_id_hex> [recipient_mnemonic]
    python spend_coin.py <coin_id_hex> -f keyfile.txt --labels 1,2,3
    python spend_coin.py <coin_id_hex> -f keyfile.txt --tweak <hex>
    python spend_coin.py <coin_id_hex> --sage
"""

import sys
import json
import argparse
import subprocess

from chia_rs import (
    PrivateKey, Program, Coin, CoinSpend, SpendBundle, AugSchemeMPL,
)
from shared import (
    mnemonic_to_master_sk, master_sk_to_scan_sk, master_sk_to_spend_sk,
    master_sk_to_wallet_sk,
    derive_onetime_sk_full,
    puzzle_for_pk, puzzle_hash_for_pk, puzzle_hash_to_address,
    calculate_synthetic_secret_key,
    build_label_map,
    GROUP_ORDER,
    TESTNET11_GENESIS,
    load_mnemonic,
)
from scanner import coinset_json, detect_coin, parse_label_indices, strip_0x

parser = argparse.ArgumentParser(description="Spend a silent payment coin")
parser.add_argument("coin_id", help="Coin ID hex to spend")
parser.add_argument("mnemonic_words", nargs="*", help="Recipient mnemonic words")
parser.add_argument("-f", "--mnemonic-file", help="File containing recipient mnemonic")
parser.add_argument("--labels", help="Comma-separated label indices to check (e.g., 1,2,3). "
                                     "The change label 0 is always checked.")
parser.add_argument("--tweak", help="Spend tweak hex reported by a scanner; skips the scan")
parser.add_argument("--sage", action="store_true", help="Submit transaction via Sage RPC")
parser.add_argument("--sage-url", help="Sage RPC URL (default: https://127.0.0.1:9257)")
parser.add_argument("--sage-cert", help="Path to Sage TLS client certificate")
parser.add_argument("--sage-key", help="Path to Sage TLS client key")


def build_spend_bundle(
    coin: Coin,
    onetime_sk: PrivateKey,
    dest_puzzle_hash: bytes,
    agg_sig_data: bytes = TESTNET11_GENESIS,
) -> SpendBundle:
    """Spend a silent payment coin with its one-time key ("Spending").

    Sends the full amount to `dest_puzzle_hash`. The coin is locked to the
    standard puzzle of the one-time public key, so the signature is made
    with the synthetic secret key of the one-time key. Raises ValueError if
    `onetime_sk` is not the key of this coin. Pure function.
    """
    onetime_pk = onetime_sk.get_g1()
    if puzzle_hash_for_pk(onetime_pk) != bytes(coin.puzzle_hash):
        raise ValueError("one-time key does not match the coin's puzzle hash")
    synthetic_sk = calculate_synthetic_secret_key(onetime_sk)

    # Conditions: send full amount to the destination
    conditions = [
        [51, dest_puzzle_hash, coin.amount],  # CREATE_COIN
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
    msg = delegated_puzzle.get_tree_hash() + coin.name() + agg_sig_data
    sig = AugSchemeMPL.sign(synthetic_sk, msg)

    coin_spend = CoinSpend(coin, puzzle_for_pk(onetime_pk), solution)
    return SpendBundle([coin_spend], sig)


def main():
    args = parser.parse_args()
    coin_id = strip_0x(args.coin_id)

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

    # Destination: the recipient's standard wallet address. (A coin at the
    # standard puzzle of B_spend itself would be visible to anyone who knows
    # the silent payment address.)
    dest_puzzle_hash = puzzle_hash_for_pk(master_sk_to_wallet_sk(master_sk, 0).get_g1())
    dest_address = puzzle_hash_to_address(dest_puzzle_hash)

    print(f"Scan pubkey:  {bytes(scan_pk).hex()}")
    print(f"Spend pubkey: {bytes(spend_pk).hex()}")
    print(f"Destination:  {dest_address}")
    print(f"Checking coin:  {coin_id}")
    print()

    if args.tweak:
        # Spend tweak supplied by a scanner: look up the coin only
        result = coinset_json("get_coin_record_by_name", "0x" + coin_id)
        if not result.get("success"):
            raise RuntimeError(f"Could not find coin: {result}")
        coin_record = result["coin_record"]
        spend_tweak = int(strip_0x(args.tweak), 16)
        if not 0 <= spend_tweak < GROUP_ORDER:
            print("ERROR: --tweak is not a scalar below the group order.")
            sys.exit(1)
    else:
        # Detect the coin with the scan key and the spend public key
        label_map = build_label_map(scan_sk, parse_label_indices(args.labels))
        coin_record, detection = detect_coin(coin_id, scan_sk, spend_pk, label_map)
        if detection is None:
            print("NO MATCH. This coin does not belong to you.")
            sys.exit(1)
        spend_tweak = int(detection["spend_tweak"], 16)
        mode = "single-input" if detection["inputs"] == 1 else f"multi-input ({detection['inputs']} coins)"
        print(f"MATCH ({mode}) -- coin belongs to you. Building spend...")
        print()

    coin_data = coin_record["coin"]
    amount = coin_data["amount"]

    if coin_record.get("spent"):
        print("ERROR: This coin has already been spent.")
        sys.exit(1)

    print(f"Coin puzzle hash: {strip_0x(coin_data['puzzle_hash'])}")
    print(f"Coin amount:      {amount} mojos")
    print()

    coin = Coin(
        bytes.fromhex(strip_0x(coin_data["parent_coin_info"])),
        bytes.fromhex(strip_0x(coin_data["puzzle_hash"])),
        amount,
    )

    # The one step that needs the spend secret key: one-time key from
    # b_spend and the spend tweak.
    onetime_sk = derive_onetime_sk_full(spend_sk, spend_tweak)
    try:
        spend_bundle = build_spend_bundle(coin, onetime_sk, dest_puzzle_hash)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

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
        print(f"Funds sent to {dest_address}.")
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
            print(f"Funds sent to {dest_address}.")
        else:
            print(f"FAILED: {response}")


if __name__ == "__main__":
    main()
