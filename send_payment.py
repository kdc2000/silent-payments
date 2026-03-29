#!/usr/bin/env python3
"""
Derive the one-time address for a silent payment on Chia testnet11.

Takes the recipient's silent payment address (tspxch1...) plus the sender's
mnemonic (or Sage wallet via --sage). Uses the sender's wallet key with
input-hash-augmented ECDH to derive a unique one-time address. The recipient
detects the payment by extracting the sender's public key from the parent
coin's on-chain puzzle reveal.

Multi-input support: when --sage is used and a single coin doesn't cover the
payment amount, multiple coins are automatically selected and their synthetic
secret keys are aggregated (a_sum = a_1 + a_2 + ... + a_n). The scanner
detects these payments by summing the synthetic public keys from each coin's
puzzle reveal (multi-input scanning, Pass 2).

Usage:
    python send_payment.py <silent_payment_address> -f keyfile.txt
    python send_payment.py <silent_payment_address> [sender_mnemonic]
    python send_payment.py <silent_payment_address> --sage --amount 1000
    python send_payment.py <silent_payment_address> --sage --amount 1000 --fee 50
"""

import sys
import argparse

from chia_rs import G1Element, Coin, CoinSpend, SpendBundle, AugSchemeMPL, Program
import json
import subprocess

from shared import (
    mnemonic_to_master_sk, master_sk_to_wallet_sk,
    calculate_synthetic_secret_key,
    aggregate_sender_sks,
    compute_input_hash, compute_shared_secret_full,
    derive_output_tweak, derive_onetime_pk_full,
    puzzle_for_pk, puzzle_hash_for_pk, puzzle_hash_to_address,
    decode_silent_payment_address,
    load_mnemonic,
    compute_coin_id,
    TESTNET11_GENESIS,
)

parser = argparse.ArgumentParser(description="Derive one-time address for a silent payment")
parser.add_argument("address", help="Recipient silent payment address (tspxch1...)")
parser.add_argument("mnemonic_words", nargs="*", help="Sender mnemonic words")
parser.add_argument("-f", "--mnemonic-file", help="File containing sender mnemonic")
parser.add_argument("--sage", action="store_true", help="Use Sage wallet RPC for sender key and coins")
parser.add_argument("--sage-url", help="Sage RPC URL (default: https://127.0.0.1:9257)")
parser.add_argument("--sage-cert", help="Path to Sage TLS client certificate")
parser.add_argument("--sage-key", help="Path to Sage TLS client key")
parser.add_argument("--fingerprint", type=int, help="Sage wallet fingerprint (auto-detects if only one wallet)")
parser.add_argument("--amount", type=int, help="Amount in mojos to send (required with --sage)")
parser.add_argument("--fee", type=int, default=0, help="Transaction fee in mojos (default: 0)")


def strip_0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


def main():
    args = parser.parse_args()
    sp_address = args.address

    if args.sage:
        # --- Sage RPC flow (supports multi-input) ---
        from sage_rpc import SageRPC

        sage = SageRPC(
            url=args.sage_url,
            cert_path=args.sage_cert,
            key_path=args.sage_key,
        )

        # Get wallet keys and select fingerprint
        keys_resp = sage.get_keys()
        keys = keys_resp.get("keys", [])
        if not keys:
            print("No wallets found in Sage.", file=sys.stderr)
            sys.exit(1)

        fingerprint = args.fingerprint
        if fingerprint is None:
            if len(keys) == 1:
                fingerprint = keys[0]["fingerprint"]
            else:
                print("Multiple wallets found. Use --fingerprint to select:", file=sys.stderr)
                for k in keys:
                    print(f"  {k['fingerprint']}: {k.get('name', 'unnamed')}", file=sys.stderr)
                sys.exit(1)

        # Login and get secret key
        sage.login(fingerprint)
        secret_resp = sage.get_secret_key(fingerprint)
        mnemonic = secret_resp["secrets"]["mnemonic"]
        master_sk = mnemonic_to_master_sk(mnemonic)

        # Build derivation index -> puzzle hash lookup (try indices 0..99)
        MAX_DERIVATION = 100
        ph_to_index = {}
        for i in range(MAX_DERIVATION):
            wsk = master_sk_to_wallet_sk(master_sk, index=i)
            ph = puzzle_hash_for_pk(wsk.get_g1())
            ph_to_index[ph] = i

        # Get spendable coins (sorted by amount descending)
        coins_resp = sage.get_coins(limit=50)
        coins = coins_resp.get("coins", [])
        if not coins:
            print("No spendable coins in Sage wallet.", file=sys.stderr)
            sys.exit(1)

        # Look up full coin records for all available coins
        all_coin_infos = []
        for sage_coin in coins:
            cid_hex = strip_0x(sage_coin["coin_id"])
            result = subprocess.run(
                ["coinset", "-t", "-r", "get_coin_record_by_name",
                 "0x" + cid_hex],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                continue
            resp = json.loads(result.stdout)
            if not resp.get("success"):
                continue
            coin_data = resp["coin_record"]["coin"]
            parent = bytes.fromhex(strip_0x(coin_data["parent_coin_info"]))
            ph = bytes.fromhex(strip_0x(coin_data["puzzle_hash"]))
            amt = coin_data["amount"]
            cid = bytes.fromhex(cid_hex)
            deriv_idx = ph_to_index.get(ph)
            if deriv_idx is None:
                continue  # skip coins we can't derive keys for
            all_coin_infos.append({
                "coin_id": cid,
                "parent_coin_info": parent,
                "puzzle_hash": ph,
                "amount": amt,
                "derivation_index": deriv_idx,
            })

        if not all_coin_infos:
            print("No spendable coins with known derivation index.", file=sys.stderr)
            sys.exit(1)

        # Select coins: prefer same derivation index so the scanner's
        # puzzle-hash grouping heuristic can detect multi-input payments.
        # Try each index group (largest coins first within group), pick the
        # first group that covers the needed amount.
        needed = (args.amount or 0) + args.fee
        from collections import defaultdict
        index_groups = defaultdict(list)
        for ci in all_coin_infos:
            index_groups[ci["derivation_index"]].append(ci)

        selected = None
        for idx in sorted(index_groups.keys()):
            group = sorted(index_groups[idx], key=lambda c: c["amount"], reverse=True)
            candidate = []
            total = 0
            for ci in group:
                candidate.append(ci)
                total += ci["amount"]
                if total >= needed:
                    break
            if total >= needed:
                selected = candidate
                break

        # Fallback: if no single index group suffices, use largest coins
        # across all indices (scanner may not detect via Pass 2)
        if selected is None:
            selected = []
            total_selected = 0
            for ci in all_coin_infos:
                selected.append(ci)
                total_selected += ci["amount"]
                if total_selected >= needed:
                    break
            if needed > 0 and total_selected < needed:
                print(f"Insufficient funds: have {total_selected} mojos across "
                      f"{len(all_coin_infos)} coins, need {needed}.", file=sys.stderr)
                sys.exit(1)
            if len(set(ci["derivation_index"] for ci in selected)) > 1:
                print("Warning: coins span multiple derivation indices. "
                      "Scanner may not detect this multi-input payment.",
                      file=sys.stderr)

        # If no --amount, just use the first coin for address derivation
        if not args.amount:
            selected = [all_coin_infos[0]]

        # Derive synthetic SK for each selected coin
        sender_sks = []
        wallet_sks = []
        for ci in selected:
            wsk = master_sk_to_wallet_sk(master_sk, index=ci["derivation_index"])
            ssk = calculate_synthetic_secret_key(wsk)
            sender_sks.append(ssk)
            wallet_sks.append(wsk)

        # Aggregate keys for multi-input or use single key
        if len(sender_sks) == 1:
            sender_sk = sender_sks[0]
            sender_pk = sender_sk.get_g1()
            multi_input = False
        else:
            sender_sk = aggregate_sender_sks(sender_sks)
            sender_pk = sender_sk.get_g1()
            multi_input = True

        coin_ids = [ci["coin_id"] for ci in selected]
        sage_coins = selected
    else:
        # --- Backward-compatible mnemonic flow (single-input only) ---
        if args.mnemonic_file:
            mnemonic = load_mnemonic(["-f", args.mnemonic_file], prompt="Enter sender mnemonic: ")
        elif args.mnemonic_words:
            mnemonic = " ".join(args.mnemonic_words)
        else:
            mnemonic = load_mnemonic([], prompt="Enter sender mnemonic: ")

        master_sk = mnemonic_to_master_sk(mnemonic)
        wallet_sk = master_sk_to_wallet_sk(master_sk, index=0)
        sender_sk = calculate_synthetic_secret_key(wallet_sk)
        sender_pk = sender_sk.get_g1()

        sender_puzzle_hash = puzzle_hash_for_pk(wallet_sk.get_g1())
        result = subprocess.run(
            ["coinset", "-t", "-r", "get_coin_records_by_puzzle_hash",
             "0x" + sender_puzzle_hash.hex()],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            coin_records = json.loads(result.stdout).get("coin_records", [])
            unspent = [cr for cr in coin_records if not cr.get("spent", False)]
        else:
            unspent = []

        if len(unspent) == 1:
            cr = unspent[0]["coin"]
            parent = bytes.fromhex(strip_0x(cr["parent_coin_info"]))
            ph = bytes.fromhex(strip_0x(cr["puzzle_hash"]))
            amount = cr["amount"]
            coin_id = compute_coin_id(parent, ph, amount)
            coin_ids = [coin_id]
            print(f"Using coin: {coin_id.hex()} ({amount} mojos)", file=sys.stderr)
        elif len(unspent) > 1:
            print(f"Multiple unspent coins ({len(unspent)}) at derivation index 0.", file=sys.stderr)
            print("Use --sage for multi-input wallets.", file=sys.stderr)
            sys.exit(1)
        else:
            print("No unspent coins found at derivation index 0.", file=sys.stderr)
            print("Use --sage or fund the wallet first.", file=sys.stderr)
            sys.exit(1)

        sage_coins = None
        wallet_sks = [wallet_sk]
        sender_sks = [sender_sk]
        multi_input = False

    # Parse recipient keys from silent payment address
    scan_pk_bytes, spend_pk_bytes = decode_silent_payment_address(sp_address)
    scan_pk = G1Element.from_bytes(scan_pk_bytes)
    spend_pk = G1Element.from_bytes(spend_pk_bytes)

    # Compute one-time output
    input_hash = compute_input_hash(coin_ids, sender_pk)
    shared_secret = compute_shared_secret_full(sender_sk, scan_pk, input_hash)
    tweak = derive_output_tweak(shared_secret, 0)
    onetime_pk = derive_onetime_pk_full(spend_pk, tweak)
    onetime_puzzle_hash = puzzle_hash_for_pk(onetime_pk)
    address = puzzle_hash_to_address(onetime_puzzle_hash)

    print()
    print("=== Silent Payment Address ===")
    print(f"Send to:     {address}")
    print(f"Puzzle hash: {onetime_puzzle_hash.hex()}")
    if multi_input:
        print(f"Mode:        multi-input ({len(coin_ids)} coins)")
    print()
    if sage_coins:
        for i, ci in enumerate(sage_coins):
            print(f"  Coin {i}: {ci['coin_id'].hex()} ({ci['amount']} mojos, "
                  f"index {ci['derivation_index']})")
        print()

    if args.sage and args.amount:
        if not sage_coins:
            print("Bug: sage_coins not set in --sage path.", file=sys.stderr)
            sys.exit(1)

        payment_amount = args.amount
        fee = args.fee
        total_value = sum(ci["amount"] for ci in sage_coins)
        change_amount = total_value - payment_amount - fee

        # Build a CoinSpend + signature for each input coin
        coin_spends = []
        sigs = []

        for i, ci in enumerate(sage_coins):
            coin_obj = Coin(ci["parent_coin_info"], ci["puzzle_hash"], ci["amount"])
            coin_puzzle = puzzle_for_pk(wallet_sks[i].get_g1())

            if i == 0:
                # First coin carries the payment output and change
                conditions = [
                    [51, onetime_puzzle_hash, payment_amount],  # CREATE_COIN
                ]
                if change_amount > 0:
                    change_ph = puzzle_hash_for_pk(wallet_sks[0].get_g1())
                    conditions.append([51, change_ph, change_amount])
                if fee > 0:
                    conditions.append([52, fee])  # RESERVE_FEE
                if len(sage_coins) > 1:
                    conditions.append([60, b''])  # CREATE_COIN_ANNOUNCEMENT for binding
            else:
                # Additional coins assert the first coin's announcement
                import hashlib as _hl
                ann_id = _hl.sha256(sage_coins[0]["coin_id"] + b'').digest()
                conditions = [[61, ann_id]]  # ASSERT_COIN_ANNOUNCEMENT

            delegated_puzzle = Program.to((1, conditions))
            dp_bytes = bytes(delegated_puzzle)
            solution = Program.from_bytes_unchecked(
                b'\xff\x80\xff' + dp_bytes + b'\xff\x80\x80'
            )

            msg = delegated_puzzle.get_tree_hash() + coin_obj.name() + TESTNET11_GENESIS
            sig = AugSchemeMPL.sign(sender_sks[i], msg)

            coin_spends.append(CoinSpend(coin_obj, coin_puzzle, solution))
            sigs.append(sig)

        # Aggregate all signatures
        agg_sig = AugSchemeMPL.aggregate(sigs)
        spend_bundle = SpendBundle(coin_spends, agg_sig)

        sage.submit_transaction(spend_bundle.to_json_dict())
        print(f"Transaction submitted via Sage!")
        print(f"Sent {payment_amount} mojos to {address}")
        if multi_input:
            print(f"Inputs: {len(sage_coins)} coins (multi-input silent payment)")
        if change_amount > 0:
            print(f"Change: {change_amount} mojos returned to sender")
    elif args.sage and not args.amount:
        print("Use --amount N to submit via Sage, or send manually to the above address.")
    else:
        print("Send XCH to the above address from your wallet.")
        print("The recipient detects the payment from the on-chain puzzle reveal.")


if __name__ == "__main__":
    main()
