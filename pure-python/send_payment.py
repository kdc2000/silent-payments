#!/usr/bin/env python3
"""
Send a silent payment on Chia testnet11.

Takes the recipient's silent payment address (tspxch1...) plus the sender's
mnemonic (or Sage wallet via --sage), and derives the one-time address from
the coins that will be spent. The recipient detects the payment from the
synthetic public keys in the puzzle reveals of those coins.

The one-time address depends on the exact set of coins spent (the spend
group), so this script builds the transaction itself when --amount is given:
every silent payment output is created by a coin of the group, and when more
than one coin is needed, the coins are bound into a single cycle of
ASSERT_CONCURRENT_SPEND conditions over exactly the coins whose keys are
summed. Without --amount only the address is derived and printed; it is valid
only for a transaction that spends the listed coin, and no other coin bound
to it, and creates the output from that coin.

Usage:
    python send_payment.py <silent_payment_address> -f keyfile.txt
    python send_payment.py <silent_payment_address> [sender_mnemonic]
    python send_payment.py <silent_payment_address> -f keyfile.txt --amount 1000
    python send_payment.py <silent_payment_address> --sage --amount 1000
    python send_payment.py <silent_payment_address> --sage --amount 1000 --fee 50
"""

import sys
import argparse

from chia_rs import G1Element, PrivateKey, Coin, CoinSpend, SpendBundle, AugSchemeMPL, Program
import json
import subprocess

from shared import (
    mnemonic_to_master_sk, master_sk_to_wallet_sk,
    calculate_synthetic_secret_key,
    derive_silent_payment_outputs,
    puzzle_for_pk, puzzle_hash_for_pk, puzzle_hash_to_address,
    decode_silent_payment_address,
    load_mnemonic,
    compute_coin_id,
    TESTNET11_GENESIS,
)

# This script transacts on testnet11 only, so it accepts testnet addresses only.
NETWORK_ADDRESS_PREFIX = "tspxch"


def build_coin_spend_conditions(
    coin_index: int,
    sage_coins: list,
    primary_outputs: list,
) -> list:
    """Build the conditions list emitted by the i-th input coin.

    For coin_index == 0: ``primary_outputs`` + (if N >= 2) one opcode-64
    condition pointing at ``sage_coins[N - 1]["coin_id"]`` (closes the cycle).
    For coin_index > 0: ``[]`` + (if N >= 2) one opcode-64 condition pointing
    at ``sage_coins[coin_index - 1]["coin_id"]``.

    This is the single cycle that "Inputs for Shared Secret Derivation"
    requires of a sender: with the coins ordered c_0 ... c_{N-1}, every coin
    c_i emits exactly one ASSERT_CONCURRENT_SPEND naming c_{(i-1) mod N}. It
    is the same pattern chia-wallet-sdk emits for ordinary multi-coin spends.
    ``sage_coins`` must be exactly the coins whose keys are summed.

    This helper is intentionally pure (no I/O, no subprocess) so the
    emission can be unit-tested without mocking Sage RPC; see
    tests/test_send_payment.py.
    """
    N = len(sage_coins)
    conditions = list(primary_outputs) if coin_index == 0 else []
    if N >= 2:
        if coin_index == 0:
            prev_coin_id = sage_coins[N - 1]["coin_id"]
        else:
            prev_coin_id = sage_coins[coin_index - 1]["coin_id"]
        conditions.append([64, prev_coin_id])  # ASSERT_CONCURRENT_SPEND
    return conditions


def build_silent_payment_spend(
    coins: list[dict],
    wallet_sks: list[PrivateKey],
    recipients: list[tuple[G1Element, G1Element, int]],
    change_puzzle_hash: bytes,
    fee: int = 0,
    agg_sig_data: bytes = TESTNET11_GENESIS,
) -> tuple[SpendBundle, list[dict]]:
    """Build a complete silent payment transaction from exactly `coins`.

    Args:
        coins: The coins to spend; together they are the spend group. Each is
            a dict with coin_id, parent_coin_info, puzzle_hash (bytes) and
            amount. Every coin must be a standard-puzzle coin of `wallet_sks`.
        wallet_sks: The wallet secret key of each coin, in the same order.
        recipients: (B_scan, B_m, amount) per output, as decoded from the
            recipients' addresses.
        change_puzzle_hash: Where the remainder goes, if there is one.
        fee: Transaction fee in mojos.
        agg_sig_data: AGG_SIG_ME additional data of the network.

    Returns (spend_bundle, outputs), outputs being the result of
    shared.derive_silent_payment_outputs in recipient order.

    The outputs are derived here, from the final set of coins, so they can
    never be stale. All of them are created by coin 0 of the group, and the
    conditions of every coin are a quoted list signed by that coin's key.
    Pure function: nothing is fetched or submitted.
    """
    if len(coins) != len(wallet_sks):
        raise ValueError("need one wallet key per coin")
    for ci, wallet_sk in zip(coins, wallet_sks):
        if compute_coin_id(ci["parent_coin_info"], ci["puzzle_hash"], ci["amount"]) != ci["coin_id"]:
            raise ValueError("coin ID does not match the coin")
        # Only standard-puzzle coins that we hold the key of can be in a spend group.
        if puzzle_hash_for_pk(wallet_sk.get_g1()) != ci["puzzle_hash"]:
            raise ValueError(f"coin {ci['coin_id'].hex()} is not a standard-puzzle coin of the given key")

    payment_total = sum(amount for _, _, amount in recipients)
    total_value = sum(ci["amount"] for ci in coins)
    change_amount = total_value - payment_total - fee
    if change_amount < 0:
        raise ValueError(
            f"Insufficient funds: have {total_value} mojos, need {payment_total + fee}."
        )

    # One synthetic secret key and one coin ID per coin of the spend group.
    sender_sks = [calculate_synthetic_secret_key(wsk) for wsk in wallet_sks]
    coin_ids = [ci["coin_id"] for ci in coins]
    outputs = derive_silent_payment_outputs(
        sender_sks, coin_ids, [(scan_pk, spend_pk) for scan_pk, spend_pk, _ in recipients]
    )

    # Coin 0 carries every CREATE_COIN (all derived outputs, then change) and the fee.
    primary_outputs = [
        [51, o["puzzle_hash"], amount]  # CREATE_COIN
        for o, (_, _, amount) in zip(outputs, recipients)
    ]
    if change_amount > 0:
        primary_outputs.append([51, change_puzzle_hash, change_amount])
    if fee > 0:
        primary_outputs.append([52, fee])  # RESERVE_FEE

    coin_spends = []
    sigs = []
    for i, ci in enumerate(coins):
        coin_obj = Coin(ci["parent_coin_info"], ci["puzzle_hash"], ci["amount"])
        coin_puzzle = puzzle_for_pk(wallet_sks[i].get_g1())

        conditions = build_coin_spend_conditions(i, coins, primary_outputs)

        delegated_puzzle = Program.to((1, conditions))
        dp_bytes = bytes(delegated_puzzle)
        solution = Program.from_bytes_unchecked(
            b'\xff\x80\xff' + dp_bytes + b'\xff\x80\x80'
        )

        msg = delegated_puzzle.get_tree_hash() + coin_obj.name() + agg_sig_data
        sig = AugSchemeMPL.sign(sender_sks[i], msg)

        coin_spends.append(CoinSpend(coin_obj, coin_puzzle, solution))
        sigs.append(sig)

    return SpendBundle(coin_spends, AugSchemeMPL.aggregate(sigs)), outputs


parser = argparse.ArgumentParser(description="Send a silent payment (or derive its one-time address)")
parser.add_argument("address", help="Recipient silent payment address (tspxch1...)")
parser.add_argument("mnemonic_words", nargs="*", help="Sender mnemonic words")
parser.add_argument("-f", "--mnemonic-file", help="File containing sender mnemonic")
parser.add_argument("--sage", action="store_true", help="Use Sage wallet RPC for sender key and coins")
parser.add_argument("--sage-url", help="Sage RPC URL (default: https://127.0.0.1:9257)")
parser.add_argument("--sage-cert", help="Path to Sage TLS client certificate")
parser.add_argument("--sage-key", help="Path to Sage TLS client key")
parser.add_argument("--fingerprint", type=int, help="Sage wallet fingerprint (auto-detects if only one wallet)")
parser.add_argument("--amount", type=int, help="Amount in mojos to send; builds and submits the transaction")
parser.add_argument("--fee", type=int, default=0, help="Transaction fee in mojos (default: 0)")


def strip_0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


def main():
    args = parser.parse_args()

    # Parse and validate the recipient's keys before touching the wallet.
    try:
        scan_pk_bytes, spend_pk_bytes = decode_silent_payment_address(
            args.address, expected_prefix=NETWORK_ADDRESS_PREFIX
        )
    except ValueError as e:
        print(f"Invalid silent payment address: {e}", file=sys.stderr)
        sys.exit(1)
    scan_pk = G1Element.from_bytes(scan_pk_bytes)
    spend_pk = G1Element.from_bytes(spend_pk_bytes)

    sage = None
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

        # Select coins, largest first, until the amount and fee are covered.
        # The coins may sit at different derivation indices: the scanner
        # groups them by their ASSERT_CONCURRENT_SPEND cycle, not by key.
        # If no --amount, just use the first coin for address derivation.
        needed = (args.amount or 0) + args.fee
        selected = []
        total_selected = 0
        for ci in all_coin_infos:
            selected.append(ci)
            total_selected += ci["amount"]
            if not args.amount or total_selected >= needed:
                break
        if args.amount and total_selected < needed:
            print(f"Insufficient funds: have {total_selected} mojos across "
                  f"{len(all_coin_infos)} coins, need {needed}.", file=sys.stderr)
            sys.exit(1)
    else:
        # --- Mnemonic flow (single-input only) ---
        if args.mnemonic_file:
            mnemonic = load_mnemonic(["-f", args.mnemonic_file], prompt="Enter sender mnemonic: ")
        elif args.mnemonic_words:
            mnemonic = " ".join(args.mnemonic_words)
        else:
            mnemonic = load_mnemonic([], prompt="Enter sender mnemonic: ")

        master_sk = mnemonic_to_master_sk(mnemonic)
        wallet_sk = master_sk_to_wallet_sk(master_sk, index=0)

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
            print(f"Using coin: {coin_id.hex()} ({amount} mojos)", file=sys.stderr)
        elif len(unspent) > 1:
            print(f"Multiple unspent coins ({len(unspent)}) at derivation index 0.", file=sys.stderr)
            print("Use --sage for multi-input wallets.", file=sys.stderr)
            sys.exit(1)
        else:
            print("No unspent coins found at derivation index 0.", file=sys.stderr)
            print("Use --sage or fund the wallet first.", file=sys.stderr)
            sys.exit(1)

        selected = [{
            "coin_id": coin_id,
            "parent_coin_info": parent,
            "puzzle_hash": ph,
            "amount": amount,
            "derivation_index": 0,
        }]

    # The spend group is exactly `selected`: one key and one coin ID per coin.
    wallet_sks = [
        master_sk_to_wallet_sk(master_sk, index=ci["derivation_index"]) for ci in selected
    ]
    multi_input = len(selected) > 1
    change_ph = puzzle_hash_for_pk(wallet_sks[0].get_g1())

    try:
        if args.amount:
            spend_bundle, outputs = build_silent_payment_spend(
                selected, wallet_sks, [(scan_pk, spend_pk, args.amount)],
                change_ph, fee=args.fee,
            )
        else:
            spend_bundle = None
            outputs = derive_silent_payment_outputs(
                [calculate_synthetic_secret_key(wsk) for wsk in wallet_sks],
                [ci["coin_id"] for ci in selected],
                [(scan_pk, spend_pk)],
            )
    except ValueError as e:
        print(f"Cannot build the silent payment: {e}", file=sys.stderr)
        sys.exit(1)

    onetime_puzzle_hash = outputs[0]["puzzle_hash"]
    address = puzzle_hash_to_address(onetime_puzzle_hash)

    print()
    print("=== Silent Payment Address ===")
    print(f"Send to:     {address}")
    print(f"Puzzle hash: {onetime_puzzle_hash.hex()}")
    if multi_input:
        print(f"Mode:        multi-input ({len(selected)} coins)")
    print()
    for i, ci in enumerate(selected):
        print(f"  Coin {i}: {ci['coin_id'].hex()} ({ci['amount']} mojos, "
              f"index {ci['derivation_index']})")
    print()

    if spend_bundle is None:
        print("This address is valid ONLY for a transaction that spends the coin")
        print("above, bound to no other coin, and creates the payment from it.")
        print("Use --amount N to let this script build and submit that transaction.")
        return

    payment_amount = args.amount
    change_amount = sum(ci["amount"] for ci in selected) - payment_amount - args.fee

    if sage is not None:
        sage.submit_transaction(spend_bundle.to_json_dict())
        print("Transaction submitted via Sage!")
    else:
        result = subprocess.run(
            ["coinset", "-t", "-r", "push_tx", json.dumps(spend_bundle.to_json_dict())],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"coinset push_tx error: {result.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
        response = json.loads(result.stdout)
        if not response.get("success"):
            print(f"FAILED: {response}", file=sys.stderr)
            sys.exit(1)
        print("Transaction submitted!")
    print(f"Sent {payment_amount} mojos to {address}")
    if multi_input:
        print(f"Inputs: {len(selected)} coins (multi-input silent payment)")
    if change_amount > 0:
        print(f"Change: {change_amount} mojos returned to sender")


if __name__ == "__main__":
    main()
