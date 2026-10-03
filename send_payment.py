#!/usr/bin/env python3
"""
Derive the one-time address for a silent payment on Chia testnet11.

Takes the recipient's silent payment address (tspxch1...) plus the sender's
mnemonic (or Sage wallet via --sage). The send bundle is built ENTIRELY through
``sdk_adapter`` (the sole ``chia_wallet_sdk`` importer): the SDK derives the
one-time puzzle hash via input-hash-augmented ECDH, emits the CREATE_COIN /
change / fee, and (for N>=2 inputs) the cyclic ASSERT_CONCURRENT_SPEND binding.
The recipient detects the payment by extracting the sender's public key from the
parent coin's on-chain puzzle reveal.

Multi-input support: when --sage is used and a single coin doesn't cover the
payment amount plus fee, the largest coins are selected until it is covered
(``select_coins``). The coins may sit at different wallet derivation indices: the
SDK aggregates the synthetic secret keys internally for the ECDH and binds all
inputs with the cyclic opcode-64 ASSERT_CONCURRENT_SPEND condition, which is what
a scanner groups on (CHIP-0057 "Scanning a Block", Pass 2).

Broadcast: the built wire dict is pushed via ``coinset push_tx`` by default, or
via the Sage RPC (``--sage``). Both consume the SAME wire dict (the adapter's
``sdk_bundle_to_wire_dict`` output). On-chain confirmation is verified manually
(your own mnemonic + live testnet11).

Usage:
    python send_payment.py <silent_payment_address> -f keyfile.txt
    python send_payment.py <silent_payment_address> [sender_mnemonic]
    python send_payment.py <silent_payment_address> --sage --amount 1000
    python send_payment.py <silent_payment_address> --sage --amount 1000 --fee 50
"""

import sys
import argparse

import sdk_adapter
import coinset

from shared import (
    puzzle_hash_to_address,
    load_mnemonic,
    compute_coin_id,
)


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

    The cyclic ASSERT_CONCURRENT_SPEND pattern matches Sage's
    chia-wallet-sdk ``Relation::AssertConcurrent`` byte-for-byte: for N input
    coins, every coin emits exactly one ``[64, predecessor_coin_id]`` with
    coin 0 wrapping to coin N-1. See CHIP-0057 "Scanning a Block" (Pass 2 groups
    the spends of such a cycle).

    This helper is intentionally pure (no I/O, no subprocess) so the emission can
    be unit-tested without mocking Sage RPC. The SDK owns this binding on the live
    build path (``sdk_adapter.build_silent_payment_send`` ->
    ``Relation.AssertConcurrent``); this helper is retained as a topology
    reference the scanner round-trip tests pin against.
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


def select_coins(coin_infos: list, needed: int):
    """Pick the coins to spend: largest first, until ``needed`` mojos are covered.

    ``coin_infos`` is a list of dicts with at least ``amount`` (int) and
    ``coin_id`` (bytes). The order is deterministic: by amount, largest first, and
    by coin ID (ascending) among coins of equal amount. Returns the selected
    coins in that order, or ``None`` if all coins together do not cover
    ``needed``. With ``needed == 0`` the single largest coin is returned.

    The selection ignores wallet derivation indices. A scanner groups the inputs
    of a multi-input payment by their ASSERT_CONCURRENT_SPEND cycle (CHIP-0057
    "Scanning a Block", Pass 2), which the SDK emits for any set of two or more
    coins, so coins at different indices are detected like coins at one index.
    """
    ordered = sorted(coin_infos, key=lambda ci: (-ci["amount"], ci["coin_id"]))
    selected = []
    total = 0
    for ci in ordered:
        selected.append(ci)
        total += ci["amount"]
        if total >= needed:
            return selected
    return None


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

    # Validate the recipient address before any wallet or chain lookup. The SDK
    # decoder enforces the CHIP-0057 format (version, payload length, both keys
    # valid non-identity G1 points); this script transacts on testnet11 only, so a
    # mainnet (spxch) address is rejected as well.
    try:
        is_testnet = sdk_adapter.silent_payment_address_is_testnet(sp_address)
    except ValueError as exc:
        print(f"Invalid silent payment address: {exc}", file=sys.stderr)
        sys.exit(1)
    if not is_testnet:
        print(
            "This script sends on testnet11: expected a tspxch1... address, "
            "got a mainnet (spxch1...) address.",
            file=sys.stderr,
        )
        sys.exit(1)

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

        # Build derivation index -> puzzle hash lookup (try indices 0..99).
        # The wallet-key derivation routes through the adapter so the script
        # stays SDK-free and carries no send-crypto.
        MAX_DERIVATION = 100
        ph_to_index = {}
        for i in range(MAX_DERIVATION):
            ph = sdk_adapter.wallet_puzzle_hash(mnemonic, i)
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
            rec = coinset.get_coin_record(cid_hex, optional=True)
            if rec is None:
                continue
            coin_data = rec["coin"]
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

        # Select coins: largest first until the amount plus fee is covered. The
        # derivation index plays no part: the SDK binds any set of two or more
        # inputs with the ASSERT_CONCURRENT_SPEND cycle the scanner groups on.
        needed = (args.amount or 0) + args.fee
        selected = select_coins(all_coin_infos, needed)
        if selected is None:
            total_available = sum(ci["amount"] for ci in all_coin_infos)
            print(f"Insufficient funds: have {total_available} mojos across "
                  f"{len(all_coin_infos)} coins, need {needed}.", file=sys.stderr)
            sys.exit(1)

        # If no --amount, just use the first coin for address derivation
        if not args.amount:
            selected = [all_coin_infos[0]]

        sage_coins = selected
        multi_input = len(selected) > 1
    else:
        # --- Backward-compatible mnemonic flow (single-input only) ---
        if args.mnemonic_file:
            mnemonic = load_mnemonic(["-f", args.mnemonic_file], prompt="Enter sender mnemonic: ")
        elif args.mnemonic_words:
            mnemonic = " ".join(args.mnemonic_words)
        else:
            mnemonic = load_mnemonic([], prompt="Enter sender mnemonic: ")

        # Index-0 wallet puzzle hash (via the adapter, no send-crypto in-script).
        sender_puzzle_hash = sdk_adapter.wallet_puzzle_hash(mnemonic, 0)
        recs = coinset.get_coin_records_by_puzzle_hash(
            "0x" + sender_puzzle_hash.hex(), optional=True
        ) or []
        unspent = [cr for cr in recs if not cr.get("spent", False)]

        if len(unspent) == 1:
            cr = unspent[0]["coin"]
            parent = bytes.fromhex(strip_0x(cr["parent_coin_info"]))
            ph = bytes.fromhex(strip_0x(cr["puzzle_hash"]))
            amount = cr["amount"]
            coin_id = compute_coin_id(parent, ph, amount)
            print(f"Using coin: {coin_id.hex()} ({amount} mojos)", file=sys.stderr)
            selected = [{
                "coin_id": coin_id,
                "parent_coin_info": parent,
                "puzzle_hash": ph,
                "amount": amount,
                "derivation_index": 0,
            }]
        elif len(unspent) > 1:
            print(f"Multiple unspent coins ({len(unspent)}) at derivation index 0.", file=sys.stderr)
            print("Use --sage for multi-input wallets.", file=sys.stderr)
            sys.exit(1)
        else:
            print("No unspent coins found at derivation index 0.", file=sys.stderr)
            print("Use --sage or fund the wallet first.", file=sys.stderr)
            sys.exit(1)

        sage_coins = selected
        multi_input = False

    coin_ids = [ci["coin_id"] for ci in selected]

    print()
    print("=== Silent Payment ===")

    # --sage requires --amount to broadcast; the mnemonic flow always resolved a
    # single coin above and broadcasts via coinset.push_tx.
    if args.sage and not args.amount:
        print(f"Selected coin: {selected[0]['coin_id'].hex()} "
              f"({selected[0]['amount']} mojos, index {selected[0]['derivation_index']})")
        print()
        print("Use --amount N to submit via Sage, or send manually to the recipient address.")
        return

    # Resolve the send amount + fee and the insufficient-funds CHECK (the SDK
    # owns the actual change arithmetic; this is the display + guard only).
    payment_amount = args.amount if args.amount else selected[0]["amount"] - args.fee
    fee = args.fee
    total_value = sum(ci["amount"] for ci in selected)
    change_amount = total_value - payment_amount - fee
    if change_amount < 0:
        print(f"Insufficient funds: have {total_value} mojos, "
              f"need {payment_amount + fee}.", file=sys.stderr)
        sys.exit(1)

    # Build per-input keys + the send bundle via the adapter (SDK owns ECDH /
    # CREATE_COIN / change / fee / cyclic opcode-64 binding).
    inputs = []
    synthetic_secret_keys = []
    for ci in selected:
        wallet_pk, wallet_sk, synthetic_sk = sdk_adapter.wallet_keys(
            mnemonic, ci["derivation_index"]
        )
        inputs.append({
            "parent_coin_info": ci["parent_coin_info"],
            "puzzle_hash": ci["puzzle_hash"],
            "amount": ci["amount"],
            "wallet_pk": wallet_pk,
            "wallet_sk": wallet_sk,
        })
        synthetic_secret_keys.append(synthetic_sk)

    change_ph = sdk_adapter.default_change_puzzle_hash(mnemonic)
    coin_spends = sdk_adapter.build_silent_payment_send(
        sp_address, inputs, change_ph, payment_amount, fee
    )

    # Recover the recipient one-time puzzle hash from the built CREATE_COIN for
    # display — exactly what lands on-chain.
    onetime_puzzle_hash = sdk_adapter.recipient_one_time_puzzle_hash(coin_spends, change_ph)
    address = puzzle_hash_to_address(onetime_puzzle_hash)

    print(f"Send to:     {address}")
    print(f"Puzzle hash: {onetime_puzzle_hash.hex()}")
    if multi_input:
        print(f"Mode:        multi-input ({len(coin_ids)} coins)")
    print()
    for i, ci in enumerate(sage_coins):
        print(f"  Coin {i}: {ci['coin_id'].hex()} ({ci['amount']} mojos, "
              f"index {ci['derivation_index']})")
    print()

    # Sign + broadcast the SAME wire dict via coinset.push_tx (default) or Sage.
    bundle = sdk_adapter.build_signed_spend_bundle(coin_spends, synthetic_secret_keys)
    wire = sdk_adapter.sdk_bundle_to_wire_dict(bundle)
    if args.sage:
        sage.submit_transaction(wire)
        via = "Sage"
    else:
        # coinset.push_tx returns the node's JSON body on a zero exit; a REJECTED
        # bundle comes back as {"success": false, "error": ...} (the node still
        # exits 0). Do NOT report success blindly — surface the node's error, or a
        # bad bundle is "submitted" yet never block-included.
        resp = coinset.push_tx(wire)
        if isinstance(resp, dict) and resp.get("success") is False:
            err = resp.get("error") or resp.get("structuredError") or resp
            print(f"coinset push_tx REJECTED the transaction: {err}", file=sys.stderr)
            sys.exit(1)
        via = "coinset push_tx"

    print(f"Transaction submitted via {via}!")
    print(f"Sent {payment_amount} mojos to {address}")
    if multi_input:
        print(f"Inputs: {len(sage_coins)} coins (multi-input silent payment)")
    if change_amount > 0:
        print(f"Change: {change_amount} mojos returned to sender")


if __name__ == "__main__":
    main()
