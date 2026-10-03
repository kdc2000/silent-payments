#!/usr/bin/env python3
"""
Spend a detected silent payment coin back to the recipient's STANDARD wallet.

Given the recipient's mnemonic and a coin ID, this program:
1. Looks up the coin on-chain via coinset and guards that it is UNSPENT.
2. Detects the coin through the SDK single-input block path — exactly the
   scan_coin.py flow: marshal the SPENT (parent) coin as the lone CoinSpend and
   the target coin as an addition (preserving the parent-coin input-hash
   asymmetry), then run sdk_adapter.tweak_data_from_block_spends +
   scan_from_tweaks (scan secret key + spend PUBLIC key). The SDK owns the
   synthetic-pk extraction and the ECDH, returning a DetectedSpCoin that carries
   the output index k, the label and the tweak ((t_k + label_scalar) mod r).
3. Derives the one-time secret key EXPLICITLY from that tweak and the spend
   secret key (sdk_adapter.derive_onetime_sk) — the only step that needs the
   spend secret key.
4. Builds the spend via the sdk_adapter standard-spend helper to the recipient's
   STANDARD wallet address m/12381/8444/2/0 (the adapter standard-wallet
   puzzle-hash deriver at index 0) — the SDK curries the SYNTHETIC of the
   one-time sk and emits a single full-amount CREATE_COIN (fee=0).
5. Signs via sdk_adapter.build_signed_spend_bundle([onetime_sk.derive_synthetic()]),
   bridges via sdk_bundle_to_wire_dict, and broadcasts via the coinset push path
   (default) or Sage (--sage), surfacing a node success:false response (a
   rejected bundle is "submitted" yet never block-included).

This script is single-input-only BY DESIGN: it feeds a one-element block (the
SPENT parent CoinSpend + the target coin) with the NON-aggregated sender key, so
it CANNOT detect a multi-input-only coin — that is scanner.py's domain (out of
scope here).

Keys come from the mnemonic with the hardened derivation CHIP-0057 requires.
--legacy-keys switches to the unhardened derivation and applies ONLY to a coin paid
to an address generated before the CHIP's hardened-derivation revision; it must
never be used for a new address.

Usage:
    python spend_coin.py <coin_id_hex> -f keyfile.txt
    python spend_coin.py <coin_id_hex> [recipient_mnemonic]
    python spend_coin.py <coin_id_hex> --sage
    python spend_coin.py <coin_id_hex> -f keyfile.txt --legacy-keys
"""

import sys
import argparse

import shared
from shared import load_mnemonic

import sdk_adapter
import coinset

parser = argparse.ArgumentParser(description="Spend a silent payment coin")
parser.add_argument("coin_id", help="Coin ID hex to spend")
parser.add_argument("mnemonic_words", nargs="*", help="Recipient mnemonic words")
parser.add_argument("-f", "--mnemonic-file", help="File containing recipient mnemonic")
parser.add_argument(
    "--legacy-keys",
    action="store_true",
    help="Derive the recipient keys with the UNHARDENED paths "
    "(m/12381/8444/12/0, m/12381/8444/13/0). Only for coins paid to an address "
    "generated before CHIP-0057 required hardened derivation; never use it for "
    "a new address",
)
parser.add_argument("--sage", action="store_true", help="Submit transaction via Sage RPC")
parser.add_argument("--sage-url", help="Sage RPC URL (default: https://127.0.0.1:9257)")
parser.add_argument("--sage-cert", help="Path to Sage TLS client certificate")
parser.add_argument("--sage-key", help="Path to Sage TLS client key")


def _strip(h: str) -> str:
    """Strip a leading ``0x`` from a coinset hex field."""
    return h[2:] if h.startswith("0x") else h


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

    # Derive recipient scan and spend keys via the adapter (no direct SDK import,
    # no shared scan-crypto — all BLS math stays on the SDK side of the FFI).
    if args.legacy_keys:
        print(sdk_adapter.LEGACY_KEYS_WARNING, file=sys.stderr)
        keys = sdk_adapter.legacy_unhardened_keys_from_mnemonic(mnemonic)
    else:
        keys = sdk_adapter.keys_from_mnemonic(mnemonic)

    print(f"Scan pubkey:  {keys.scan_pk().to_bytes().hex()}")
    print(f"Spend pubkey: {keys.spend_pk().to_bytes().hex()}")
    print(f"Checking coin: {coin_id}")
    print()

    # Look up the target coin and guard that it is UNSPENT before doing any work.
    target_rec = coinset.get_coin_record(coin_id)
    target_coin = target_rec["coin"]
    coin_ph = _strip(target_coin["puzzle_hash"])
    amount = target_coin["amount"]

    if target_rec.get("spent"):
        print("ERROR: This coin has already been spent.")
        sys.exit(1)

    print(f"Coin puzzle hash: {coin_ph}")
    print(f"Coin amount:      {amount} mojos")
    print()

    # DETECT (the scan_coin.py single-input path, verbatim): the SPENT parent coin
    # carries the sender's standard puzzle reveal; the SDK extracts the synthetic
    # pk from it and computes the input_hash over the PARENT coin id (the
    # parent-coin asymmetry). Fetch BOTH the puzzle reveal AND the solution
    # (the SDK runs the puzzle).
    parent_id = _strip(target_coin["parent_coin_info"])
    parent_rec = coinset.get_coin_record(parent_id)
    if not parent_rec.get("spent"):
        print("Parent coin is not spent — cannot extract puzzle")
        sys.exit(1)

    pspend = coinset.get_puzzle_and_solution(parent_id)

    coin_spends = [
        sdk_adapter.coin_spend_from_record(
            parent_rec, pspend["puzzle_reveal"], pspend["solution"]
        )
    ]
    additions = [sdk_adapter.coin_from_addition(target_rec)]

    # Detection needs only the scan secret key and the spend PUBLIC key.
    td = sdk_adapter.tweak_data_from_block_spends(coin_spends, additions)
    dets = sdk_adapter.scan_from_tweaks(
        keys.scan_sk(),
        keys.spend_pk(),
        td,
        sdk_adapter.label_registry(keys.scan_sk(), []),
        shared.K_MAX,
    )

    match = next((d for d in dets if bytes(d.coin_id) == bytes.fromhex(coin_id)), None)

    if match is None:
        print("NO MATCH. This coin does not belong to you.")
        sys.exit(1)

    print("MATCH! This coin belongs to you. Building spend...")
    print(f"One-time puzzle hash: {bytes(match.puzzle_hash).hex()}")
    print(f"Output index k:       {match.k}")
    print(f"Label:                {match.label}")
    print()

    # Destination: the recipient's STANDARD wallet m/12381/8444/2/0. The SDK
    # derives the puzzle hash; shared.puzzle_hash_to_address is IO/display glue only.
    dest_ph = sdk_adapter.wallet_puzzle_hash(mnemonic, 0)
    dest_address = shared.puzzle_hash_to_address(dest_ph)
    print(f"Destination address: {dest_address}")
    print(f"Destination PH:      {dest_ph.hex()}")
    print()

    # The one-time secret key is (spend_sk + tweak) mod r: derived here, explicitly,
    # from the detection's tweak and the spend SECRET key — the only place the
    # spend secret key is used.
    onetime_sk = sdk_adapter.derive_onetime_sk(keys.spend_sk(), match.tweak)

    # The signing key is the SYNTHETIC of the one-time sk (the curried AGG_SIG_ME
    # pk is the synthetic, never the raw one-time sk). Build the spend
    # via the adapter (fee=0 -> one full-amount CREATE_COIN, no reserve_fee).
    synthetic_sk = onetime_sk.derive_synthetic()
    spend_coin_spends = sdk_adapter.build_spend_to_address(
        onetime_sk, match, dest_ph, match.amount, fee=0
    )

    bundle = sdk_adapter.build_signed_spend_bundle(spend_coin_spends, [synthetic_sk])
    wire = sdk_adapter.sdk_bundle_to_wire_dict(bundle)

    print(f"Sending {amount} mojos to your standard wallet address...")

    if args.sage:
        from sage_rpc import SageRPC
        sage = SageRPC(
            url=args.sage_url,
            cert_path=args.sage_cert,
            key_path=args.sage_key,
        )
        sage.submit_transaction(wire)
        via = "Sage"
    else:
        # The coinset push call returns the node's JSON body on a zero exit; a
        # REJECTED bundle comes back as {"success": false, "error": ...} (the node
        # still exits 0). Do NOT report success blindly — surface the node's error,
        # or a bad bundle is "submitted" yet never block-included.
        resp = coinset.push_tx(wire)
        if isinstance(resp, dict) and resp.get("success") is False:
            err = resp.get("error") or resp.get("structuredError") or resp
            print(f"push_tx REJECTED the transaction: {err}", file=sys.stderr)
            sys.exit(1)
        via = "coinset (push_tx)"

    print(f"SUCCESS! Transaction submitted via {via}.")
    print(f"Sent {amount} mojos to {dest_address}")


if __name__ == "__main__":
    main()
