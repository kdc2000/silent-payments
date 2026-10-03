#!/usr/bin/env python3
"""
Check if a coin belongs to a silent payment recipient.

Given the recipient's mnemonic and a coin ID, this program:
1. Looks up the coin on-chain via coinset
2. Marshals the SPENT (parent) coin as the lone CoinSpend and the target coin as
   an addition (preserving the parent-coin input-hash asymmetry)
3. Routes detection through the SDK block path
   (sdk_adapter.tweak_data_from_block_spends + scan_from_tweaks) — the SDK owns
   the synthetic-pk extraction, the ECDH, and the puzzle-hash derivation
4. Reports MATCH iff the SDK returns a detection whose coin id is the target coin

Detection uses the scan secret key and the spend PUBLIC key only. On a match the
script prints the output index k, the label, and the detection's tweak
((t_k + label_scalar) mod r) — never a secret key. spend_coin.py combines that
tweak with the spend secret key to spend the coin.

Keys come from the mnemonic with the hardened derivation CHIP-0057 requires.
--legacy-keys switches to the unhardened derivation and applies ONLY to a coin paid
to an address generated before the CHIP's hardened-derivation revision; it must
never be used for a new address.

This script is single-input-only BY DESIGN: it feeds a one-element block
(``coin_spends=[parent_CoinSpend]``, ``additions=[target_coin]``) and the
NON-aggregated sender key. Multi-input / block-range detection is scanner.py.

Usage:
    python scan_coin.py <coin_id_hex> -f keyfile.txt
    python scan_coin.py <coin_id_hex> [recipient_mnemonic]
    python scan_coin.py <coin_id_hex> -f keyfile.txt --legacy-keys
"""

import sys
import argparse

import shared
from shared import load_mnemonic

import sdk_adapter
import coinset

parser = argparse.ArgumentParser(description="Check if a coin belongs to a silent payment recipient")
parser.add_argument("coin_id", help="Coin ID hex to check")
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

    # Look up the target coin.
    target_rec = coinset.get_coin_record(coin_id)
    target_coin = target_rec["coin"]
    coin_ph = _strip(target_coin["puzzle_hash"])

    print(f"Coin puzzle hash: {coin_ph}")
    print(f"Coin amount:      {target_coin['amount']} mojos")
    print()

    # The SPENT (parent) coin carries the sender's standard puzzle reveal; the SDK
    # extracts the synthetic pk from it and computes the input_hash over the PARENT
    # coin id (the parent-coin asymmetry). Fetch BOTH the puzzle reveal AND the
    # solution (the SDK runs the puzzle to extract any opcode-64 edges; a single
    # coin has none, but the SDK still parses).
    parent_id = _strip(target_coin["parent_coin_info"])
    parent_rec = coinset.get_coin_record(parent_id)
    if not parent_rec.get("spent"):
        print("Parent coin is not spent — cannot extract puzzle")
        sys.exit(1)

    pspend = coinset.get_puzzle_and_solution(parent_id)

    # Marshal the one-element block: parent as the CoinSpend, target as the addition.
    coin_spends = [
        sdk_adapter.coin_spend_from_record(
            parent_rec, pspend["puzzle_reveal"], pspend["solution"]
        )
    ]
    additions = [sdk_adapter.coin_from_addition(target_rec)]

    # SDK block path: extract tweak data, then scan with the scan SECRET key and
    # the spend PUBLIC key (the spend secret key is not needed to detect). The
    # change label m=0 is always checked by the SDK. For a single coin a raise IS
    # a legitimate "could not process" error — let it propagate; do NOT swallow
    # it.
    td = sdk_adapter.tweak_data_from_block_spends(coin_spends, additions)
    dets = sdk_adapter.scan_from_tweaks(
        keys.scan_sk(),
        keys.spend_pk(),
        td,
        sdk_adapter.label_registry(keys.scan_sk(), []),
        shared.K_MAX,
    )

    match = next((d for d in dets if bytes(d.coin_id) == bytes.fromhex(coin_id)), None)

    if match is not None:
        print("MATCH! This coin belongs to you.")
        print()
        record = sdk_adapter.detections_to_records([match])[0]
        label = record["label"]
        label_str = "none" if label is None else ("0 (change)" if label == 0 else str(label))
        print(f"One-time puzzle hash: {record['puzzle_hash']}")
        print(f"Output index k:       {record['k']}")
        print(f"Label:                {label_str}")
        # The spend handoff: (t_k + label_scalar) mod r. Not a secret key — the
        # one-time key is (spend_sk + tweak) mod r, derived by spend_coin.py.
        print(f"Tweak:                {record['tweak']}")
    else:
        print("NO MATCH. This coin does not belong to you.")


if __name__ == "__main__":
    main()
