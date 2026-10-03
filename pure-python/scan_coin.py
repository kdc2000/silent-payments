#!/usr/bin/env python3
"""
Check if a coin belongs to a silent payment recipient.

Given a coin ID and the recipient's scanning keys, this program:
1. Looks up the coin on-chain via coinset
2. Scans the block that created the coin exactly as scanner.py does: it
   forms the block's spend groups (every standard-puzzle spend on its own,
   plus every ASSERT_CONCURRENT_SPEND cycle), performs scanner-side ECDH
   with each, and derives the candidate one-time puzzle hashes
3. Reports whether the coin is one of the detected outputs

Only the scan SECRET key and the spend PUBLIC key are needed, so the check
can be run watch-only. No secret key is printed: a match is reported with
its output index, label and spend tweak. The holder of the spend secret key
turns the spend tweak into the one-time key (see spend_coin.py).

Usage:
    python scan_coin.py <coin_id_hex> -f keyfile.txt
    python scan_coin.py <coin_id_hex> [recipient_mnemonic]
    python scan_coin.py <coin_id_hex> --scan-key <hex> --spend-pubkey <hex>
    python scan_coin.py <coin_id_hex> -f keyfile.txt --labels 1,2,3
"""

import argparse

from shared import build_label_map, load_scan_keys
from scanner import detect_coin, parse_label_indices, strip_0x

parser = argparse.ArgumentParser(description="Check if a coin belongs to a silent payment recipient")
parser.add_argument("coin_id", help="Coin ID hex to check")
parser.add_argument("mnemonic_words", nargs="*", help="Recipient mnemonic words")
parser.add_argument("-f", "--mnemonic-file", help="File containing recipient mnemonic")
parser.add_argument("--scan-key", help="Scan SECRET key hex (watch-only mode, with --spend-pubkey)")
parser.add_argument("--spend-pubkey", help="Spend PUBLIC key hex (watch-only mode, with --scan-key)")
parser.add_argument("--labels", help="Comma-separated label indices to check (e.g., 1,2,3). "
                                     "The change label 0 is always checked.")


def main():
    args = parser.parse_args()

    coin_id = strip_0x(args.coin_id)

    # Scan secret key + spend public key: given directly, or from a mnemonic
    try:
        scan_sk, spend_pk = load_scan_keys(
            args.scan_key, args.spend_pubkey, args.mnemonic_file, args.mnemonic_words
        )
    except ValueError as e:
        parser.error(str(e))
    scan_pk = scan_sk.get_g1()
    label_map = build_label_map(scan_sk, parse_label_indices(args.labels))

    print(f"Scan pubkey:  {bytes(scan_pk).hex()}")
    print(f"Spend pubkey: {bytes(spend_pk).hex()}")
    print(f"Checking coin: {coin_id}")
    print()

    # Look up the coin and scan the block that created it
    coin_record, detection = detect_coin(coin_id, scan_sk, spend_pk, label_map)

    print(f"Coin puzzle hash: {strip_0x(coin_record['coin']['puzzle_hash'])}")
    print(f"Coin amount:      {coin_record['coin']['amount']} mojos")
    print(f"Created in block: {coin_record['confirmed_block_index']}")
    print()

    if detection is None:
        print("NO MATCH. This coin does not belong to you.")
        return

    if detection["label"] is None:
        label_str = "none"
    elif detection["label"] == 0:
        label_str = "0 (change)"
    else:
        label_str = str(detection["label"])

    print("MATCH! This coin belongs to you.")
    print()
    print(f"Inputs in spend group: {detection['inputs']}")
    print(f"Output index (k):      {detection['k']}")
    print(f"Label:                 {label_str}")
    print(f"Spend tweak:           {detection['spend_tweak']}")
    print()
    print("The one-time secret key is (spend secret key + spend tweak) mod r.")
    print("Use spend_coin.py to spend the coin.")


if __name__ == "__main__":
    main()
