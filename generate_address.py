#!/usr/bin/env python3
"""
Generate a silent payment address from a Chia mnemonic or Sage wallet.

The silent payment address consists of two BLS G1 public keys:
- B_scan: used by senders for ECDH derivation
- B_spend: used to derive one-time output keys

Both keys are encoded in a bech32m address. Share the address with
senders -- each payment will arrive at a unique, unlinkable on-chain
puzzle hash.

Usage:
    python generate_address.py -f keyfile.txt
    python generate_address.py "your twenty four word mnemonic ..."
    python generate_address.py                # interactive prompt
    python generate_address.py --sage
    python generate_address.py --sage --fingerprint 123
"""

import sys
import argparse
from shared import (
    mnemonic_to_master_sk,
    master_sk_to_scan_sk,
    master_sk_to_spend_sk,
    encode_silent_payment_address,
    generate_label,
    generate_labeled_spend_pk,
    load_mnemonic,
)

parser = argparse.ArgumentParser(description="Generate a silent payment address")
parser.add_argument("mnemonic_words", nargs="*", help="Mnemonic words")
parser.add_argument("-f", "--mnemonic-file", help="File containing mnemonic")
parser.add_argument("--sage", action="store_true", help="Derive address from Sage wallet data")
parser.add_argument("--sage-url", help="Sage RPC URL")
parser.add_argument("--sage-cert", help="Path to Sage TLS client certificate")
parser.add_argument("--sage-key", help="Path to Sage TLS client key")
parser.add_argument("--fingerprint", type=int, help="Sage wallet fingerprint")
parser.add_argument("--label", type=int, help="Label index m (e.g., 1 for donations, 2 for invoices; 0 is reserved for change)")


def derive_and_print_address(mnemonic: str, label: int | None = None):
    """Derive scan/spend keys from mnemonic and print the silent payment address."""
    master_sk = mnemonic_to_master_sk(mnemonic)
    scan_sk = master_sk_to_scan_sk(master_sk)
    scan_pk = scan_sk.get_g1()
    spend_sk = master_sk_to_spend_sk(master_sk)
    spend_pk = spend_sk.get_g1()

    if label is not None:
        _, label_pk = generate_label(scan_sk, label)
        labeled_spend_pk = generate_labeled_spend_pk(spend_pk, label_pk)
        addr = encode_silent_payment_address(bytes(scan_pk), bytes(labeled_spend_pk))

        print()
        print(f"=== Silent Payment Address (label {label}) ===")
        print(addr)
        print()
        print(f"  Scan key  (B_scan):  {bytes(scan_pk).hex()}")
        print(f"  Spend key (B_spend): {bytes(spend_pk).hex()}")
        print(f"  Label key (B_m):     {bytes(labeled_spend_pk).hex()}")
        print()
        print("Share this address with senders. Scan with --labels", label)
    else:
        addr = encode_silent_payment_address(bytes(scan_pk), bytes(spend_pk))

        print()
        print("=== Silent Payment Address ===")
        print(addr)
        print()
        print(f"  Scan key  (B_scan):  {bytes(scan_pk).hex()}")
        print(f"  Spend key (B_spend): {bytes(spend_pk).hex()}")
        print()
        print("Share this address with senders.")


def main():
    args = parser.parse_args()

    if args.sage:
        # --- Sage RPC flow ---
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

        sage.login(fingerprint)
        secret_resp = sage.get_secret_key(fingerprint)
        mnemonic = secret_resp["secrets"]["mnemonic"]
        derive_and_print_address(mnemonic, label=args.label)
    else:
        # --- Backward-compatible mnemonic flow ---
        if args.mnemonic_file:
            mnemonic = load_mnemonic(["-f", args.mnemonic_file], prompt="Enter recipient mnemonic: ")
        elif args.mnemonic_words:
            mnemonic = " ".join(args.mnemonic_words)
        else:
            mnemonic = load_mnemonic([], prompt="Enter recipient mnemonic: ")
        derive_and_print_address(mnemonic, label=args.label)


if __name__ == "__main__":
    main()
