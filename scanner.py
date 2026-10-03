#!/usr/bin/env python3
"""Scan testnet11 blocks for silent payments addressed to a recipient.

Built on the SDK block path: each transaction block is detected via the SDK's
``tweak_data_from_block_spends`` + ``scan_from_tweaks`` (through ``sdk_adapter``),
which form the block's spend groups as in CHIP-0057 "Scanning a Block" — Pass 1:
every standard-puzzle spend on its own; Pass 2: every strongly connected component
of two or more standard-puzzle spends in the opcode-64 ASSERT_CONCURRENT_SPEND
graph (the directed SCC is the concurrent-spend pollution defense) — INTERNALLY in
Rust. This script owns ONLY coinset I/O (through ``coinset.py``), per-block
marshaling (through ``sdk_adapter`` marshalers), and the result print/UX. ZERO
crypto, ZERO direct ``chia_wallet_sdk`` import, ZERO inline coinset subprocess.

Scanning needs the scan SECRET key and the spend PUBLIC key only (CHIP-0057
"Scanning a Spend Group"). They come either from a mnemonic (hardened derivation)
or, for a WATCH-ONLY scanner that never holds a spend secret, from
``--scan-key <scan secret key hex> --spend-key <spend public key hex>``.
``--legacy-keys`` derives the mnemonic's keys with the unhardened paths instead;
it applies ONLY to coins paid to an address generated before the CHIP's
hardened-derivation revision and must never be used for a new address.

Each detection record carries the output index ``k``, the ``label`` (``None``
unlabeled, 0 change, m >= 1 labeled) and the ``tweak`` ((t_k + label_scalar) mod
r). No one-time SECRET key is derived, printed or stored here: spend_coin.py
derives it from the tweak and the spend secret key. The change label m = 0 is
always checked by the SDK, whatever ``--labels`` says.
"""

import sys
import argparse

import shared
from shared import load_mnemonic, puzzle_hash_to_address

import sdk_adapter
import coinset


def process_block(height, scan_sk, spend_pk, labels):
    """Detect silent payments in a single transaction block via the SDK block path.

    ``scan_sk`` is the scan SECRET key, ``spend_pk`` the spend PUBLIC key — the
    spend secret key is never needed to scan. Returns the
    ``sdk_adapter.detections_to_records`` dicts (``coin_id`` / ``parent_coin_id`` /
    ``puzzle_hash`` / ``amount`` / ``block_height`` / ``k`` / ``label`` / ``tweak``).

    Fetches the block's additions/removals through ``coinset``, filters coinbase
    coins caller-side (coinbase coins have no parent spend / puzzle reveal to
    fetch), marshals each non-coinbase removal into an SDK ``CoinSpend`` (with BOTH
    its puzzle reveal AND solution — the SDK runs the puzzle to extract opcode-64
    edges) and each non-coinbase addition into an SDK ``Coin``, then calls
    ``tweak_data_from_block_spends`` + ``scan_from_tweaks``. The SDK owns ALL
    grouping (per-spend single-input groups plus the concurrent-spend SCC over the
    opcode-64 directed graph), ECDH, puzzle-hash derivation, and the
    concurrent-spend pollution defense; no Python grouping, no manual de-dup. Two
    coins that share a one-time puzzle hash are BOTH reported (CHIP-0057 "Outputs
    Sharing a Puzzle Hash").

    Per-block SDK raises are caught-and-continued so one bad block never aborts a
    range scan; the function returns ``[]`` on any failure.
    """
    try:
        data = coinset.get_additions_and_removals(height)
    except Exception:
        return []

    # Caller-side coinbase filter. Non-standard puzzles are filtered by the SDK's
    # Stage 1 internally, so only the coinbase guard stays here.
    removals = [r for r in data["removals"] if not r.get("coinbase", False)]
    additions = [a for a in data["additions"] if not a.get("coinbase", False)]

    coin_spends = []
    for removal in removals:
        # Coin id is DELEGATED to the SDK (never pre-compute it). Build
        # the SDK Coin once and read its coin_id() for the puzzle/solution lookup.
        coin_id = sdk_adapter.coin_from_addition(removal).coin_id().hex()

        pspend = coinset.get_puzzle_and_solution(coin_id, optional=True)
        if (
            pspend is None
            or "puzzle_reveal" not in pspend
            or "solution" not in pspend
        ):
            # Coin not accessible (e.g. not yet spent) — skip; the SDK will still
            # skip non-standard puzzles it can't parse.
            continue

        coin_spends.append(
            sdk_adapter.coin_spend_from_record(
                removal, pspend["puzzle_reveal"], pspend["solution"]
            )
        )

    addition_coins = [sdk_adapter.coin_from_addition(a) for a in additions]

    try:
        td = sdk_adapter.tweak_data_from_block_spends(coin_spends, addition_coins)
        dets = sdk_adapter.scan_from_tweaks(
            scan_sk, spend_pk, td, labels, shared.K_MAX
        )
    except Exception:
        return []

    return sdk_adapter.detections_to_records(dets, block_height=height)


def _tx_block_heights(start, end):
    """Transaction block heights in [start, end) — blocks with a non-None timestamp.

    Heights pass through ``coinset.get_block_records`` VERBATIM (no 0x prefix).
    """
    records = coinset.get_block_records(start, end)
    return sorted(
        br["height"] for br in records if br.get("timestamp") is not None
    )


def scan_blocks(
    scan_sk,
    spend_pk,
    start_height,
    end_height=None,
    labels=None,
    batch_size=50,
):
    """Scan a range of testnet11 blocks for silent payments via the SDK block path.

    ``scan_sk`` is the scan SECRET key and ``spend_pk`` the spend PUBLIC key (no
    spend secret key). ``labels`` is an SDK ``LabelRegistry`` (built by
    ``sdk_adapter.label_registry``) or ``None`` — when ``None``, an empty registry
    is built inside (unlabeled + change outputs; the SDK always checks the change
    label). Block records are fetched in batches of ``batch_size``; with no
    ``end_height`` the scan runs to the current chain tip.
    """
    if labels is None:
        labels = sdk_adapter.label_registry(scan_sk, [])

    if end_height is None:
        end_height = coinset.get_blockchain_state()["blockchain_state"]["peak"]["height"]

    all_detected = []

    batch_start = start_height
    while batch_start <= end_height:
        batch_end = min(batch_start + batch_size, end_height + 1)

        # Find transaction blocks in this batch
        tx_heights = _tx_block_heights(batch_start, batch_end)

        # Process each transaction block
        for h in tx_heights:
            results = process_block(h, scan_sk, spend_pk, labels)
            all_detected.extend(results)

        print(
            f"Scanning blocks {batch_start}-{batch_end - 1}... "
            f"({len(all_detected)} found so far)",
            file=sys.stderr,
        )

        batch_start = batch_end

    return all_detected


def main():
    """CLI entry point for the blockchain scanner."""
    parser = argparse.ArgumentParser(
        description="Scan testnet11 blocks for silent payments addressed to a recipient."
    )
    parser.add_argument(
        "address",
        nargs="?",
        help="Silent payment address (tspxch1...) to scan for",
    )
    parser.add_argument(
        "-s", "--start",
        type=int,
        required=True,
        help="Start block height (inclusive)",
    )
    parser.add_argument(
        "-e", "--end",
        type=int,
        default=None,
        help="End block height (inclusive, default=chain tip)",
    )
    parser.add_argument(
        "-f",
        metavar="FILE",
        help="Mnemonic file path",
    )
    parser.add_argument(
        "--scan-key",
        help="Watch-only: scan SECRET key hex (use with --spend-key, instead of a mnemonic)",
    )
    parser.add_argument(
        "--spend-key",
        help="Watch-only: spend PUBLIC key hex (use with --scan-key, instead of a mnemonic)",
    )
    parser.add_argument(
        "--legacy-keys",
        action="store_true",
        help="Derive the recipient keys from the mnemonic with the UNHARDENED "
        "paths (m/12381/8444/12/0, m/12381/8444/13/0). Only for coins paid to an "
        "address generated before CHIP-0057 required hardened derivation; never "
        "use it for a new address",
    )
    parser.add_argument(
        "--labels",
        help="Comma-separated label indices (e.g., 1,2,3)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Blocks per batch for block record queries (default: 50)",
    )
    parser.add_argument(
        "--node",
        help="Full node API host for coinset (e.g., https://mynode:8555)",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Use local full node instead of hosted API",
    )
    parser.add_argument(
        "mnemonic_words",
        nargs="*",
        help="Mnemonic words (if not using -f or --scan-key)",
    )

    args = parser.parse_args()

    # Route --node/--local through coinset.py's BASE_ARGS; coinset.py owns ALL
    # coinset subprocess calls.
    if args.node:
        coinset.BASE_ARGS.clear()
        coinset.BASE_ARGS.extend(["--api", args.node])
    elif args.local:
        coinset.BASE_ARGS.clear()
        coinset.BASE_ARGS.append("--local")

    # Scanning needs the scan SECRET key and the spend PUBLIC key only. Two ways
    # to supply them (all key handling goes through the adapter — no direct SDK
    # import, no shared scan-crypto):
    #   * watch-only: --scan-key + --spend-key (no spend secret key anywhere);
    #   * mnemonic:   -f FILE / words / prompt (hardened, or --legacy-keys).
    if args.scan_key or args.spend_key:
        if not (args.scan_key and args.spend_key):
            parser.error("watch-only scanning needs BOTH --scan-key and --spend-key")
        if args.f or args.mnemonic_words or args.legacy_keys:
            parser.error(
                "--scan-key/--spend-key replace the mnemonic: do not combine them "
                "with -f, mnemonic words or --legacy-keys"
            )
        try:
            scan_sk, spend_pk = sdk_adapter.watch_only_keys(args.scan_key, args.spend_key)
        except ValueError as exc:
            parser.error(f"invalid --scan-key/--spend-key: {exc}")
    else:
        mnemonic_args = []
        if args.f:
            mnemonic_args = ["-f", args.f]
        elif args.mnemonic_words:
            mnemonic_args = args.mnemonic_words

        mnemonic = load_mnemonic(mnemonic_args, prompt="Enter recipient mnemonic: ")
        if args.legacy_keys:
            print(sdk_adapter.LEGACY_KEYS_WARNING, file=sys.stderr)
            keys = sdk_adapter.legacy_unhardened_keys_from_mnemonic(mnemonic)
        else:
            keys = sdk_adapter.keys_from_mnemonic(mnemonic)
        scan_sk, spend_pk = keys.scan_sk(), keys.spend_pk()

    # If address provided, validate it matches the scanning keys.
    if args.address:
        try:
            _addr_scan_pk, addr_spend_pk = sdk_adapter.decode_silent_payment_address(args.address)
        except ValueError as exc:
            parser.error(f"invalid silent payment address: {exc}")
        if spend_pk.to_bytes() != addr_spend_pk.to_bytes():
            print(
                "Warning: spend key does not match address spend key",
                file=sys.stderr,
            )

    # Build label registry if requested (m>=1 registered). The change label m=0
    # needs no registration: the SDK always checks it and reports it as label 0.
    if args.labels:
        label_indices = [int(x.strip()) for x in args.labels.split(",")]
        labels = sdk_adapter.label_registry(scan_sk, label_indices)
    else:
        labels = sdk_adapter.label_registry(scan_sk, [])

    # Determine end height
    end_height = args.end

    print("=== Silent Payment Scanner ===", file=sys.stderr)
    print(
        f"Scanning blocks {args.start} to {end_height or 'tip'}...",
        file=sys.stderr,
    )
    print(file=sys.stderr)

    # Run the scan
    detections = scan_blocks(
        scan_sk,
        spend_pk,
        start_height=args.start,
        end_height=end_height,
        labels=labels,
        batch_size=args.batch_size,
    )

    # Print results
    print(file=sys.stderr)
    print(f"Found {len(detections)} silent payment(s):", file=sys.stderr)
    print(file=sys.stderr)

    for d in detections:
        address = puzzle_hash_to_address(bytes.fromhex(d["puzzle_hash"]))
        if d["label"] is None:
            label_str = "none"
        elif d["label"] == 0:
            label_str = "0 (change)"
        else:
            label_str = str(d["label"])
        print(f"  Coin ID:      {d['coin_id']}")
        print(f"  Amount:       {d['amount']} mojos")
        print(f"  Block Height: {d['block_height']}")
        print(f"  Address:      {address}")
        print(f"  Output k:     {d['k']}")
        print(f"  Label:        {label_str}")
        # (t_k + label_scalar) mod r — the spend handoff; not a secret key.
        print(f"  Tweak:        {d['tweak']}")
        print()


if __name__ == "__main__":
    main()
