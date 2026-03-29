#!/usr/bin/env python3
"""Scan testnet11 blocks for silent payments addressed to a recipient."""

import sys
import json
import subprocess
import argparse

from chia_rs import G1Element, PrivateKey, Program
from shared import (
    extract_synthetic_pk,
    scan_for_silent_payment,
    mnemonic_to_master_sk,
    master_sk_to_scan_sk,
    master_sk_to_spend_sk,
    puzzle_hash_to_address,
    load_mnemonic,
    decode_silent_payment_address,
    generate_label,
    compute_coin_id,
    aggregate_sender_pks,
)


COINSET_BASE_ARGS: list[str] = ["-t"]  # default: testnet


def coinset_json(command: str, *args: str) -> dict:
    cmd = ["coinset"] + COINSET_BASE_ARGS + ["-r", command] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"coinset error: {result.stderr.strip()}")
    return json.loads(result.stdout)


def get_tip_height() -> int:
    state = coinset_json("get_blockchain_state")
    return state["blockchain_state"]["peak"]["height"]


def get_tx_block_heights(start: int, end: int) -> list[int]:
    """Transaction block heights in [start, end) — blocks with non-None timestamp."""
    records = coinset_json("get_block_records", str(start), str(end))
    tx_heights = [
        br["height"]
        for br in records.get("block_records", [])
        if br.get("timestamp") is not None
    ]
    return sorted(tx_heights)


def strip_0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h



def process_block(
    height: int,
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    labels: dict | None = None,
) -> list[dict]:
    """Process a single transaction block for silent payment detections."""
    data = coinset_json("get_additions_and_removals", str(height))
    additions = data.get("additions", [])
    removals = data.get("removals", [])

    detected = []

    for removal in removals:
        # Skip coinbase removals (farming rewards have no parent spend)
        if removal.get("coinbase", False):
            continue

        # Compute the removal's coin name: SHA256(parent || puzzle_hash || amount)
        coin = removal["coin"]
        parent = bytes.fromhex(strip_0x(coin["parent_coin_info"]))
        ph = bytes.fromhex(strip_0x(coin["puzzle_hash"]))
        amount = coin["amount"]
        coin_name = compute_coin_id(parent, ph, amount)

        # Fetch puzzle reveal for the spent coin
        try:
            spend_data = coinset_json(
                "get_puzzle_and_solution", "0x" + coin_name.hex()
            )
            coin_solution = spend_data.get("coin_solution") or spend_data.get("coin_spend")
            if not coin_solution or "puzzle_reveal" not in coin_solution:
                continue
        except (RuntimeError, KeyError):
            # Coin may not be accessible; skip
            continue

        # Parse puzzle and extract sender's synthetic PK
        puzzle_hex = strip_0x(coin_solution["puzzle_reveal"])
        puzzle = Program.from_bytes(bytes.fromhex(puzzle_hex))
        sender_pk = extract_synthetic_pk(puzzle)

        # Skip non-standard puzzles (SCAN-04)
        if sender_pk is None:
            continue

        # Find additions created by this removal
        # (additions whose parent_coin_info matches this removal's coin name)
        coin_name_hex = coin_name.hex()
        matching_additions = [
            a for a in additions
            if strip_0x(a["coin"]["parent_coin_info"]) == coin_name_hex
            and not a.get("coinbase", False)
        ]

        if not matching_additions:
            continue

        # Build output puzzle hashes for detection
        output_phs = [
            bytes.fromhex(strip_0x(a["coin"]["puzzle_hash"]))
            for a in matching_additions
        ]

        # Run silent payment detection
        results = scan_for_silent_payment(
            scan_sk, spend_pk, sender_pk,
            [coin_name], output_phs,
            labels=labels,
        )

        # Build detection records — match by puzzle hash, not by k index.
        # k is the ECDH output tweak index (k=0 = first recipient), not the
        # index into matching_additions.
        for d in results:
            matched_ph_hex = d["puzzle_hash"].hex()
            matched_addition = next(
                (a for a in matching_additions
                 if strip_0x(a["coin"]["puzzle_hash"]) == matched_ph_hex),
                None,
            )
            if matched_addition is None:
                continue
            matched_coin = matched_addition["coin"]

            # Compute the output coin's ID
            out_parent = bytes.fromhex(strip_0x(matched_coin["parent_coin_info"]))
            out_ph = bytes.fromhex(strip_0x(matched_coin["puzzle_hash"]))
            out_amount = matched_coin["amount"]
            out_coin_id = compute_coin_id(out_parent, out_ph, out_amount)

            detected.append({
                "coin_id": out_coin_id.hex(),
                "amount": out_amount,
                "block_height": height,
                "puzzle_hash": d["puzzle_hash"].hex(),
                "label": d["label"],
            })

    # --- Pass 2: Multi-input detection ---
    # Precompute: which removals have children (additions parented by them)?
    from collections import defaultdict

    non_coinbase_removals = [r for r in removals if not r.get("coinbase", False)]
    removal_names = {}  # removal index -> coin_name
    for i, r in enumerate(non_coinbase_removals):
        coin = r["coin"]
        parent = bytes.fromhex(strip_0x(coin["parent_coin_info"]))
        r_ph = bytes.fromhex(strip_0x(coin["puzzle_hash"]))
        r_amount = coin["amount"]
        removal_names[i] = compute_coin_id(parent, r_ph, r_amount)

    addition_parents = {
        strip_0x(a["coin"]["parent_coin_info"])
        for a in additions if not a.get("coinbase", False)
    }

    has_children = {}  # removal index -> bool
    for i, cn in removal_names.items():
        has_children[i] = cn.hex() in addition_parents

    # Track coin IDs already detected in Pass 1 to avoid duplicates
    detected_coin_ids = {d["coin_id"] for d in detected}

    def _try_multi_input_group(group_indices):
        """Try aggregated-key detection on a group of removal indices."""
        pks = []
        group_coin_ids = []
        all_coin_names = []

        for i in group_indices:
            r_coin_name = removal_names[i]
            all_coin_names.append(r_coin_name)

            try:
                spend_data = coinset_json(
                    "get_puzzle_and_solution", "0x" + r_coin_name.hex()
                )
                coin_solution = spend_data.get("coin_solution") or spend_data.get("coin_spend")
                if not coin_solution or "puzzle_reveal" not in coin_solution:
                    continue
            except (RuntimeError, KeyError):
                continue

            puzzle_hex = strip_0x(coin_solution["puzzle_reveal"])
            puzzle = Program.from_bytes(bytes.fromhex(puzzle_hex))
            pk = extract_synthetic_pk(puzzle)
            if pk is None:
                continue
            pks.append(pk)
            group_coin_ids.append(r_coin_name)

        if len(pks) < 2:
            return

        pk_sum = aggregate_sender_pks(pks)
        if pk_sum == G1Element():  # Zero-sum guard
            return

        # Collect additions parented by ANY removal in this group
        group_name_hexes = {cn.hex() for cn in all_coin_names}
        group_additions = [
            a for a in additions
            if strip_0x(a["coin"]["parent_coin_info"]) in group_name_hexes
            and not a.get("coinbase", False)
        ]

        if not group_additions:
            return

        output_phs = [
            bytes.fromhex(strip_0x(a["coin"]["puzzle_hash"]))
            for a in group_additions
        ]

        results = scan_for_silent_payment(
            scan_sk, spend_pk, pk_sum,
            group_coin_ids, output_phs,
            labels=labels,
        )

        for d in results:
            matched_ph_hex = d["puzzle_hash"].hex()
            matched_addition = next(
                (a for a in group_additions
                 if strip_0x(a["coin"]["puzzle_hash"]) == matched_ph_hex),
                None,
            )
            if matched_addition is None:
                continue
            matched_coin = matched_addition["coin"]

            out_parent = bytes.fromhex(strip_0x(matched_coin["parent_coin_info"]))
            out_ph = bytes.fromhex(strip_0x(matched_coin["puzzle_hash"]))
            out_amount = matched_coin["amount"]
            out_coin_id = compute_coin_id(out_parent, out_ph, out_amount)

            if out_coin_id.hex() in detected_coin_ids:
                continue

            detected.append({
                "coin_id": out_coin_id.hex(),
                "amount": out_amount,
                "block_height": height,
                "puzzle_hash": d["puzzle_hash"].hex(),
                "label": d["label"],
            })
            detected_coin_ids.add(out_coin_id.hex())

    # Pass 2a: Group by puzzle hash (same derivation index)
    ph_groups = defaultdict(list)
    for i, r in enumerate(non_coinbase_removals):
        ph = strip_0x(r["coin"]["puzzle_hash"])
        ph_groups[ph].append(i)

    for ph, indices in ph_groups.items():
        if len(indices) >= 2:
            _try_multi_input_group(indices)

    # Pass 2b: Group by announcement linkage (different derivation indices)
    # Parse solutions to find coins linked by CREATE/ASSERT_COIN_ANNOUNCEMENT.
    # This is immune to pollution from unrelated childless spends in the block.
    import hashlib as _hl

    # For each removal, fetch solution and extract announcement conditions
    announces = {}   # index -> set of announcement messages (from opcode 60)
    asserts = {}     # index -> set of announcement IDs being asserted (from opcode 61)

    for i in removal_names:
        r_coin_name = removal_names[i]
        try:
            spend_data = coinset_json(
                "get_puzzle_and_solution", "0x" + r_coin_name.hex()
            )
            coin_solution = spend_data.get("coin_solution") or spend_data.get("coin_spend")
            if not coin_solution or "solution" not in coin_solution:
                continue
        except (RuntimeError, KeyError):
            continue

        try:
            solution_hex = strip_0x(coin_solution["solution"])
            solution = Program.from_bytes(bytes.fromhex(solution_hex))
            # Solution is (() delegated_puzzle ()), delegated_puzzle is (1 . conditions)
            # Run the puzzle to get output conditions
            puzzle_hex = strip_0x(coin_solution["puzzle_reveal"])
            puzzle = Program.from_bytes(bytes.fromhex(puzzle_hex))
            _, output = puzzle.run(solution)
            # output is a list of conditions: ((opcode args...) . rest)
            conditions = []
            node = output
            while node.pair:
                cond, node = node.pair
                if cond.pair:
                    opcode_node, args_node = cond.pair
                    if opcode_node.atom is not None:
                        opcode = int.from_bytes(opcode_node.atom, "big") if opcode_node.atom else 0
                        # Extract first argument
                        arg1 = b''
                        if args_node.pair:
                            arg1_node, _ = args_node.pair
                            if arg1_node.atom is not None:
                                arg1 = arg1_node.atom
                        conditions.append((opcode, arg1))

            for opcode, arg in conditions:
                if opcode == 60:  # CREATE_COIN_ANNOUNCEMENT
                    ann_id = _hl.sha256(r_coin_name + arg).digest()
                    announces.setdefault(i, set()).add(ann_id)
                elif opcode == 61:  # ASSERT_COIN_ANNOUNCEMENT
                    asserts.setdefault(i, set()).add(arg)
        except Exception:
            continue

    # Build groups: for each announcer, find all coins that assert its announcement
    announcement_groups = {}  # announcer index -> set of linked indices
    for announcer_idx, ann_ids in announces.items():
        linked = {announcer_idx}
        for asserter_idx, asserted_ids in asserts.items():
            if ann_ids & asserted_ids:  # intersection — this coin asserts this announcement
                linked.add(asserter_idx)
        if len(linked) >= 2:
            key = frozenset(linked)
            announcement_groups[key] = linked

    for group_indices in announcement_groups.values():
        _try_multi_input_group(list(group_indices))

    return detected


def scan_blocks(
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    start_height: int,
    end_height: int | None = None,
    labels: dict | None = None,
    batch_size: int = 50,
) -> list[dict]:
    """Scan a range of testnet11 blocks for silent payments."""
    if end_height is None:
        end_height = get_tip_height()

    all_detected = []

    batch_start = start_height
    while batch_start <= end_height:
        batch_end = min(batch_start + batch_size, end_height + 1)

        # Find transaction blocks in this batch
        tx_heights = get_tx_block_heights(batch_start, batch_end)

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
        help="Scan secret key hex (alternative to mnemonic)",
    )
    parser.add_argument(
        "--spend-key",
        help="Spend public key hex (alternative to mnemonic)",
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

    if args.node:
        COINSET_BASE_ARGS.clear()
        COINSET_BASE_ARGS.extend(["--api", args.node])
    elif args.local:
        COINSET_BASE_ARGS.clear()
        COINSET_BASE_ARGS.append("--local")

    # Derive keys
    if args.scan_key and args.spend_key:
        scan_sk = PrivateKey.from_bytes(bytes.fromhex(args.scan_key))
        spend_pk = G1Element.from_bytes(bytes.fromhex(args.spend_key))
    else:
        # Need mnemonic to derive keys
        mnemonic_args = []
        if args.f:
            mnemonic_args = ["-f", args.f]
        elif args.mnemonic_words:
            mnemonic_args = args.mnemonic_words

        mnemonic = load_mnemonic(mnemonic_args, prompt="Enter recipient mnemonic: ")
        master_sk = mnemonic_to_master_sk(mnemonic)
        scan_sk = master_sk_to_scan_sk(master_sk)
        spend_pk = master_sk_to_spend_sk(master_sk).get_g1()

    # If address provided, validate it matches derived keys
    if args.address:
        addr_scan_pk_bytes, addr_spend_pk_bytes = decode_silent_payment_address(args.address)
        expected_scan_pk = G1Element.from_bytes(addr_scan_pk_bytes)
        expected_spend_pk = G1Element.from_bytes(addr_spend_pk_bytes)
        if bytes(spend_pk) != bytes(expected_spend_pk):
            print(
                "Warning: spend key from mnemonic does not match address spend key",
                file=sys.stderr,
            )

    # Build label map if requested
    label_map = None
    if args.labels:
        label_indices = [int(x.strip()) for x in args.labels.split(",")]
        label_map = {}
        for m in label_indices:
            _, label_pk = generate_label(scan_sk, m)
            label_map[bytes(label_pk)] = m

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
        scan_sk, spend_pk,
        start_height=args.start,
        end_height=end_height,
        labels=label_map,
        batch_size=args.batch_size,
    )

    # Print results
    print(file=sys.stderr)
    print(f"Found {len(detections)} silent payment(s):", file=sys.stderr)
    print(file=sys.stderr)

    for d in detections:
        address = puzzle_hash_to_address(bytes.fromhex(d["puzzle_hash"]))
        label_str = str(d["label"]) if d["label"] is not None else "none"
        print(f"  Coin ID:      {d['coin_id']}")
        print(f"  Amount:       {d['amount']} mojos")
        print(f"  Block Height: {d['block_height']}")
        print(f"  Address:      {address}")
        print(f"  Label:        {label_str}")
        print()


if __name__ == "__main__":
    main()
