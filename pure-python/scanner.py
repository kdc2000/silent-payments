#!/usr/bin/env python3
"""Scan testnet11 blocks for silent payments addressed to a recipient.

The scanner needs only the scan SECRET key and the spend PUBLIC key. It can
be run from a mnemonic (both keys are derived) or watch-only, from the two
keys themselves. It never derives or prints a one-time secret key: each
detection carries the spend tweak, which a signer holding the spend secret
key turns into the one-time key (see spend_coin.py).

Usage:
    python scanner.py -s <start_height> [-e <end_height>] -f keyfile.txt
    python scanner.py <silent_payment_address> -s <start_height> -f keyfile.txt
    python scanner.py -s <start_height> --scan-key <hex> --spend-pubkey <hex>
    python scanner.py -s <start_height> -f keyfile.txt --labels 1,2,3

The block-level logic (spend groups, tweak points, ScanBlock) is in pure
functions that take coin spends and coins, so it can be used and tested
without a node.
"""

import sys
import json
import subprocess
import argparse
from typing import Callable

from chia_rs import Coin, CoinSpend, G1Element, PrivateKey, Program
from shared import (
    extract_synthetic_pk,
    scan_for_silent_payment,
    scan_tweak_point,
    compute_tweak_point,
    build_label_map,
    puzzle_hash_to_address,
    load_scan_keys,
    decode_silent_payment_address,
    aggregate_sender_pks,
)


COINSET_BASE_ARGS: list[str] = ["-t"]  # default: testnet

# CLVM execution constants for extracting a spend's output conditions (the
# consensus block-cost ceiling). Used by `Program.run_rust(max_cost, flags, args)`.
MAX_COST = 11_000_000_000
RUN_FLAGS = 0

# ASSERT_CONCURRENT_SPEND as consensus parses it: the condition code is the
# ONE-byte atom 0x40. Any other encoding of the number 64 (0x0040, for
# example) is not this condition and must not be accepted.
ASSERT_CONCURRENT_SPEND = b"\x40"


def tarjan_scc(graph: dict[bytes, list[bytes]]) -> list[list[bytes]]:
    """Iterative Tarjan's strongly connected components.

    Args:
        graph: adjacency map. Keys are ALL graph nodes (even isolated ones).
            `graph[v]` is the list of v's directed-edge successors.

    Returns:
        List of SCCs. Each SCC is a list of node IDs (bytes). Size-1 SCCs
        (isolated nodes and self-loops) are included; callers should filter
        to len(scc) >= 2 for Pass 2.

    Iterative variant — does not hit Python's default recursion limit of 1000
    on adversarial blocks. Reference:
    https://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm
    """
    index_counter = 0
    stack: list[bytes] = []
    on_stack: set[bytes] = set()
    indices: dict[bytes, int] = {}
    lowlinks: dict[bytes, int] = {}
    result: list[list[bytes]] = []

    for start in list(graph):
        if start in indices:
            continue
        # Iterative DFS. work_stack holds (node, iterator_over_successors).
        work_stack: list = []
        indices[start] = index_counter
        lowlinks[start] = index_counter
        index_counter += 1
        stack.append(start)
        on_stack.add(start)
        work_stack.append((start, iter(graph.get(start, ()))))

        while work_stack:
            v, it = work_stack[-1]
            try:
                w = next(it)
            except StopIteration:
                # Post-order: finalize SCC if v is a root
                if lowlinks[v] == indices[v]:
                    scc: list[bytes] = []
                    while True:
                        x = stack.pop()
                        on_stack.discard(x)
                        scc.append(x)
                        if x == v:
                            break
                    result.append(scc)
                work_stack.pop()
                if work_stack:
                    parent, _ = work_stack[-1]
                    lowlinks[parent] = min(lowlinks[parent], lowlinks[v])
                continue
            if w not in indices:
                indices[w] = index_counter
                lowlinks[w] = index_counter
                index_counter += 1
                stack.append(w)
                on_stack.add(w)
                work_stack.append((w, iter(graph.get(w, ()))))
            elif w in on_stack:
                lowlinks[v] = min(lowlinks[v], indices[w])

    return result


# --- Spend groups ("Inputs for Shared Secret Derivation") ---

def find_eligible_spends(coin_spends: list[CoinSpend]) -> list[tuple[CoinSpend, G1Element]]:
    """The block's eligible spends, each paired with its synthetic public key.

    An eligible spend is a coin spend whose puzzle reveal is the standard
    puzzle. The kind of coin does not matter (a spent farming reward coin
    held in the standard puzzle is eligible). Every other spend is ignored
    from here on: it contributes no key, no coin ID and no edge.
    """
    eligible = []
    seen: set[bytes] = set()
    for coin_spend in coin_spends:
        coin_id = bytes(coin_spend.coin.name())
        if coin_id in seen:
            continue
        pk = extract_synthetic_pk(coin_spend.puzzle_reveal)
        if pk is None:
            continue
        seen.add(coin_id)
        eligible.append((coin_spend, pk))
    return eligible


def asserted_concurrent_spends(coin_spend: CoinSpend) -> list[bytes]:
    """Coin IDs named by the ASSERT_CONCURRENT_SPEND conditions a spend outputs.

    Runs the puzzle with its solution and walks the output conditions. Only
    what consensus treats as ASSERT_CONCURRENT_SPEND counts: a one-byte
    condition code 64 whose first argument is a 32-byte atom.
    """
    try:
        # NOTE: chia_rs Program exposes run_rust(max_cost, flags, args), NOT
        # a plain run(args).
        _, output = coin_spend.puzzle_reveal.run_rust(
            MAX_COST, RUN_FLAGS, coin_spend.solution
        )
    except Exception:
        return []  # a spend that cannot be run outputs no conditions

    asserted = []
    node = output
    while node.pair:
        cond, node = node.pair
        if not cond.pair:
            continue
        op_node, args_node = cond.pair
        if op_node.atom != ASSERT_CONCURRENT_SPEND:
            continue
        if not args_node.pair:
            continue
        a1, _ = args_node.pair
        if a1.atom is None or len(a1.atom) != 32:
            continue
        asserted.append(bytes(a1.atom))
    return asserted


def form_spend_groups(coin_spends: list[CoinSpend]) -> list[list[tuple[CoinSpend, G1Element]]]:
    """All spend groups of a block.

    Returns every single-input group first (one per eligible spend, Pass 1),
    then every multi-input group (Pass 2): the strongly connected components
    of size two or more of the concurrent-spend graph. The vertices of that
    graph are the eligible spends only; there is an edge X -> Y when eligible
    spend X outputs ASSERT_CONCURRENT_SPEND naming eligible spend Y.

    Strongly connected components (not weakly connected ones) keep a third
    party out: a spend that asserts a group member's coin ID without being
    asserted back only adds a one-way edge.
    """
    eligible = find_eligible_spends(coin_spends)

    # Pass 1: every eligible spend on its own
    groups = [[entry] for entry in eligible]

    # Pass 2: concurrent-spend graph over the eligible spends
    graph: dict[bytes, list[bytes]] = {
        bytes(coin_spend.coin.name()): [] for coin_spend, _ in eligible
    }
    for coin_spend, _ in eligible:
        coin_id = bytes(coin_spend.coin.name())
        for asserted_coin_id in asserted_concurrent_spends(coin_spend):
            # A condition naming a coin that is not an eligible spend in this
            # block adds no edge.
            if asserted_coin_id in graph:
                graph[coin_id].append(asserted_coin_id)

    for scc in tarjan_scc(graph):
        if len(scc) < 2:
            continue
        members = set(scc)
        groups.append([
            entry for entry in eligible if bytes(entry[0].coin.name()) in members
        ])

    return groups


def block_tweak_points(coin_spends: list[CoinSpend]) -> list[G1Element]:
    """The tweak points of a block ("Tweak Points").

    One T = input_hash * A_sum for each spend group — every single-input
    group and every multi-input group — leaving out groups whose key sum is
    the identity element or whose input_hash is zero.
    """
    tweak_points = []
    for group in form_spend_groups(coin_spends):
        coin_ids = [bytes(coin_spend.coin.name()) for coin_spend, _ in group]
        pk_sum = aggregate_sender_pks([pk for _, pk in group])  # one term per coin
        tweak_point = compute_tweak_point(coin_ids, pk_sum)
        if tweak_point is not None:
            tweak_points.append(tweak_point)
    return tweak_points


def scan_block(
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    coin_spends: list[CoinSpend],
    additions: list[Coin],
    labels: dict[bytes, int] | None = None,
    output_filter: Callable[[Coin], bool] | None = None,
) -> list[dict]:
    """Procedure ScanBlock ("Scanning a Block").

    Args:
        scan_sk: Recipient's scan secret key.
        spend_pk: Recipient's spend public key.
        coin_spends: All coin spends in the block.
        additions: All new coins in the block.
        labels: Optional dict mapping bytes(label_pk) -> m (the change label
            m = 0 is always checked).
        output_filter: Optional wallet policy, see scan_for_silent_payment.

    Each spend group is checked against the additions created by coins of
    that group, so reward coins (which have no parent spend) are never
    matched.

    Returns the detections of scan_for_silent_payment, each with one more
    key, group_coin_ids: the coin IDs of the spend group that paid it. A
    coin is reported once.
    """
    if labels is None or 0 not in labels.values():
        labels = {**build_label_map(scan_sk), **(labels or {})}

    additions_by_parent: dict[bytes, list[Coin]] = {}
    for coin in additions:
        additions_by_parent.setdefault(bytes(coin.parent_coin_info), []).append(coin)

    detected = []
    detected_coin_ids: set[bytes] = set()
    for group in form_spend_groups(coin_spends):
        coin_ids = [bytes(coin_spend.coin.name()) for coin_spend, _ in group]
        pk_sum = aggregate_sender_pks([pk for _, pk in group])  # one term per coin
        outputs = [
            coin for coin_id in coin_ids for coin in additions_by_parent.get(coin_id, [])
        ]
        if not outputs:
            continue
        results = scan_for_silent_payment(
            scan_sk, spend_pk, pk_sum, coin_ids, outputs,
            labels=labels, output_filter=output_filter,
        )
        for d in results:
            if d["coin_id"] in detected_coin_ids:
                continue
            detected_coin_ids.add(d["coin_id"])
            detected.append({**d, "group_coin_ids": coin_ids})
    return detected


def scan_block_tweak_points(
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    tweak_points: list[bytes],
    additions: list[Coin],
    labels: dict[bytes, int] | None = None,
    output_filter: Callable[[Coin], bool] | None = None,
) -> list[dict]:
    """Scan a block from tweak points supplied by another party ("Tweak Points").

    Args:
        tweak_points: The block's tweak points, 48 bytes each.
        additions: All additions of the block that were created by a coin
            spend. Reward coins must be left out by the caller.

    Every tweak point is validated before it is multiplied by the scan
    secret key (ValueError if one is not a valid, non-identity element of
    the prime-order subgroup), and is checked against all of `additions`,
    because a tweak point carries no parent information.
    """
    if labels is None or 0 not in labels.values():
        labels = {**build_label_map(scan_sk), **(labels or {})}

    detected = []
    detected_coin_ids: set[bytes] = set()
    for tweak_point in tweak_points:
        results = scan_tweak_point(
            scan_sk, spend_pk, bytes(tweak_point), additions,
            labels=labels, output_filter=output_filter,
        )
        for d in results:
            if d["coin_id"] in detected_coin_ids:
                continue
            detected_coin_ids.add(d["coin_id"])
            detected.append(d)
    return detected


# --- Chain access (coinset CLI) ---

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


def _coin_from_json(coin: dict) -> Coin:
    return Coin(
        bytes.fromhex(strip_0x(coin["parent_coin_info"])),
        bytes.fromhex(strip_0x(coin["puzzle_hash"])),
        coin["amount"],
    )


def fetch_block(height: int) -> tuple[list[CoinSpend], list[Coin]]:
    """Fetch a block's coin spends and its additions created by a coin spend."""
    data = coinset_json("get_additions_and_removals", str(height))

    coin_spends = []
    for removal in data.get("removals", []):
        # Reward coins are spends like any other: no removal is skipped here.
        coin = _coin_from_json(removal["coin"])
        try:
            spend_data = coinset_json(
                "get_puzzle_and_solution", "0x" + bytes(coin.name()).hex()
            )
            coin_solution = spend_data.get("coin_solution") or spend_data.get("coin_spend")
            if not coin_solution or "puzzle_reveal" not in coin_solution:
                continue
            puzzle = Program.from_bytes(
                bytes.fromhex(strip_0x(coin_solution["puzzle_reveal"]))
            )
            solution = Program.from_bytes(
                bytes.fromhex(strip_0x(coin_solution.get("solution", "0x80")))
            )
        except (RuntimeError, KeyError, ValueError):
            # Spend data not available; skip
            continue
        coin_spends.append(CoinSpend(coin, puzzle, solution))

    # Reward coins have no parent spend and cannot be silent payment outputs.
    additions = [
        _coin_from_json(a["coin"])
        for a in data.get("additions", [])
        if not a.get("coinbase", False)
    ]
    return coin_spends, additions


def process_block(
    height: int,
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    labels: dict | None = None,
    min_amount: int = 0,
) -> list[dict]:
    """Process a single transaction block for silent payment detections.

    `min_amount` is a wallet policy: smaller outputs are not reported. They
    still count as matches while scanning, so a dust output never hides the
    outputs that follow it.

    Returns one dict per detected coin with keys coin_id, parent_coin_info,
    puzzle_hash, spend_tweak (hex), amount, block_height, k and label.
    """
    coin_spends, additions = fetch_block(height)
    output_filter = (lambda coin: coin.amount >= min_amount) if min_amount > 0 else None

    detected = []
    for d in scan_block(scan_sk, spend_pk, coin_spends, additions, labels, output_filter):
        coin = d["coin"]
        detected.append({
            "coin_id": d["coin_id"].hex(),
            "parent_coin_info": bytes(coin.parent_coin_info).hex(),
            "amount": coin.amount,
            "block_height": height,
            "puzzle_hash": d["puzzle_hash"].hex(),
            "k": d["k"],
            "label": d["label"],
            "spend_tweak": f"{d['spend_tweak']:064x}",
            "inputs": len(d["group_coin_ids"]),
        })
    return detected


def scan_blocks(
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    start_height: int,
    end_height: int | None = None,
    labels: dict | None = None,
    batch_size: int = 50,
    min_amount: int = 0,
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
            results = process_block(h, scan_sk, spend_pk, labels, min_amount)
            all_detected.extend(results)

        print(
            f"Scanning blocks {batch_start}-{batch_end - 1}... "
            f"({len(all_detected)} found so far)",
            file=sys.stderr,
        )

        batch_start = batch_end

    return all_detected


def detect_coin(
    coin_id_hex: str,
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    labels: dict | None = None,
) -> tuple[dict, dict | None]:
    """Check one coin: scan the block that created it and look for the coin.

    Returns (coin_record, detection); detection is None when the coin is not
    a silent payment to these keys. Scanning the whole block is what forms
    the spend groups, so single-input and multi-input payments are both
    found.
    """
    coin_id_hex = strip_0x(coin_id_hex)
    result = coinset_json("get_coin_record_by_name", "0x" + coin_id_hex)
    if not result.get("success"):
        raise RuntimeError(f"Could not find coin: {result}")
    coin_record = result["coin_record"]
    height = coin_record["confirmed_block_index"]
    for d in process_block(height, scan_sk, spend_pk, labels):
        if d["coin_id"] == coin_id_hex:
            return coin_record, d
    return coin_record, None


def parse_label_indices(text: str | None) -> list[int]:
    """Parse a comma-separated list of label indices (e.g. "1,2,3")."""
    if not text:
        return []
    return [int(x.strip()) for x in text.split(",") if x.strip()]


def main():
    """CLI entry point for the blockchain scanner."""
    parser = argparse.ArgumentParser(
        description="Scan testnet11 blocks for silent payments addressed to a recipient."
    )
    parser.add_argument(
        "words",
        nargs="*",
        metavar="address_or_mnemonic_word",
        help="Optional unlabeled silent payment address (tspxch1...) to check "
             "the keys against, then the mnemonic words (if not using -f or "
             "--scan-key)",
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
        "-f", "--mnemonic-file",
        metavar="FILE",
        help="Mnemonic file path",
    )
    parser.add_argument(
        "--scan-key",
        help="Scan SECRET key hex (watch-only mode, with --spend-pubkey)",
    )
    parser.add_argument(
        "--spend-pubkey", "--spend-key",
        dest="spend_pubkey",
        help="Spend PUBLIC key hex (watch-only mode, with --scan-key)",
    )
    parser.add_argument(
        "--labels",
        help="Comma-separated label indices to scan for (e.g., 1,2,3). "
             "The change label 0 is always scanned for.",
    )
    parser.add_argument(
        "--min-amount",
        type=int,
        default=0,
        help="Do not report outputs smaller than this many mojos (default: 0)",
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

    args = parser.parse_args()

    if args.node:
        COINSET_BASE_ARGS.clear()
        COINSET_BASE_ARGS.extend(["--api", args.node])
    elif args.local:
        COINSET_BASE_ARGS.clear()
        COINSET_BASE_ARGS.append("--local")

    # A leading positional that looks like a silent payment address is the
    # address; everything else is the mnemonic.
    address = None
    mnemonic_words = list(args.words)
    if mnemonic_words and mnemonic_words[0].lower().startswith(("spxch1", "tspxch1")):
        address = mnemonic_words.pop(0)

    # Scan secret key + spend public key: given directly, or from a mnemonic
    try:
        scan_sk, spend_pk = load_scan_keys(
            args.scan_key, args.spend_pubkey, args.mnemonic_file, mnemonic_words
        )
    except ValueError as e:
        parser.error(str(e))

    # If an address is provided, check that it belongs to these keys
    if address:
        addr_scan_pk, addr_spend_pk = decode_silent_payment_address(address)
        if addr_scan_pk != bytes(scan_sk.get_g1()) or addr_spend_pk != bytes(spend_pk):
            print(
                "Warning: the address does not match the scan and spend keys "
                "(a labeled address differs in its second key)",
                file=sys.stderr,
            )

    # Label map: the requested labels plus the change label m = 0
    label_map = build_label_map(scan_sk, parse_label_indices(args.labels))

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
        min_amount=args.min_amount,
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
        print(f"  Output index: {d['k']}")
        print(f"  Label:        {label_str}")
        print(f"  Spend tweak:  {d['spend_tweak']}")
        print()


if __name__ == "__main__":
    main()
