"""
Tests for the SDK-backed blockchain scanner (scanner.py) with mocked coinset CLI.

``scanner.py`` runs on the SDK block path: ``process_block``/``scan_blocks``
marshal each block's removals/additions through ``sdk_adapter`` and call
``tweak_data_from_block_spends`` + ``scan_from_tweaks`` (the SDK owns ALL grouping
— the single concurrent-spend SCC Pass 2 over the opcode-64 directed graph — ECDH,
one-time derivation, and the pollution defense INTERNALLY).

The mocked coinset dispatcher patches ``coinset.subprocess.run`` (scanner.py does
not import subprocess — ``coinset.py`` owns the boundary) and feeds per-block
fixture shapes. The coin marshaling delegates coin-id computation to the SDK
(``Coin.coin_id()`` == ``make_coin_name`` SHA256), so the per-coin-id
``get_puzzle_and_solution`` dispatch keys match.

Coverage:
  * single-input detection (coin_id/amount/block_height reported),
  * coinbase removals skipped (no puzzle/solution lookup attempted),
  * non-standard puzzles produce no detection (SDK standard-puzzle-filter skip),
  * empty range returns [],
  * multi-input same-derivation-index (concurrent-spend group, A_sum = sp+sp),
  * multi-input cross-index (opcode-64 concurrent-spend SCC cycle),
  * directed-SCC pollution defense (the polluter is NOT aggregated),
  * mixed same-index + cross-index in one block,
  * sender->scanner round-trip (send_payment.build_coin_spend_conditions output).
"""

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from chia_rs import Program

import shared
import sdk_adapter
from scanner import scan_blocks, process_block


# --- SDK-backed offline output builder ---
#
# The fixture builders below synthesize offline silent-payment outputs and sender
# puzzles through the SDK adapter (compute_input_hash + derive_one_time_puzzle_hash
# + aggregate_sender_sks/pks, and clvm.standard_spend for the sender puzzle
# reveal) — the same primitives the SDK send path uses.


def create_silent_payment_outputs(sender_sks, coin_ids, recipients):
    """Build offline silent-payment outputs via the SDK adapter.

    For the single-recipient case this test uses. ``sender_sks`` is a single SDK
    ``SecretKey`` (synthetic) or a list of them; ``recipients`` is
    ``[(scan_pk, spend_pk)]``. Returns ``[(None, puzzle_hash_bytes)]`` — only the
    puzzle hash (index 1) is consumed by the tests.
    """
    sks = sender_sks if isinstance(sender_sks, list) else [sender_sks]
    scan_pk, spend_pk = recipients[0]
    agg_sk = sdk_adapter.aggregate_sender_sks(sks)
    agg_pk = sdk_adapter.aggregate_sender_pks([sk.public_key() for sk in sks])
    input_hash = sdk_adapter.compute_input_hash(list(coin_ids), agg_pk)
    ph = sdk_adapter.derive_one_time_puzzle_hash(scan_pk, spend_pk, agg_sk, input_hash, 0)
    return [(None, bytes(ph))]


# --- Test helpers ---

def mock_coinset_response(stdout_dict, returncode=0):
    """Create a mock subprocess.CompletedProcess with JSON stdout."""
    return MagicMock(
        returncode=returncode,
        stdout=json.dumps(stdout_dict),
        stderr="" if returncode == 0 else "some error",
    )


def make_coin_name(parent_hex: str, puzzle_hash_hex: str, amount: int) -> bytes:
    """Compute coin name = SHA256(parent || puzzle_hash || amount).

    Chia's variable-length big-endian amount encoding for coin IDs — byte-equal to
    the SDK's ``Coin.coin_id()``, so the dispatcher's per-coin-id keys match the
    ids scanner.py derives via ``sdk_adapter.coin_from_addition``.
    """
    parent = bytes.fromhex(parent_hex)
    ph = bytes.fromhex(puzzle_hash_hex)
    if amount == 0:
        amt_bytes = b"\x00"
    else:
        byte_count = (amount.bit_length() + 8) >> 3
        amt_bytes = amount.to_bytes(byte_count, "big")
    return hashlib.sha256(parent + ph + amt_bytes).digest()


def _strip_0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h


def _empty_labels():
    """Empty SDK LabelRegistry (unlabeled scan) for the recipient scan key."""
    return sdk_adapter.label_registry(_scan_sk_sdk, [])


def _build_opcode_64_solution(predecessor_coin_id: bytes) -> bytes:
    """Build a CLVM solution emitting exactly one [64, predecessor_coin_id] condition.

    Mirrors the standard p2_delegated_puzzle_or_hidden_puzzle solution shape:
    (() delegated_puzzle ()) where delegated_puzzle = (1 . [[64, predecessor]]).
    """
    delegated = Program.to((1, [[64, predecessor_coin_id]]))
    dp_bytes = bytes(delegated)
    return b"\xff\x80\xff" + dp_bytes + b"\xff\x80\x80"


def _create_coin_solution(output_ph: bytes, amount: int, *, also_op64=None) -> bytes:
    """Standard-spend solution emitting a recipient CREATE_COIN (+ optional op64)."""
    conds = [[51, output_ph, amount]]
    if also_op64 is not None:
        conds.append([64, also_op64])
    delegated = Program.to((1, conds))
    return b"\xff\x80\xff" + bytes(delegated) + b"\xff\x80\x80"


# --- Key fixtures (recipient TV + deterministic senders) ---

# Recipient: derives scan and spend keys through the SDK (hardened CHIP-0057
# derivation). The scan path takes the scan SECRET key and the
# spend PUBLIC key only; the spend secret key is kept for the tests that turn a
# detection's tweak into the one-time key.
_RECIPIENT_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
_recipient_keys = sdk_adapter.keys_from_mnemonic(_RECIPIENT_MNEMONIC)
_scan_sk_sdk = _recipient_keys.scan_sk()
_spend_sk_sdk = _recipient_keys.spend_sk()
_scan_pk = _recipient_keys.scan_pk()
_spend_pk = _recipient_keys.spend_pk()
_spend_pk_sdk = _spend_pk


def _detect(height, removals_block):
    """Run the SDK-backed process_block with an empty (unlabeled) registry."""
    return process_block(
        height, _scan_sk_sdk, _spend_pk_sdk, _empty_labels()
    )


# Senders at distinct derivation indices (fixed mnemonic — never a real wallet).
# Each carries the SYNTHETIC sk (the ECDH key) + the standard puzzle that curries
# the synthetic pk (what the SDK extracts on-chain), built via clvm.standard_spend
# so no shared.py crypto is referenced.
_SENDER_MNEMONIC = (
    "legal winner thank year wave sausage worth useful "
    "legal winner thank yellow"
)


def _sender(index: int) -> dict:
    wallet_pk, _wallet_sk, synthetic_sk = sdk_adapter.wallet_keys(_SENDER_MNEMONIC, index)
    clvm = sdk_adapter.Clvm()
    spend = clvm.standard_spend(wallet_pk.derive_synthetic(), clvm.delegated_spend([]))
    return {
        "synthetic_sk": synthetic_sk,
        "puzzle_hex": bytes(spend.puzzle.serialize()).hex(),
        "puzzle_hash": bytes(spend.puzzle.tree_hash()).hex(),
    }


_s0 = _sender(0)
_s1 = _sender(1)
_s2 = _sender(2)
_sM = _sender(3)  # polluter
_s4 = _sender(4)
_s5 = _sender(5)


# ==========================================================================
# Single-input detection + the negative/skip paths
# ==========================================================================

class TestScanBlocksSingleInput:

    @patch("coinset.subprocess.run")
    def test_scan_blocks_finds_payment(self, mock_run):
        """scan_blocks detects a single-input silent payment and reports the dict."""
        block_height = 100
        parent = "aa" * 32
        amount = 1_000_000
        coin_name = make_coin_name(parent, _s0["puzzle_hash"], amount)

        outputs = create_silent_payment_outputs(
            _s0["synthetic_sk"], [coin_name], [(_scan_pk, _spend_pk)]
        )
        _, output_ph = outputs[0]
        output_amount = 500_000
        solution = _create_coin_solution(output_ph, output_amount).hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [{"height": block_height, "timestamp": 1700000000}]
                })
            elif command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + coin_name.hex(),
                                  "puzzle_hash": "0x" + output_ph.hex(),
                                  "amount": output_amount}, "coinbase": False},
                        # coinbase addition that must be ignored
                        {"coin": {"parent_coin_info": "0x" + ("00" * 32),
                                  "puzzle_hash": "0x" + ("ff" * 32),
                                  "amount": 1_750_000_000_000}, "coinbase": True},
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + parent,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amount}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "success": True,
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _s0["puzzle_hex"],
                        "solution": "0x" + solution,
                    },
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(
            _scan_sk_sdk, _spend_pk_sdk,
            start_height=100, end_height=100,
        )

        assert len(detections) == 1
        d = detections[0]
        assert {"coin_id", "amount", "block_height", "puzzle_hash", "k", "label", "tweak"} <= set(d)
        # A record carries the tweak, never a one-time SECRET key.
        assert "onetime_sk" not in d
        assert d["k"] == 0 and d["label"] is None
        # The tweak + the spend SECRET key give the key that owns the coin.
        onetime_sk = sdk_adapter.derive_onetime_sk(_spend_sk_sdk, d["tweak"])
        clvm = sdk_adapter.Clvm()
        onetime_ph = clvm.standard_spend(
            onetime_sk.derive_synthetic().public_key(), clvm.delegated_spend([])
        ).puzzle.tree_hash()
        assert bytes(onetime_ph).hex() == d["puzzle_hash"]
        assert d["amount"] == output_amount
        assert d["block_height"] == block_height
        assert d["puzzle_hash"] == output_ph.hex()

    @patch("coinset.subprocess.run")
    def test_scan_blocks_skips_nonstandard(self, mock_run):
        """A non-standard puzzle reveal yields zero detections (SDK standard-puzzle-filter skip)."""
        block_height = 200
        nonstandard_puzzle_hex = "ff01ff8080"
        fake_parent = "bb" * 32
        fake_ph = "cc" * 32

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [{"height": block_height, "timestamp": 1700000000}]
                })
            elif command == "get_additions_and_removals":
                removal_coin_name = make_coin_name(fake_parent, fake_ph, 100)
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + removal_coin_name.hex(),
                                  "puzzle_hash": "0x" + ("dd" * 32),
                                  "amount": 50}, "coinbase": False},
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + fake_parent,
                                  "puzzle_hash": "0x" + fake_ph,
                                  "amount": 100}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "success": True,
                    "coin_solution": {
                        "puzzle_reveal": "0x" + nonstandard_puzzle_hex,
                        "solution": "0x80",
                    },
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(
            _scan_sk_sdk, _spend_pk_sdk,
            start_height=200, end_height=200,
        )
        assert detections == []

    @patch("coinset.subprocess.run")
    def test_scan_blocks_skips_coinbase(self, mock_run):
        """Coinbase removals never trigger a puzzle/solution lookup (caller filter)."""
        block_height = 300

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [{"height": block_height, "timestamp": 1700000000}]
                })
            elif command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + ("ab" * 32),
                                  "puzzle_hash": "0x" + ("cd" * 32),
                                  "amount": 100}, "coinbase": True},
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + ("ef" * 32),
                                  "puzzle_hash": "0x" + ("12" * 32),
                                  "amount": 200}, "coinbase": True},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                raise AssertionError("get_puzzle_and_solution should not be called for coinbase")
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(
            _scan_sk_sdk, _spend_pk_sdk,
            start_height=300, end_height=300,
        )
        assert detections == []

    @patch("coinset.subprocess.run")
    def test_scan_blocks_empty_range(self, mock_run):
        """No transaction blocks in range -> empty detections."""

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [
                        {"height": 400, "timestamp": None},
                        {"height": 401, "timestamp": None},
                        {"height": 402, "timestamp": None},
                    ]
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(
            _scan_sk_sdk, _spend_pk_sdk,
            start_height=400, end_height=402,
        )
        assert detections == []


class TestProcessBlock:

    @patch("coinset.subprocess.run")
    def test_process_block_returns_detection_dict(self, mock_run):
        """process_block returns dicts with coin_id/amount/block_height (new signature)."""
        block_height = 500
        parent = "aa" * 32
        amount = 1_000_000
        coin_name = make_coin_name(parent, _s0["puzzle_hash"], amount)
        outputs = create_silent_payment_outputs(
            _s0["synthetic_sk"], [coin_name], [(_scan_pk, _spend_pk)]
        )
        _, output_ph = outputs[0]
        output_amount = 500_000
        solution = _create_coin_solution(output_ph, output_amount).hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + coin_name.hex(),
                                  "puzzle_hash": "0x" + output_ph.hex(),
                                  "amount": output_amount}, "coinbase": False},
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + parent,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amount}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "success": True,
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _s0["puzzle_hex"],
                        "solution": "0x" + solution,
                    },
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(
            block_height, _scan_sk_sdk, _spend_pk_sdk, _empty_labels()
        )
        assert len(results) == 1
        assert results[0]["block_height"] == block_height
        assert results[0]["amount"] == output_amount
        assert "coin_id" in results[0]


    @patch("coinset.subprocess.run")
    def test_process_block_reports_both_coins_sharing_one_time_ph(self, mock_run):
        """CHIP-0057 "Outputs Sharing a Puzzle Hash": one spend creates TWO coins
        with the same one-time puzzle hash (different amounts); process_block
        reports both, with the same k and tweak."""
        block_height = 300
        parent = "ab" * 32
        amount = 2_000_000
        coin_name = make_coin_name(parent, _s0["puzzle_hash"], amount)

        outputs = create_silent_payment_outputs(
            _s0["synthetic_sk"], [coin_name], [(_scan_pk, _spend_pk)]
        )
        _, output_ph = outputs[0]
        amounts = (400_000, 600_000)
        delegated = Program.to((1, [[51, output_ph, a] for a in amounts]))
        solution = (b"\xff\x80\xff" + bytes(delegated) + b"\xff\x80\x80").hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + coin_name.hex(),
                                  "puzzle_hash": "0x" + output_ph.hex(),
                                  "amount": a}, "coinbase": False}
                        for a in amounts
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + parent,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amount}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "success": True,
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _s0["puzzle_hex"],
                        "solution": "0x" + solution,
                    },
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(block_height, _scan_sk_sdk, _spend_pk_sdk, _empty_labels())

        assert len(results) == 2
        assert sorted(r["amount"] for r in results) == sorted(amounts)
        assert len({r["coin_id"] for r in results}) == 2
        assert {r["puzzle_hash"] for r in results} == {output_ph.hex()}
        assert {r["k"] for r in results} == {0}
        assert {r["label"] for r in results} == {None}
        assert len({r["tweak"] for r in results}) == 1
        assert {r["parent_coin_id"] for r in results} == {coin_name.hex()}


# ==========================================================================
# Multi-input: same-derivation-index + cross-index (opcode-64 concurrent-spend SCC)
# ==========================================================================

class TestProcessBlockMultiInput:

    @patch("coinset.subprocess.run")
    def test_process_block_same_index_no_cycle_not_detectable(self, mock_run):
        """Two SAME-index removals (same puzzle hash, A_sum = sp + sp) with NO
        opcode-64 ASSERT_CONCURRENT_SPEND cycle are by-design NOT detectable.

        CHIP-0057 "Scanning a Block" has a single Pass 2: same-puzzle-hash
        multi-input sets detect ONLY when bound by the opcode-64 cycle (a CHIP MUST
        for multi-input sends). Without the cycle the spends do not form an SCC, the
        aggregated A_sum output is never derived, and process_block returns no match
        for the multi-input output. There is no standalone same-puzzle-hash
        grouping pass.
        """
        block_height = 600
        parent_0 = "aa" * 32
        parent_1 = "bb" * 32
        amount_0 = 1_000_000
        amount_1 = 2_000_000
        coin_0 = make_coin_name(parent_0, _s0["puzzle_hash"], amount_0)
        coin_1 = make_coin_name(parent_1, _s0["puzzle_hash"], amount_1)

        outputs = create_silent_payment_outputs(
            [_s0["synthetic_sk"], _s0["synthetic_sk"]],
            [coin_0, coin_1],
            [(_scan_pk, _spend_pk)],
        )
        _, output_ph = outputs[0]
        output_amount = 1_500_000
        # No opcode-64 cycle; coin 0 emits the recipient CREATE_COIN only. Under
        # single-Pass-2 the unbound same-PH pair does not regroup -> no detection.
        sol_0 = _create_coin_solution(output_ph, output_amount).hex()
        sol_1 = (b"\xff\x80\xff" + bytes(Program.to((1, []))) + b"\xff\x80\x80").hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + coin_0.hex(),
                                  "puzzle_hash": "0x" + output_ph.hex(),
                                  "amount": output_amount}, "coinbase": False},
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + parent_0,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amount_0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + parent_1,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amount_1}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = _strip_0x(cmd[4])
                sol = sol_0 if coin_hex == coin_0.hex() else sol_1
                return mock_coinset_response({
                    "success": True,
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _s0["puzzle_hex"],
                        "solution": "0x" + sol,
                    },
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(
            block_height, _scan_sk_sdk, _spend_pk_sdk, _empty_labels()
        )
        matches = [r for r in results if r["puzzle_hash"] == output_ph.hex()]
        assert len(matches) == 0, (
            "same-PH multi-input WITHOUT an opcode-64 cycle must NOT be detected "
            f"under the single-Pass-2 CHIP contract, got {len(matches)}"
        )

    @patch("coinset.subprocess.run")
    def test_process_block_concurrent_spend_scc_two_coin_cycle(self, mock_run):
        """Cross-index opcode-64 2-cycle (A_sum = idx0 + idx1) detected via SDK SCC."""
        block_height = 1000
        parent_0 = "11" * 32
        parent_1 = "22" * 32
        amount_0 = 1_000_000
        amount_1 = 2_000_000
        coin_0 = make_coin_name(parent_0, _s0["puzzle_hash"], amount_0)
        coin_1 = make_coin_name(parent_1, _s1["puzzle_hash"], amount_1)

        outputs = create_silent_payment_outputs(
            [_s0["synthetic_sk"], _s1["synthetic_sk"]],
            [coin_0, coin_1],
            [(_scan_pk, _spend_pk)],
        )
        _, output_ph = outputs[0]
        output_amount = 1_500_000

        # coin 0 -> recipient CREATE_COIN + asserts coin 1; coin 1 asserts coin 0.
        sol_0 = _create_coin_solution(output_ph, output_amount, also_op64=coin_1).hex()
        sol_1 = _build_opcode_64_solution(coin_0).hex()

        table = {
            coin_0.hex(): (_s0["puzzle_hex"], sol_0),
            coin_1.hex(): (_s1["puzzle_hex"], sol_1),
        }

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + coin_0.hex(),
                                  "puzzle_hash": "0x" + output_ph.hex(),
                                  "amount": output_amount}, "coinbase": False},
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + parent_0,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amount_0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + parent_1,
                                  "puzzle_hash": "0x" + _s1["puzzle_hash"],
                                  "amount": amount_1}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = _strip_0x(cmd[4])
                pz, sol = table[coin_hex]
                return mock_coinset_response({
                    "success": True,
                    "coin_solution": {"puzzle_reveal": "0x" + pz, "solution": "0x" + sol},
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(
            block_height, _scan_sk_sdk, _spend_pk_sdk, _empty_labels()
        )
        matches = [r for r in results if r["puzzle_hash"] == output_ph.hex()]
        assert len(matches) == 1, (
            f"expected 1 concurrent-spend detection, got {len(matches)}: {results}"
        )
        assert matches[0]["amount"] == output_amount

    @patch("coinset.subprocess.run")
    def test_process_block_concurrent_spend_pollution_defense(self, mock_run):
        """A polluter c->a (one-way) is isolated by the directed SCC; the legit
        a<->b output is detected, the polluted pk_a+pk_b+pk_c output is NOT.

        Discriminator: an undirected-CC scanner would pull c into the victim group
        and derive the polluted PH. The SDK's directed-SCC defense must not.
        """
        block_height = 1200
        parent_a = "41" * 32
        parent_b = "42" * 32
        parent_c = "4d" * 32
        amount_a = 1_000_000
        amount_b = 2_000_000
        amount_c = 5_000_000
        coin_a = make_coin_name(parent_a, _s0["puzzle_hash"], amount_a)
        coin_b = make_coin_name(parent_b, _s1["puzzle_hash"], amount_b)
        coin_c = make_coin_name(parent_c, _sM["puzzle_hash"], amount_c)

        legit_outputs = create_silent_payment_outputs(
            [_s0["synthetic_sk"], _s1["synthetic_sk"]],
            [coin_a, coin_b],
            [(_scan_pk, _spend_pk)],
        )
        _, legit_ph = legit_outputs[0]
        polluted_outputs = create_silent_payment_outputs(
            [_s0["synthetic_sk"], _s1["synthetic_sk"], _sM["synthetic_sk"]],
            [coin_a, coin_b, coin_c],
            [(_scan_pk, _spend_pk)],
        )
        _, polluted_ph = polluted_outputs[0]
        assert legit_ph != polluted_ph, "test setup error: pollution PH equals legit PH"

        output_amount = 4_500_000
        # legit cycle a<->b; polluter c->a (one-way).
        sol_a = _create_coin_solution(legit_ph, output_amount, also_op64=coin_b).hex()
        sol_b = _build_opcode_64_solution(coin_a).hex()
        sol_c = _build_opcode_64_solution(coin_a).hex()

        table = {
            coin_a.hex(): (_s0["puzzle_hex"], sol_a),
            coin_b.hex(): (_s1["puzzle_hex"], sol_b),
            coin_c.hex(): (_sM["puzzle_hex"], sol_c),
        }

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + coin_a.hex(),
                                  "puzzle_hash": "0x" + legit_ph.hex(),
                                  "amount": output_amount}, "coinbase": False},
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + parent_a,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amount_a}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + parent_b,
                                  "puzzle_hash": "0x" + _s1["puzzle_hash"],
                                  "amount": amount_b}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + parent_c,
                                  "puzzle_hash": "0x" + _sM["puzzle_hash"],
                                  "amount": amount_c}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = _strip_0x(cmd[4])
                pz, sol = table[coin_hex]
                return mock_coinset_response({
                    "success": True,
                    "coin_solution": {"puzzle_reveal": "0x" + pz, "solution": "0x" + sol},
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(
            block_height, _scan_sk_sdk, _spend_pk_sdk, _empty_labels()
        )
        detected_phs = {r["puzzle_hash"] for r in results}
        assert legit_ph.hex() in detected_phs, f"legit a<->b output not detected: {results}"
        assert polluted_ph.hex() not in detected_phs, (
            "polluter was aggregated into the victim group (directed-SCC defense failed)"
        )

    @patch("coinset.subprocess.run")
    def test_process_block_mixed_same_index_and_concurrent_spend(self, mock_run):
        """One block with an unbound same-PH group AND an opcode-64 concurrent-spend
        cycle group: under the single-Pass-2 CHIP contract ONLY the cycle group is
        detected. Group A (same-PH, NO opcode-64) is by-design NOT detectable; Group
        B (cross-index opcode-64 2-cycle) IS detected exactly once.
        """
        block_height = 1400
        # Group A (same-index, same puzzle hash, NO opcode-64 -> not detectable).
        pa0, pa1 = "c0" * 32, "c1" * 32
        amt_a0, amt_a1 = 1_000_000, 2_000_000
        ca0 = make_coin_name(pa0, _s0["puzzle_hash"], amt_a0)
        ca1 = make_coin_name(pa1, _s0["puzzle_hash"], amt_a1)
        outs_a = create_silent_payment_outputs(
            [_s0["synthetic_sk"], _s0["synthetic_sk"]], [ca0, ca1], [(_scan_pk, _spend_pk)]
        )
        _, group_a_ph = outs_a[0]

        # Group B (concurrent-spend): two cross-index coins bound by an opcode-64
        # 2-cycle -> detected via the single Pass-2 SCC.
        pb0, pb1 = "d0" * 32, "d1" * 32
        amt_b0, amt_b1 = 3_000_000, 4_000_000
        cb0 = make_coin_name(pb0, _s1["puzzle_hash"], amt_b0)
        cb1 = make_coin_name(pb1, _s2["puzzle_hash"], amt_b1)
        outs_b = create_silent_payment_outputs(
            [_s1["synthetic_sk"], _s2["synthetic_sk"]], [cb0, cb1], [(_scan_pk, _spend_pk)]
        )
        _, group_b_ph = outs_b[0]
        assert group_a_ph != group_b_ph

        amt_a, amt_b = 2_750_000, 3_500_000
        sol_a0 = _create_coin_solution(group_a_ph, amt_a).hex()
        sol_a1 = (b"\xff\x80\xff" + bytes(Program.to((1, []))) + b"\xff\x80\x80").hex()
        sol_b0 = _create_coin_solution(group_b_ph, amt_b, also_op64=cb1).hex()
        sol_b1 = _build_opcode_64_solution(cb0).hex()

        table = {
            ca0.hex(): (_s0["puzzle_hex"], sol_a0),
            ca1.hex(): (_s0["puzzle_hex"], sol_a1),
            cb0.hex(): (_s1["puzzle_hex"], sol_b0),
            cb1.hex(): (_s2["puzzle_hex"], sol_b1),
        }

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + ca0.hex(),
                                  "puzzle_hash": "0x" + group_a_ph.hex(),
                                  "amount": amt_a}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + cb0.hex(),
                                  "puzzle_hash": "0x" + group_b_ph.hex(),
                                  "amount": amt_b}, "coinbase": False},
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + pa0,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amt_a0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + pa1,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amt_a1}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + pb0,
                                  "puzzle_hash": "0x" + _s1["puzzle_hash"],
                                  "amount": amt_b0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + pb1,
                                  "puzzle_hash": "0x" + _s2["puzzle_hash"],
                                  "amount": amt_b1}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = _strip_0x(cmd[4])
                pz, sol = table[coin_hex]
                return mock_coinset_response({
                    "success": True,
                    "coin_solution": {"puzzle_reveal": "0x" + pz, "solution": "0x" + sol},
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(
            block_height, _scan_sk_sdk, _spend_pk_sdk, _empty_labels()
        )
        detected_phs = {r["puzzle_hash"] for r in results}
        # Group A (same-PH, no cycle) is NOT detectable under single-Pass-2.
        assert group_a_ph.hex() not in detected_phs, (
            f"unbound same-PH group A must NOT be detected (single-Pass-2): {results}"
        )
        # Group B (opcode-64 cycle) IS detected, exactly once.
        assert group_b_ph.hex() in detected_phs, (
            f"concurrent-spend group B not detected: {results}"
        )
        unique = {r["coin_id"] for r in results if r["puzzle_hash"] == group_b_ph.hex()}
        assert len(unique) == 1, f"expected 1 unique concurrent-spend detection: {results}"


# ==========================================================================
# Sender<->scanner round-trip via the actual sender helper
# ==========================================================================

class TestSenderScannerRoundtrip:

    @patch("coinset.subprocess.run")
    def test_sender_scanner_roundtrip_two_coin_cycle(self, mock_run):
        """A spend bundle emitted by send_payment.build_coin_spend_conditions (the
        actual sender helper) is detected by the SDK-backed process_block's SCC path.

        Fails if EITHER side breaks: a non-cyclic sender pattern won't form the SCC,
        and a broken SDK condition walker won't extract the cycle.
        """
        from send_payment import build_coin_spend_conditions

        block_height = 1500
        parent_0 = "e0" * 32
        parent_1 = "e1" * 32
        amount_0 = 1_000_000
        amount_1 = 2_000_000
        coin_0 = make_coin_name(parent_0, _s0["puzzle_hash"], amount_0)
        coin_1 = make_coin_name(parent_1, _s1["puzzle_hash"], amount_1)

        outputs = create_silent_payment_outputs(
            [_s0["synthetic_sk"], _s1["synthetic_sk"]],
            [coin_0, coin_1],
            [(_scan_pk, _spend_pk)],
        )
        _, output_ph = outputs[0]
        output_amount = 2_500_000

        sage_coins = [
            {"parent_coin_info": parent_0, "puzzle_hash": _s0["puzzle_hash"],
             "amount": amount_0, "coin_id": coin_0},
            {"parent_coin_info": parent_1, "puzzle_hash": _s1["puzzle_hash"],
             "amount": amount_1, "coin_id": coin_1},
        ]
        primary_outputs = [[51, output_ph, output_amount]]
        conditions_0 = build_coin_spend_conditions(0, sage_coins, primary_outputs)
        conditions_1 = build_coin_spend_conditions(1, sage_coins, [])

        # Guard: the sender helper must emit the cyclic opcode-64 binding.
        op64_0 = [c for c in conditions_0 if c[0] == 64]
        op64_1 = [c for c in conditions_1 if c[0] == 64]
        assert len(op64_0) == 1 and op64_0[0][1] == coin_1
        assert len(op64_1) == 1 and op64_1[0][1] == coin_0

        def _serialize(conds):
            delegated = Program.to((1, conds))
            return b"\xff\x80\xff" + bytes(delegated) + b"\xff\x80\x80"

        sol_0 = _serialize(conditions_0).hex()
        sol_1 = _serialize(conditions_1).hex()
        table = {
            coin_0.hex(): (_s0["puzzle_hex"], sol_0),
            coin_1.hex(): (_s1["puzzle_hex"], sol_1),
        }

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {"coin": {"parent_coin_info": "0x" + coin_0.hex(),
                                  "puzzle_hash": "0x" + output_ph.hex(),
                                  "amount": output_amount}, "coinbase": False},
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + parent_0,
                                  "puzzle_hash": "0x" + _s0["puzzle_hash"],
                                  "amount": amount_0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + parent_1,
                                  "puzzle_hash": "0x" + _s1["puzzle_hash"],
                                  "amount": amount_1}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = _strip_0x(cmd[4])
                pz, sol = table[coin_hex]
                return mock_coinset_response({
                    "success": True,
                    "coin_solution": {"puzzle_reveal": "0x" + pz, "solution": "0x" + sol},
                })
            return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = process_block(
            block_height, _scan_sk_sdk, _spend_pk_sdk, _empty_labels()
        )
        matches = [d for d in detections if d["puzzle_hash"] == output_ph.hex()]
        assert len(matches) == 1, (
            f"sender<->scanner round-trip failed: expected 1 detection, got "
            f"{len(matches)}; results: {detections}"
        )
        assert matches[0]["amount"] == output_amount
        assert matches[0]["block_height"] == block_height
