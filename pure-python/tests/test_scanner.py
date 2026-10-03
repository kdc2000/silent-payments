"""
Tests for blockchain scanner with mocked coinset CLI responses.

Covers: block-range scanning, sender PK extraction from removals,
coin_id + amount + block_height reporting, skipping non-standard puzzles,
and multi-input detection through ASSERT_CONCURRENT_SPEND cycles.
"""

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from chia_rs import G1Element, PrivateKey

from shared import (
    create_silent_payment_outputs,
    master_sk_to_scan_sk,
    master_sk_to_spend_sk,
    master_sk_to_wallet_sk,
    puzzle_for_pk,
    calculate_synthetic_public_key,
    calculate_synthetic_secret_key,
    aggregate_sender_sks,
    aggregate_sender_pks,
    compute_coin_id,
)
from scanner import coinset_json, scan_blocks, process_block, strip_0x


# --- Test helpers ---

def mock_coinset_response(stdout_dict, returncode=0):
    """Create a mock subprocess.CompletedProcess with JSON stdout."""
    return MagicMock(
        returncode=returncode,
        stdout=json.dumps(stdout_dict),
        stderr="" if returncode == 0 else "some error",
    )


def make_coin_name(parent_hex: str, puzzle_hash_hex: str, amount: int) -> bytes:
    """Compute coin name = SHA256(parent || puzzle_hash || amount)."""
    parent = bytes.fromhex(parent_hex)
    ph = bytes.fromhex(puzzle_hash_hex)
    # Chia uses variable-length big-endian encoding for amounts in coin IDs
    if amount == 0:
        amt_bytes = b"\x00"
    else:
        byte_count = (amount.bit_length() + 8) >> 3
        amt_bytes = amount.to_bytes(byte_count, "big")
    return hashlib.sha256(parent + ph + amt_bytes).digest()


# --- Key fixtures for payment detection test ---

# Sender: derives a wallet key, then the SYNTHETIC key (matches what the scanner extracts)
_sender_master = PrivateKey.from_seed(bytes([2] * 32))
_sender_wallet_sk = master_sk_to_wallet_sk(_sender_master, 0)
_sender_wallet_pk = _sender_wallet_sk.get_g1()
_sender_sk = calculate_synthetic_secret_key(_sender_wallet_sk)  # synthetic SK used for ECDH
_sender_pk = _sender_sk.get_g1()  # synthetic PK = what extract_synthetic_pk returns

# Build the sender's standard puzzle (curries synthetic PK)
_sender_synthetic_pk = calculate_synthetic_public_key(_sender_wallet_pk)
_sender_puzzle = puzzle_for_pk(_sender_wallet_pk)
_sender_puzzle_hex = bytes(_sender_puzzle).hex()

# Recipient: derives scan and spend keys
_recipient_master = PrivateKey.from_seed(bytes([3] * 32))
_scan_sk = master_sk_to_scan_sk(_recipient_master)
_scan_pk = _scan_sk.get_g1()
_spend_sk = master_sk_to_spend_sk(_recipient_master)
_spend_pk = _spend_sk.get_g1()

# A fake parent coin for the sender's spent coin
_fake_parent_info = "aa" * 32
_sender_puzzle_hash = _sender_puzzle.get_tree_hash().hex()

# The sender's spent coin (removal) identity
_sender_coin_amount = 1_000_000
_sender_coin_name = make_coin_name(_fake_parent_info, _sender_puzzle_hash, _sender_coin_amount)

# Create a valid silent payment output from sender to recipient
# Uses synthetic SK so sender_pk in ECDH matches what the scanner extracts from puzzle
_sp_outputs = create_silent_payment_outputs(
    _sender_sk,
    [_sender_coin_name],
    [(_scan_pk, _spend_pk)],
)
_onetime_pk, _output_puzzle_hash = _sp_outputs[0]

# The output coin (addition) has the sender's coin as parent
_output_amount = 500_000

# --- Multi-input fixtures ---

# Second sender coin: same puzzle hash (same wallet, same derivation index), different parent
_fake_parent_info_2 = "bb" * 32
_sender_coin_amount_2 = 2_000_000
_sender_coin_name_2 = make_coin_name(_fake_parent_info_2, _sender_puzzle_hash, _sender_coin_amount_2)

# Multi-input: aggregate two copies of the same synthetic SK (same derivation index)
_multi_agg_sk = aggregate_sender_sks([_sender_sk, _sender_sk])
_multi_agg_pk = _multi_agg_sk.get_g1()

_multi_sp_outputs = create_silent_payment_outputs(
    [_sender_sk, _sender_sk],
    [_sender_coin_name, _sender_coin_name_2],
    [(_scan_pk, _spend_pk)],
)
_multi_onetime_pk, _multi_output_puzzle_hash = _multi_sp_outputs[0]
_multi_output_amount = 1_500_000


# --- Tests ---

class TestCoinsetJson:
    """Tests for the coinset_json CLI wrapper."""

    @patch("scanner.subprocess.run")
    def test_coinset_json_success(self, mock_run):
        """coinset_json returns parsed JSON dict on success."""
        expected = {"blockchain_state": {"peak": {"height": 3875000}}}
        mock_run.return_value = mock_coinset_response(expected)

        result = coinset_json("get_blockchain_state")

        assert result == expected
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert "coinset" in call_args[0][0]
        assert "get_blockchain_state" in call_args[0][0]

    @patch("scanner.subprocess.run")
    def test_coinset_json_error(self, mock_run):
        """coinset_json raises RuntimeError on non-zero exit code."""
        mock_run.return_value = mock_coinset_response({}, returncode=1)

        with pytest.raises(RuntimeError, match="coinset error"):
            coinset_json("get_blockchain_state")


class TestStripHex:
    """Tests for hex prefix normalization."""

    def test_hex_normalization(self):
        """strip_0x handles both prefixed and unprefixed hex consistently."""
        assert strip_0x("0xabcdef") == "abcdef"
        assert strip_0x("abcdef") == "abcdef"
        assert strip_0x("0x") == ""
        assert strip_0x("") == ""


class TestScanBlocks:
    """Tests for the main scan_blocks function."""

    @patch("scanner.subprocess.run")
    def test_scan_blocks_finds_payment(self, mock_run):
        """scan_blocks detects a valid silent payment coin and returns coin_id, amount, block_height."""
        block_height = 100

        # Mock coinset responses for different commands
        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]  # ["coinset", "-t", "-r", <command>, ...]

            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [
                        {"height": block_height, "timestamp": 1700000000},
                    ]
                })
            elif command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _sender_coin_name.hex(),
                                "puzzle_hash": "0x" + _output_puzzle_hash.hex(),
                                "amount": _output_amount,
                            },
                            "coinbase": False,
                        },
                        # A coinbase addition that should be ignored
                        {
                            "coin": {
                                "parent_coin_info": "0x" + ("00" * 32),
                                "puzzle_hash": "0x" + ("ff" * 32),
                                "amount": 1_750_000_000_000,
                            },
                            "coinbase": True,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _fake_parent_info,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": _sender_coin_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _sender_puzzle_hex,
                        "solution": "0x80",
                    }
                })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(_scan_sk, _spend_pk, start_height=100, end_height=100)

        assert len(detections) == 1
        d = detections[0]
        assert "coin_id" in d
        assert "amount" in d
        assert "block_height" in d
        assert d["amount"] == _output_amount
        assert d["block_height"] == block_height

    @patch("scanner.subprocess.run")
    def test_scan_blocks_skips_nonstandard(self, mock_run):
        """scan_blocks produces zero detections when extract_synthetic_pk returns None."""
        block_height = 200

        # A non-standard puzzle that extract_synthetic_pk can't parse
        nonstandard_puzzle_hex = "ff01ff8080"  # some arbitrary CLVM

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [
                        {"height": block_height, "timestamp": 1700000000},
                    ]
                })
            elif command == "get_additions_and_removals":
                fake_parent = "bb" * 32
                fake_ph = "cc" * 32
                removal_coin_name = make_coin_name(fake_parent, fake_ph, 100)
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + removal_coin_name.hex(),
                                "puzzle_hash": "0x" + ("dd" * 32),
                                "amount": 50,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent,
                                "puzzle_hash": "0x" + fake_ph,
                                "amount": 100,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "coin_solution": {
                        "puzzle_reveal": "0x" + nonstandard_puzzle_hex,
                        "solution": "0x80",
                    }
                })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(_scan_sk, _spend_pk, start_height=200, end_height=200)

        assert len(detections) == 0

    @patch("scanner.subprocess.run")
    def test_scan_blocks_skips_coinbase(self, mock_run):
        """scan_blocks never reports a reward coin (coinbase addition).

        Reward coins have no parent spend, so they are left out of the
        additions that are matched, even if one carries a puzzle hash that
        would otherwise match.
        """
        block_height = 300

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [
                        {"height": block_height, "timestamp": 1700000000},
                    ]
                })
            elif command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _sender_coin_name.hex(),
                                "puzzle_hash": "0x" + _output_puzzle_hash.hex(),
                                "amount": _output_amount,
                            },
                            "coinbase": True,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _fake_parent_info,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": _sender_coin_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _sender_puzzle_hex,
                        "solution": "0x80",
                    }
                })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(_scan_sk, _spend_pk, start_height=300, end_height=300)

        assert len(detections) == 0

    @patch("scanner.subprocess.run")
    def test_scan_blocks_spent_reward_coin_is_eligible(self, mock_run):
        """A spent farming reward coin held in the standard puzzle is an
        eligible spend: a payment it creates is detected.

        The removal is flagged as a reward coin (coinbase); what matters is
        only that its puzzle reveal is the standard puzzle.
        """
        block_height = 310

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [
                        {"height": block_height, "timestamp": 1700000000},
                    ]
                })
            elif command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _sender_coin_name.hex(),
                                "puzzle_hash": "0x" + _output_puzzle_hash.hex(),
                                "amount": _output_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _fake_parent_info,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": _sender_coin_amount,
                            },
                            "coinbase": True,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _sender_puzzle_hex,
                        "solution": "0x80",
                    }
                })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(_scan_sk, _spend_pk, start_height=310, end_height=310)

        assert len(detections) == 1
        assert detections[0]["puzzle_hash"] == _output_puzzle_hash.hex()
        assert detections[0]["amount"] == _output_amount

    @patch("scanner.subprocess.run")
    def test_scan_blocks_empty_range(self, mock_run):
        """scan_blocks returns empty list when no transaction blocks exist in range."""

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [
                        # All blocks have timestamp=None (not transaction blocks)
                        {"height": 400, "timestamp": None},
                        {"height": 401, "timestamp": None},
                        {"height": 402, "timestamp": None},
                    ]
                })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(_scan_sk, _spend_pk, start_height=400, end_height=402)

        assert detections == []


class TestProcessBlock:
    """Tests for per-block processing."""

    @patch("scanner.subprocess.run")
    def test_process_block_returns_detection_dict(self, mock_run):
        """process_block returns list of dicts with coin_id, amount, block_height."""
        block_height = 500

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _sender_coin_name.hex(),
                                "puzzle_hash": "0x" + _output_puzzle_hash.hex(),
                                "amount": _output_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _fake_parent_info,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": _sender_coin_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _sender_puzzle_hex,
                        "solution": "0x80",
                    }
                })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(block_height, _scan_sk, _spend_pk)

        assert len(results) == 1
        assert results[0]["block_height"] == block_height
        assert results[0]["amount"] == _output_amount
        assert "coin_id" in results[0]


class TestScanBlocksMultiInput:
    """Tests for the single Pass 2 multi-input contract.

    Pass 2 links a multi-input payment's inputs through a cycle of
    ASSERT_CONCURRENT_SPEND (opcode 64) conditions. A multi-input set that
    merely shares a puzzle hash, with NO opcode-64 cycle, carries no on-chain
    linkage and is by design not detectable.
    """

    @patch("scanner.subprocess.run")
    def test_process_block_same_puzzle_hash_no_cycle_not_detected(self, mock_run):
        """Two removals share a puzzle hash but emit no opcode-64 cycle.

        Without an ASSERT_CONCURRENT_SPEND linkage the scanner cannot form a
        multi-input group, so the aggregated-key output is not detected.
        """
        block_height = 600

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _sender_coin_name.hex(),
                                "puzzle_hash": "0x" + _multi_output_puzzle_hash.hex(),
                                "amount": _multi_output_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _fake_parent_info,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": _sender_coin_amount,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _fake_parent_info_2,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": _sender_coin_amount_2,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _sender_puzzle_hex,
                        "solution": "0x80",
                    }
                })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(block_height, _scan_sk, _spend_pk)

        # Pass 1 cannot detect it (single-removal ECDH uses the wrong key for a
        # multi-input output), and Pass 2 has no opcode-64 cycle to group the
        # removals — so the multi-input output is not detected.
        multi_results = [r for r in results if r["puzzle_hash"] == _multi_output_puzzle_hash.hex()]
        assert multi_results == []

    @patch("scanner.subprocess.run")
    def test_scan_blocks_mixed_single_multi(self, mock_run):
        """Block with a single-input payment and an unlinked multi-input set.

        The single-input payment is detected via Pass 1. The multi-input set
        shares a puzzle hash but emits no opcode-64 cycle, so Pass 2 cannot
        group it and its aggregated-key output is not detected.
        """
        block_height = 700

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_block_records":
                return mock_coinset_response({
                    "block_records": [
                        {"height": block_height, "timestamp": 1700000000},
                    ]
                })
            elif command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        # Single-input output (from removal at index 0 alone)
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _sender_coin_name.hex(),
                                "puzzle_hash": "0x" + _output_puzzle_hash.hex(),
                                "amount": _output_amount,
                            },
                            "coinbase": False,
                        },
                        # Multi-input output (from grouped removals)
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _sender_coin_name.hex(),
                                "puzzle_hash": "0x" + _multi_output_puzzle_hash.hex(),
                                "amount": _multi_output_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        # Removal 0: creates single-input output
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _fake_parent_info,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": _sender_coin_amount,
                            },
                            "coinbase": False,
                        },
                        # Removal 1: same puzzle hash as removal 0 but no opcode-64
                        # cycle, so it forms no detectable multi-input group
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _fake_parent_info_2,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": _sender_coin_amount_2,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _sender_puzzle_hex,
                        "solution": "0x80",
                    }
                })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(_scan_sk, _spend_pk, start_height=700, end_height=700)

        # Single-input (Pass 1) is detected; the unlinked multi-input set is not.
        detected_phs = {d["puzzle_hash"] for d in detections}
        assert _output_puzzle_hash.hex() in detected_phs
        assert _multi_output_puzzle_hash.hex() not in detected_phs

    @patch("scanner.subprocess.run")
    def test_process_block_no_duplicate_detection(self, mock_run):
        """Single-removal detection in Pass 1 is not duplicated by Pass 2."""
        block_height = 800

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _sender_coin_name.hex(),
                                "puzzle_hash": "0x" + _output_puzzle_hash.hex(),
                                "amount": _output_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + _fake_parent_info,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": _sender_coin_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                return mock_coinset_response({
                    "coin_solution": {
                        "puzzle_reveal": "0x" + _sender_puzzle_hex,
                        "solution": "0x80",
                    }
                })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(block_height, _scan_sk, _spend_pk)

        # Should detect exactly once (Pass 1 only; Pass 2 skips groups of size < 2)
        assert len(results) == 1

    @patch("scanner.subprocess.run")
    def test_process_block_identity_pk_skip(self, mock_run):
        """An opcode-64 group whose PKs sum to identity is skipped (no crash).

        The two removals are linked by an opcode-64 2-cycle so Pass 2 forms a
        group, but their synthetic PKs cancel (pk + (-pk) = identity). The
        zero-sum guard must drop the group rather than attempt detection.
        """
        block_height = 900

        # Create a puzzle whose extracted PK is the negation of _sender_pk so the
        # group's aggregated PK is the identity element.
        from shared import negate_g1
        from shared import curry, MOD

        neg_pk = negate_g1(_sender_pk)
        neg_puzzle = curry(MOD, bytes(neg_pk))
        neg_puzzle_hex = bytes(neg_puzzle).hex()
        neg_puzzle_hash = neg_puzzle.get_tree_hash().hex()

        # Coin 1 uses _sender_puzzle (yields _sender_pk).
        # Coin 2 uses neg_puzzle (yields -_sender_pk). Their sum is identity.
        fake_parent_1 = "cc" * 32
        fake_parent_2 = "dd" * 32

        coin_name_1 = make_coin_name(fake_parent_1, _sender_puzzle_hash, 100)
        coin_name_2 = make_coin_name(fake_parent_2, neg_puzzle_hash, 200)

        # Bind the two removals with a cyclic opcode-64 linkage so Pass 2 groups
        # them; the zero-sum guard should then skip the group.
        solution_1 = _build_opcode_64_solution(coin_name_2).hex()
        solution_2 = _build_opcode_64_solution(coin_name_1).hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + coin_name_1.hex(),
                                "puzzle_hash": "0x" + ("ee" * 32),
                                "amount": 50,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_1,
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": 100,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_2,
                                "puzzle_hash": "0x" + neg_puzzle_hash,
                                "amount": 200,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = cmd[4] if len(cmd) > 4 else ""
                coin_hex_stripped = coin_hex[2:] if coin_hex.startswith("0x") else coin_hex
                if coin_hex_stripped == coin_name_2.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + neg_puzzle_hex,
                            "solution": "0x" + solution_2,
                        }
                    })
                else:
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex,
                            "solution": "0x" + solution_1,
                        }
                    })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        # Should not crash and should produce no detections from the identity group.
        results = process_block(block_height, _scan_sk, _spend_pk)

        # The grouped identity-sum produces nothing, and the lone "ee"*32 output
        # is not a valid silent payment for anyone.
        assert isinstance(results, list)
        assert all(r["puzzle_hash"] != "ee" * 32 for r in results)


# --- Pass 2 fixtures: SCC-based concurrent-spend detection ---

# Three sender wallets at distinct derivation indices. Each has a DIFFERENT
# puzzle hash, so the only on-chain signal linking them is the opcode-64
# ASSERT_CONCURRENT_SPEND cycle that Pass 2 follows.
_sender_wallet_sk_0 = master_sk_to_wallet_sk(_sender_master, 0)
_sender_sk_0 = calculate_synthetic_secret_key(_sender_wallet_sk_0)
_sender_pk_0 = _sender_sk_0.get_g1()
_sender_puzzle_0 = puzzle_for_pk(_sender_wallet_sk_0.get_g1())
_sender_puzzle_hex_0 = bytes(_sender_puzzle_0).hex()
_sender_puzzle_hash_0 = _sender_puzzle_0.get_tree_hash().hex()

_sender_wallet_sk_1 = master_sk_to_wallet_sk(_sender_master, 1)
_sender_sk_1 = calculate_synthetic_secret_key(_sender_wallet_sk_1)
_sender_pk_1 = _sender_sk_1.get_g1()
_sender_puzzle_1 = puzzle_for_pk(_sender_wallet_sk_1.get_g1())
_sender_puzzle_hex_1 = bytes(_sender_puzzle_1).hex()
_sender_puzzle_hash_1 = _sender_puzzle_1.get_tree_hash().hex()

_sender_wallet_sk_2 = master_sk_to_wallet_sk(_sender_master, 2)
_sender_sk_2 = calculate_synthetic_secret_key(_sender_wallet_sk_2)
_sender_pk_2 = _sender_sk_2.get_g1()
_sender_puzzle_2 = puzzle_for_pk(_sender_wallet_sk_2.get_g1())
_sender_puzzle_hex_2 = bytes(_sender_puzzle_2).hex()
_sender_puzzle_hash_2 = _sender_puzzle_2.get_tree_hash().hex()

# Polluter wallet — used in pollution defense test. NOT part of any SP group.
_sender_wallet_sk_M = master_sk_to_wallet_sk(_sender_master, 3)
_sender_sk_M = calculate_synthetic_secret_key(_sender_wallet_sk_M)
_sender_pk_M = _sender_sk_M.get_g1()
_sender_puzzle_M = puzzle_for_pk(_sender_wallet_sk_M.get_g1())
_sender_puzzle_hex_M = bytes(_sender_puzzle_M).hex()
_sender_puzzle_hash_M = _sender_puzzle_M.get_tree_hash().hex()

# Disjoint-groups fixtures: two more senders at distinct derivation
# indices for the second cycle (Group B) of the disjoint-groups test. Index 3
# is already used by the polluter (_sender_*_M), so we use indices 4 and 5.
_sender_wallet_sk_4 = master_sk_to_wallet_sk(_sender_master, 4)
_sender_sk_4 = calculate_synthetic_secret_key(_sender_wallet_sk_4)
_sender_pk_4 = _sender_sk_4.get_g1()
_sender_puzzle_4 = puzzle_for_pk(_sender_wallet_sk_4.get_g1())
_sender_puzzle_hex_4 = bytes(_sender_puzzle_4).hex()
_sender_puzzle_hash_4 = _sender_puzzle_4.get_tree_hash().hex()

_sender_wallet_sk_5 = master_sk_to_wallet_sk(_sender_master, 5)
_sender_sk_5 = calculate_synthetic_secret_key(_sender_wallet_sk_5)
_sender_pk_5 = _sender_sk_5.get_g1()
_sender_puzzle_5 = puzzle_for_pk(_sender_wallet_sk_5.get_g1())
_sender_puzzle_hex_5 = bytes(_sender_puzzle_5).hex()
_sender_puzzle_hash_5 = _sender_puzzle_5.get_tree_hash().hex()


def _build_opcode_64_solution(predecessor_coin_id: bytes) -> bytes:
    """Build a CLVM solution emitting exactly one [64, predecessor_coin_id] condition.

    Mirrors the standard p2_delegated_puzzle_or_hidden_puzzle solution shape:
    (() delegated_puzzle ()) where delegated_puzzle = (1 . [[64, predecessor]]).
    """
    from chia_rs import Program
    delegated = Program.to((1, [[64, predecessor_coin_id]]))
    dp_bytes = bytes(delegated)
    # Solution shape: ff 80 ff <delegated_puzzle> ff 80 80
    return b'\xff\x80\xff' + dp_bytes + b'\xff\x80\x80'


class TestScanBlocksConcurrentSpend:
    """Tests for Pass 2: SCC-based multi-input detection via ASSERT_CONCURRENT_SPEND.

    Covers the two-coin cycle, the three-coin cycle, and pollution defense via
    strongly-connected-component selection.
    """

    @patch("scanner.subprocess.run")
    def test_scc_two_coin_cycle_detected(self, mock_run):
        """Two removals with different puzzle hashes, cyclic opcode-64.

        Removal 0 (puzzle index 0) asserts coin_1_id. Removal 1 (puzzle index 1)
        asserts coin_0_id. The puzzle hashes are heterogeneous, so the only
        linkage is the opcode-64 cycle, which the Pass 2 SCC detects before
        aggregating pk_0 + pk_1.
        """
        block_height = 1000

        fake_parent_0 = "11" * 32
        fake_parent_1 = "22" * 32
        amount_0 = 1_000_000
        amount_1 = 2_000_000
        coin_0_id = make_coin_name(fake_parent_0, _sender_puzzle_hash_0, amount_0)
        coin_1_id = make_coin_name(fake_parent_1, _sender_puzzle_hash_1, amount_1)

        # Aggregated SP output derived from sum(pk_0, pk_1).
        sp_outputs = create_silent_payment_outputs(
            [_sender_sk_0, _sender_sk_1],
            [coin_0_id, coin_1_id],
            [(_scan_pk, _spend_pk)],
        )
        _, expected_output_ph = sp_outputs[0]
        output_amount = 1_500_000

        # Coin 0 asserts coin 1; coin 1 asserts coin 0 (two-cycle).
        solution_0 = _build_opcode_64_solution(coin_1_id).hex()
        solution_1 = _build_opcode_64_solution(coin_0_id).hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + coin_0_id.hex(),
                                "puzzle_hash": "0x" + expected_output_ph.hex(),
                                "amount": output_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_0,
                                "puzzle_hash": "0x" + _sender_puzzle_hash_0,
                                "amount": amount_0,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_1,
                                "puzzle_hash": "0x" + _sender_puzzle_hash_1,
                                "amount": amount_1,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = strip_0x(cmd[4])
                if coin_hex == coin_0_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_0,
                            "solution": "0x" + solution_0,
                        }
                    })
                elif coin_hex == coin_1_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_1,
                            "solution": "0x" + solution_1,
                        }
                    })
                return mock_coinset_response({})
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(block_height, _scan_sk, _spend_pk)

        matches = [r for r in results if r["puzzle_hash"] == expected_output_ph.hex()]
        assert len(matches) == 1, f"expected 1 detection, got {len(matches)}: {results}"
        assert matches[0]["amount"] == output_amount
        assert matches[0]["block_height"] == block_height

    @patch("scanner.subprocess.run")
    def test_scc_three_coin_cycle_detected(self, mock_run):
        """Three removals with distinct puzzle hashes, cyclic opcode-64.

        Sender pattern (matching Sage's chia-wallet-sdk emission): coin 0 emits
        [64, coin_N-1_id]; coin i (i>0) emits [64, coin_i-1_id]. For N=3:
        coin 0 -> coin 2; coin 1 -> coin 0; coin 2 -> coin 1 (single SCC).
        """
        block_height = 1100

        fake_parent_0 = "31" * 32
        fake_parent_1 = "32" * 32
        fake_parent_2 = "33" * 32
        amount_0 = 1_000_000
        amount_1 = 2_000_000
        amount_2 = 3_000_000
        coin_0_id = make_coin_name(fake_parent_0, _sender_puzzle_hash_0, amount_0)
        coin_1_id = make_coin_name(fake_parent_1, _sender_puzzle_hash_1, amount_1)
        coin_2_id = make_coin_name(fake_parent_2, _sender_puzzle_hash_2, amount_2)

        sp_outputs = create_silent_payment_outputs(
            [_sender_sk_0, _sender_sk_1, _sender_sk_2],
            [coin_0_id, coin_1_id, coin_2_id],
            [(_scan_pk, _spend_pk)],
        )
        _, expected_output_ph = sp_outputs[0]
        output_amount = 4_000_000

        # Sage's cyclic pattern: coin 0 -> coin N-1; coin i -> coin i-1.
        solution_0 = _build_opcode_64_solution(coin_2_id).hex()
        solution_1 = _build_opcode_64_solution(coin_0_id).hex()
        solution_2 = _build_opcode_64_solution(coin_1_id).hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + coin_0_id.hex(),
                                "puzzle_hash": "0x" + expected_output_ph.hex(),
                                "amount": output_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_0,
                                "puzzle_hash": "0x" + _sender_puzzle_hash_0,
                                "amount": amount_0,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_1,
                                "puzzle_hash": "0x" + _sender_puzzle_hash_1,
                                "amount": amount_1,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_2,
                                "puzzle_hash": "0x" + _sender_puzzle_hash_2,
                                "amount": amount_2,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = strip_0x(cmd[4])
                if coin_hex == coin_0_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_0,
                            "solution": "0x" + solution_0,
                        }
                    })
                elif coin_hex == coin_1_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_1,
                            "solution": "0x" + solution_1,
                        }
                    })
                elif coin_hex == coin_2_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_2,
                            "solution": "0x" + solution_2,
                        }
                    })
                return mock_coinset_response({})
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(block_height, _scan_sk, _spend_pk)

        matches = [r for r in results if r["puzzle_hash"] == expected_output_ph.hex()]
        assert len(matches) == 1, f"expected 1 detection, got {len(matches)}: {results}"
        assert matches[0]["amount"] == output_amount
        assert matches[0]["block_height"] == block_height

    @patch("scanner.subprocess.run")
    def test_scc_pollution_defense(self, mock_run):
        """A third-party polluter M asserts a victim coin's ID with no
        return edge. The legitimate SP group (coins 0,1,2) MUST still be detected
        and M MUST be excluded from the aggregated key.

        SCC discriminator: if the scanner had used undirected connected components,
        M would be pulled into the victim's group, the aggregated PK would include
        M, and the output PH would derive from pk_0+pk_1+pk_2+pk_M instead of
        pk_0+pk_1+pk_2. We assert the detection matches the FORMER (correct,
        polluter-excluded) PH, not the latter.
        """
        block_height = 1200

        fake_parent_0 = "41" * 32
        fake_parent_1 = "42" * 32
        fake_parent_2 = "43" * 32
        fake_parent_M = "4d" * 32
        amount_0 = 1_000_000
        amount_1 = 2_000_000
        amount_2 = 3_000_000
        amount_M = 5_000_000
        coin_0_id = make_coin_name(fake_parent_0, _sender_puzzle_hash_0, amount_0)
        coin_1_id = make_coin_name(fake_parent_1, _sender_puzzle_hash_1, amount_1)
        coin_2_id = make_coin_name(fake_parent_2, _sender_puzzle_hash_2, amount_2)
        coin_M_id = make_coin_name(fake_parent_M, _sender_puzzle_hash_M, amount_M)

        # Correct (pollution-resistant) SP output PH: pk_0 + pk_1 + pk_2.
        sp_outputs_correct = create_silent_payment_outputs(
            [_sender_sk_0, _sender_sk_1, _sender_sk_2],
            [coin_0_id, coin_1_id, coin_2_id],
            [(_scan_pk, _spend_pk)],
        )
        _, expected_output_ph = sp_outputs_correct[0]

        # Pollution-would-have-broken PH: pk_0 + pk_1 + pk_2 + pk_M (this is what
        # an undirected-CC scanner would derive). We construct it to ensure the
        # discriminator is sharp — the test asserts we get expected_output_ph,
        # NOT polluted_output_ph.
        sp_outputs_polluted = create_silent_payment_outputs(
            [_sender_sk_0, _sender_sk_1, _sender_sk_2, _sender_sk_M],
            [coin_0_id, coin_1_id, coin_2_id, coin_M_id],
            [(_scan_pk, _spend_pk)],
        )
        _, polluted_output_ph = sp_outputs_polluted[0]
        assert expected_output_ph != polluted_output_ph, (
            "test setup error: pollution PH equals correct PH"
        )

        output_amount = 4_500_000

        # Legitimate cycle: 0 -> 2, 1 -> 0, 2 -> 1.
        solution_0 = _build_opcode_64_solution(coin_2_id).hex()
        solution_1 = _build_opcode_64_solution(coin_0_id).hex()
        solution_2 = _build_opcode_64_solution(coin_1_id).hex()
        # Polluter M asserts coin_0_id with NO return edge from any coin.
        solution_M = _build_opcode_64_solution(coin_0_id).hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + coin_0_id.hex(),
                                "puzzle_hash": "0x" + expected_output_ph.hex(),
                                "amount": output_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_0,
                                "puzzle_hash": "0x" + _sender_puzzle_hash_0,
                                "amount": amount_0,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_1,
                                "puzzle_hash": "0x" + _sender_puzzle_hash_1,
                                "amount": amount_1,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_2,
                                "puzzle_hash": "0x" + _sender_puzzle_hash_2,
                                "amount": amount_2,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + fake_parent_M,
                                "puzzle_hash": "0x" + _sender_puzzle_hash_M,
                                "amount": amount_M,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = strip_0x(cmd[4])
                if coin_hex == coin_0_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_0,
                            "solution": "0x" + solution_0,
                        }
                    })
                elif coin_hex == coin_1_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_1,
                            "solution": "0x" + solution_1,
                        }
                    })
                elif coin_hex == coin_2_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_2,
                            "solution": "0x" + solution_2,
                        }
                    })
                elif coin_hex == coin_M_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_M,
                            "solution": "0x" + solution_M,
                        }
                    })
                return mock_coinset_response({})
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        results = process_block(block_height, _scan_sk, _spend_pk)

        # The legitimate (polluter-excluded) PH is detected.
        correct_matches = [r for r in results if r["puzzle_hash"] == expected_output_ph.hex()]
        assert len(correct_matches) == 1, (
            f"polluter M should NOT have broken SP detection; got results: {results}"
        )
        assert correct_matches[0]["amount"] == output_amount

        # The polluted PH is NOT detected (discriminator: undirected-CC scanners
        # would have produced this; SCC scanners must not).
        polluted_matches = [r for r in results if r["puzzle_hash"] == polluted_output_ph.hex()]
        assert len(polluted_matches) == 0, (
            "polluter was incorrectly aggregated into victim's group "
            "(scanner is treating edges as undirected, not SCC)"
        )

    @patch("scanner.subprocess.run")
    def test_disjoint_groups_detected_independently(self, mock_run):
        """One block with two disjoint opcode-64 cycles.

        Group A: coins 0,1,2 form a 3-cycle (0->2, 1->0, 2->1) with distinct
        puzzle hashes (senders at derivation indices 0/1/2).
        Group B: coins 3,4 form a 2-cycle (3->4, 4->3) with distinct puzzle
        hashes (senders at derivation indices 4/5).

        All five puzzle hashes are distinct, so the only linkage is the opcode-64
        cycles. Pass 2 must produce TWO independent multi-input detections, one
        for each cycle's aggregated SP output.
        """
        block_height = 1300

        # Group A coins (indices 0/1/2 of the senders fixture set).
        fake_parent_a0 = "a0" * 32
        fake_parent_a1 = "a1" * 32
        fake_parent_a2 = "a2" * 32
        amount_a0 = 1_000_000
        amount_a1 = 2_000_000
        amount_a2 = 3_000_000
        coin_a0_id = make_coin_name(fake_parent_a0, _sender_puzzle_hash_0, amount_a0)
        coin_a1_id = make_coin_name(fake_parent_a1, _sender_puzzle_hash_1, amount_a1)
        coin_a2_id = make_coin_name(fake_parent_a2, _sender_puzzle_hash_2, amount_a2)

        # Group B coins (indices 4/5 of the senders fixture set — index 3 is the polluter).
        fake_parent_b0 = "b0" * 32
        fake_parent_b1 = "b1" * 32
        amount_b0 = 4_000_000
        amount_b1 = 5_000_000
        coin_b0_id = make_coin_name(fake_parent_b0, _sender_puzzle_hash_4, amount_b0)
        coin_b1_id = make_coin_name(fake_parent_b1, _sender_puzzle_hash_5, amount_b1)

        # Aggregated SP outputs for each group: A from pk_0+pk_1+pk_2; B from pk_4+pk_5.
        sp_outputs_a = create_silent_payment_outputs(
            [_sender_sk_0, _sender_sk_1, _sender_sk_2],
            [coin_a0_id, coin_a1_id, coin_a2_id],
            [(_scan_pk, _spend_pk)],
        )
        _, group_a_ph = sp_outputs_a[0]
        sp_outputs_b = create_silent_payment_outputs(
            [_sender_sk_4, _sender_sk_5],
            [coin_b0_id, coin_b1_id],
            [(_scan_pk, _spend_pk)],
        )
        _, group_b_ph = sp_outputs_b[0]

        # Sanity: distinct outputs (otherwise the assertion below is trivially true).
        assert group_a_ph != group_b_ph, "test setup error: group A and B aggregated PHs collide"

        group_a_amount = 5_500_000
        group_b_amount = 8_500_000

        # Group A cyclic predecessors (Sage pattern: coin 0 -> N-1; i>0 -> i-1).
        solution_a0 = _build_opcode_64_solution(coin_a2_id).hex()
        solution_a1 = _build_opcode_64_solution(coin_a0_id).hex()
        solution_a2 = _build_opcode_64_solution(coin_a1_id).hex()
        # Group B cyclic predecessors (N=2: coin 0 -> coin 1; coin 1 -> coin 0).
        solution_b0 = _build_opcode_64_solution(coin_b1_id).hex()
        solution_b1 = _build_opcode_64_solution(coin_b0_id).hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + coin_a0_id.hex(),
                                "puzzle_hash": "0x" + group_a_ph.hex(),
                                "amount": group_a_amount,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + coin_b0_id.hex(),
                                "puzzle_hash": "0x" + group_b_ph.hex(),
                                "amount": group_b_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + fake_parent_a0,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_0,
                                  "amount": amount_a0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + fake_parent_a1,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_1,
                                  "amount": amount_a1}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + fake_parent_a2,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_2,
                                  "amount": amount_a2}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + fake_parent_b0,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_4,
                                  "amount": amount_b0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + fake_parent_b1,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_5,
                                  "amount": amount_b1}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = strip_0x(cmd[4])
                table = {
                    coin_a0_id.hex(): (_sender_puzzle_hex_0, solution_a0),
                    coin_a1_id.hex(): (_sender_puzzle_hex_1, solution_a1),
                    coin_a2_id.hex(): (_sender_puzzle_hex_2, solution_a2),
                    coin_b0_id.hex(): (_sender_puzzle_hex_4, solution_b0),
                    coin_b1_id.hex(): (_sender_puzzle_hex_5, solution_b1),
                }
                if coin_hex in table:
                    pz_hex, sol_hex = table[coin_hex]
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + pz_hex,
                            "solution": "0x" + sol_hex,
                        }
                    })
                return mock_coinset_response({})
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = process_block(block_height, _scan_sk, _spend_pk)

        # Both groups' aggregated PHs must be detected.
        group_a_ph_hex = group_a_ph.hex()
        group_b_ph_hex = group_b_ph.hex()
        detected_phs = {d["puzzle_hash"] for d in detections}
        assert group_a_ph_hex in detected_phs, (
            f"Group A (3-cycle) not detected; results: {detections}"
        )
        assert group_b_ph_hex in detected_phs, (
            f"Group B (2-cycle) not detected; results: {detections}"
        )

        # Exactly two detections matching our two expected outputs (no spurious
        # cross-group aggregations, no duplicates).
        matched = [d for d in detections if d["puzzle_hash"] in {group_a_ph_hex, group_b_ph_hex}]
        assert len(matched) == 2, (
            f"expected 2 disjoint-group detections, got {len(matched)}: {matched}"
        )

    @patch("scanner.subprocess.run")
    def test_same_block_concurrent_spend_group_with_no_cycle_group(self, mock_run):
        """One block with two multi-input candidate groups, only one linked.

        Group A: two coins at derivation index 0 (same puzzle hash, same
        synthetic PK) emitting NO opcode-64 conditions. Under the single
        Pass 2 contract this group is, by design, NOT detectable: with no
        ASSERT_CONCURRENT_SPEND cycle the scanner has no on-chain signal
        linking the inputs.
        Group B: two coins at derivation indices 1 and 2 (distinct puzzle
        hashes), bound by a 2-cycle of opcode-64 conditions — detectable.

        Only Group B is detected; Group A is silently skipped.
        """
        block_height = 1400

        # Group A: two coins, same puzzle hash, same PK (index 0). No opcode-64 emitted.
        fake_parent_a0 = "c0" * 32
        fake_parent_a1 = "c1" * 32
        amount_a0 = 1_000_000
        amount_a1 = 2_000_000
        coin_a0_id = make_coin_name(fake_parent_a0, _sender_puzzle_hash_0, amount_a0)
        coin_a1_id = make_coin_name(fake_parent_a1, _sender_puzzle_hash_0, amount_a1)

        # Group B: two coins, distinct puzzle hashes, opcode-64 2-cycle.
        fake_parent_b0 = "d0" * 32
        fake_parent_b1 = "d1" * 32
        amount_b0 = 3_000_000
        amount_b1 = 4_000_000
        coin_b0_id = make_coin_name(fake_parent_b0, _sender_puzzle_hash_1, amount_b0)
        coin_b1_id = make_coin_name(fake_parent_b1, _sender_puzzle_hash_2, amount_b1)

        # Group A aggregated PK: 2*PK_0 (point doubling — two coins at same derivation index).
        sp_outputs_a = create_silent_payment_outputs(
            [_sender_sk_0, _sender_sk_0],
            [coin_a0_id, coin_a1_id],
            [(_scan_pk, _spend_pk)],
        )
        _, group_a_ph = sp_outputs_a[0]

        # Group B aggregated PK: PK_1 + PK_2.
        sp_outputs_b = create_silent_payment_outputs(
            [_sender_sk_1, _sender_sk_2],
            [coin_b0_id, coin_b1_id],
            [(_scan_pk, _spend_pk)],
        )
        _, group_b_ph = sp_outputs_b[0]

        assert group_a_ph != group_b_ph, "test setup error: group A and B aggregated PHs collide"

        group_a_amount = 2_750_000
        group_b_amount = 3_500_000

        # Group A coins emit NO opcode-64 — solution is empty atom 0x80.
        # Group B coins emit a cyclic opcode-64 linkage.
        solution_b0 = _build_opcode_64_solution(coin_b1_id).hex()
        solution_b1 = _build_opcode_64_solution(coin_b0_id).hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + coin_a0_id.hex(),
                                "puzzle_hash": "0x" + group_a_ph.hex(),
                                "amount": group_a_amount,
                            },
                            "coinbase": False,
                        },
                        {
                            "coin": {
                                "parent_coin_info": "0x" + coin_b0_id.hex(),
                                "puzzle_hash": "0x" + group_b_ph.hex(),
                                "amount": group_b_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + fake_parent_a0,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_0,
                                  "amount": amount_a0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + fake_parent_a1,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_0,
                                  "amount": amount_a1}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + fake_parent_b0,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_1,
                                  "amount": amount_b0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + fake_parent_b1,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_2,
                                  "amount": amount_b1}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = strip_0x(cmd[4])
                # Group A coins: same puzzle (index 0), empty solution (no opcode-64).
                if coin_hex == coin_a0_id.hex() or coin_hex == coin_a1_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_0,
                            "solution": "0x80",
                        }
                    })
                # Group B coins: distinct puzzles + cyclic opcode-64.
                elif coin_hex == coin_b0_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_1,
                            "solution": "0x" + solution_b0,
                        }
                    })
                elif coin_hex == coin_b1_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_2,
                            "solution": "0x" + solution_b1,
                        }
                    })
                return mock_coinset_response({})
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = process_block(block_height, _scan_sk, _spend_pk)

        # Group B (opcode-64 cycle) is detected; Group A (no cycle) is not.
        detected_phs = {d["puzzle_hash"] for d in detections}
        assert group_b_ph.hex() in detected_phs, (
            f"concurrent-spend group B not detected; results: {detections}"
        )
        assert group_a_ph.hex() not in detected_phs, (
            f"group A with no opcode-64 cycle is not detectable under single "
            f"Pass 2; results: {detections}"
        )

        # Dedupe sanity: collapse by coin_id; expect exactly 1 unique detection
        # (Group B only) for our expected output PHs.
        unique_by_coin_id = {d["coin_id"]: d for d in detections
                             if d["puzzle_hash"] in {group_a_ph.hex(), group_b_ph.hex()}}
        assert len(unique_by_coin_id) == 1, (
            f"expected 1 unique concurrent-spend detection, got {len(unique_by_coin_id)}: "
            f"{list(unique_by_coin_id.values())}"
        )

    @patch("scanner.subprocess.run")
    def test_sender_scanner_roundtrip_two_coin_cycle(self, mock_run):
        """Sender↔scanner end-to-end contract: a spend bundle emitted by
        `send_payment.build_coin_spend_conditions` (the actual sender helper)
        is detected by `scanner.process_block`'s Pass 2 SCC walker.

        This test fails if EITHER side breaks:
          - If `build_coin_spend_conditions` emits a non-cyclic pattern (star,
            random, etc.), the scanner's Pass 2 won't form an SCC of size 2
            and detection fails.
          - If the scanner's Pass 2 condition walker or `tarjan_scc` is buggy,
            the cycle isn't extracted and detection fails.
        """
        from chia_rs import Program
        from send_payment import build_coin_spend_conditions

        block_height = 1500

        # Two senders at distinct derivation indices (module-level fixtures).
        fake_parent_0 = "e0" * 32
        fake_parent_1 = "e1" * 32
        amount_0 = 1_000_000
        amount_1 = 2_000_000
        coin_0_id = make_coin_name(fake_parent_0, _sender_puzzle_hash_0, amount_0)
        coin_1_id = make_coin_name(fake_parent_1, _sender_puzzle_hash_1, amount_1)

        # Aggregated SP output (sum(pk_0, pk_1)) — the target the scanner must derive.
        sp_outputs = create_silent_payment_outputs(
            [_sender_sk_0, _sender_sk_1],
            [coin_0_id, coin_1_id],
            [(_scan_pk, _spend_pk)],
        )
        _, expected_output_ph = sp_outputs[0]
        output_amount = 2_500_000

        # Shape the sage_coins list as send_payment.py constructs it (with coin_id key).
        sage_coins = [
            {"parent_coin_info": fake_parent_0, "puzzle_hash": _sender_puzzle_hash_0,
             "amount": amount_0, "coin_id": coin_0_id},
            {"parent_coin_info": fake_parent_1, "puzzle_hash": _sender_puzzle_hash_1,
             "amount": amount_1, "coin_id": coin_1_id},
        ]

        # Primary outputs only on coin 0 (mirrors actual sender: outputs on i==0 only).
        primary_outputs = [[51, expected_output_ph, output_amount]]
        conditions_0 = build_coin_spend_conditions(0, sage_coins, primary_outputs)
        conditions_1 = build_coin_spend_conditions(1, sage_coins, [])

        # Sanity (also verified in tests/test_send_payment.py — repeat as a guard
        # so this integration test fails loudly if the sender's pattern regresses).
        opcode_64_conds_0 = [c for c in conditions_0 if c[0] == 64]
        opcode_64_conds_1 = [c for c in conditions_1 if c[0] == 64]
        assert len(opcode_64_conds_0) == 1 and opcode_64_conds_0[0][1] == coin_1_id, (
            "sender helper regression: coin 0 should assert coin_1_id (wraps to N-1)"
        )
        assert len(opcode_64_conds_1) == 1 and opcode_64_conds_1[0][1] == coin_0_id, (
            "sender helper regression: coin 1 should assert coin_0_id (predecessor)"
        )

        # Serialize each coin's conditions using the SAME pattern as the sender
        # (send_payment.build_silent_payment_spend): Program.to((1, conditions))
        # then the standard p2_delegated_puzzle_or_hidden_puzzle solution wrapper.
        def _serialize_conditions(conds):
            delegated = Program.to((1, conds))
            dp_bytes = bytes(delegated)
            return b'\xff\x80\xff' + dp_bytes + b'\xff\x80\x80'

        solution_0 = _serialize_conditions(conditions_0).hex()
        solution_1 = _serialize_conditions(conditions_1).hex()

        def mock_dispatcher(cmd, **kwargs):
            command = cmd[3]
            if command == "get_additions_and_removals":
                return mock_coinset_response({
                    "additions": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + coin_0_id.hex(),
                                "puzzle_hash": "0x" + expected_output_ph.hex(),
                                "amount": output_amount,
                            },
                            "coinbase": False,
                        },
                    ],
                    "removals": [
                        {"coin": {"parent_coin_info": "0x" + fake_parent_0,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_0,
                                  "amount": amount_0}, "coinbase": False},
                        {"coin": {"parent_coin_info": "0x" + fake_parent_1,
                                  "puzzle_hash": "0x" + _sender_puzzle_hash_1,
                                  "amount": amount_1}, "coinbase": False},
                    ],
                })
            elif command == "get_puzzle_and_solution":
                coin_hex = strip_0x(cmd[4])
                if coin_hex == coin_0_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_0,
                            "solution": "0x" + solution_0,
                        }
                    })
                elif coin_hex == coin_1_id.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex_1,
                            "solution": "0x" + solution_1,
                        }
                    })
                return mock_coinset_response({})
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        # End-to-end: scanner ingests the sender-emitted solution bytes and detects.
        detections = process_block(block_height, _scan_sk, _spend_pk)

        matches = [d for d in detections if d["puzzle_hash"] == expected_output_ph.hex()]
        assert len(matches) == 1, (
            f"sender↔scanner round-trip failed: expected 1 detection for the "
            f"aggregated output, got {len(matches)}; results: {detections}"
        )
        assert matches[0]["amount"] == output_amount
        assert matches[0]["block_height"] == block_height
