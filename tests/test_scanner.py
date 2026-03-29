"""
Tests for blockchain scanner with mocked coinset CLI responses.

Covers: SCAN-01 (block-range scanning), SCAN-02 (sender PK extraction from removals),
SCAN-03 (coin_id + amount + block_height reporting), SCAN-04 (skip non-standard puzzles).
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

# --- Multi-input fixtures (INPUT-03) ---

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
        """scan_blocks does not attempt puzzle extraction for coinbase removals."""
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
                                "parent_coin_info": "0x" + ("ab" * 32),
                                "puzzle_hash": "0x" + ("cd" * 32),
                                "amount": 100,
                            },
                            "coinbase": True,
                        },
                    ],
                    "removals": [
                        {
                            "coin": {
                                "parent_coin_info": "0x" + ("ef" * 32),
                                "puzzle_hash": "0x" + ("12" * 32),
                                "amount": 200,
                            },
                            "coinbase": True,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                # This should NOT be called for coinbase removals
                raise AssertionError("get_puzzle_and_solution should not be called for coinbase")
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        detections = scan_blocks(_scan_sk, _spend_pk, start_height=300, end_height=300)

        assert len(detections) == 0

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
    """Tests for multi-input detection via puzzle-hash grouping (INPUT-03)."""

    @patch("scanner.subprocess.run")
    def test_process_block_multi_input_detection(self, mock_run):
        """Two removals with same puzzle hash are grouped; aggregated-key ECDH detects output."""
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

        # Pass 1 won't detect it (single-removal ECDH uses wrong key for multi-input output)
        # Pass 2 groups the two removals, aggregates PKs, detects the output
        multi_results = [r for r in results if r["puzzle_hash"] == _multi_output_puzzle_hash.hex()]
        assert len(multi_results) == 1
        assert multi_results[0]["amount"] == _multi_output_amount
        assert multi_results[0]["block_height"] == block_height

    @patch("scanner.subprocess.run")
    def test_scan_blocks_mixed_single_multi(self, mock_run):
        """Block with one single-input payment and one multi-input payment: both detected."""
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
                        # Removal 1: part of multi-input group (same puzzle hash as removal 0)
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

        # Should detect both: single-input (Pass 1) and multi-input (Pass 2)
        assert len(detections) >= 2
        detected_phs = {d["puzzle_hash"] for d in detections}
        assert _output_puzzle_hash.hex() in detected_phs
        assert _multi_output_puzzle_hash.hex() in detected_phs

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
        """Two removals whose PKs sum to identity are skipped (no crash)."""
        block_height = 900

        # Create a puzzle whose extracted PK will be the negation of _sender_pk
        # We need two removals with PKs that cancel. We'll use mock to return
        # different puzzle reveals for each removal.
        from shared import negate_g1, calculate_synthetic_public_key

        neg_pk = negate_g1(_sender_pk)
        # Build a puzzle that curries neg_pk as the synthetic PK
        from shared import curry, MOD
        neg_puzzle = curry(MOD, bytes(neg_pk))
        neg_puzzle_hex = bytes(neg_puzzle).hex()
        neg_puzzle_hash = neg_puzzle.get_tree_hash().hex()

        # Coin 1 uses _sender_puzzle (yields _sender_pk)
        # Coin 2 uses neg_puzzle (yields neg_pk = -_sender_pk)
        # Their sum is identity
        fake_parent_1 = "cc" * 32
        fake_parent_2 = "dd" * 32

        coin_name_1 = make_coin_name(fake_parent_1, _sender_puzzle_hash, 100)
        coin_name_2 = make_coin_name(fake_parent_2, neg_puzzle_hash, 200)

        call_count = {"puzzle": 0}

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
                                "puzzle_hash": "0x" + _sender_puzzle_hash,
                                "amount": 200,
                            },
                            "coinbase": False,
                        },
                    ],
                })
            elif command == "get_puzzle_and_solution":
                # Both removals share _sender_puzzle_hash for grouping,
                # but we return different puzzle reveals to get different PKs.
                # The coin_name in the args tells us which removal this is for.
                call_count["puzzle"] += 1
                coin_hex = cmd[4] if len(cmd) > 4 else ""
                coin_hex_stripped = coin_hex[2:] if coin_hex.startswith("0x") else coin_hex
                if coin_hex_stripped == coin_name_2.hex():
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + neg_puzzle_hex,
                            "solution": "0x80",
                        }
                    })
                else:
                    return mock_coinset_response({
                        "coin_solution": {
                            "puzzle_reveal": "0x" + _sender_puzzle_hex,
                            "solution": "0x80",
                        }
                    })
            else:
                return mock_coinset_response({})

        mock_run.side_effect = mock_dispatcher

        # Should not crash and should produce no detections from the identity group
        results = process_block(block_height, _scan_sk, _spend_pk)

        # Neither individual removal nor the grouped identity should detect anything
        # (the output puzzle hash "ee"*32 isn't a valid silent payment for anyone)
        assert isinstance(results, list)
