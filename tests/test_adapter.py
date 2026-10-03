"""Tests for the SDK adapter: the wire bridge, the aggregate guards, and the
single-importer / coinset-consolidation invariants.

Covers ``sdk_adapter.py`` and ``coinset.py``.

Runs behind the session-scoped `tests/conftest.py` freshness gate (the wheel and
`sys.executable` must be under the venv with silent-payment support).

`sdk_adapter` and `coinset` are imported LOCALLY inside each test (never at
module scope) so a missing module only fails the tests that need it, keeping this
file collectible (no file-level ImportError).
"""

import json
import re
from pathlib import Path
from unittest import mock

import pytest

import chia_rs
import chia_wallet_sdk as sdk

# Repo root (this file lives in <repo>/tests/).
REPO = Path(__file__).resolve().parent.parent

# BLS12-381 curve order — inlined for the zero-sum cancelling-pair fixture.
GROUP_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


# ==========================================================================
# Wire-bridge (single-input + multi-input + bonus)
#
# Build the SAME logical spend two ways and assert byte-equal wire dicts. The
# aggregated signature is an infinity G2Element — the bridge is pure
# serialization, NO signing required.
# ==========================================================================


def test_wire_bridge_matches_chia_rs():
    """Single-input: SDK SpendBundle -> wire dict == the proven
    chia_rs.SpendBundle(...).to_json_dict() for the same logical spend.
    """
    from sdk_adapter import sdk_bundle_to_wire_dict

    # Fixed inputs: identical bytes feed BOTH sides.
    parent = bytes.fromhex("aa" * 32)
    ph = bytes.fromhex("bb" * 32)
    amount = 1234
    puzzle_reveal = bytes.fromhex("ff0980")  # a small valid CLVM program
    solution = bytes.fromhex("80")  # nil
    sig_bytes = bytes(chia_rs.G2Element())  # infinity is a valid G2Element (no signing)

    # SDK side -> bridge.
    sdk_coin = sdk.Coin(parent, ph, amount)
    sdk_spend = sdk.CoinSpend(sdk_coin, puzzle_reveal, solution)
    sdk_sig = sdk.Signature.from_bytes(sig_bytes)
    sdk_bundle = sdk.SpendBundle([sdk_spend], sdk_sig)
    bridged = sdk_bundle_to_wire_dict(sdk_bundle)

    # Reference side: the proven chia_rs wire path (the format testnet11 accepts).
    rs_coin = chia_rs.Coin(parent, ph, amount)
    rs_spend = chia_rs.CoinSpend(
        rs_coin,
        chia_rs.Program.from_bytes(puzzle_reveal),
        chia_rs.Program.from_bytes(solution),
    )
    rs_sig = chia_rs.G2Element.from_bytes(sig_bytes)
    expected = chia_rs.SpendBundle([rs_spend], rs_sig).to_json_dict()

    assert bridged == expected  # byte-equal dicts


def test_wire_bridge_multi_input():
    """Multi-input: 3 distinct CoinSpends on BOTH sides exercise the per-CoinSpend
    bridge loop (N>1 coverage). Same byte-equal assertion. Still NO signing — one
    shared infinity aggregated signature.
    """
    from sdk_adapter import sdk_bundle_to_wire_dict

    sig_bytes = bytes(chia_rs.G2Element())  # one shared aggregated sig (infinity)

    sdk_spends = []
    rs_spends = []
    for i in range(1, 4):
        parent = bytes([i]) * 32
        ph = bytes([i + 10]) * 32
        amount = 1000 + i
        puzzle_reveal = bytes.fromhex("ff0980")
        solution = bytes.fromhex("80")

        sdk_spends.append(
            sdk.CoinSpend(sdk.Coin(parent, ph, amount), puzzle_reveal, solution)
        )
        rs_spends.append(
            chia_rs.CoinSpend(
                chia_rs.Coin(parent, ph, amount),
                chia_rs.Program.from_bytes(puzzle_reveal),
                chia_rs.Program.from_bytes(solution),
            )
        )

    sdk_bundle = sdk.SpendBundle(sdk_spends, sdk.Signature.from_bytes(sig_bytes))
    bridged = sdk_bundle_to_wire_dict(sdk_bundle)

    expected = chia_rs.SpendBundle(
        rs_spends, chia_rs.G2Element.from_bytes(sig_bytes)
    ).to_json_dict()

    assert bridged == expected  # byte-equal dicts across the 3-CoinSpend loop


def test_bonus_to_bytes_round_trip():
    """Whole-bundle cross-crate byte-compat: SDK chia-protocol vs venv chia_rs.
    Verified to hold; the production bridge stays the field-by-field rebuild
    regardless.
    """
    parent = bytes.fromhex("aa" * 32)
    ph = bytes.fromhex("bb" * 32)
    amount = 1234
    puzzle_reveal = bytes.fromhex("ff0980")
    solution = bytes.fromhex("80")
    sig_bytes = bytes(chia_rs.G2Element())

    sdk_coin = sdk.Coin(parent, ph, amount)
    sdk_spend = sdk.CoinSpend(sdk_coin, puzzle_reveal, solution)
    sdk_bundle = sdk.SpendBundle([sdk_spend], sdk.Signature.from_bytes(sig_bytes))

    rs_coin = chia_rs.Coin(parent, ph, amount)
    rs_spend = chia_rs.CoinSpend(
        rs_coin,
        chia_rs.Program.from_bytes(puzzle_reveal),
        chia_rs.Program.from_bytes(solution),
    )
    expected = chia_rs.SpendBundle(
        [rs_spend], chia_rs.G2Element.from_bytes(sig_bytes)
    ).to_json_dict()

    rt = chia_rs.SpendBundle.from_bytes(sdk_bundle.to_bytes()).to_json_dict()
    assert rt == expected


# ==========================================================================
# Zero-sum / identity guard (sk path, pk path, happy path)
#
# The adapter wrappers `sdk_adapter.aggregate_sender_sks` / `aggregate_sender_pks`
# MUST raise. The SDK sk aggregate raises on a zero sum itself (with an ASCII
# hyphen); the adapter re-raises it with the verbatim CHIP-0057 message (em-dash
# U+2014). `PublicKey.aggregate` returns the identity silently, so the pk-path
# guard is the adapter's (substring "identity").
# ==========================================================================


def _pubkey(sk):
    """SDK SecretKey -> PublicKey via .public_key()."""
    return sk.public_key()


def test_aggregate_sks_zero_sum_raises():
    """sk path: two SecretKeys whose sum is zero mod r must raise the verbatim
    ValueError. Cancelling pair: a + (r - a) == 0 mod r.
    """
    import sdk_adapter

    a = 7
    b = (GROUP_ORDER - 7) % GROUP_ORDER
    sk_a = sdk.SecretKey.from_bytes(a.to_bytes(32, "big"))
    sk_b = sdk.SecretKey.from_bytes(b.to_bytes(32, "big"))

    with pytest.raises(ValueError) as exc:
        sdk_adapter.aggregate_sender_sks([sk_a, sk_b])
    assert str(exc.value) == "aggregated sender key sum is zero — invalid for ECDH"

    # The SDK itself raises on the zero sum (the adapter only rewords it).
    with pytest.raises(ValueError, match="key sum is zero"):
        sdk.SilentPayments.aggregate_sender_sks([sk_a, sk_b])


def test_aggregate_pks_identity_raises():
    """pk path: two public keys summing to the identity/infinity point must raise an
    analogous ValueError. Same cancelling pair as the sk test => their public keys
    sum to infinity.
    """
    import sdk_adapter

    a = 7
    b = (GROUP_ORDER - 7) % GROUP_ORDER
    sk_a = sdk.SecretKey.from_bytes(a.to_bytes(32, "big"))
    sk_b = sdk.SecretKey.from_bytes(b.to_bytes(32, "big"))
    pk_a = _pubkey(sk_a)
    pk_b = _pubkey(sk_b)

    # Sanity: this cancelling pair aggregates to infinity (so the guard fires).
    assert sdk.PublicKey.aggregate([pk_a, pk_b]).is_infinity()

    with pytest.raises(ValueError) as exc:
        sdk_adapter.aggregate_sender_pks([pk_a, pk_b])
    assert "identity" in str(exc.value).lower()


def test_aggregate_happy_path():
    """Happy path: a non-cancelling pair (7, 11) aggregates to a
    non-zero SecretKey (7 + 11 = 18) and a non-identity PublicKey — the guard does
    NOT fire.
    """
    import sdk_adapter

    sk_a = sdk.SecretKey.from_bytes((7).to_bytes(32, "big"))
    sk_b = sdk.SecretKey.from_bytes((11).to_bytes(32, "big"))

    agg_sk = sdk_adapter.aggregate_sender_sks([sk_a, sk_b])
    assert agg_sk.to_bytes() == (18).to_bytes(32, "big")  # the sum, as a SecretKey
    assert isinstance(agg_sk, sdk.SecretKey)

    agg_pk = sdk_adapter.aggregate_sender_pks([_pubkey(sk_a), _pubkey(sk_b)])
    assert agg_pk.is_infinity() == False  # non-identity PublicKey


# ==========================================================================
# Single-importer / coinset-consolidation invariants + error model
#
# Static checks scan repo-root *.py NON-RECURSIVELY (no rglob): the suite under
# tests/ legitimately imports chia_wallet_sdk, so tests/ is NOT scanned. The unit
# tests mock coinset.subprocess.run — no live CLI required. Uses the module-level
# json/re/Path/mock/pytest/REPO.
# ==========================================================================


def test_sole_sdk_importer():
    """Only `sdk_adapter.py` may import chia_wallet_sdk at the repo ROOT. Root
    scripts live at repo root (non-recursive glob); the suite under tests/ imports
    the SDK too, so tests/ is NOT scanned.
    """
    root_pys = list(REPO.glob("*.py"))  # non-recursive: repo root only
    offenders = [
        p.name
        for p in root_pys
        if p.name != "sdk_adapter.py"
        and re.search(
            r"(?m)^\s*(import chia_wallet_sdk|from chia_wallet_sdk)", p.read_text()
        )
    ]
    assert offenders == [], offenders


def test_coinset_consolidated():
    """coinset.py is the consolidation point — it owns the subprocess + CLI
    boundary. Asserts coinset.py exists and holds the boundary.
    """
    cs = REPO / "coinset.py"
    assert cs.exists()
    txt = cs.read_text()
    assert "subprocess.run" in txt and "coinset" in txt


def test_no_direct_coinset_in_root_scripts():
    """Static check: NO root script invokes coinset directly — all calls
    route through coinset.py. Scans repo-root *.py excluding coinset.py for the
    direct `subprocess.run([... "coinset" ...])` pattern.
    """
    offenders = [
        p.name
        for p in REPO.glob("*.py")
        if p.name != "coinset.py"
        and re.search(r'subprocess\.run\(\s*\[[^\]]*"coinset"', p.read_text())
    ]
    assert offenders == [], offenders


def test_coinset_error_model():
    """Mandatory getter raises RuntimeError on failure; the optional variant returns
    the sentinel. Three cases, each in its own mock.patch block.
    """
    import coinset

    # Case A (mandatory raises on returncode != 0).
    with mock.patch("coinset.subprocess.run") as m:
        m.return_value = mock.Mock(returncode=1, stderr="boom", stdout="")
        with pytest.raises(RuntimeError):
            coinset.get_coin_record("ab" * 32)

    # Case B (mandatory raises on success == False).
    with mock.patch("coinset.subprocess.run") as m:
        m.return_value = mock.Mock(
            returncode=0, stdout=json.dumps({"success": False}), stderr=""
        )
        with pytest.raises(RuntimeError):
            coinset.get_coin_record("ab" * 32)

    # Case C (optional variant returns sentinel None — non-fatal sweep).
    with mock.patch("coinset.subprocess.run") as m:
        m.return_value = mock.Mock(returncode=1, stderr="boom", stdout="")
        assert coinset.get_coin_record("ab" * 32, optional=True) is None


def test_coinset_height_args_not_prefixed():
    """get_block_records passes height args as plain strings WITHOUT a 0x prefix
    (0x-prefixing breaks the CLI).
    """
    import coinset

    with mock.patch("coinset.subprocess.run") as m:
        m.return_value = mock.Mock(
            returncode=0, stdout=json.dumps({"block_records": []}), stderr=""
        )
        coinset.get_block_records(100, 200)
        called = m.call_args[0][0]  # the argv list
        assert "100" in called and "200" in called
        assert "0x100" not in called and "0x200" not in called
