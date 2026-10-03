"""Unit tests for the cyclic ASSERT_CONCURRENT_SPEND emission in send_payment.py.

These tests exercise the pure helper `build_coin_spend_conditions` directly,
verifying that the N-coin cyclic opcode-64 binding pattern (matching Sage's
chia-wallet-sdk `Relation::AssertConcurrent`) is constructed as required by
the multi-input silent-payment contract:

- N == 1: zero opcode-64 conditions (no binding needed).
- N >= 2: every coin emits exactly one opcode-64 condition pointing at its
  predecessor; coin 0 wraps to coin N-1 (closing the cycle).

Exercising the condition list independently of the on-chain spend bundle
guards against the binding pattern silently drifting away from a single cycle,
which is what the scanner's Pass 2 SCC walker relies on.
"""
import pytest

from send_payment import build_coin_spend_conditions


def test_single_input_no_binding():
    """N=1: helper returns the primary outputs verbatim, with no opcode-64."""
    sage_coins = [{"coin_id": b"\xaa" * 32}]
    primary = [[51, b"\xbb" * 32, 1000]]
    result = build_coin_spend_conditions(0, sage_coins, primary)
    assert result == primary
    assert all(c[0] != 64 for c in result)


def test_two_coin_cycle_predecessors():
    """N=2: coin 0 asserts coin 1 (wrap); coin 1 asserts coin 0."""
    a_id, b_id = b"A" * 32, b"B" * 32
    sage_coins = [{"coin_id": a_id}, {"coin_id": b_id}]
    primary = [[51, b"\xcc" * 32, 500]]

    c0 = build_coin_spend_conditions(0, sage_coins, primary)
    c1 = build_coin_spend_conditions(1, sage_coins, [])

    assert c0 == [[51, b"\xcc" * 32, 500], [64, b_id]]  # coin 0 -> coin 1 (wrap)
    assert c1 == [[64, a_id]]                            # coin 1 -> coin 0


def test_three_coin_cycle_predecessors():
    """N=3: coin 0 -> coin 2 (wrap); coin 1 -> coin 0; coin 2 -> coin 1."""
    a, b, c = b"A" * 32, b"B" * 32, b"C" * 32
    sage_coins = [{"coin_id": a}, {"coin_id": b}, {"coin_id": c}]

    c0 = build_coin_spend_conditions(0, sage_coins, [[51, b"\xdd" * 32, 100]])
    c1 = build_coin_spend_conditions(1, sage_coins, [])
    c2 = build_coin_spend_conditions(2, sage_coins, [])

    # Coin 0 should have the primary output followed by the opcode-64 wrap.
    assert c0[0] == [51, b"\xdd" * 32, 100]
    assert c0[-1] == [64, c]   # coin 0 wraps to coin 2
    assert len(c0) == 2
    assert c1 == [[64, a]]     # coin 1 -> coin 0
    assert c2 == [[64, b]]     # coin 2 -> coin 1


@pytest.mark.parametrize("N", [2, 3, 5, 10])
def test_cycle_predecessor_pointer_exactness(N):
    """For every N in {2, 3, 5, 10}, the multiset of (asserter, asserted)
    edges equals exactly {(coins[i], coins[(i-1) % N]) for i in range(N)}.

    This is the canonical "every coin asserts its predecessor; the cycle
    closes via coin 0 -> coin N-1" check.
    """
    sage_coins = [{"coin_id": bytes([i]) * 32} for i in range(N)]
    edges = set()
    for i in range(N):
        conds = build_coin_spend_conditions(i, sage_coins, [])
        op64 = [c for c in conds if c[0] == 64]
        assert len(op64) == 1, f"coin {i} did not emit exactly one opcode-64"
        edges.add((sage_coins[i]["coin_id"], op64[0][1]))

    expected = {
        (sage_coins[i]["coin_id"], sage_coins[(i - 1) % N]["coin_id"])
        for i in range(N)
    }
    assert edges == expected


def test_imports_no_announcement_symbols():
    """Sender module exposes no announcement-binding helper names."""
    import send_payment
    assert not hasattr(send_payment, "bind_msg")
    assert not hasattr(send_payment, "ann_id")
