"""Unit tests for send_payment.py: the cyclic ASSERT_CONCURRENT_SPEND emission
and the coin selection (`select_coins`).

These tests exercise the pure helper `build_coin_spend_conditions` directly,
verifying that the N-coin cyclic opcode-64 binding pattern (Sage's
`Relation::AssertConcurrent`) is constructed exactly as required by the
silent-payments protocol:

- N == 1: zero opcode-64 conditions (no binding needed).
- N >= 2: every coin emits exactly one opcode-64 condition pointing at its
  predecessor; coin 0 wraps to coin N-1 (closing the cycle).

Exercising the condition list independently of the on-chain spend bundle guards
against a dead `puzzle.run` path going undetected.
"""
import pytest

from send_payment import build_coin_spend_conditions, select_coins


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


# --------------------------------------------------------------------------
# select_coins: largest first, deterministic, derivation index ignored
# --------------------------------------------------------------------------

def _coin(tag: int, amount: int, index: int = 0) -> dict:
    return {"coin_id": bytes([tag]) * 32, "amount": amount, "derivation_index": index}


def test_select_coins_single_coin_covers():
    """One coin is enough: the largest coin alone is selected."""
    coins = [_coin(1, 300), _coin(2, 1_000), _coin(3, 500)]
    assert select_coins(coins, 800) == [_coin(2, 1_000)]
    assert select_coins(coins, 1_000) == [_coin(2, 1_000)]  # exact cover


def test_select_coins_largest_first_until_covered():
    """Coins are added largest first and selection stops as soon as the total
    covers the need; smaller coins are left alone."""
    coins = [_coin(1, 300), _coin(2, 1_000), _coin(3, 500), _coin(4, 50)]
    assert select_coins(coins, 1_001) == [_coin(2, 1_000), _coin(3, 500)]
    assert select_coins(coins, 1_800) == [_coin(2, 1_000), _coin(3, 500), _coin(1, 300)]
    assert select_coins(coins, 1_850) == [
        _coin(2, 1_000), _coin(3, 500), _coin(1, 300), _coin(4, 50)
    ]


def test_select_coins_is_independent_of_input_order():
    """Equal amounts are ordered by coin ID, so the result does not depend on the
    order the wallet lists its coins in."""
    coins = [_coin(9, 400), _coin(2, 400), _coin(5, 400), _coin(7, 100)]
    expected = [_coin(2, 400), _coin(5, 400)]
    assert select_coins(coins, 800) == expected
    assert select_coins(list(reversed(coins)), 800) == expected


def test_select_coins_ignores_derivation_index():
    """A larger coin at another derivation index is preferred over several
    smaller coins at one index, and a selection may span indices."""
    coins = [_coin(1, 400, index=0), _coin(2, 400, index=0), _coin(3, 700, index=5)]
    assert select_coins(coins, 700) == [_coin(3, 700, index=5)]
    spanning = select_coins(coins, 1_000)
    assert spanning == [_coin(3, 700, index=5), _coin(1, 400, index=0)]
    assert {c["derivation_index"] for c in spanning} == {0, 5}


def test_select_coins_insufficient_funds_and_edge_cases():
    """All coins together not covering the need -> None. A need of 0 selects the
    single largest coin; no coins at all -> None. The input list is not mutated."""
    coins = [_coin(1, 300), _coin(2, 1_000)]
    snapshot = list(coins)
    assert select_coins(coins, 1_301) is None
    assert select_coins(coins, 1_300) == [_coin(2, 1_000), _coin(1, 300)]
    assert select_coins(coins, 0) == [_coin(2, 1_000)]
    assert select_coins([], 0) is None
    assert select_coins([], 1) is None
    assert coins == snapshot


def test_send_payment_has_no_same_index_warning():
    """The sender does not warn that a multi-input payment spanning derivation
    indices might be missed: such a payment is bound by the ASSERT_CONCURRENT_SPEND
    cycle and detected (tests/test_recipient_flow.py::
    test_selected_mixed_index_coins_are_detected_and_spent)."""
    import inspect

    import send_payment
    source = inspect.getsource(send_payment)
    assert "may not detect" not in source
    assert "span multiple derivation indices" not in source
