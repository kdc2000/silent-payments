"""
CAT2/NFT1 silent payment feasibility tests.

Validates that the sender's synthetic public key can be extracted from
CAT2 and NFT1 puzzle structures by recursively uncurrying puzzle layers.
Covers requirements EXT-01 (CAT2) and EXT-02 (NFT1).
"""

from chia_rs import G1Element, PrivateKey, Program
from chia_puzzles_py.programs import (
    CAT_PUZZLE,
    CAT_PUZZLE_HASH,
    NFT_OWNERSHIP_LAYER,
    NFT_OWNERSHIP_LAYER_HASH,
    NFT_STATE_LAYER,
    NFT_STATE_LAYER_HASH,
    P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE,
    SINGLETON_TOP_LAYER_V1_1,
    SINGLETON_TOP_LAYER_V1_1_HASH,
)
from shared import _encode_atom, calculate_synthetic_public_key, extract_synthetic_pk, master_sk_to_wallet_sk, mnemonic_to_master_sk, puzzle_for_pk

TEST_MNEMONIC_1 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

P2_MOD = Program.from_bytes(P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE)
P2_MOD_HASH = P2_MOD.get_tree_hash()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def lazy_node_to_bytes(node) -> bytes:
    """Recursively serialize a LazyNode tree back to CLVM bytes.

    LazyNode (from ``Program.uncurry_rust()``) has only ``.atom`` and
    ``.pair`` attributes -- no serialization method.  This helper
    rebuilds the canonical CLVM byte representation so that the result
    can be fed back into ``Program.from_bytes()``.
    """
    if node.atom is not None:
        return _encode_atom(node.atom)
    left, right = node.pair
    return b"\xff" + lazy_node_to_bytes(left) + lazy_node_to_bytes(right)


def curry_program(mod_bytes: bytes, args: list) -> Program:
    """Curry a mix of byte-atom and Program-tree arguments into *mod_bytes*.

    Each element of *args* is either:
    * ``bytes`` -- treated as an atom and encoded with ``_encode_atom``.
    * ``Program`` -- treated as a full tree and quoted in place.

    Produces the standard curried CLVM structure::

        (2 (1 . MOD_tree) (4 (1 . arg_N) ... (4 (1 . arg_1) 1)))
    """
    # Build the argument chain from right (innermost) to left (outermost).
    args_clvm = b"\x01"  # atom 1
    for arg in reversed(args):
        if isinstance(arg, Program):
            quoted_arg = b"\xff\x01" + bytes(arg)
        else:
            quoted_arg = b"\xff\x01" + _encode_atom(arg)
        args_clvm = b"\xff\x04\xff" + quoted_arg + b"\xff" + args_clvm + b"\x80"

    mod_prog = Program.from_bytes(mod_bytes)
    quote_mod = b"\xff\x01" + bytes(mod_prog)
    full = b"\xff\x02\xff" + quote_mod + b"\xff" + args_clvm + b"\x80"
    return Program.from_bytes_unchecked(full)


def extract_pk_from_puzzle(puzzle: Program) -> G1Element | None:
    """Extract the synthetic PK from any standard, CAT2, or NFT1 puzzle.

    Recursively uncurries layers by comparing the MOD tree-hash against
    known constants and navigating to the inner puzzle at each level.
    """
    try:
        mod_node, args_node = puzzle.uncurry_rust()
    except Exception:
        return None

    # Convert the mod LazyNode to a Program so we can hash it.
    try:
        mod_prog = Program.from_bytes(lazy_node_to_bytes(mod_node))
        mod_hash = mod_prog.get_tree_hash()
    except Exception:
        return None

    def _nth_arg(args, n):
        """Return the *n*-th curried argument LazyNode."""
        node = args
        for _ in range(n):
            _, node = node.pair
        first, _ = node.pair
        return first

    def _arg_to_program(arg_node) -> Program:
        return Program.from_bytes(lazy_node_to_bytes(arg_node))

    # Singleton top layer: inner puzzle is 2nd curried arg (index 1)
    if mod_hash == SINGLETON_TOP_LAYER_V1_1_HASH:
        inner = _arg_to_program(_nth_arg(args_node, 1))
        return extract_pk_from_puzzle(inner)

    # NFT state layer: inner puzzle is 4th curried arg (index 3)
    if mod_hash == NFT_STATE_LAYER_HASH:
        inner = _arg_to_program(_nth_arg(args_node, 3))
        return extract_pk_from_puzzle(inner)

    # NFT ownership layer: inner puzzle is 4th curried arg (index 3)
    if mod_hash == NFT_OWNERSHIP_LAYER_HASH:
        inner = _arg_to_program(_nth_arg(args_node, 3))
        return extract_pk_from_puzzle(inner)

    # CAT2 outer puzzle: inner puzzle is 3rd curried arg (index 2)
    if mod_hash == CAT_PUZZLE_HASH:
        inner = _arg_to_program(_nth_arg(args_node, 2))
        return extract_pk_from_puzzle(inner)

    # Standard p2 base case: synthetic PK is 1st curried arg (index 0)
    if mod_hash == P2_MOD_HASH:
        return extract_synthetic_pk(puzzle)

    return None


# ---------------------------------------------------------------------------
# Puzzle construction helpers
# ---------------------------------------------------------------------------


def _get_test_synthetic_pk() -> G1Element:
    """Derive a deterministic synthetic PK from TEST_MNEMONIC_1 index 0."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    wallet_sk = master_sk_to_wallet_sk(master, 0)
    return calculate_synthetic_public_key(wallet_sk.get_g1())


def _build_inner_p2() -> Program:
    """Build the standard p2 puzzle using the test synthetic PK."""
    master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    wallet_sk = master_sk_to_wallet_sk(master, 0)
    return puzzle_for_pk(wallet_sk.get_g1())


def build_cat2_puzzle(inner_puzzle: Program, tail_hash: bytes) -> Program:
    """Build a CAT2 puzzle wrapping *inner_puzzle*."""
    return curry_program(
        CAT_PUZZLE,
        [CAT_PUZZLE_HASH, tail_hash, inner_puzzle],
    )


def build_nft_puzzle(inner_puzzle: Program, with_ownership: bool) -> Program:
    """Build an NFT1 puzzle stack wrapping *inner_puzzle*.

    If *with_ownership* is True, a 4-layer stack is built
    (singleton -> state -> ownership -> p2).  Otherwise 3 layers
    (singleton -> state -> p2).
    """
    current = inner_puzzle

    # Optional: ownership layer
    if with_ownership:
        current = curry_program(
            NFT_OWNERSHIP_LAYER,
            [
                NFT_OWNERSHIP_LAYER_HASH,          # MOD_HASH
                b"\x00" * 32,                       # CURRENT_OWNER placeholder
                Program.from_bytes(b"\x80"),         # TRANSFER_PROGRAM placeholder (nil)
                current,                             # INNER_PUZZLE
            ],
        )

    # State layer
    current = curry_program(
        NFT_STATE_LAYER,
        [
            NFT_STATE_LAYER_HASH,                   # MOD_HASH
            Program.from_bytes(b"\x80"),              # METADATA placeholder (nil)
            b"\x00" * 32,                            # UPDATER_HASH placeholder
            current,                                  # INNER_PUZZLE
        ],
    )

    # Singleton top layer
    # Build singleton_struct: (SINGLETON_MOD_HASH . (LAUNCHER_ID . ()))
    singleton_struct = Program.from_bytes(
        b"\xff"
        + _encode_atom(SINGLETON_TOP_LAYER_V1_1_HASH)
        + b"\xff"
        + _encode_atom(b"\x00" * 32)
        + b"\x80"
    )
    current = curry_program(
        SINGLETON_TOP_LAYER_V1_1,
        [singleton_struct, current],
    )

    return current


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cat2_mod_identification():
    """EXT-01: Verify that a CAT2 puzzle's MOD can be identified by hash.

    Builds a CAT2 puzzle, uncurries it, converts the MOD LazyNode back
    to a Program, and asserts its tree-hash equals CAT_PUZZLE_HASH.
    """
    inner = _build_inner_p2()
    tail_hash = b"\xaa" * 32
    cat_puzzle = build_cat2_puzzle(inner, tail_hash)

    mod_node, _args_node = cat_puzzle.uncurry_rust()
    mod_bytes = lazy_node_to_bytes(mod_node)
    mod_prog = Program.from_bytes(mod_bytes)

    assert mod_prog.get_tree_hash() == CAT_PUZZLE_HASH, (
        f"Expected CAT_PUZZLE_HASH {CAT_PUZZLE_HASH.hex()}, "
        f"got {mod_prog.get_tree_hash().hex()}"
    )


def test_cat2_pk_extraction():
    """EXT-01: Extract synthetic PK from a CAT2 puzzle wrapping standard p2.

    Builds a CAT2 puzzle around a known p2 inner puzzle and verifies
    that extract_pk_from_puzzle() peels the CAT layer and returns the
    correct synthetic public key.
    """
    expected_pk = _get_test_synthetic_pk()
    inner = _build_inner_p2()
    tail_hash = b"\xbb" * 32
    cat_puzzle = build_cat2_puzzle(inner, tail_hash)

    extracted = extract_pk_from_puzzle(cat_puzzle)

    assert extracted is not None, "extract_pk_from_puzzle returned None for CAT2 puzzle"
    assert extracted == expected_pk, (
        f"Extracted PK {bytes(extracted).hex()} "
        f"does not match expected {bytes(expected_pk).hex()}"
    )


def test_nft1_4layer_pk_extraction():
    """EXT-02: Extract synthetic PK from a 4-layer NFT puzzle.

    Builds singleton -> state -> ownership -> p2 and verifies that
    extract_pk_from_puzzle() peels all four layers to reach the
    synthetic public key.
    """
    expected_pk = _get_test_synthetic_pk()
    inner = _build_inner_p2()
    nft_puzzle = build_nft_puzzle(inner, with_ownership=True)

    extracted = extract_pk_from_puzzle(nft_puzzle)

    assert extracted is not None, (
        "extract_pk_from_puzzle returned None for 4-layer NFT puzzle"
    )
    assert extracted == expected_pk, (
        f"Extracted PK {bytes(extracted).hex()} "
        f"does not match expected {bytes(expected_pk).hex()}"
    )


def test_nft1_3layer_pk_extraction():
    """EXT-02: Extract synthetic PK from a 3-layer NFT puzzle (no ownership).

    Builds singleton -> state -> p2 (skipping ownership layer) and
    verifies PK extraction still works correctly.
    """
    expected_pk = _get_test_synthetic_pk()
    inner = _build_inner_p2()
    nft_puzzle = build_nft_puzzle(inner, with_ownership=False)

    extracted = extract_pk_from_puzzle(nft_puzzle)

    assert extracted is not None, (
        "extract_pk_from_puzzle returned None for 3-layer NFT puzzle"
    )
    assert extracted == expected_pk, (
        f"Extracted PK {bytes(extracted).hex()} "
        f"does not match expected {bytes(expected_pk).hex()}"
    )


def test_nft1_layer_detection():
    """EXT-02: Verify that extract_pk_from_puzzle correctly detects
    both 3-layer and 4-layer NFT variants.

    Builds both variants with the same inner p2 puzzle and asserts
    that the same synthetic PK is extracted from each.
    """
    expected_pk = _get_test_synthetic_pk()
    inner = _build_inner_p2()

    nft_4layer = build_nft_puzzle(inner, with_ownership=True)
    nft_3layer = build_nft_puzzle(inner, with_ownership=False)

    pk_4layer = extract_pk_from_puzzle(nft_4layer)
    pk_3layer = extract_pk_from_puzzle(nft_3layer)

    assert pk_4layer is not None, "4-layer extraction returned None"
    assert pk_3layer is not None, "3-layer extraction returned None"
    assert pk_4layer == expected_pk, "4-layer PK does not match expected"
    assert pk_3layer == expected_pk, "3-layer PK does not match expected"
    assert pk_4layer == pk_3layer, (
        "4-layer and 3-layer extractions returned different PKs"
    )
