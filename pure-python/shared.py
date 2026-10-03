"""
Shared primitives for the CHIP-0057 Silent Payments reference implementation.

Protocol overview:
  - Recipient publishes a static silent payment address: a scan public key and
    a spend public key (both BLS12-381 G1 points) in a versioned bech32m string.
  - Sender uses ECDH between its input keys and the scan key to derive a
    one-time public key for each payment.
  - Only the holder of the scan secret key can detect the resulting coin, and
    only the holder of the spend secret key can spend it.

Docstrings refer to the sections of CHIP-0057 by name.
"""

import hashlib
import sys
from typing import Callable, Iterable

from chia_rs import Coin, G1Element, PrivateKey, Program
from chia_puzzles_py.programs import P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE

# BLS12-381 curve order
GROUP_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

# Maximum number of outputs per scan key in one spend group. A sender never
# creates more, and a scanner never looks further ("K_max: Maximum Outputs Per
# Spend Group").
K_MAX = 2400


def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


# Testnet11 genesis challenge (used for AGG_SIG_ME)
TESTNET11_GENESIS = bytes.fromhex(
    "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
)

# Standard puzzle
MOD = Program.from_bytes(P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE)
DEFAULT_HIDDEN_PUZZLE = Program.from_bytes(bytes.fromhex("ff0980"))
DEFAULT_HIDDEN_PUZZLE_HASH = DEFAULT_HIDDEN_PUZZLE.get_tree_hash()


def _scalar(sk: PrivateKey) -> int:
    """A secret key as an integer mod r."""
    return int.from_bytes(bytes(sk), "big")


def _private_key(scalar: int) -> PrivateKey:
    """An integer mod r as a secret key (ser256)."""
    return PrivateKey.from_bytes(scalar.to_bytes(32, "big"))


# --- Key derivation from mnemonic ---

def mnemonic_to_master_sk(mnemonic_phrase: str) -> PrivateKey:
    seed = hashlib.pbkdf2_hmac(
        "sha512", mnemonic_phrase.encode("utf-8"), b"mnemonic", 2048, dklen=64
    )
    return PrivateKey.from_seed(seed)


def load_mnemonic(args: list[str], prompt: str = "Enter mnemonic: ") -> str:
    """Load mnemonic from -f file flag, positional args, or interactive prompt."""
    import getpass
    import os

    if len(args) >= 2 and args[0] == "-f":
        filepath = args[1]
        if not os.path.isfile(filepath):
            print(f"Error: mnemonic file not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        with open(filepath, "r") as f:
            return f.read().strip()
    elif len(args) >= 1 and args[0] != "-f":
        return " ".join(args).strip()
    else:
        return getpass.getpass(prompt).strip()


def master_sk_to_wallet_sk(master_sk: PrivateKey, index: int = 0) -> PrivateKey:
    """Derive wallet secret key at m/12381/8444/2/<index> (all unhardened).

    This is Chia's standard wallet path. It is used for the sender's coins
    only, never for silent payment keys.
    """
    return (
        master_sk
        .derive_unhardened(12381)
        .derive_unhardened(8444)
        .derive_unhardened(2)
        .derive_unhardened(index)
    )


def master_sk_to_scan_sk(master_sk: PrivateKey) -> PrivateKey:
    """Derive the scan key at m/12381n/8444n/12n/0n ("Key Derivation").

    Every level is hardened. With unhardened derivation, a leaked scan key
    plus the wallet's master public key would reveal the master secret key.
    """
    return (master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(12)
        .derive_hardened(0))


def master_sk_to_spend_sk(master_sk: PrivateKey) -> PrivateKey:
    """Derive the spend key at m/12381n/8444n/13n/0n ("Key Derivation").

    Every level is hardened, as for the scan key.
    """
    return (master_sk
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(13)
        .derive_hardened(0))


def parse_g1_point(data: bytes, name: str = "point") -> G1Element:
    """Deserialize a point supplied by another party ("Point Validation").

    Raises ValueError unless `data` is the 48-byte compressed encoding of a
    valid element of the prime-order G1 subgroup other than the identity.
    """
    if len(data) != 48:
        raise ValueError(f"{name} must be 48 bytes, got {len(data)}")
    try:
        # G1Element.from_bytes checks that the point is on the curve and in
        # the prime-order subgroup (from_bytes_unchecked does not).
        point = G1Element.from_bytes(data)
    except ValueError as e:
        raise ValueError(f"{name} is not a valid G1 element: {e}") from None
    if point == G1Element():
        raise ValueError(f"{name} is the identity element")
    return point


def parse_watch_only_keys(scan_sk_hex: str, spend_pk_hex: str) -> tuple[PrivateKey, G1Element]:
    """Parse the two keys a watch-only scanner holds: b_scan and B_spend (hex)."""
    scan_bytes = bytes.fromhex(scan_sk_hex.removeprefix("0x"))
    if len(scan_bytes) != 32:
        raise ValueError(f"scan secret key must be 32 bytes, got {len(scan_bytes)}")
    if int.from_bytes(scan_bytes, "big") == 0:
        raise ValueError("scan secret key is zero")
    scan_sk = PrivateKey.from_bytes(scan_bytes)
    spend_pk = parse_g1_point(
        bytes.fromhex(spend_pk_hex.removeprefix("0x")), "spend public key"
    )
    return scan_sk, spend_pk


def load_scan_keys(
    scan_sk_hex: str | None,
    spend_pk_hex: str | None,
    mnemonic_file: str | None = None,
    mnemonic_words: list[str] | None = None,
    prompt: str = "Enter recipient mnemonic: ",
) -> tuple[PrivateKey, G1Element]:
    """The two keys a scanner needs: (b_scan, B_spend).

    Watch-only when the scan secret key and spend public key are given as
    hex; otherwise both are derived from a mnemonic (file, words, or prompt).
    """
    if scan_sk_hex or spend_pk_hex:
        if not (scan_sk_hex and spend_pk_hex):
            raise ValueError(
                "watch-only mode needs both the scan secret key and the spend public key"
            )
        return parse_watch_only_keys(scan_sk_hex, spend_pk_hex)

    if mnemonic_file:
        mnemonic = load_mnemonic(["-f", mnemonic_file], prompt=prompt)
    elif mnemonic_words:
        mnemonic = " ".join(mnemonic_words)
    else:
        mnemonic = load_mnemonic([], prompt=prompt)
    master_sk = mnemonic_to_master_sk(mnemonic)
    return master_sk_to_scan_sk(master_sk), master_sk_to_spend_sk(master_sk).get_g1()


# --- Standard puzzle functions ---

def _encode_atom(atom: bytes) -> bytes:
    """Encode a byte string as a CLVM atom with length prefix."""
    if len(atom) == 0:
        return b'\x80'
    if len(atom) == 1 and atom[0] <= 0x7f:
        return atom
    size = len(atom)
    if size < 0x40:
        return bytes([0x80 | size]) + atom
    if size < 0x2000:
        return bytes([0xc0 | (size >> 8), size & 0xff]) + atom
    raise ValueError(f"Atom too large: {size}")


def curry(mod: Program, *args) -> Program:
    """Curry arguments into a CLVM module, preserving mod as a tree.

    Builds: (2 (1 . MOD_TREE) (4 (1 . arg_N) ... (4 (1 . arg_1) 1)))
    The MOD is kept as a tree (not flattened to a blob) so the resulting
    puzzle hash matches what the Chia wallet produces.
    """
    # Build args: (4 (1 . arg) <rest>) for each arg
    args_clvm = b'\x01'  # atom 1
    for arg in reversed(args):
        quoted_arg = b'\xff\x01' + _encode_atom(arg)
        args_clvm = b'\xff\x04\xff' + quoted_arg + b'\xff' + args_clvm + b'\x80'

    # Build: (2 (1 . MOD_tree) args)
    quote_mod = b'\xff\x01' + bytes(mod)
    full = b'\xff\x02\xff' + quote_mod + b'\xff' + args_clvm + b'\x80'
    return Program.from_bytes_unchecked(full)


def calculate_synthetic_offset(pk: G1Element, hidden_puzzle_hash: bytes) -> int:
    """Synthetic offset, with the digest read as a signed integer
    ("Synthetic Key Computation Note")."""
    blob = hashlib.sha256(bytes(pk) + hidden_puzzle_hash).digest()
    return int.from_bytes(blob, "big", signed=True) % GROUP_ORDER


def calculate_synthetic_public_key(pk: G1Element) -> G1Element:
    offset = calculate_synthetic_offset(pk, DEFAULT_HIDDEN_PUZZLE_HASH)
    offset_pk = _private_key(offset).get_g1()
    return pk + offset_pk


def calculate_synthetic_secret_key(sk: PrivateKey) -> PrivateKey:
    pk = sk.get_g1()
    offset = calculate_synthetic_offset(pk, DEFAULT_HIDDEN_PUZZLE_HASH)
    synthetic = (_scalar(sk) + offset) % GROUP_ORDER
    return _private_key(synthetic)


def puzzle_for_pk(pk: G1Element) -> Program:
    synthetic_pk = calculate_synthetic_public_key(pk)
    return curry(MOD, bytes(synthetic_pk))


def puzzle_hash_for_pk(pk: G1Element) -> bytes:
    return puzzle_for_pk(pk).get_tree_hash()


def extract_synthetic_pk(puzzle: Program) -> G1Element | None:
    """Return the synthetic public key of a standard puzzle, else None
    ("Extracting the Synthetic Public Key").

    A key is returned only when `puzzle` is exactly
    `p2_delegated_puzzle_or_hidden_puzzle` curried with one 48-byte G1 public
    key and nothing else: the whole puzzle must hash to the same tree hash as
    the known module curried with the extracted key. That covers the required
    module-hash check, and also rejects outer puzzle layers, a different
    module that happens to have a key as its first argument, and extra
    curried arguments. A spend whose puzzle reveal passes is an eligible
    spend.
    """
    try:
        _, args_node = puzzle.uncurry_rust()
        if not args_node.pair:
            return None
        first, rest = args_node.pair
        if first.atom is None or len(first.atom) != 48:
            return None
        if rest.pair:
            return None  # more than one curried argument
        # from_bytes validates the encoding and the subgroup membership
        pk = G1Element.from_bytes(first.atom)
        if curry(MOD, bytes(pk)).get_tree_hash() != puzzle.get_tree_hash():
            return None
        return pk
    except Exception:
        return None


# --- Silent payment cryptography ---


def scalar_mult_g1(scalar: int, point: G1Element) -> G1Element:
    """Compute scalar * point using double-and-add on BLS12-381 G1.

    This is a Python-level implementation because chia_rs does not expose
    general scalar multiplication on arbitrary G1 points. If chia_rs
    exposed the underlying blst_p1_mult function (e.g., as
    G1Element.multiply(scalar_bytes)), this entire function could be
    replaced with a single native call, which would be significantly
    faster for production scanning.
    """
    result = G1Element()  # identity (point at infinity)
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = result + addend
        addend = addend + addend
        scalar >>= 1
    return result


def negate_g1(point: G1Element) -> G1Element:
    """Negate a G1 point by flipping the y-coordinate sign bit in compressed serialization.

    The chia_rs Rust code implements Neg and Sub traits on G1Element using
    blst_p1_cneg, but the Python bindings do not expose __neg__ or __sub__.
    If they did, this function could be replaced with: return -point
    """
    serialized = bytes(point)
    if serialized == bytes(G1Element()):  # point at infinity
        return point
    negated_bytes = bytes([serialized[0] ^ 0x20]) + serialized[1:]
    return G1Element.from_bytes(negated_bytes)


def subtract_g1(a: G1Element, b: G1Element) -> G1Element:
    """Compute a - b on G1."""
    return a + negate_g1(b)


def aggregate_sender_sks(sender_sks: list[PrivateKey]) -> PrivateKey:
    """Sum the sender's synthetic secret keys, one per coin in the spend group.

    Each sk MUST be a synthetic secret key (from calculate_synthetic_secret_key),
    NOT a raw wallet key. Returns a_sum = (a_1 + a_2 + ... + a_n) mod r.

    Raises ValueError if the sum is zero ("Identity Element (Zero-Sum
    Prevention)").
    """
    total = 0
    for sk in sender_sks:
        total = (total + _scalar(sk)) % GROUP_ORDER
    if total == 0:
        raise ValueError("aggregated sender key sum is zero — invalid for ECDH")
    return _private_key(total)


def aggregate_sender_pks(sender_pks: list[G1Element]) -> G1Element:
    """Sum the synthetic public keys of a spend group, one term per coin.

    Returns A_sum = A_1 + A_2 + ... + A_n (G1 point addition).
    The result is the identity element when the keys cancel; such a group is
    skipped by compute_tweak_point and scan_for_silent_payment.
    """
    result = G1Element()  # identity (point at infinity)
    for pk in sender_pks:
        result = result + pk
    return result


def compute_input_hash(coin_ids: list[bytes], sender_pk_sum: G1Element) -> int:
    """Compute input_hash from the smallest coin ID and aggregated sender PK.

    Adapts BIP-352 input hash for Chia: uses coin IDs (SHA256 of
    parent_info || puzzle_hash || amount) instead of Bitcoin outpoints.
    The result can be zero (with negligible probability); senders fail and
    scanners skip the group in that case ("Zero Scalars").
    """
    coin_id_L = min(coin_ids)  # lexicographically smallest
    hash_bytes = tagged_hash("Chia_SP/Inputs", coin_id_L + bytes(sender_pk_sum))
    return int.from_bytes(hash_bytes, "big") % GROUP_ORDER


def compute_tweak_point(coin_ids: list[bytes], sender_pk_sum: G1Element) -> G1Element | None:
    """Tweak point of a spend group: T = input_hash * A_sum ("Tweak Points").

    Returns None for a group that has no tweak point and must be skipped:
    A_sum is the identity element, or input_hash is zero.
    """
    if sender_pk_sum == G1Element():
        return None  # zero-sum guard
    input_hash = compute_input_hash(coin_ids, sender_pk_sum)
    if input_hash == 0:
        return None
    return scalar_mult_g1(input_hash, sender_pk_sum)


def compute_shared_secret_full(
    sender_sk: PrivateKey,
    recipient_scan_pk: G1Element,
    input_hash: int,
) -> bytes:
    """Sender-side ECDH shared secret: SHA256(serialize((input_hash * a_sum) * B_scan))."""
    adjusted_scalar = (input_hash * _scalar(sender_sk)) % GROUP_ORDER
    ecdh_point = scalar_mult_g1(adjusted_scalar, recipient_scan_pk)
    return hashlib.sha256(bytes(ecdh_point)).digest()


def compute_shared_secret_from_tweak_point(scan_sk: PrivateKey, tweak_point: G1Element) -> bytes:
    """Scanner-side ECDH shared secret: SHA256(serialize(b_scan * T)).

    `tweak_point` must already be validated (see parse_g1_point) when it
    comes from another party.
    """
    ecdh_point = scalar_mult_g1(_scalar(scan_sk), tweak_point)
    return hashlib.sha256(bytes(ecdh_point)).digest()


def derive_output_tweak(shared_secret: bytes, k: int) -> int:
    """Derive the output tweak t_k for output index k.

    The result can be zero (with negligible probability); senders fail and
    scanners stop in that case ("Zero Scalars").
    """
    tweak_data = shared_secret + k.to_bytes(4, "big")
    return int.from_bytes(
        tagged_hash("Chia_SP/SharedSecret", tweak_data), "big"
    ) % GROUP_ORDER


def derive_onetime_pk_full(spend_pk: G1Element, tweak: int) -> G1Element:
    """One-time PK: B_m + t_k * G (B_m is B_spend for an unlabeled address)."""
    tweak_pk = _private_key(tweak).get_g1()
    return spend_pk + tweak_pk


def combine_spend_tweak(t_k: int, label_scalar: int = 0) -> int:
    """The single value a scanner hands to the signer: (t_k + label_scalar) mod r."""
    return (t_k + label_scalar) % GROUP_ORDER


def derive_onetime_sk_full(spend_sk: PrivateKey, tweak: int) -> PrivateKey:
    """One-time SK for spending a detected coin: (b_spend + tweak) mod r ("Spending").

    `tweak` is the spend tweak recorded with the detection: t_k for an
    unlabeled output, (t_k + label_scalar) mod r for a labeled one. This is
    the only step of the protocol that needs the spend secret key.
    """
    onetime = (_scalar(spend_sk) + tweak) % GROUP_ORDER
    return _private_key(onetime)


# --- Labels ---

def compute_label_scalar(scan_sk: PrivateKey, m: int) -> int:
    """label_scalar = int(tagged_hash("Chia_SP/Label", ser256(b_scan) || ser32(m))) mod r."""
    if not 0 <= m < 2**32:
        raise ValueError(f"label index must fit in 32 bits, got {m}")
    label_data = bytes(scan_sk) + m.to_bytes(4, "big")
    return int.from_bytes(
        tagged_hash("Chia_SP/Label", label_data), "big"
    ) % GROUP_ORDER


def generate_label(scan_sk: PrivateKey, m: int) -> tuple[int, G1Element]:
    """Generate label m. Returns (label_scalar, label_point).

    Label m=0 is reserved for the wallet's own change outputs: it is scanned
    for, but its address is never handed out (see generate_labeled_address
    and own_change_recipient).

    Raises ValueError if the label scalar is zero: such a label would make
    the labeled address identical to the unlabeled one and must not be used
    ("Zero Scalars").
    """
    label_scalar = compute_label_scalar(scan_sk, m)
    if label_scalar == 0:
        raise ValueError(f"label index {m} has a zero label scalar and must not be used")
    label_pk = _private_key(label_scalar).get_g1()
    return label_scalar, label_pk


def generate_labeled_spend_pk(spend_pk: G1Element, label_pk: G1Element) -> G1Element:
    """B_m = B_spend + label_point."""
    return spend_pk + label_pk


def build_label_map(scan_sk: PrivateKey, indices: Iterable[int] = ()) -> dict[bytes, int]:
    """Label map for scanning: bytes(label_pk) -> m.

    The change label m = 0 is always included, whatever `indices` says, so
    that change outputs are found even by a wallet that uses no other labels
    ("Labels for change", "Backup and Recovery").
    """
    label_map: dict[bytes, int] = {}
    for m in sorted({0, *indices}):
        label_scalar = compute_label_scalar(scan_sk, m)
        if label_scalar == 0:
            if m == 0:
                continue  # the change label is unusable with this scan key
            raise ValueError(f"label index {m} has a zero label scalar and must not be used")
        label_map[bytes(_private_key(label_scalar).get_g1())] = m
    return label_map


def own_change_recipient(scan_sk: PrivateKey, spend_pk: G1Element) -> tuple[G1Element, G1Element]:
    """Recipient entry (B_scan, B_0) for the wallet's OWN change outputs.

    Use the result only as a recipient in a transaction this wallet builds
    itself. It is deliberately not encoded as an address: the label m = 0
    address must never be handed out, or someone else could create payments
    that are wrongly identified as change ("Change Detection (m = 0)").
    """
    _, label_pk = generate_label(scan_sk, 0)
    return scan_sk.get_g1(), generate_labeled_spend_pk(spend_pk, label_pk)


# --- Sending ---

def derive_silent_payment_outputs(
    sender_sks: "PrivateKey | list[PrivateKey]",
    coin_ids: list[bytes],
    recipients: list[tuple[G1Element, G1Element]],
) -> list[dict]:
    """Procedure SendSilentPayment ("Sending"), with all intermediate values.

    Args:
        sender_sks: The synthetic secret keys of the coins in the spend group,
            one per coin (a list as long as `coin_ids`). A single PrivateKey
            is taken as the already aggregated key a_sum.
        coin_ids: Coin IDs of ALL coins in the spend group, and of no others.
        recipients: List of (B_scan, B_m) pairs, where B_m is the second key
            of the recipient's address. The same pair may appear several
            times. Entries that share a B_scan are assigned output indices
            k = 0, 1, ... in list order, across labels.

    Returns:
        One dict per recipient entry, in the order of `recipients`, with keys
        k, shared_secret (bytes), t_k (int), onetime_pk (G1Element) and
        puzzle_hash (bytes).

    Raises ValueError when the procedure fails: a recipient key is the
    identity element, a scan key has more than K_MAX entries, the key sum is
    zero, or input_hash or a t_k is zero.

    The caller must create every returned output, from a coin in the spend
    group, and bind the group's coins as "Inputs for Shared Secret Derivation"
    requires (see send_payment.build_silent_payment_spend).
    """
    if isinstance(sender_sks, PrivateKey):
        sender_sks = [sender_sks]
    elif len(sender_sks) != len(coin_ids):
        raise ValueError(
            f"need one secret key per coin in the spend group: "
            f"{len(sender_sks)} keys for {len(coin_ids)} coins"
        )
    if not coin_ids:
        raise ValueError("a spend group has at least one coin")
    if any(len(coin_id) != 32 for coin_id in coin_ids):
        raise ValueError("coin IDs must be 32 bytes")
    if len(set(coin_ids)) != len(coin_ids):
        raise ValueError("duplicate coin ID in the spend group")

    identity = G1Element()
    for scan_pk, spend_pk in recipients:
        if scan_pk == identity or spend_pk == identity:
            raise ValueError("recipient key is the identity element")

    # Group recipients by B_scan, preserving original order
    groups: dict[bytes, list[tuple[int, G1Element]]] = {}
    for idx, (scan_pk, spend_pk) in enumerate(recipients):
        groups.setdefault(bytes(scan_pk), []).append((idx, spend_pk))
    for entries in groups.values():
        if len(entries) > K_MAX:
            raise ValueError(
                f"{len(entries)} outputs for one scan key exceeds K_max = {K_MAX}"
            )

    sender_sk = aggregate_sender_sks(sender_sks)  # fails on a zero sum
    sender_pk = sender_sk.get_g1()
    input_hash = compute_input_hash(coin_ids, sender_pk)
    if input_hash == 0:
        raise ValueError("input_hash is zero")

    outputs: list = [None] * len(recipients)
    for scan_pk_bytes, entries in groups.items():
        scan_pk = G1Element.from_bytes(scan_pk_bytes)
        shared_secret = compute_shared_secret_full(sender_sk, scan_pk, input_hash)
        for k, (orig_idx, spend_pk) in enumerate(entries):
            tweak = derive_output_tweak(shared_secret, k)
            if tweak == 0:
                raise ValueError(f"output tweak t_{k} is zero")
            onetime_pk = derive_onetime_pk_full(spend_pk, tweak)
            outputs[orig_idx] = {
                "k": k, "shared_secret": shared_secret, "t_k": tweak,
                "onetime_pk": onetime_pk,
                "puzzle_hash": puzzle_hash_for_pk(onetime_pk),
            }

    return outputs


def create_silent_payment_outputs(
    sender_sks: "PrivateKey | list[PrivateKey]",
    coin_ids: list[bytes],
    recipients: list[tuple[G1Element, G1Element]],
) -> list[tuple[G1Element, bytes]]:
    """Derive the outputs of a silent payment transaction.

    Same arguments and failure cases as derive_silent_payment_outputs.

    Returns:
        List of (onetime_pk, puzzle_hash) tuples, one per recipient entry.
        Order matches the input recipients list.
    """
    return [
        (o["onetime_pk"], o["puzzle_hash"])
        for o in derive_silent_payment_outputs(sender_sks, coin_ids, recipients)
    ]


# --- Scanning ---

def scan_for_silent_payment(
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    sender_pk: G1Element,
    coin_ids: list[bytes],
    outputs: list[Coin],
    labels: dict[bytes, int] | None = None,
    output_filter: Callable[[Coin], bool] | None = None,
) -> list[dict]:
    """Procedure ScanForSilentPayment ("Scanning a Spend Group").

    Needs only the scan SECRET key and the spend PUBLIC key.

    Args:
        scan_sk: Recipient's scan secret key (b_scan).
        spend_pk: Recipient's spend public key (B_spend).
        sender_pk: A_sum, the sum of the synthetic public keys of all coins
            in the spend group (for a single-input group, the one key).
        coin_ids: Coin IDs of all coins in the spend group.
        outputs: The output coins to check (see "Output Matching Scope").
        labels: Optional dict mapping bytes(label_pk) -> m. The change label
            m = 0 is checked even when it is not in the dict.
        output_filter: Optional wallet policy (a dust filter, for example).
            A coin for which it returns False is left out of the result, but
            still counts as a match: the scan continues to the next index.

    Returns:
        One dict for EVERY output coin that carries a matching puzzle hash,
        with keys: coin (Coin), coin_id (bytes), k (output index), label
        (int|None), t_k (int), spend_tweak (int, (t_k + label_scalar) mod r),
        puzzle_hash (bytes), onetime_pk (G1Element). No secret key is
        derived here; see derive_onetime_sk_full.
    """
    tweak_point = compute_tweak_point(coin_ids, sender_pk)
    if tweak_point is None:
        return []  # identity key sum or zero input_hash: skip this group
    return _scan_with_tweak_point(
        scan_sk, spend_pk, tweak_point, outputs, labels, output_filter
    )


def scan_tweak_point(
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    tweak_point: bytes,
    outputs: list[Coin],
    labels: dict[bytes, int] | None = None,
    output_filter: Callable[[Coin], bool] | None = None,
) -> list[dict]:
    """Scan with a tweak point received from another party ("Tweak Points").

    `tweak_point` is the 48-byte serialization of T = input_hash * A_sum. It
    is validated (valid G1 element, in the prime-order subgroup, not the
    identity) BEFORE it is multiplied by the scan secret key; ValueError is
    raised if it fails.

    A tweak point carries no parent information, so `outputs` should be all
    additions of the block that were created by a coin spend ("Output
    Matching Scope"). The remaining arguments and the result are those of
    scan_for_silent_payment.
    """
    point = parse_g1_point(bytes(tweak_point), "tweak point")
    return _scan_with_tweak_point(
        scan_sk, spend_pk, point, outputs, labels, output_filter
    )


def _scan_with_tweak_point(
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    tweak_point: G1Element,
    outputs: list[Coin],
    labels: dict[bytes, int] | None,
    output_filter: Callable[[Coin], bool] | None,
) -> list[dict]:
    """The part of ScanForSilentPayment that follows the tweak point."""
    shared_secret = compute_shared_secret_from_tweak_point(scan_sk, tweak_point)

    # Always check the change label m = 0; try labels in ascending order of m.
    label_map = dict(labels or {})
    if 0 not in label_map.values():
        label_map.update(build_label_map(scan_sk))
    label_entries = sorted((m, label_pk_bytes) for label_pk_bytes, m in label_map.items())

    # Candidate puzzle hashes are matched by lookup. Several coins can carry
    # the same puzzle hash; all of them are recorded.
    coins_by_puzzle_hash: dict[bytes, list[Coin]] = {}
    for coin in outputs:
        coins_by_puzzle_hash.setdefault(bytes(coin.puzzle_hash), []).append(coin)

    detected: list[dict] = []

    def record(k, tweak, label, label_scalar, onetime_pk, puzzle_hash):
        for coin in coins_by_puzzle_hash[puzzle_hash]:
            # Wallet policy only decides what is reported. It never decides
            # whether the scan continues to k+1.
            if output_filter is not None and not output_filter(coin):
                continue
            detected.append({
                "coin": coin, "coin_id": bytes(coin.name()),
                "k": k, "label": label,
                "t_k": tweak,
                "spend_tweak": combine_spend_tweak(tweak, label_scalar),
                "puzzle_hash": puzzle_hash, "onetime_pk": onetime_pk,
            })

    for k in range(K_MAX):
        tweak = derive_output_tweak(shared_secret, k)
        if tweak == 0:
            break
        base_pk = derive_onetime_pk_full(spend_pk, tweak)
        base_ph = puzzle_hash_for_pk(base_pk)

        # The unlabeled candidate is tried first.
        if base_ph in coins_by_puzzle_hash:
            record(k, tweak, None, 0, base_pk, base_ph)
            continue

        # Labels are checked by forward computation; the first match wins.
        found = False
        for m, label_pk_bytes in label_entries:
            labeled_pk = base_pk + G1Element.from_bytes(label_pk_bytes)
            labeled_ph = puzzle_hash_for_pk(labeled_pk)
            if labeled_ph in coins_by_puzzle_hash:
                label_scalar, label_pk = generate_label(scan_sk, m)
                if bytes(label_pk) != label_pk_bytes:
                    raise ValueError(f"label map entry for m = {m} does not belong to this scan key")
                record(k, tweak, m, label_scalar, labeled_pk, labeled_ph)
                found = True
                break

        if not found:
            break

    return detected


# --- Bech32m address encoding ---

BECH32M_CONST = 0x2bc830a3
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32m_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32m_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    """Regroup bits. With pad=False (decoding), leftover bits must be fewer
    than `frombits` and all zero, otherwise ValueError is raised."""
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits:
        raise ValueError("excess padding")
    elif (acc << (tobits - bits)) & maxv:
        raise ValueError("non-zero padding bits")
    return ret


def bech32m_encode(prefix: str, data: list[int]) -> str:
    """Encode 5-bit values as a bech32m string, with no length limit."""
    checksum = _bech32m_polymod(_bech32m_hrp_expand(prefix) + data + [0] * 6) ^ BECH32M_CONST
    data = data + [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
    return prefix + "1" + "".join(BECH32_CHARSET[d] for d in data)


def puzzle_hash_to_address(puzzle_hash: bytes, prefix: str = "txch") -> str:
    """Encode a puzzle hash as a bech32m address (txch for testnet, xch for mainnet)."""
    return bech32m_encode(prefix, _convertbits(puzzle_hash, 8, 5))


# --- Coin ID utilities ---

def int_to_bytes(v: int) -> bytes:
    """Variable-length big-endian encoding matching Chia's int_to_bytes."""
    if v == 0:
        return b"\x00"
    byte_count = (v.bit_length() + 8) >> 3
    return v.to_bytes(byte_count, "big")


def compute_coin_id(parent: bytes, puzzle_hash: bytes, amount: int) -> bytes:
    """Compute a coin's ID: SHA256(parent_coin_info || puzzle_hash || amount)."""
    return hashlib.sha256(parent + puzzle_hash + int_to_bytes(amount)).digest()


# --- Silent payment address ---

SP_ADDRESS_VERSION = 0  # the version this implementation emits (96-byte payload)
SP_ADDRESS_MAX_LENGTH = 1023  # silent payment addresses exceed bech32's 90 characters
SP_ADDRESS_PREFIXES = ("spxch", "tspxch")  # mainnet, testnet


def encode_silent_payment_address(scan_pk: bytes, spend_pk: bytes, prefix: str = "tspxch") -> str:
    """Encode scan + spend public keys as a version 0 silent payment address
    ("Silent Payment Address").

    The data part is the version character followed by the 96-byte payload
    serialize(B_scan) || serialize(B_spend). For a labeled address pass B_m
    as `spend_pk`. Both keys are validated, so that no address is produced
    that a decoder has to reject.
    """
    if prefix not in SP_ADDRESS_PREFIXES:
        raise ValueError(f"Invalid silent payment address prefix: '{prefix}'")
    if len(scan_pk) != 48:
        raise ValueError(f"scan_pk must be 48 bytes, got {len(scan_pk)}")
    if len(spend_pk) != 48:
        raise ValueError(f"spend_pk must be 48 bytes, got {len(spend_pk)}")
    parse_g1_point(scan_pk, "scan key")
    parse_g1_point(spend_pk, "spend key")

    payload = scan_pk + spend_pk  # 96 bytes
    return bech32m_encode(prefix, [SP_ADDRESS_VERSION] + _convertbits(payload, 8, 5))


def decode_silent_payment_address(
    address: str, expected_prefix: str | None = None
) -> tuple[bytes, bytes]:
    """Decode a silent payment address into (scan_pk, spend_pk) bytes.

    Rules of "Silent Payment Address" and "Address Versioning":
    - up to 1,023 characters;
    - version 0: the payload must be exactly 96 bytes;
    - versions 1-30 (forward compatible): the payload must be at least 96
      bytes; the first 96 bytes are the keys and the rest is ignored;
    - version 31: always rejected;
    - leftover padding bits must be zero;
    - both keys must be valid elements of the prime-order G1 subgroup and
      must not be the identity element.

    A sender passes `expected_prefix` ("spxch" or "tspxch") to reject an
    address for a network other than the one it is transacting on.

    Raises ValueError for an address that must be rejected.
    """
    if len(address) > SP_ADDRESS_MAX_LENGTH:
        raise ValueError(
            f"Address too long: {len(address)} characters (max {SP_ADDRESS_MAX_LENGTH})"
        )
    # bech32m: all lower case or all upper case, never mixed
    if address != address.lower() and address != address.upper():
        raise ValueError("Invalid bech32m address: mixed case")
    address = address.lower()

    # Find separator (last '1')
    sep = address.rfind("1")
    if sep < 1:
        raise ValueError("Invalid bech32m address: no separator found")

    hrp = address[:sep]
    if hrp not in SP_ADDRESS_PREFIXES:
        raise ValueError(f"Invalid silent payment address prefix: '{hrp}' (expected 'tspxch' or 'spxch')")
    if expected_prefix is not None and hrp != expected_prefix:
        raise ValueError(
            f"Address is for another network: prefix '{hrp}', expected '{expected_prefix}'"
        )

    data_part_str = address[sep + 1:]

    # Decode bech32 characters to 5-bit integers
    charset_map = {c: i for i, c in enumerate(BECH32_CHARSET)}
    data_5bit = []
    for c in data_part_str:
        if c not in charset_map:
            raise ValueError(f"Invalid bech32 character: '{c}'")
        data_5bit.append(charset_map[c])

    # Verify checksum
    if _bech32m_polymod(_bech32m_hrp_expand(hrp) + data_5bit) != BECH32M_CONST:
        raise ValueError("Invalid bech32m checksum")

    # Need at least the version character plus the 6-value checksum.
    if len(data_5bit) < 7:
        raise ValueError("Invalid silent payment address: data part too short")

    version = data_5bit[0]
    if version == 31:
        raise ValueError(
            "Silent payment address version 31 is reserved for a backward-incompatible "
            "upgrade; this implementation cannot send to it"
        )

    # Strip version character + 6-value checksum, convert from 5-bit to 8-bit
    try:
        payload = bytes(_convertbits(data_5bit[1:-6], 5, 8, pad=False))
    except ValueError as e:
        raise ValueError(f"Invalid silent payment address payload: {e}") from None

    if version == 0:
        if len(payload) != 96:
            raise ValueError(f"Invalid v0 payload length: expected 96 bytes, got {len(payload)}")
    elif len(payload) < 96:
        raise ValueError(
            f"Invalid v{version} payload length: expected at least 96 bytes, got {len(payload)}"
        )

    # Forward compatibility (versions 1-30): use the first 96 bytes, ignore the rest.
    scan_pk, spend_pk = payload[:48], payload[48:96]
    parse_g1_point(scan_pk, "scan key")
    parse_g1_point(spend_pk, "spend key")
    return scan_pk, spend_pk


def generate_labeled_address(
    scan_sk: PrivateKey, spend_pk: G1Element, m: int, prefix: str = "tspxch"
) -> str:
    """The labeled address (B_scan, B_m) for label index m >= 1 ("Label Generation").

    Refuses m = 0: that label is reserved for the wallet's own change and its
    address must never be handed out (see own_change_recipient).
    """
    if m < 1:
        raise ValueError(
            "label index must be 1 or higher: m = 0 is reserved for change "
            "and is never handed out as an address"
        )
    _, label_pk = generate_label(scan_sk, m)
    labeled_spend_pk = generate_labeled_spend_pk(spend_pk, label_pk)
    return encode_silent_payment_address(
        bytes(scan_sk.get_g1()), bytes(labeled_spend_pk), prefix
    )
