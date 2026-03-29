"""
Shared utilities for Chia Silent Payments prototype.

Protocol overview:
  - Recipient publishes a static silent payment address (a BLS G1 public key).
  - Sender uses ECDH to derive a one-time public key for each payment.
  - Only the recipient can detect and spend the resulting coin.
"""

import hashlib
import sys
from chia_rs import G1Element, PrivateKey, Program
from chia_puzzles_py.programs import P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE

# BLS12-381 curve order
GROUP_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


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
    """Derive wallet secret key at m/12381/8444/2/<index> (all unhardened)."""
    return (
        master_sk
        .derive_unhardened(12381)
        .derive_unhardened(8444)
        .derive_unhardened(2)
        .derive_unhardened(index)
    )


def master_sk_to_scan_sk(master_sk: PrivateKey) -> PrivateKey:
    """Derive scan key at m/12381/8444/12/0 (unhardened)."""
    return (master_sk
        .derive_unhardened(12381)
        .derive_unhardened(8444)
        .derive_unhardened(12)
        .derive_unhardened(0))


def master_sk_to_spend_sk(master_sk: PrivateKey) -> PrivateKey:
    """Derive spend key at m/12381/8444/13/0 (unhardened)."""
    return (master_sk
        .derive_unhardened(12381)
        .derive_unhardened(8444)
        .derive_unhardened(13)
        .derive_unhardened(0))


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
    blob = hashlib.sha256(bytes(pk) + hidden_puzzle_hash).digest()
    return int.from_bytes(blob, "big", signed=True) % GROUP_ORDER


def calculate_synthetic_public_key(pk: G1Element) -> G1Element:
    offset = calculate_synthetic_offset(pk, DEFAULT_HIDDEN_PUZZLE_HASH)
    offset_pk = PrivateKey.from_bytes(offset.to_bytes(32, "big")).get_g1()
    return pk + offset_pk


def calculate_synthetic_secret_key(sk: PrivateKey) -> PrivateKey:
    pk = sk.get_g1()
    offset = calculate_synthetic_offset(pk, DEFAULT_HIDDEN_PUZZLE_HASH)
    synthetic = (int.from_bytes(bytes(sk), "big") + offset) % GROUP_ORDER
    return PrivateKey.from_bytes(synthetic.to_bytes(32, "big"))


def puzzle_for_pk(pk: G1Element) -> Program:
    synthetic_pk = calculate_synthetic_public_key(pk)
    return curry(MOD, bytes(synthetic_pk))


def puzzle_hash_for_pk(pk: G1Element) -> bytes:
    return puzzle_for_pk(pk).get_tree_hash()


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
    """Sum multiple sender synthetic secret keys for multi-input ECDH.

    Each sk MUST be a synthetic secret key (from calculate_synthetic_secret_key),
    NOT a raw wallet key. Returns a_sum = (a_1 + a_2 + ... + a_n) mod r.

    Raises ValueError if the sum is zero (BIP-352 edge case).
    """
    total = 0
    for sk in sender_sks:
        total = (total + int.from_bytes(bytes(sk), "big")) % GROUP_ORDER
    if total == 0:
        raise ValueError("aggregated sender key sum is zero — invalid for ECDH")
    return PrivateKey.from_bytes(total.to_bytes(32, "big"))


def aggregate_sender_pks(sender_pks: list[G1Element]) -> G1Element:
    """Sum multiple sender synthetic public keys for multi-input scanning.

    Returns A_sum = A_1 + A_2 + ... + A_n (G1 point addition).
    Caller must check result != G1Element() (identity) before using for ECDH.
    """
    result = G1Element()  # identity (point at infinity)
    for pk in sender_pks:
        result = result + pk
    return result


def compute_input_hash(coin_ids: list[bytes], sender_pk_sum: G1Element) -> int:
    """Compute input_hash from the smallest coin ID and aggregated sender PK.

    Adapts BIP-352 input hash for Chia: uses coin IDs (SHA256 of
    parent_info || puzzle_hash || amount) instead of Bitcoin outpoints.
    """
    coin_id_L = min(coin_ids)  # lexicographically smallest
    hash_bytes = tagged_hash("Chia_SP/Inputs", coin_id_L + bytes(sender_pk_sum))
    return int.from_bytes(hash_bytes, "big") % GROUP_ORDER


def compute_shared_secret_full(
    sender_sk: PrivateKey,
    recipient_scan_pk: G1Element,
    input_hash: int,
) -> bytes:
    """ECDH shared secret with input hash: SHA256((input_hash * sender_sk) * B_scan)."""
    sender_scalar = int.from_bytes(bytes(sender_sk), "big")
    adjusted_scalar = (input_hash * sender_scalar) % GROUP_ORDER
    ecdh_point = scalar_mult_g1(adjusted_scalar, recipient_scan_pk)
    return hashlib.sha256(bytes(ecdh_point)).digest()


def derive_output_tweak(shared_secret: bytes, k: int) -> int:
    """Derive the output tweak t_k for output index k."""
    tweak_data = shared_secret + k.to_bytes(4, "big")
    return int.from_bytes(
        tagged_hash("Chia_SP/SharedSecret", tweak_data), "big"
    ) % GROUP_ORDER


def derive_onetime_pk_full(spend_pk: G1Element, tweak: int) -> G1Element:
    """One-time PK: B_spend + t_k * G."""
    tweak_pk = PrivateKey.from_bytes(tweak.to_bytes(32, "big")).get_g1()
    return spend_pk + tweak_pk


def derive_onetime_sk_full(spend_sk: PrivateKey, tweak: int) -> PrivateKey:
    """One-time SK: b_spend + t_k."""
    sk_int = int.from_bytes(bytes(spend_sk), "big")
    onetime = (sk_int + tweak) % GROUP_ORDER
    return PrivateKey.from_bytes(onetime.to_bytes(32, "big"))


def generate_label(scan_sk: PrivateKey, m: int) -> tuple[int, G1Element]:
    """Generate label m. Returns (label_scalar, label_point).

    Label m=0 is reserved for change outputs.
    """
    label_data = bytes(scan_sk) + m.to_bytes(4, "big")
    label_scalar = int.from_bytes(
        tagged_hash("Chia_SP/Label", label_data), "big"
    ) % GROUP_ORDER
    label_pk = PrivateKey.from_bytes(label_scalar.to_bytes(32, "big")).get_g1()
    return label_scalar, label_pk


def generate_labeled_spend_pk(spend_pk: G1Element, label_pk: G1Element) -> G1Element:
    """B_m = B_spend + label_point."""
    return spend_pk + label_pk


def create_silent_payment_outputs(
    sender_sks: "PrivateKey | list[PrivateKey]",
    coin_ids: list[bytes],
    recipients: list[tuple[G1Element, G1Element]],
) -> list[tuple[G1Element, bytes]]:
    """Create multi-output silent payment derivations.

    Args:
        sender_sks: Sender's secret key(s). A single PrivateKey for single-input,
            or list[PrivateKey] for multi-input (each must be a synthetic SK).
        coin_ids: List of coin IDs being spent (for input_hash).
        recipients: List of (B_scan, B_spend_or_B_m) tuples. Multiple entries
            with the same B_scan are grouped and assigned output indices k=0,1,...

    Returns:
        List of (onetime_pk, puzzle_hash) tuples, one per recipient entry.
        Order matches the input recipients list.
    """
    from collections import defaultdict

    # Normalize to aggregated key
    if isinstance(sender_sks, PrivateKey):
        sender_sk = sender_sks
    else:
        sender_sk = aggregate_sender_sks(sender_sks)

    sender_pk = sender_sk.get_g1()
    input_hash = compute_input_hash(coin_ids, sender_pk)

    # Group recipients by B_scan, preserving original order
    groups = defaultdict(list)
    for idx, (scan_pk, spend_pk) in enumerate(recipients):
        groups[bytes(scan_pk)].append((idx, spend_pk))

    outputs = [None] * len(recipients)
    for scan_pk_bytes, entries in groups.items():
        scan_pk = G1Element.from_bytes(scan_pk_bytes)
        shared_secret = compute_shared_secret_full(sender_sk, scan_pk, input_hash)
        for k, (orig_idx, spend_pk) in enumerate(entries):
            tweak = derive_output_tweak(shared_secret, k)
            onetime_pk = derive_onetime_pk_full(spend_pk, tweak)
            ph = puzzle_hash_for_pk(onetime_pk)
            outputs[orig_idx] = (onetime_pk, ph)

    return outputs


def scan_for_silent_payment(
    scan_sk: PrivateKey,
    spend_pk: G1Element,
    sender_pk: G1Element,
    coin_ids: list[bytes],
    output_puzzle_hashes: list[bytes],
    labels: dict[bytes, int] | None = None,
) -> list[dict]:
    """Check if any outputs are silent payments for this recipient.

    Args:
        scan_sk: Recipient's scan secret key.
        spend_pk: Recipient's spend public key (B_spend).
        sender_pk: Sender's public key (from on-chain puzzle reveal).
        coin_ids: Sender's coin IDs (for input_hash).
        output_puzzle_hashes: List of puzzle hashes from the transaction outputs.
        labels: Optional dict mapping bytes(label_pk) -> m for label detection.

    Returns:
        List of dicts with keys: k (output index), tweak (int), label (int|None),
        puzzle_hash (bytes), onetime_pk (G1Element).
    """
    input_hash = compute_input_hash(coin_ids, sender_pk)

    # Scanner-side ECDH: b_scan * (input_hash * A)
    input_hash_times_A = scalar_mult_g1(input_hash, sender_pk)
    scan_scalar = int.from_bytes(bytes(scan_sk), "big")
    ecdh_point = scalar_mult_g1(scan_scalar, input_hash_times_A)
    shared_secret = hashlib.sha256(bytes(ecdh_point)).digest()

    detected = []
    k = 0
    while True:
        tweak = derive_output_tweak(shared_secret, k)
        base_pk = derive_onetime_pk_full(spend_pk, tweak)
        base_ph = puzzle_hash_for_pk(base_pk)

        found = False
        for ph in output_puzzle_hashes:
            if ph == base_ph:
                detected.append({
                    "k": k, "tweak": tweak, "label": None,
                    "puzzle_hash": ph, "onetime_pk": base_pk,
                })
                found = True
                break

            # Check labels by forward computation
            if labels:
                for label_pk_bytes, m in labels.items():
                    label_pk = G1Element.from_bytes(label_pk_bytes)
                    labeled_pk = base_pk + label_pk
                    labeled_ph = puzzle_hash_for_pk(labeled_pk)
                    if ph == labeled_ph:
                        detected.append({
                            "k": k, "tweak": tweak, "label": m,
                            "puzzle_hash": ph, "onetime_pk": labeled_pk,
                        })
                        found = True
                        break
                if found:
                    break

        if not found:
            break
        k += 1

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
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def puzzle_hash_to_address(puzzle_hash: bytes, prefix: str = "txch") -> str:
    """Encode a puzzle hash as a bech32m address (txch for testnet, xch for mainnet)."""
    data = _convertbits(puzzle_hash, 8, 5)
    checksum = _bech32m_polymod(_bech32m_hrp_expand(prefix) + data + [0]*6) ^ BECH32M_CONST
    data += [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
    return prefix + "1" + "".join(BECH32_CHARSET[d] for d in data)


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


def encode_silent_payment_address(scan_pk: bytes, spend_pk: bytes, prefix: str = "tspxch") -> str:
    """Encode scan + spend public keys as a bech32m silent payment address."""
    if len(scan_pk) != 48:
        raise ValueError(f"scan_pk must be 48 bytes, got {len(scan_pk)}")
    if len(spend_pk) != 48:
        raise ValueError(f"spend_pk must be 48 bytes, got {len(spend_pk)}")

    payload = scan_pk + spend_pk  # 96 bytes
    data = _convertbits(payload, 8, 5)
    checksum = _bech32m_polymod(_bech32m_hrp_expand(prefix) + data + [0] * 6) ^ BECH32M_CONST
    data += [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
    return prefix + "1" + "".join(BECH32_CHARSET[d] for d in data)


def decode_silent_payment_address(address: str) -> tuple[bytes, bytes]:
    """Decode a bech32m silent payment address into (scan_pk, spend_pk) bytes."""
    # Find separator (last '1')
    sep = address.rfind("1")
    if sep < 1:
        raise ValueError("Invalid bech32m address: no separator found")

    hrp = address[:sep]
    if hrp not in ("tspxch", "spxch"):
        raise ValueError(f"Invalid silent payment address prefix: '{hrp}' (expected 'tspxch' or 'spxch')")

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

    # Strip 6-value checksum, convert from 5-bit to 8-bit
    payload = bytes(_convertbits(data_5bit[:-6], 5, 8, pad=False))

    if len(payload) != 96:
        raise ValueError(f"Invalid payload length: expected 96 bytes, got {len(payload)}")

    return payload[:48], payload[48:]


def _parse_clvm(blob: bytes, pos: int = 0):
    """Parse serialized CLVM into a nested tuple/bytes tree."""
    b = blob[pos]
    if b == 0xff:
        left, pos = _parse_clvm(blob, pos + 1)
        right, pos = _parse_clvm(blob, pos)
        return (left, right), pos
    if b == 0x80:
        return b'', pos + 1
    if b <= 0x7f:
        return bytes([b]), pos + 1
    if b < 0xc0:
        size = b & 0x3f
    elif b < 0xe0:
        size = ((b & 0x1f) << 8) | blob[pos + 1]
        pos += 1
    else:
        raise ValueError(f"Unsupported CLVM length byte: {b:#x}")
    pos += 1
    return blob[pos:pos + size], pos + size


def extract_synthetic_pk(puzzle: Program) -> G1Element | None:
    """Extract the synthetic public key curried into a standard p2 puzzle.

    Handles both on-chain puzzles (tree-structured curry from Chia wallet)
    and locally-built puzzles (atom-blob curry from our curry() function).
    """
    try:
        # Try uncurry_rust first — works for on-chain Chia wallet puzzles
        mod_node, args_node = puzzle.uncurry_rust()
        if args_node.pair:
            first, _ = args_node.pair
            if first.atom is not None and len(first.atom) == 48:
                return G1Element.from_bytes(first.atom)

        # Fall back to CLVM byte parsing — works for our curry() format
        # where MOD and args are stored as opaque atom blobs
        tree = _parse_clvm(bytes(puzzle))[0]
        _, rest = tree
        _, rest2 = rest
        args = rest2[0]

        # args is a flat atom blob when built by our curry()
        if isinstance(args, bytes) and len(args) > 0:
            args_tree = _parse_clvm(args)[0]
        elif isinstance(args, tuple):
            args_tree = args
        else:
            return None

        _, args_rest = args_tree
        quoted_pk, _ = args_rest
        _, pk_bytes = quoted_pk

        if len(pk_bytes) != 48:
            return None
        return G1Element.from_bytes(pk_bytes)
    except Exception:
        return None


