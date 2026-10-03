"""
Shared format/constants glue for the Chia Silent Payments example scripts.

The BLS12-381 silent-payment cryptography (key derivation, ECDH, synthetic
keys, one-time puzzle hashes, scanning) lives in the chia-wallet-sdk and is
consumed via sdk_adapter.py. What remains here is pure-Python + hashlib glue
with no BLS crypto and no chia_rs / chia_puzzles_py imports:
  - load_mnemonic: read a mnemonic from -f file, positional args, or prompt.
  - bech32m address encoding (puzzle_hash_to_address).
  - silent-payment address encode/decode (encode/decode_silent_payment_address):
    a bytes-in/bytes-out wrapper that DELEGATES to the SDK codec through
    sdk_adapter. The SDK implements the CHIP-0057 versioned format and validates
    that both keys are non-identity elements of the G1 subgroup; this module
    carries no codec of its own.
  - coin-id utilities (int_to_bytes, compute_coin_id).
  - constants (K_MAX, TESTNET11_GENESIS, SP_ADDRESS_VERSION, SP_ADDRESS_MAX_LENGTH).
"""

import hashlib
import sys

# Testnet11 genesis challenge (used for AGG_SIG_ME)
TESTNET11_GENESIS = bytes.fromhex(
    "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
)

K_MAX = 2400  # CHIP-0057 "K_max: Maximum Outputs Per Spend Group". A limit shared by senders
              # and scanners: a sender MUST NOT create more than K_MAX outputs for one scan key
              # in a spend group, and a scanner MUST stop at k == K_MAX so that all scanners
              # find the same payments. The SDK caps the scan at this value whatever is passed.
              # See BUILD.md "K_MAX note".


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


# CHIP-0057 Address Versioning: the data part of an SP address is a single
# 5-bit version character followed by the payload.
SP_ADDRESS_VERSION = 0  # the version this implementation emits (v0: 96-byte payload)
SP_ADDRESS_MAX_LENGTH = 1023  # SP addresses exceed bech32's 90-char limit; CHIP cap

_SP_PREFIXES = ("tspxch", "spxch")


def encode_silent_payment_address(scan_pk: bytes, spend_pk: bytes, prefix: str = "tspxch") -> str:
    """Encode scan + spend public keys as a CHIP-0057 v0 silent payment address.

    Thin delegation to the SDK encoder (via sdk_adapter). Raises ValueError if a
    key is not 48 bytes, is not a valid G1 subgroup element, or is the identity
    element, or if ``prefix`` is not ``tspxch`` / ``spxch``.
    """
    if len(scan_pk) != 48:
        raise ValueError(f"scan_pk must be 48 bytes, got {len(scan_pk)}")
    if len(spend_pk) != 48:
        raise ValueError(f"spend_pk must be 48 bytes, got {len(spend_pk)}")
    if prefix not in _SP_PREFIXES:
        raise ValueError(
            f"Invalid silent payment address prefix: '{prefix}' (expected 'tspxch' or 'spxch')"
        )

    import sdk_adapter  # local import: sdk_adapter imports this module

    return sdk_adapter.encode_silent_payment_address_from_bytes(
        scan_pk, spend_pk, testnet=(prefix == "tspxch")
    )


def decode_silent_payment_address(address: str) -> tuple[bytes, bytes]:
    """Decode a CHIP-0057 silent payment address into (scan_pk, spend_pk) bytes.

    Thin delegation to the SDK decoder (via sdk_adapter), which enforces the
    CHIP-0057 rules: 1,023-character cap, v0 = exactly 96 payload bytes, v1-30
    forward-compatible (first 96 bytes are the keys), v31 rejected, zero padding
    bits, and both keys valid non-identity elements of the G1 subgroup. Raises
    ValueError on any violation. Pre-versioning addresses are rejected.
    """
    import sdk_adapter  # local import: sdk_adapter imports this module

    scan_pk, spend_pk = sdk_adapter.decode_silent_payment_address(address)
    return bytes(scan_pk.to_bytes()), bytes(spend_pk.to_bytes())
