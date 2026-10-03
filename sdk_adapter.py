"""Silent-payment SDK adapter — the SOLE importer of ``chia_wallet_sdk``.

Every ``chia_wallet_sdk`` symbol the example code touches enters through this
module. Root scripts import the adapter, never the SDK directly; a static test
enforces this — only ``sdk_adapter.py`` may carry an ``import chia_wallet_sdk``
at the repo root.

Design rules:

* Crypto is DELEGATED to the SDK and never re-implemented in Python on SDK
  bytes. Chia computes the synthetic offset from a SIGNED big-endian integer
  (``int_from_bytes``); a Python re-derivation that reads it as unsigned yields a
  different key for some inputs, so the offset and all BLS scalar math stay in
  the SDK. The adapter's only net-new logic is (a) the ``chia_rs`` serialization
  bridge, (b) the aggregation guards, and (c) the manual-signing seam — the SDK
  pyo3 wheel exports NO transaction signer (``sign_transaction`` lives only in the
  chia-sdk-test crate), so ``sign_coin_spends`` reconstructs nothing: it signs
  exactly the ``AGG_SIG_ME`` the SDK already emitted.
* The wire-bridge ``sdk_bundle_to_wire_dict`` is PURE serialization — no signing,
  no chain I/O. The SDK ``SpendBundle`` has no JSON method, so we rebuild
  ``chia_rs`` objects field-by-field and call the proven ``to_json_dict()`` (the
  exact wire format live testnet11 coinset/Sage accept).
* Scan side: keys, address encode/decode, one-time puzzle-hash derive,
  tweak-extract/scan, the wire-bridge, and the guarded aggregates.
* Recipient keys use the HARDENED derivation CHIP-0057 requires
  (``keys_from_mnemonic``). The unhardened derivation that addresses generated
  before the CHIP's hardened-derivation revision used survives only as
  ``legacy_unhardened_keys_from_mnemonic``, to find and spend coins already paid
  to such addresses. Scanning needs the scan secret key and the spend PUBLIC key
  only; a detection carries a tweak, and the one-time secret key is derived from
  it with the spend secret key (``derive_onetime_sk``) only when a coin is spent.
  The SDK owns the versioned address codec, including point validation.
* Send side: the send-build pipeline (``build_silent_payment_send`` — single +
  multi-input) and the manual-signing seam (``sign_coin_spends`` /
  ``build_signed_spend_bundle``). The test suite covers everything up to
  broadcast; nothing in it touches the chain.
"""

from typing import NoReturn

import chia_rs
from chia_wallet_sdk import (
    Action,                   # send-build pipeline
    Clvm,
    Coin,
    CoinSpend,                # re-exported for callers/typing
    LabelRegistry,            # labeled/change detection registry
    Mnemonic,                 # phrase -> Mnemonic happens inside the adapter
    Program,                  # parse SDK-emitted AGG_SIG_ME (manual sign)
    PublicKey,
    Relation,                 # cyclic opcode-64 binding (N>=2)
    ScalarField,              # a detection's tweak (hex/bytes -> SDK scalar)
    SecretKey,                # re-exported for callers/typing
    Signature,                # aggregate the per-coin signatures
    SilentPaymentAddress,
    SilentPaymentKeys,
    SilentPaymentNetwork,
    SilentPaymentRegisteredKey,        # per-input RAW pk registration
    SilentPaymentRegisteredSecretKey,  # per-input RAW sk registration
    SilentPayments,
    SpendBundle,              # signed-bundle assembly
    Spends,
)

import shared  # retained glue: K_MAX (the value scan_from_tweaks must use)

# The message of the CHIP-0057 "Sending" procedure for a zero key sum (em-dash
# U+2014). The SDK raises the same condition with an ASCII hyphen.
ZERO_KEY_SUM_MESSAGE = "aggregated sender key sum is zero — invalid for ECDH"
_SDK_ZERO_KEY_SUM = "key sum is zero"


# ---------------------------------------------------------------------------
# Wire-bridge
# ---------------------------------------------------------------------------
def sdk_bundle_to_wire_dict(sdk_bundle) -> dict:
    """Bridge an SDK ``SpendBundle`` to the coinset/Sage wire-dict.

    The SDK ``SpendBundle`` exposes only ``to_bytes()``/``from_bytes()``/``hash()``
    — there is NO ``to_json_dict()`` on it. So we rebuild ``chia_rs`` objects
    field-by-field from the SDK bundle and call the proven ``to_json_dict()``.
    This does NOT rely on SDK<->chia_rs byte-serialization compatibility
    (unverified cross-crate compat).

    The result is byte-equal to the live ``chia_rs.SpendBundle(...).to_json_dict()``
    the existing scripts already broadcast — the format testnet11 accepts.
    """
    cs = []
    for s in sdk_bundle.coin_spends:                          # SDK CoinSpend
        coin = chia_rs.Coin(
            s.coin.parent_coin_info,                          # SDK Coin.parent_coin_info: bytes
            s.coin.puzzle_hash,                               # SDK Coin.puzzle_hash: bytes
            s.coin.amount,                                    # SDK Coin.amount: int
        )
        cs.append(chia_rs.CoinSpend(
            coin,
            chia_rs.Program.from_bytes(s.puzzle_reveal),      # SDK puzzle_reveal: bytes
            chia_rs.Program.from_bytes(s.solution),           # SDK solution: bytes
        ))
    sig = chia_rs.G2Element.from_bytes(
        sdk_bundle.aggregated_signature.to_bytes()            # SDK Signature.to_bytes()
    )
    return chia_rs.SpendBundle(cs, sig).to_json_dict()


# ---------------------------------------------------------------------------
# Zero-sum / identity guards
#
# The SDK sk aggregate raises on a zero sum itself; the wrapper only normalizes
# the message to the CHIP wording. ``PublicKey.aggregate`` returns the
# identity/infinity point silently, so that wrapper is the enforcement point —
# call the native SDK aggregate and add ONLY the guard (never re-sum in Python).
# ---------------------------------------------------------------------------
def _raise_zero_key_sum(exc) -> NoReturn:
    """Re-raise an SDK zero-key-sum error with the CHIP-0057 message; else re-raise."""
    if _SDK_ZERO_KEY_SUM in str(exc):
        raise ValueError(ZERO_KEY_SUM_MESSAGE) from exc
    raise exc


def aggregate_sender_sks(sks):
    """Aggregate sender synthetic secret keys (one per coin of the spend group).

    Returns the sum mod r as an SDK ``SecretKey`` — the value
    ``derive_one_time_puzzle_hash`` takes as ``aggregated_sender_sk``. The SDK
    raises when the sum is zero (invalid for ECDH); that error is re-raised as a
    ``ValueError`` carrying the verbatim CHIP-0057 message
    (``ZERO_KEY_SUM_MESSAGE``, em-dash U+2014).
    """
    try:
        return SilentPayments.aggregate_sender_sks(sks)
    except ValueError as exc:
        _raise_zero_key_sum(exc)


def aggregate_sender_pks(pks):
    """Aggregate sender synthetic public keys, guarding the identity-point case.

    Returns the SDK ``PublicKey`` sum. Raises an analogous ``ValueError`` if the
    aggregate is the identity/infinity point — unspendable for ECDH.
    """
    agg = PublicKey.aggregate(pks)   # -> PublicKey; infinity on the identity case
    if agg.is_infinity():
        raise ValueError("aggregated sender public key is the identity point — invalid for ECDH")
    return agg


# ---------------------------------------------------------------------------
# Keys / address / one-time puzzle-hash / input-hash / tweak-scan surface
#
# Thin pass-throughs to the SDK symbols. Crypto is delegated to the SDK — never
# re-implemented here.
# ---------------------------------------------------------------------------
def keys_from_mnemonic(phrase: str):
    """Derive SP scan/spend keys from a BIP-39 mnemonic PHRASE (CHIP-0057 paths).

    ``SilentPaymentKeys.from_mnemonic`` uses EIP-2333 HARDENED derivation at every
    level: scan key ``m/12381n/8444n/12n/0n``, spend key ``m/12381n/8444n/13n/0n``
    (CHIP-0057 "Key Derivation"). This is the only derivation new addresses may
    use. The adapter owns ``Mnemonic`` construction so root scripts never import
    ``chia_wallet_sdk`` to build it. The caller uses ``.scan_sk()`` /
    ``.spend_sk()`` / ``.scan_pk()`` / ``.spend_pk()`` /
    ``.unlabeled_address(...)`` on the returned ``SilentPaymentKeys``.
    """
    return SilentPaymentKeys.from_mnemonic(Mnemonic(phrase))


# The legacy derivation: Chia's UNHARDENED derivation, which silent payment
# addresses used before CHIP-0057 was revised to require hardened derivation. The
# CHIP forbids it for silent payment keys (an unhardened child secret key plus the
# parent public key reveals the parent secret key).
_LEGACY_UNHARDENED_SCAN_PATH = [12381, 8444, 12, 0]
_LEGACY_UNHARDENED_SPEND_PATH = [12381, 8444, 13, 0]

LEGACY_KEYS_WARNING = (
    "WARNING: --legacy-keys uses the UNHARDENED key derivation "
    "(m/12381/8444/12/0, m/12381/8444/13/0) of addresses generated before "
    "CHIP-0057 required hardened derivation; it is unsafe for new addresses — "
    "use it only to find or spend coins already paid to such an address."
)


def legacy_unhardened_keys_from_mnemonic(phrase: str):
    """LEGACY ONLY: derive SP keys with the UNHARDENED paths.

    Scan key ``m/12381/8444/12/0`` and spend key ``m/12381/8444/13/0``, derived
    unhardened, then wrapped with ``SilentPaymentKeys.from_secret_keys``.

    This applies ONLY to addresses generated before CHIP-0057 was revised to
    require hardened derivation ("Key Derivation"). Coins paid to such an address
    can be found and spent only with these keys, which is the sole reason this
    helper exists (``--legacy-keys`` on scan_coin.py / scanner.py /
    spend_coin.py). The CHIP forbids this derivation: it must NEVER be used for a
    new address, and generate_address.py does not offer it.
    """
    master = SecretKey.from_seed(Mnemonic(phrase).to_seed(""))
    return SilentPaymentKeys.from_secret_keys(
        master.derive_unhardened_path(_LEGACY_UNHARDENED_SCAN_PATH),
        master.derive_unhardened_path(_LEGACY_UNHARDENED_SPEND_PATH),
    )


def watch_only_keys(scan_sk_hex: str, spend_pk_hex: str):
    """Parse a watch-only key pair: scan SECRET key hex + spend PUBLIC key hex.

    Returns ``(scan_sk, spend_pk)`` as SDK ``SecretKey`` / ``PublicKey`` — all a
    scanner needs (CHIP-0057 "Scanning a Spend Group"). Raises ``ValueError`` on
    malformed hex, a wrong length, a scan key that is zero or not below the group
    order, a spend key that is not a valid G1 element, or a spend key that is the
    identity element.
    """
    scan_sk_bytes = bytes.fromhex(_strip(scan_sk_hex))
    spend_pk_bytes = bytes.fromhex(_strip(spend_pk_hex))
    if len(scan_sk_bytes) != 32:
        raise ValueError(f"scan secret key must be 32 bytes, got {len(scan_sk_bytes)}")
    if scan_sk_bytes == bytes(32):
        raise ValueError("scan secret key must not be zero")
    if len(spend_pk_bytes) != 48:
        raise ValueError(f"spend public key must be 48 bytes, got {len(spend_pk_bytes)}")
    scan_sk = SecretKey.from_bytes(scan_sk_bytes)
    spend_pk = PublicKey.from_bytes(spend_pk_bytes)
    if spend_pk.is_infinity() or not spend_pk.is_valid():
        raise ValueError("spend public key is not a valid non-identity G1 element")
    return scan_sk, spend_pk


def _network(testnet: bool = True):
    return SilentPaymentNetwork.Testnet if testnet else SilentPaymentNetwork.Mainnet


def encode_silent_payment_address(keys, network=SilentPaymentNetwork.Testnet):
    """Encode the canonical (unlabeled) SP address via the SDK encoder.

    ``SilentPaymentKeys.unlabeled_address(network).encode()`` — a CHIP-0057 v0
    address (version character ``q``).
    """
    return keys.unlabeled_address(network).encode()


def labeled_address(keys, m: int, network=SilentPaymentNetwork.Testnet) -> str:
    """Encode the LABELED (m>=1) SP address via the SDK.

    m=0 is reserved for change; the SDK raises on the reserved label (use
    ``change_address``). Recover the labeled spend pk (B_m) for display via
    ``decode_silent_payment_address(addr)[1]``.
    """
    return keys.labeled_address(network, m).encode()


def change_address(keys, network=SilentPaymentNetwork.Testnet) -> str:
    """Encode the wallet's own CHANGE address (reserved label m = 0) via the SDK.

    CHIP-0057 "Change Detection": a wallet MUST NOT hand this address out. The
    scanner always checks the change label and reports a match as label 0.
    """
    return keys.change_address(network).encode()


def encode_silent_payment_address_from_bytes(
    scan_pk: bytes, spend_pk: bytes, testnet: bool = True
) -> str:
    """Encode two 48-byte public keys as a CHIP-0057 v0 address via the SDK.

    The SDK validates both keys: a key that is not a valid element of the G1
    subgroup, or is the identity element, raises ``ValueError``.
    """
    return SilentPaymentAddress(
        PublicKey.from_bytes(bytes(scan_pk)),
        PublicKey.from_bytes(bytes(spend_pk)),
        _network(testnet),
    ).encode()


def decode_silent_payment_address(address):
    """Decode an SP address via the SDK decoder, returning (scan_pk, spend_pk).

    The SDK implements the CHIP-0057 versioned format: v0 needs exactly 96 payload
    bytes, v1-30 use the first 96 bytes, v31 is rejected, and both keys must be
    valid non-identity elements of the G1 subgroup. Raises ``ValueError`` on any
    invalid address.
    """
    decoded = SilentPaymentAddress.decode(address)
    return decoded.scan_pk, decoded.spend_pk


def silent_payment_address_is_testnet(address) -> bool:
    """Decode (and so validate) an SP address; True for ``tspxch``, False for ``spxch``."""
    return SilentPaymentAddress.decode(address).network == SilentPaymentNetwork.Testnet


def generate_label(scan_sk, m: int):
    """Label ``m`` of a scan key via the SDK: ``(label_scalar, label_pk)``.

    ``label_scalar`` is an SDK ``ScalarField`` and ``label_pk`` a ``PublicKey``
    (CHIP-0057 "Label Generation"). m = 0 is the reserved change label.
    """
    label = SilentPayments.generate_label(scan_sk, m)
    return label.scalar, label.public_key


# ---------------------------------------------------------------------------
# Sender wallet-key derivation (keep send_payment.py SDK-free)
#
# send_payment.py gets the wallet's BIP-39 mnemonic + a per-coin wallet
# derivation index; it must NOT import chia_wallet_sdk to turn those into key
# objects. These helpers derive the wallet keys ENTIRELY through the SDK along
# the standard unhardened path m/12381/8444/2/<index>, so the script stays
# SDK-free and all BLS math stays on the SDK side of the FFI: never re-derive a
# synthetic offset in Python.
# ---------------------------------------------------------------------------
_WALLET_PATH = (12381, 8444, 2)  # m/12381/8444/2/<index> (unhardened)


def _wallet_secret_key(mnemonic: str, index: int):
    """Derive the unhardened wallet ``SecretKey`` at m/12381/8444/2/<index>.

    Seed via ``Mnemonic(mnemonic).to_seed("")`` -> ``SecretKey.from_seed(seed)``,
    then the standard path through ``derive_unhardened``.
    """
    sk = SecretKey.from_seed(Mnemonic(mnemonic).to_seed(""))
    for step in _WALLET_PATH:
        sk = sk.derive_unhardened(step)
    return sk.derive_unhardened(index)


def wallet_keys(mnemonic: str, index: int):
    """Derive the sender's wallet keys for a mnemonic + wallet index via the SDK.

    Returns ``(wallet_pk, wallet_sk, synthetic_sk)`` as SDK key objects:

    * ``wallet_sk``  — the RAW (un-synthesized) wallet ``SecretKey`` at
      m/12381/8444/2/<index>.
    * ``wallet_pk``  — ``wallet_sk.public_key()`` (the RAW wallet ``PublicKey``).
    * ``synthetic_sk`` — ``wallet_sk.derive_synthetic()`` (the SIGNING key).

    The caller (send_payment.py) feeds the RAW ``wallet_pk`` / ``wallet_sk`` into
    ``build_silent_payment_send``'s ``inputs`` (the build helper handles the
    raw-vs-synthetic split internally) and the ``synthetic_sk`` list into
    ``build_signed_spend_bundle`` for signing — so the script never calls
    ``.derive_synthetic()`` on a raw SDK object itself.
    """
    wallet_sk = _wallet_secret_key(mnemonic, index)
    return wallet_sk.public_key(), wallet_sk, wallet_sk.derive_synthetic()


def wallet_puzzle_hash(mnemonic: str, index: int) -> bytes:
    """Return the standard p2 puzzle hash for a wallet mnemonic + index via the SDK.

    Builds the standard p2 puzzle for the SYNTHETIC wallet pk at index and returns
    its tree hash (the standard puzzle synthesizes the offset internally). Lets
    send_payment.py build its derivation-index -> puzzle-hash lookup without
    importing the SDK or send-side crypto.
    """
    wallet_pk, _wallet_sk, _synthetic_sk = wallet_keys(mnemonic, index)
    clvm = Clvm()
    spend = clvm.standard_spend(wallet_pk.derive_synthetic(), clvm.delegated_spend([]))
    return bytes(spend.puzzle.tree_hash())


def default_change_puzzle_hash(mnemonic: str) -> bytes:
    """Return the index-0 wallet p2 puzzle hash — the change destination.

    The standard p2 puzzle hash for the index-0 wallet synthetic key.
    """
    return wallet_puzzle_hash(mnemonic, 0)


def derive_one_time_puzzle_hash(scan_pk, spend_pk, aggregated_sender_sk, input_hash, k=0):
    """Derive the one-time puzzle hash for a silent-payment output (send primitive).

    ``SilentPayments.derive_one_time_puzzle_hash``. ``k`` defaults to 0 (the first
    output for this scan key). ``aggregated_sender_sk`` is the ``SecretKey``
    returned by ``aggregate_sender_sks``; ``spend_pk`` is the second key of the
    recipient's address (B_spend, or B_m for a labeled or change address).
    """
    return SilentPayments.derive_one_time_puzzle_hash(
        scan_pk, spend_pk, aggregated_sender_sk, input_hash, k
    )


def compute_input_hash(coin_ids, aggregated_sender_pk):
    """Compute the CHIP-0057 input hash via the SDK -> ``ScalarField``."""
    return SilentPayments.compute_input_hash(coin_ids, aggregated_sender_pk)


def tweak_data_from_block_spends(coin_spends, additions):
    """Extract tweak data from block spends via the SDK -> ``TweakData``.

    Preserves the parent-coin asymmetry: ``coin_spends`` are the SPENT (parent)
    coins, ``additions`` are the output coins.
    """
    return SilentPayments.tweak_data_from_block_spends(coin_spends, additions)


def scan_from_tweaks(scan_sk, spend_pk, data, labels, k_max=shared.K_MAX):
    """Scan tweak data for the recipient's coins via the SDK.

    Needs the scan SECRET key and the spend PUBLIC key only (CHIP-0057 "Scanning a
    Spend Group") — it runs on a watch-only device. Each returned ``DetectedSpCoin``
    carries ``k``, ``label`` and ``tweak`` (the combined ``(t_k + label_scalar)
    mod r``), not a spendable key; ``derive_onetime_sk`` turns the tweak into the
    one-time secret key once the spend secret key is at hand.

    ``k_max`` defaults to ``shared.K_MAX`` (the CHIP's K_max, 2400); the SDK caps a
    larger value at 2400. ``labels`` is a ``LabelRegistry`` (``label_registry``).
    The change label m = 0 is ALWAYS checked, registered or not, and a match is
    reported as label 0. Several detections can share one puzzle hash: every coin
    that carries a matching one-time puzzle hash is reported.
    """
    return SilentPayments.scan_from_tweaks(scan_sk, spend_pk, data, labels, k_max)


def derive_onetime_sk(spend_sk, tweak):
    """The one-time secret key of a detected coin: ``(spend_sk + tweak) mod r``.

    The only step of receiving a silent payment that needs the spend SECRET key
    (CHIP-0057 "Spending"). ``tweak`` is a detection's combined tweak: an SDK
    ``ScalarField`` (``DetectedSpCoin.tweak``), or its 32-byte / hex form as
    stored in a ``detections_to_records`` record. The coin is spent with the
    SYNTHETIC key of the result (``build_spend_to_address``).
    """
    if isinstance(tweak, str):
        tweak = bytes.fromhex(_strip(tweak))
    if isinstance(tweak, (bytes, bytearray)):
        if len(tweak) != 32:
            raise ValueError(f"tweak must be 32 bytes, got {len(tweak)}")
        tweak = ScalarField.from_bytes(bytes(tweak))
    return SilentPayments.derive_onetime_sk(spend_sk, tweak)


# ---------------------------------------------------------------------------
# Scan-side marshalers
#
# Pure data-shuffling around the existing scan primitives — ZERO crypto, ZERO
# chain I/O. These keep the SDK types (Coin / CoinSpend / LabelRegistry /
# DetectedSpCoin) behind the chokepoint: the root scripts
# (scan_coin.py / scanner.py) pass plain coinset dicts + hex in and receive
# plain dicts out, never touching a chia_wallet_sdk type. The SDK owns every
# grouping/ECDH/derivation decision (tweak_data_from_block_spends /
# scan_from_tweaks above); these helpers only translate the coinset wire shapes
# into the SDK's typed inputs and the DetectedSpCoin results back into dicts.
# ---------------------------------------------------------------------------
def _strip(h):
    """Strip a leading ``0x`` from a coinset hex field (no-op on non-str/bare hex).

    coinset records carry ``0x``-prefixed hex (``"0x" + parent.hex()``); the
    scripts normalize with ``h[2:] if h.startswith("0x")``. This mirrors that
    exactly so ``bytes.fromhex`` accepts the value.
    """
    return h[2:] if isinstance(h, str) and h.startswith("0x") else h


def coin_spend_from_record(coin_record, puzzle_reveal_hex, solution_hex):
    """Marshal a coinset coin record + its puzzle/solution hex into an SDK ``CoinSpend``.

    ``coin_record`` is either a bare coin dict
    ``{"parent_coin_info","puzzle_hash","amount"}`` or a ``{"coin": <coin dict>}``
    removal/addition wrapper (both shapes appear across coinset getters); it is
    normalized to the inner coin dict. Builds ``Coin(parent, ph, amount)`` and
    wraps it with the puzzle reveal + solution bytes into a ``CoinSpend``.

    The coin id is NOT pre-computed here — the SDK derives it from
    ``Coin(...).coin_id()`` (double-computing the id invites an
    amount-serialization boundary mismatch). Coin/CoinSpend stay behind the
    adapter chokepoint; the caller feeds the SPENT (parent) coin as the CoinSpend
    so the parent-coin input-hash asymmetry is preserved by
    tweak_data_from_block_spends.
    """
    coin = coin_record.get("coin", coin_record)
    sdk_coin = Coin(
        bytes.fromhex(_strip(coin["parent_coin_info"])),
        bytes.fromhex(_strip(coin["puzzle_hash"])),
        coin["amount"],
    )
    return CoinSpend(
        sdk_coin,
        bytes.fromhex(_strip(puzzle_reveal_hex)),
        bytes.fromhex(_strip(solution_hex)),
    )


def coin_from_addition(addition):
    """Marshal a coinset addition record into an SDK ``Coin`` (output coin).

    ``addition`` is either a bare coin dict or a ``{"coin": <coin dict>}`` wrapper;
    it is normalized to the inner coin dict. Builds ``Coin(parent, ph, amount)``
    for the CREATED/output coin fed to ``tweak_data_from_block_spends`` as an
    addition. The coin id is delegated to the SDK (``Coin(...).coin_id()``);
    nothing is pre-computed or attached here. The SDK Coin type stays behind the
    chokepoint.
    """
    coin = addition.get("coin", addition)
    return Coin(
        bytes.fromhex(_strip(coin["parent_coin_info"])),
        bytes.fromhex(_strip(coin["puzzle_hash"])),
        coin["amount"],
    )


def label_registry(scan_sk, label_indices):
    """Build an SDK ``LabelRegistry`` registering each label index m >= 1.

    Registers a label point for every requested custom label m (>= 1) via
    ``register(scan_sk, m)``. The change label m = 0 is not registered here because
    the SDK scanner always checks it on its own and reports a match as label 0
    (CHIP-0057: "labels SHOULD always contain the change label"). Pass an empty
    ``label_indices`` (``[]``) to scan for unlabeled and change outputs only — the
    returned registry is ``.is_empty()``.

    The LabelRegistry SDK type stays behind the chokepoint: the caller passes plain
    int indices and feeds the result straight to ``scan_from_tweaks``.
    """
    reg = LabelRegistry()
    for m in label_indices:
        if m >= 1:
            reg.register(scan_sk, m)
    return reg


def detections_to_records(detections, block_height=None):
    """Normalize SDK ``DetectedSpCoin`` results into plain dicts (no SDK types out).

    Maps each ``DetectedSpCoin`` to
    ``{"coin_id", "parent_coin_id", "puzzle_hash", "amount", "block_height", "k",
    "label", "tweak"}`` with all bytes fields hex-encoded — so scan_coin.py /
    scanner.py report detections without ever touching a chia_wallet_sdk type.
    ``k`` is the output index; ``label`` is ``None`` for an unlabeled
    output, 0 for change, or the int m for a labeled hit. ``tweak`` (hex) is the
    combined ``(t_k + label_scalar) mod r`` — the spend handoff. A record holds NO
    secret key: ``derive_onetime_sk(spend_sk, record["tweak"])`` yields the
    one-time key when the coin is spent. (The tweak is still private data: together
    with the address it links the coin to its recipient.)
    """
    return [
        {
            "coin_id": bytes(d.coin_id).hex(),
            "parent_coin_id": bytes(d.parent_coin_id).hex(),
            "puzzle_hash": bytes(d.puzzle_hash).hex(),
            "amount": d.amount,
            "block_height": block_height,
            "k": d.k,
            "label": d.label,
            "tweak": bytes(d.tweak.to_bytes()).hex(),
        }
        for d in detections
    ]


# ---------------------------------------------------------------------------
# Send-build pipeline
#
# Drives the SDK Spends/Action.silent_payment_send pipeline end-to-end and returns the UNSIGNED
# CoinSpends. The SDK emits the one-time CREATE_COIN, change, fee, synthetic-key
# derivation, multi-input ECDH aggregation, and the cyclic opcode-64
# ASSERT_CONCURRENT_SPEND binding INTERNALLY at finish time — Python only selects
# coins (the caller), registers keys, applies the action, and standard-spends each
# pending coin. Crypto stays on the SDK side of the FFI: never re-derive a
# tweak/offset in Python.
#
# Canonical sequence: the SDK's pyo3/tests/test_silent_payments.py
# (test_unlabeled_e2e single, test_multi_input_e2e multi).
# ---------------------------------------------------------------------------
def build_silent_payment_send(
    sp_address, inputs, change_puzzle_hash, amount, fee=0, testnet=True
):
    """Run the SDK ``Spends``/``Action.silent_payment_send`` pipeline -> UNSIGNED ``CoinSpend``s.

    Handles a single input (no binding condition is emitted) and multiple inputs
    (two or more coins: ALL input keys registered + the cyclic opcode-64
    ``ASSERT_CONCURRENT_SPEND`` binding the SDK builds internally).
    ``Relation.AssertConcurrent`` is ALWAYS passed to ``prepare``: the SDK requires
    it whenever the transaction spends two or more XCH coins, counting an
    intermediate coin it may itself create (and then includes in the key sum), and
    it emits nothing when only one coin is spent.

    Raises ``ValueError`` if the address is invalid, if it is for the other
    network (CHIP-0057: a sender SHOULD reject an address whose human-readable
    part does not match the network it transacts on), or if the SDK rejects the
    send (zero key sum, missing or non-synthetic key, ...).

    Args:
        sp_address: the recipient's silent-payment address (``tspxch1…`` on
            testnet).
        inputs: list of per-input dicts, each carrying ``parent_coin_info``
            (bytes), ``puzzle_hash`` (bytes, the input coin's p2 puzzle hash),
            ``amount`` (int), and the RAW (un-synthesized) SDK keys ``wallet_pk``
            (``PublicKey``) and ``wallet_sk`` (``SecretKey``).
        change_puzzle_hash: the sender's change p2 puzzle hash (bytes).
        amount: the send amount (int).
        fee: optional network fee (int); ``Action.fee`` is appended only when > 0.
        testnet: the network being transacted on (default True — the scripts are
            testnet11-only); the address must be for that network.

    Returns:
        list of UNSIGNED SDK ``CoinSpend`` objects (sign via ``sign_coin_spends``
        / ``build_signed_spend_bundle``).

    Key-role split:
        register the RAW wallet key with ``with_silent_payment_keys`` — under the
        SDK's fund-safety guards the facade synthesizes the synthetic key
        INTERNALLY via ``from_raw`` (= ``derive_synthetic``, default hidden
        puzzle), so the registered ECDH still runs on the synthetic sender key
        that matches the recipient's standard puzzle; a runtime guard backstops
        curry_tree_hash(pk) == coin p2_ph + sk.public_key() == pk before signing.
        ``from_raw`` is byte-identical to ``derive_synthetic``, so registering the
        raw key yields the same one-time puzzle hash as the synthetic key does.
        SEPARATELY, the
        standard-spend/signing role still passes the SYNTHETIC pk
        (``wallet_pk.derive_synthetic()``) to ``clvm.standard_spend`` because the
        input coins sit at a synthetic-key p2 puzzle hash, which synthesizes
        inside ``puzzle_for_pk``.
    """
    recipient = SilentPaymentAddress.decode(sp_address)  # validates version + both keys
    if recipient.network != _network(testnet):
        raise ValueError(
            "silent payment address is for the wrong network "
            f"(expected a {'tspxch' if testnet else 'spxch'} address)"
        )

    clvm = Clvm()
    spends = Spends(clvm, change_puzzle_hash)
    for inp in inputs:
        spends.add_xch(Coin(inp["parent_coin_info"], inp["puzzle_hash"], inp["amount"]))

    actions = [Action.silent_payment_send(recipient, amount, None)]
    if fee > 0:
        actions.append(Action.fee(fee))

    # Register every input with its RAW wallet keys: under the SDK's fund-safety
    # guards the facade `with_silent_payment_keys` takes the RAW wallet key and
    # synthesizes the synthetic key internally via `SyntheticPublicKey::from_raw` /
    # `SyntheticSecretKey::from_raw` (= DeriveSynthetic::derive_synthetic, default
    # hidden puzzle). Passing already-synthetic keys here would double-synthesize.
    # A finish-time runtime backstop validates curry_tree_hash(registered_pk) ==
    # the coin's p2_puzzle_hash AND sk.public_key() == registered_pk per
    # non-ephemeral XCH input before signing, so a mismatched key fails loud
    # rather than producing an unspendable coin.
    spends.with_silent_payment_keys(
        [SilentPaymentRegisteredKey(inp["puzzle_hash"], inp["wallet_pk"]) for inp in inputs],
        [SilentPaymentRegisteredSecretKey(inp["puzzle_hash"], inp["wallet_sk"]) for inp in inputs],
    )

    # Bind the inputs: Relation.AssertConcurrent makes every spent coin assert
    # its predecessor (a closed opcode-64 cycle), which is how a scanner
    # reconstructs the spend group. The SDK refuses a silent-payment send that
    # spends two or more XCH coins without it, and it counts intermediate coins
    # (created and spent inside the transaction), which the caller cannot predict —
    # so it is passed unconditionally. With a single spent coin no condition is
    # emitted. Optional arguments must be passed explicitly in this wheel.
    #
    # The SDK aggregates the group's SYNTHETIC secret keys itself (intermediate
    # coins included) and fails on a zero sum, so no separate guard runs here; its
    # zero-sum error is re-raised with the CHIP-0057 message.
    deltas = spends.apply(actions)
    try:
        finished = spends.prepare(deltas, Relation.AssertConcurrent)
    except ValueError as exc:
        _raise_zero_key_sum(exc)

    # Standard-spend each pending coin with the SYNTHETIC pk.
    pk_by_ph = {inp["puzzle_hash"]: inp["wallet_pk"] for inp in inputs}
    for pending in finished.pending_spends():
        wallet_pk = pk_by_ph[pending.p2_puzzle_hash()]
        finished.insert(
            pending.coin().coin_id(),
            clvm.standard_spend(
                wallet_pk.derive_synthetic(),
                clvm.delegated_spend(pending.conditions()),
            ),
        )

    finished.spend()
    return clvm.coin_spends()


def recipient_one_time_puzzle_hash(coin_spends, change_puzzle_hash):
    """Parse the recipient one-time CREATE_COIN puzzle hash from built CoinSpends.

    Runs each CoinSpend's puzzle against its solution (one shared ``Clvm``
    allocator — see ``sign_coin_spends`` for why), walks the emitted conditions,
    and returns the single CREATE_COIN puzzle hash that is NOT the sender's
    change puzzle hash. This is the one-time puzzle hash the SDK derived via ECDH
    — exactly what lands on-chain — so send_payment.py can display the matching
    ``tspxch``/``txch`` address without re-deriving any crypto.

    Returns ``bytes`` (the one-time puzzle hash) or ``None`` if no recipient
    CREATE_COIN is found (the caller falls back gracefully).
    """
    clvm = Clvm()
    for cs in coin_spends:
        puzzle = clvm.deserialize(bytes(cs.puzzle_reveal))
        solution = clvm.deserialize(bytes(cs.solution))
        output = puzzle.run(solution, _MAX_COST, False)
        for condition in output.value.to_list():
            create_coin = condition.parse_create_coin()
            if create_coin is None:
                continue
            if create_coin.puzzle_hash != change_puzzle_hash:
                return create_coin.puzzle_hash
    return None


# ---------------------------------------------------------------------------
# Spend-build helper — standard-spend a DETECTED one-time coin.
#
# This is the OPPOSITE of
# ``build_silent_payment_send`` (which DRIVES the ``Spends``/``Action.silent_payment_send``
# pipeline to CREATE a silent payment). Here we already hold a detected one-time
# coin (a ``DetectedSpCoin`` from ``scan_from_tweaks``) and its one-time secret
# key (``derive_onetime_sk(spend_sk, detection.tweak)``), and spend it with a plain
# standard spend + a single CREATE_COIN to a known destination puzzle hash — the
# ``clvm.standard_spend`` + ``clvm.spend_coin`` recipe, NOT ``Spends``/``Action``.
#
# Canonical source: the SDK's pyo3/tests/test_silent_payments.py
# (test_unlabeled_e2e) — detect -> onetime_sk(spend_sk) -> derive_synthetic ->
# create_coin -> delegated_spend -> standard_spend(synthetic_pk, …) -> spend_coin
# -> coin_spends.
#
# Allocator discipline: ONE ``Clvm`` for the whole build; do NOT share it with the
# signer — ``coin_spends()`` serializes to bytes and ``sign_coin_spends``
# re-deserializes into its OWN allocator.
#
# Rules this helper follows: the synthetic offset is never re-derived in Python
# (always ``derive_synthetic``; see the design rules at the top of this file);
# the ``(nil dp nil)`` solution blob is never hand-built (``clvm.delegated_spend``
# emits the exact tree); the coin id is never pre-computed (the SDK ``Coin`` owns
# it); and the ``Coin`` is built INSIDE the adapter from plain bytes/int, never by
# the caller.
# ---------------------------------------------------------------------------
def build_spend_to_address(onetime_sk, coin, dest_puzzle_hash, amount, fee=0):
    """Standard-spend a detected one-time coin to ``dest_puzzle_hash`` -> UNSIGNED CoinSpends.

    Args:
        onetime_sk: the one-time SDK ``SecretKey`` of the coin, from
            ``derive_onetime_sk(spend_sk, detection.tweak)`` — the detection itself
            carries only the tweak. Synthesized internally via
            ``derive_synthetic()`` — the curried/signing key is the SYNTHETIC pk,
            never the raw one-time sk.
        coin: the one-time coin to spend — either a ``DetectedSpCoin``-like object
            exposing ``.parent_coin_id`` / ``.puzzle_hash`` / ``.amount``, OR a
            plain ``(parent_id, puzzle_hash, amount)`` tuple. The SDK ``Coin`` is
            built INSIDE this helper (kept behind the chokepoint); its coin id is
            delegated to the SDK, never pre-computed.
        dest_puzzle_hash: the destination p2 puzzle hash (bytes) — typically the
            recipient's STANDARD wallet ``m/.../2/0`` (``wallet_puzzle_hash``); the
            single CREATE_COIN pays it.
        amount: the CREATE_COIN amount (int) — the full coin amount when ``fee=0``.
        fee: optional network fee (int, default 0). With ``fee=0`` the CREATE_COIN
            pays the full ``amount`` and NO ``reserve_fee`` is emitted. With
            ``fee>0`` the CREATE_COIN amount is reduced by the fee and a
            ``reserve_fee(fee)`` condition is appended (never emit the full amount +
            a reserve_fee).

    Returns:
        list of UNSIGNED SDK ``CoinSpend`` objects. Signing is done SEPARATELY by
        ``build_signed_spend_bundle([onetime_sk.derive_synthetic()])`` /
        ``sign_coin_spends`` (the signer re-deserializes into its OWN ``Clvm``).
    """
    # Normalize the coin to (parent_id, puzzle_hash, amount) without leaking the
    # SDK Coin type to the caller — accept a DetectedSpCoin-like object or a tuple.
    if hasattr(coin, "parent_coin_id"):
        parent_id = bytes(coin.parent_coin_id)
        coin_ph = bytes(coin.puzzle_hash)
        coin_amount = coin.amount
    else:
        parent_id, coin_ph, coin_amount = coin
        parent_id = bytes(parent_id)
        coin_ph = bytes(coin_ph)

    # Build the SDK Coin INSIDE the chokepoint; coin id delegated to the SDK.
    sdk_coin = Coin(parent_id, coin_ph, coin_amount)

    # The curried/signing key is the SYNTHETIC pk (the one-time coin's p2 ph
    # synthesizes inside puzzle_for_pk), so the built reveal tree hash == coin ph.
    synthetic_pk = onetime_sk.derive_synthetic().public_key()

    # ONE Clvm for the whole build (do NOT share with the signer).
    clvm = Clvm()
    create_amount = amount - fee if fee > 0 else amount
    conditions = [clvm.create_coin(bytes(dest_puzzle_hash), create_amount, None)]
    if fee > 0:
        conditions.append(clvm.reserve_fee(fee))

    delegated = clvm.delegated_spend(conditions)
    standard = clvm.standard_spend(synthetic_pk, delegated)
    clvm.spend_coin(sdk_coin, standard)
    return clvm.coin_spends()


# ---------------------------------------------------------------------------
# Manual-signing seam
#
# The SDK pyo3 wheel exports NO transaction signer: `sign_transaction` lives only
# in the chia-sdk-test crate (simulator-only), unreachable from the wheel. The
# exported surface is SecretKey.sign(message) + Signature.aggregate([...]). So we
# re-implement the Rust signer in Python.
#
# Sign what the SDK actually emits (robust to any extra signed conditions): run
# each CoinSpend's puzzle against its solution, walk the emitted conditions, and
# for every AGG_SIG_ME(public_key, message) sign the CONSENSUS message with the
# matching synthetic SK and aggregate.
#
# CONSENSUS AUGMENTATION: Chia validates an AGG_SIG_ME signature over
# `message || coin_id || agg_sig_me_additional_data`, NOT over the bare `message`
# the condition carries. `parse_agg_sig_me().message` is only the first segment
# (the 32-byte delegated-puzzle hash for the standard puzzle); signing it verbatim
# yields a signature the full node ACCEPTS into the mempool but silently DROPS at
# validation (never block-included). So we append `cs.coin.coin_id()`
# (per-CoinSpend) and `shared.TESTNET11_GENESIS` (the testnet11
# agg_sig_me_additional_data, byte-identical to the node's
# get_aggsig_additional_data 37a90eb5…) before signing. The standard puzzle emits
# one AGG_SIG_ME per coin signed by the SYNTHETIC pk.
# ---------------------------------------------------------------------------
_MAX_COST = 11_000_000_000  # CLVM cost ceiling for Program.run (matches scanner.py)


def sign_coin_spends(coin_spends, synthetic_secret_keys):
    """Manually sign the SDK-emitted ``AGG_SIG_ME`` conditions -> aggregated ``Signature``.

    Args:
        coin_spends: list of SDK ``CoinSpend`` (typically from
            ``build_silent_payment_send``).
        synthetic_secret_keys: list of SDK ``SecretKey`` already in SYNTHETIC
            form (the caller passes ``wallet_sk.derive_synthetic()``). The SIGNING
            key is the synthetic sk, NOT the raw wallet sk.

    Returns:
        the aggregated SDK ``Signature`` over every emitted ``AGG_SIG_ME``.

    Raises:
        ValueError: if an emitted ``AGG_SIG_ME`` public_key has no matching
            synthetic SK — a signing-key mismatch fails loudly (never silently
            drops a signature, which would yield an invalid bundle).
    """
    sk_by_pk = {sk.public_key().to_bytes(): sk for sk in synthetic_secret_keys}

    # Deserialize SDK CoinSpend bytes into SDK Programs via Clvm.deserialize.
    # NOTE: do NOT use Program.from_bytes — chia_rs and chia_wallet_sdk BOTH bind
    # methods onto the same `builtins.Program` class (pyo3 class collision), so
    # Program.from_bytes is unreliable across import orders and rejects the SDK's
    # own bytes type ("Argument 'bytes' has incorrect type"). Clvm.deserialize is
    # the SDK's own, collision-proof deserializer.
    clvm = Clvm()
    sigs = []
    for cs in coin_spends:
        # Per-CoinSpend coin id: the AGG_SIG_ME message is augmented with the id of
        # the coin being spent (consensus rule), so it MUST be recomputed per spend.
        coin_id = bytes(cs.coin.coin_id())
        puzzle = clvm.deserialize(bytes(cs.puzzle_reveal))
        solution = clvm.deserialize(bytes(cs.solution))
        output = puzzle.run(solution, _MAX_COST, False)
        for condition in output.value.to_list():
            agg_sig_me = condition.parse_agg_sig_me()
            if agg_sig_me is None:
                continue
            pk_bytes = agg_sig_me.public_key.to_bytes()
            sk = sk_by_pk.get(pk_bytes)
            if sk is None:
                raise ValueError(
                    "no synthetic secret key matches an emitted AGG_SIG_ME public key "
                    "— refusing to produce a partially-signed (invalid) bundle"
                )
            # Consensus message = condition message || coin_id || additional_data.
            message = bytes(agg_sig_me.message) + coin_id + shared.TESTNET11_GENESIS
            sigs.append(sk.sign(message))

    return Signature.aggregate(sigs)


def build_signed_spend_bundle(coin_spends, synthetic_secret_keys):
    """Compose a signed SDK ``SpendBundle`` from unsigned CoinSpends + synthetic SKs.

    ``SpendBundle(coin_spends, sign_coin_spends(coin_spends, synthetic_secret_keys))``.
    Feed the result to ``sdk_bundle_to_wire_dict`` for broadcast (wired to
    ``coinset.push_tx`` / Sage). The aggregated signature is a REAL (non-infinity)
    G2 the wire bridge serializes byte-equally.
    """
    return SpendBundle(
        coin_spends, sign_coin_spends(coin_spends, synthetic_secret_keys)
    )
