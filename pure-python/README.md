# Silent Payments — pure-Python reference implementation

A dependency-light, from-scratch implementation of CHIP-0057 silent payments
for Chia (testnet11). This component is intended as a **readable reference**:
the cryptography is hand-rolled so you can follow every step of the ECDH key
derivation and on-chain detection without trusting a high-level wallet
library.

In particular, it does **not** depend on `chia-wallet-sdk`. The BLS12-381
elliptic-curve math, ECDH shared-secret computation, and one-time key
derivation all live in `shared.py` and are implemented directly on top of the
`chia_rs` primitive types (`G1Element`, `PrivateKey`, `Program`). The point of
this component is to keep that crypto path small and auditable.

The CHIP is the specification. Docstrings and comments refer to its sections
by name (for example "Inputs for Shared Secret Derivation" or "Scanning a
Spend Group"), and the function that implements a procedure of the CHIP says
so.

## What this is (and isn't)

- **Is**: a clear, self-contained walk-through of how a silent payment is
  derived, sent, scanned for, and spent. Optimised for readability over
  performance.
- **Isn't**: a production wallet. For an SDK-backed implementation see the
  sibling components in this repository.

## Dependencies

See `requirements.txt`. The footprint is intentionally minimal:

- `chia_rs` — BLS primitives, CLVM `Program`, coin-id hashing.
- `chia-puzzles-py` — the standard `p2_delegated_puzzle_or_hidden_puzzle`.
- `requests` — HTTP for the optional Sage wallet RPC path.
- `pytest` — to run the test suite.

On-chain lookups use the `coinset` CLI (`coinset -t` for testnet11), which must
be installed and on `PATH`. The tests need `pytest` and no network access.

## Keys and addresses

- **Key derivation.** The scan and spend keys are derived from the mnemonic
  with hardened derivation at every level: scan key `m/12381n/8444n/12n/0n`,
  spend key `m/12381n/8444n/13n/0n`. The sender's coins use Chia's standard
  wallet path `m/12381/8444/2/<index>`, which stays unhardened.
- **Address format.** A bech32m string with prefix `spxch` (mainnet) or
  `tspxch` (testnet): one version character, then the payload. This
  implementation emits version 0 (96-byte payload, scan key then spend key).
  When decoding it accepts version 0 with exactly 96 bytes, accepts versions
  1–30 using the first 96 bytes, rejects version 31, accepts up to 1,023
  characters, and requires zero padding bits. Both keys must be valid,
  non-identity elements of the prime-order G1 subgroup.
- **Labels.** `generate_address.py --label m` prints a labeled address for
  `m >= 1`. Label 0 is reserved for the wallet's own change: it is always
  scanned for and never handed out as an address.

## Scripts

```bash
# Generate a silent payment address from a mnemonic (add --label 1 for a
# labeled address, --mainnet for an spxch address)
python generate_address.py "mnemonic words ..."

# Derive the one-time address for a silent payment to a recipient
python send_payment.py <silent_payment_address> [sender_mnemonic]

# Build and submit the payment from the wallet's coin at derivation index 0
python send_payment.py <silent_payment_address> -f keyfile.txt --amount 1000

# Send via Sage with multi-input support (auto-selects coins)
python send_payment.py <silent_payment_address> --sage --amount 1000

# Check whether a single coin belongs to a silent payment recipient
python scan_coin.py <coin_id_hex> [recipient_mnemonic]
python scan_coin.py <coin_id_hex> --scan-key <hex> --spend-pubkey <hex>

# Scan a range of testnet11 blocks for incoming silent payments
python scanner.py -s <start_height> [-e <end_height>] -f keyfile.txt
python scanner.py -s <start_height> --scan-key <hex> --spend-pubkey <hex> --labels 1,2

# Spend a detected silent payment coin back to the recipient's wallet
python spend_coin.py <coin_id_hex> [recipient_mnemonic]
python spend_coin.py <coin_id_hex> -f keyfile.txt --tweak <spend_tweak_hex>
```

Mnemonics can be supplied as arguments, via `-f <keyfile>`, or entered
interactively. Put options after the mnemonic words when the words are given
on the command line.

**Watch-only scanning.** `scanner.py` and `scan_coin.py` need only the scan
*secret* key and the spend *public* key, given with `--scan-key` and
`--spend-pubkey`. They never print a secret key. For each detected coin they
report the output index `k`, the label, and the *spend tweak*
`(t_k + label_scalar) mod r`. `spend_coin.py`, which holds the spend secret
key, derives the one-time key as `(b_spend + spend tweak) mod r`; pass the
tweak with `--tweak` to skip its own scan.

**Sending.** The one-time address depends on the exact set of coins that are
spent, so `send_payment.py --amount N` builds the whole transaction itself:
the outputs are derived from the final set of coins, every silent payment
output is created by one of those coins, and when more than one coin is
spent they are bound into a single cycle of `ASSERT_CONCURRENT_SPEND`
conditions. Without `--amount` the script only prints the address, which is
valid only for a transaction that spends the listed coin alone and creates
the payment from it. The script transacts on testnet11 and rejects `spxch`
addresses.

## Scanner detection model

The scanner (`scanner.py`) forms the block's *spend groups* and runs the
detection procedure on each one. Only *eligible spends* take part: coin
spends whose puzzle reveal is exactly the standard puzzle curried with one
public key. Any other spend (a CAT, an NFT, any puzzle that wraps the
standard puzzle) contributes no key, no coin ID and no edge.

- **Pass 1 — single-input groups.** Every eligible spend is a group on its
  own. The sender's synthetic public key is taken from the puzzle reveal,
  ECDH is performed with the recipient's scan key, and the derived one-time
  puzzle hashes are matched against the coins that spend created.

- **Pass 2 — multi-input groups.** A multi-input silent payment binds its
  inputs with a directed cycle of `ASSERT_CONCURRENT_SPEND` (condition code
  64) conditions. The scanner runs each eligible spend's puzzle with its
  solution, and builds a directed graph whose vertices are the eligible
  spends (edge `u -> v` when `u` asserts coin `v`, and `v` is an eligible
  spend in the block). Only what consensus treats as the condition counts:
  the one-byte code `0x40` with a 32-byte first argument. Every **strongly
  connected component** of size ≥ 2 (iterative Tarjan) is a group whose
  synthetic public keys are summed before ECDH.

  Using directed SCCs (rather than undirected connectivity) keeps third
  parties out: a spend that asserts a victim's coin id creates only a one-way
  edge and stays outside the victim's group.

For each group the scanner tries output indices `k = 0, 1, ...` up to
`K_max = 2400`. At each index it tries the unlabeled candidate first, then
the labels in ascending order (label 0, the change label, is always
included), and records **every** coin that carries the matching puzzle hash.
It continues to `k+1` whenever there was a match — also when the wallet's own
policy (`--min-amount`) leaves the matched coin out of the report. Groups
whose key sum is the identity element, or whose `input_hash` is zero, are
skipped.

A multi-input set that emits **no** `ASSERT_CONCURRENT_SPEND` cycle carries no
on-chain linkage signal and is, by design, not detectable as a group.

### Tweak points

Everything a scanner needs from a spend group is one G1 point, the group's
tweak point `T = input_hash · A_sum` (`shared.compute_tweak_point`,
`scanner.block_tweak_points`). `scanner.scan_block_tweak_points` scans a block
from tweak points supplied by another party: each point is validated (valid,
in the prime-order subgroup, not the identity) before it is multiplied by the
scan secret key, and is matched against all additions of the block that were
created by a coin spend.

## Tests

```bash
python -m pytest tests/ -q
```

The suite needs no node; chain access is mocked. It covers:

- the CHIP's Test Vectors 1–8 with their intermediate values
  (`tests/test_vectors.py`). Vectors 1–7 treat the recipient keys as given
  values, so those tests take the keys from hex constants; Vector 8 covers
  the hardened key derivation;
- the machine-readable vectors (`tests/test_chip_vectors_json.py`, driven by
  `tests/data/chip-0057-test_vectors.json`): every payment, label, address,
  address case and the key derivation, recomputed by this implementation;
- every bullet of the CHIP's "Required Behaviors", plus zero scalars, `K_max`,
  label rules, tweak points and the scripts
  (`tests/test_required_behaviors.py`);
- the block scanner against mocked `coinset` responses
  (`tests/test_scanner.py`), protocol primitives (`tests/test_protocol.py`),
  and the sender's condition cycle (`tests/test_send_payment.py`).

## Test vector generator

`gen_test_vectors.py` regenerates the CHIP's machine-readable vectors file
using only this implementation:

```bash
python gen_test_vectors.py test_vectors.json

# also compare every value printed in the CHIP's Test Cases section
python gen_test_vectors.py test_vectors.json --check chip-0057.md
```

The output is byte-identical to the vectors file that accompanies the CHIP
(and to the copy under `tests/data/`).
