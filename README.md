# Silent Payments for Chia — example code

Example implementations of silent payments for the Chia blockchain (testnet11),
following CHIP-0057.

A recipient publishes one static address. A sender uses ECDH over BLS12-381 to
derive a unique one-time puzzle hash from it for every payment, so payments to
the same address cannot be linked on chain. The recipient scans the chain with
a scan key to find its payments, and spends each one with a one-time key
derived from its spend key.

**Testnet only. Do not use this code to move mainnet funds.**

## The CHIP

**CHIP-0057 (Silent Payments)** is the specification:
https://github.com/Chia-Network/chips/pull/198

Read it for the protocol: address format, key derivation, sending, scanning,
labels, and the test vectors. Comments in this repository refer to its sections
by name.

## What's in this repository

Three independent implementations:

| Directory | What it is |
|-----------|------------|
| top level | **SDK examples.** Scripts that use the [chia-wallet-sdk](https://github.com/xch-dev/chia-wallet-sdk) Python bindings for all cryptography and spend construction. |
| [`pure-python/`](pure-python/README.md) | **From-scratch reference implementation.** The protocol written out directly on `chia_rs` primitives, with no wallet SDK, so every step can be read. It also generates the CHIP's test vectors. |
| [`rust-scanner/`](rust-scanner/README.md) | **Scanning service and light client** in Rust: a server that indexes each block's tweak points, and a client that scans them locally. |

All three follow the revised CHIP:

- **Hardened key derivation.** The scan key is `m/12381n/8444n/12n/0n` and the
  spend key is `m/12381n/8444n/13n/0n`, hardened at every level.
- **Scanning with the scan key and the spend public key only.** A scanner holds
  the scan secret key and the spend *public* key. It reports, for each coin it
  finds, the output index, the label and a tweak. The spend secret key is
  needed only to spend, where it is combined with that tweak. Each
  implementation has a watch-only mode that never sees the spend secret key.
- **Versioned addresses.** The SDK examples and `pure-python/` emit version 0
  addresses (`spxch1q…` / `tspxch1q…`) and apply the CHIP's decoding rules.
  `rust-scanner/` works with keys directly and has no address codec.

## SDK examples (top level)

### Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The scripts also need the `chia_wallet_sdk` wheel **with silent-payment
support**, which is not yet in a release on PyPI. Build it from the pinned
source as described in [`BUILD.md`](BUILD.md).

On-chain lookups and broadcasting use the
[`coinset`](https://github.com/AbandonedFactory/coinset) CLI, which must be on
your `PATH`. Sending through a [Sage](https://github.com/xch-dev/sage) wallet
(`--sage`) is optional. Neither is needed to run the tests.

### Commands

```bash
# Generate a silent payment address (add --label 1 for a labeled address)
python generate_address.py -f mnemonic.txt

# Send a silent payment: the single coin at the first wallet address, via coinset
python send_payment.py <silent_payment_address> -f mnemonic.txt
# ... or through a Sage wallet (selects coins; several coins are bound together)
python send_payment.py <silent_payment_address> --sage --amount 1000 [--fee 50]

# Scan a block range for incoming payments
python scanner.py -s <start_height> [-e <end_height>] -f mnemonic.txt [--labels 1,2,3]

# Watch-only scan: scan secret key + spend PUBLIC key, no mnemonic
python scanner.py -s <start_height> --scan-key <scan_sk_hex> --spend-key <spend_pk_hex>

# Check whether one coin is a payment to you (single-input payments only)
python scan_coin.py <coin_id_hex> -f mnemonic.txt

# Spend a detected coin to your standard wallet address
python spend_coin.py <coin_id_hex> -f mnemonic.txt [--sage]
```

A mnemonic can be given with `-f <file>`, as words on the command line, or at a
hidden prompt.

`scanner.py` and `scan_coin.py` print the output index `k`, the label and the
tweak of each coin they find, never a secret key. The change label (0) is always
scanned for.

**`--legacy-keys`** (`scanner.py`, `scan_coin.py`, `spend_coin.py`) derives the
recipient keys with the unhardened paths `m/12381/8444/12/0` and
`m/12381/8444/13/0`. It applies only to addresses generated before the CHIP was
revised to require hardened derivation: coins paid to such an address can be
found and spent only with those keys. It must never be used for a new address,
and `generate_address.py` does not offer it.

### Tests

```bash
python -m pytest
```

The tests run offline. They refuse to start unless the pinned `chia_wallet_sdk`
wheel is installed in the active virtualenv (see `BUILD.md`). They cover the
CHIP's machine-readable test vectors (`tests/test_chip0057_vectors.py`), the
recipient flow end to end in the SDK's simulator, including the scripts
(`tests/test_recipient_flow.py`), the block scanner against mocked `coinset`
responses, and the SDK adapter.

## pure-python

```bash
cd pure-python
pip install -r requirements.txt
python -m pytest tests/ -q
```

The scripts have the same names as the SDK examples; see
[`pure-python/README.md`](pure-python/README.md) for their options, including
watch-only scanning with `--scan-key` and `--spend-pubkey`.

`pure-python/gen_test_vectors.py` regenerates the CHIP's machine-readable test
vectors (the `test_vectors.json` that accompanies the CHIP), using only that
implementation:

```bash
python gen_test_vectors.py test_vectors.json
```

Copies of that file drive the tests of both Python implementations
(`pure-python/tests/data/` and `tests/data/`).

## rust-scanner

```bash
cd rust-scanner
cargo build
cargo test
```

See [`rust-scanner/README.md`](rust-scanner/README.md) for the service's tweak
list, the client's watch-only mode, and its limitations.

## License

The code in this repository is licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE). CHIP-0057 itself is published under CC0.
