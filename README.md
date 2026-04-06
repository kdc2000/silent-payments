# Chia Silent Payments

A prototype implementing [BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)-style silent payments for the Chia blockchain. Recipients publish a single static address; senders use ECDH to derive unique, unlinkable one-time addresses per payment. No interaction is required, and the resulting transactions are indistinguishable from normal Chia spends.

See the draft proposal [CHIP-0057](https://github.com/Chia-Network/chips/blob/448fdc4b690b985c4ccc8bcf38480494124d4fa8/CHIPs/chip-0057.md).

**This is a prototype for testnet use only. Do not use with real funds.**

The protocol is described in [chip-silent-payments.md](chip-silent-payments.md).

## Requirements

- Python 3.10+
- [coinset](https://github.com/coinset-org/cli) CLI (for on-chain lookups)
- [Sage](https://github.com/xch-dev/sage) wallet (optional, for sending transactions via RPC)

### Installing coinset

`coinset` is a command-line tool for querying the Chia blockchain. Install it following the instructions at https://github.com/coinset-org/cli. It must be available in your PATH.

### Installing Python dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The Python dependencies are:

| Package | Purpose |
|---------|---------|
| `chia_rs` | BLS12-381 cryptography, CLVM program handling |
| `chia-puzzles-py` | Compiled Chia puzzle bytecode (standard transaction, CAT, NFT, singleton) |
| `mnemonic` | BIP-39 mnemonic word list |
| `requests` | HTTPS client for Sage wallet RPC (only needed with `--sage`) |

## Usage

### Generate a silent payment address

```bash
python generate_address.py -f mnemonic.txt
python generate_address.py -f mnemonic.txt --label 1
```

The mnemonic file should contain a BIP-39 mnemonic (12 or 24 words). If `-f` is not provided, the mnemonic is prompted interactively. The `--label` flag generates a labeled sub-address for distinguishing payment streams.

### Send a silent payment

```bash
# Derive the one-time address (no send)
python send_payment.py <silent_payment_address> -f mnemonic.txt

# Send via Sage wallet RPC
python send_payment.py <silent_payment_address> --sage --amount 1000
python send_payment.py <silent_payment_address> --sage --amount 1000 --fee 50
```

When using `--sage`, the script connects to a local Sage wallet via RPC, selects coins, builds a spend bundle, and submits the transaction. Multi-input sends (spending multiple coins) are supported automatically.

Without `--sage`, the script uses the first derivation index (m/12381/8444/2/0) to derive the sender key and looks up the coin via coinset. The one-time address is printed for manual sending from any wallet.

### Scan for incoming payments

```bash
python scanner.py -s <start_height> -f mnemonic.txt
python scanner.py -s <start_height> -e <end_height> -f mnemonic.txt
python scanner.py -s <start_height> -f mnemonic.txt --labels 1,2,3
```

The scanner examines every coin spend from `start_height` to the chain tip (or `end_height`), extracts sender public keys from puzzle reveals, and checks for silent payments using ECDH. Multi-input payments are detected via puzzle-hash grouping and announcement linkage.

### Spend a detected coin

```bash
python spend_coin.py <coin_id> -f mnemonic.txt
python spend_coin.py <coin_id> -f mnemonic.txt --sage
```

Detects whether the coin belongs to the recipient (trying both single-input and multi-input), derives the one-time secret key, and submits a spend bundle sending the funds to the recipient's standard wallet address.

### Check a single coin

```bash
python scan_coin.py <coin_id> -f mnemonic.txt
```

Checks whether a specific coin is a silent payment to the recipient without spending it.

## Running tests

```bash
python -m pytest tests/ -v
```

The test suite includes:
- `test_vectors.py` -- CHIP test vectors with all intermediate cryptographic values
- `test_protocol.py` -- Protocol mechanism tests (labels, multi-input, edge cases)
- `test_scanner.py` -- Scanner integration tests
- `test_feasibility.py` -- CAT2/NFT1 puzzle extraction tests

## Files

| File | Description |
|------|-------------|
| `shared.py` | Core library: key derivation, ECDH, puzzle construction, scanning |
| `generate_address.py` | Generate a silent payment address from a mnemonic |
| `send_payment.py` | Derive one-time address and optionally send via Sage |
| `scanner.py` | Scan testnet11 blocks for incoming silent payments |
| `scan_coin.py` | Check if a single coin is a silent payment |
| `spend_coin.py` | Spend a detected silent payment coin |
| `sage_rpc.py` | Sage wallet HTTPS RPC client |
| `chip-silent-payments.md` | Protocol specification (CHIP) |

## License

[CC0](https://creativecommons.org/publicdomain/zero/1.0/)
