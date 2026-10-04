# rust-scanner

A Rust sample implementation of a silent-payment scanning service and light
client for CHIP-0057 silent payments on the Chia blockchain.

Silent payments let a sender derive a unique one-time puzzle hash per payment
from a static recipient address using ECDH (over BLS12-381), so on-chain
outputs are unlinkable to the recipient's published address. This workspace
shows how a server can index the data needed for detection (CHIP-0057
"Appendix A: Light Client Support") and how a light client can scan for its
own payments without giving the server any of its keys.

## Workspace layout

The workspace is a Cargo workspace with three crates:

- **`sp-common`** — Shared cryptographic primitives and protocol logic:
  scalar-field arithmetic, tagged hashing, key derivation (mnemonic to scan/
  spend keys), ECDH shared-secret computation, standard Chia puzzle-hash
  construction, and the sender, scanner and label procedures used by both the
  service and the client. Includes the CHIP test vectors as tests. It has no
  address codec.

- **`sp-service`** — The scanning service. Reads blocks from a local Chia full
  node database, extracts sender synthetic public keys from on-chain puzzle
  reveals, forms the spend groups, stores each block's tweak points and
  outputs in an index, serves them over WebSocket, follows the chain tip, and
  prunes blocks whose outputs are all spent. Ships a `sp-service` binary.

- **`sp-client`** — The light client. Connects to the service over WebSocket,
  fetches the tweak points and outputs of every block, scans them locally,
  and stores detected coins in a local SQLite database. Ships a `sp-client`
  binary.

`sp-service` and `sp-client` both depend on `sp-common`; `sp-client` also
depends on `sp-service` for shared message and type definitions.

## Keys

The scan and spend keys are derived from the mnemonic with hardened derivation
at every level, as CHIP-0057 "Key Derivation" requires: scan key
`m/12381n/8444n/12n/0n`, spend key `m/12381n/8444n/13n/0n`. The sender's coins
use Chia's standard wallet path `m/12381/8444/2/<index>`, which stays
unhardened.

## The service's tweak list

For each block the service publishes the tweak list CHIP-0057 defines in
"Scanning a Block" and "Tweak Points" (`crates/sp-service/src/grouping.rs`):

- Only *eligible spends* take part: spends whose puzzle reveal is the standard
  puzzle with one public key curried in. Any other spend contributes no key,
  no coin ID and no edge.
- **One tweak point per eligible spend** (Pass 1, the single-input groups).
- **One tweak point per multi-input group** (Pass 2): every strongly connected
  component of two or more eligible spends in the directed graph of
  `ASSERT_CONCURRENT_SPEND` (opcode 64) conditions. Using directed components
  keeps out a third party that merely asserts someone else's coin. A spend
  that belongs to a multi-input group still has its own single-input tweak
  point.
- A group whose key sum is the identity element, or whose `input_hash` is
  zero, is left out.

A tweak point is `T = input_hash * A_sum`. Each group's `input_hash` uses the
lexicographically smallest coin ID of the group. The block's outputs are all
coins created by its spends.

## The client

- **Scan key and spend public key only.** Syncing needs the scan secret key
  and the spend *public* key. Given a mnemonic, the client derives both and
  drops the spend secret key at once. In watch-only mode it is given the two
  keys directly and never sees a mnemonic or a spend secret key:

  ```bash
  sp-client --scan-sk-file scan.key --spend-pk <96 hex chars> --db-path coins.db
  ```

  `--scan-sk-file` names a file holding the scan secret key (64 hex
  characters); `--spend-pk` is the spend public key. The two flags must be
  given together and cannot be combined with `--mnemonic-file`.

- **The coin store keeps a tweak, not a secret key.** For each detected coin
  the database holds the output index `k`, the label, and the combined tweak
  `(t_k + label_scalar) mod r`. A signer that holds the spend secret key
  turns the tweak into the one-time key (`derive_onetime_sk_from_tweak` in
  `crates/sp-client/src/scanner.rs`). A database written with an earlier
  schema, which stored one-time secret keys, is rejected; delete it and
  rescan.

- **Every block is fetched during catch-up.** A silent payment's puzzle hash
  is not known before the block's tweak points have been run through ECDH, so
  no block can be ruled out in advance. The client requests the tweak points
  and outputs of every indexed block in range and scans all of them; it does
  not use the service's compact filters or its UTXO-aware range request to
  skip blocks. A live block that is not the direct successor of the last
  scanned height first triggers a range request for the heights in between.

- Tweak points come from another party, so each is validated (a valid element
  of the prime-order G1 subgroup, not the identity) before it is multiplied by
  the scan secret key.

- The change label (`m = 0`) is always scanned for; `--max-labels N` adds the
  labels `1..=N`. The scan stops at `K_max = 2400` outputs per spend group.

## Measuring tweak data on mainnet

`sp_measure` (in `crates/sp-service`) walks a height range of a synced full node's
database, read-only, and writes one CSV row per transaction block: eligible spends,
multi-input groups, the length of the tweak list, additions and distinct puzzle
hashes, and the size of the transactions filter and of the header block. It can also
time the client's per-tweak-point work. The output of a run on 2026-10-03 is in
[`measurements/`](measurements/README.md).

## Limitations

- **Chain reorganisations are not handled.** Neither the service's index nor
  the client's coin store rolls back when a block is replaced: data recorded
  for an orphaned block stays, and the block that replaced it is not
  re-indexed or rescanned.
- The client trusts the service to return every tweak point and output of
  every block: a service that withholds data can hide a payment. The service
  never receives the client's keys, and the block requests do not show which
  outputs are the client's, because the client asks for every block.
- **Spend-status checks reveal the client's coins to the service.** To track
  which detected coins have been spent, the client sends the coin IDs of its
  unspent coins to the service (`CheckCoinStatus`). A service that receives
  them knows those coins belong to one wallet.
- This is sample code for testnet use, not a production wallet.

## Build, test and run

```bash
cargo build
cargo test
```

The service runs next to a synced Chia full node and reads its block database
and RPC certificates (`--chia-db`, `--rpc-cert`, `--rpc-key` override the
defaults). The client connects to the service's `/ws` endpoint. The service
listens on port `9999` by default (`--port`), and the client's default
`--server-url` is `ws://127.0.0.1:9999/ws`:

```bash
cargo run --bin sp-service -- --network testnet11
cargo run --bin sp-client -- --db-path coins.db --mnemonic-file mnemonic.txt
cargo run --bin sp-client -- --list-coins --db-path coins.db
```

`cargo test` runs the unit tests in each crate, the CHIP test-vector tests in
`crates/sp-common/tests/chip_vectors.rs` (every intermediate value of the
CHIP's vectors that these crates implement), the WebSocket API tests in
`crates/sp-service/tests/ws_integration.rs`, and client-against-service sync
tests in `crates/sp-client/tests/sync.rs`. These need no node and no network.

The tests in `crates/sp-service/tests/integration.rs` use a local Chia full
node:

- Six of them read real blocks from the node's database
  (`~/.chia/mainnet/db/blockchain_v2_mainnet.sqlite`, opened read-only). When
  that file is absent they have nothing to check.
- `test_live_sync_peak` queries the node's RPC. It is opt-in: it runs only when
  the environment variable `SP_TEST_LIVE_NODE` is set to `1`
  (`SP_TEST_LIVE_NODE=1 cargo test -p sp-service --test integration`), so a
  plain `cargo test` never contacts a node.

Rust has no runtime "skipped" status: a test that does not apply prints a
`SKIP:` line to stderr and returns, so it is reported as passed without having
checked anything (`cargo test -- --nocapture` shows the lines).
