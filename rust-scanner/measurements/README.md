# Mainnet measurements

`2026-10-03/` holds the output of `sp_measure` (see `crates/sp-service/src/bin/sp_measure.rs`)
run against a synced mainnet full node database, opened read-only, on 2026-10-03.

| File | Content |
|------|---------|
| `window_recent_9361300_9381300.csv` | One row per transaction block, heights 9,361,300–9,381,299 (2026-09-29 to 2026-10-04) |
| `window_1y_7680000_7685000.csv` | Heights 7,680,000–7,684,999 (2025-09-29 to 2025-09-30) |
| `window_2y_6000000_6005000.csv` | Heights 6,000,000–6,004,999 (2024-09-30 to 2024-10-01) |
| `*.meta.txt` | Non-transaction block counts, filter-hash mismatches (none), walk rate |
| `stats_recent.txt`, `stats_older.txt` | Summary statistics produced by `analyze.py` |
| `bench_recent.txt` | Per-tweak-point client CPU on one core of a Xeon E5-2690 v2 |
| `probes/` | Five 300-height probes used to date the change in block contents in mid-2026 |

Each row gives, for one transaction block: the number of coin spends, eligible spends
and multi-input groups; the length of the block's tweak list (CHIP-0057, Tweak Points);
the number of additions and of distinct addition puzzle hashes; the size and element
count of the block's transactions filter, rebuilt from the block and checked against
the header's `filter_hash`; and the serialized size of the header block with and
without the filter.

To reproduce a window:

```bash
cargo run --release -p sp-service --bin sp_measure -- walk --help
```

The tool only reads the database. It needs a synced full node's
`blockchain_v2_mainnet.sqlite`.
