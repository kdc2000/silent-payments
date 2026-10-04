#!/usr/bin/env python3
"""Statistics over sp_measure CSVs. Percentiles are nearest-rank."""
import csv, math, sys, datetime

BLOCKS_PER_DAY = 4608
MAX_TWEAKS = 13749


def pct(sorted_vals, p):
    if not sorted_vals:
        return 0
    k = max(1, math.ceil(p / 100 * len(sorted_vals)))
    return sorted_vals[k - 1]


def stats(vals):
    s = sorted(vals)
    n = len(s)
    if n == 0:
        return (0, 0, 0, 0)
    return (sum(s) / n, pct(s, 50), pct(s, 95), s[-1])


def fmt(st):
    return "mean %.1f  median %d  p95 %d  max %d" % st


def analyze(path, cpu_us=None):
    meta = dict(l.strip().split("=", 1) for l in open(path.replace(".csv", ".meta.txt")))
    rows = [{k: (int(v) if v != "" else None) for k, v in r.items()} for r in csv.DictReader(open(path))]
    heights = int(meta["heights_read"])
    ntx = len(rows)
    print("=" * 78)
    print(path.split("/")[-1])
    print("heights [%s, %s)  read %d  missing %s  non-tx %s  tx %s  gen errors %s  filter mismatches %s  scc disagreements %s"
          % (meta["start"], meta["end_exclusive"], heights, meta["heights_missing"], meta["non_transaction_blocks"],
             meta["transaction_blocks"], meta["generator_errors"], meta["filter_hash_mismatches"], meta["scc_disagreements"]))
    t0, t1 = rows[0]["timestamp"], rows[-1]["timestamp"]
    d = lambda t: datetime.datetime.utcfromtimestamp(t).strftime("%Y-%m-%d %H:%M")
    span_h = rows[-1]["height"] - rows[0]["height"]
    print("time %s .. %s UTC; observed %.0f heights/day (%.2f days); walk %s s at %s heights/s"
          % (d(t0), d(t1), span_h / ((t1 - t0) / 86400), (t1 - t0) / 86400, meta["elapsed_seconds"], meta["heights_per_second"]))
    print("tx-block share: %.2f%% (%d of %d)" % (100 * ntx / heights, ntx, heights))

    col = lambda c: [r[c] for r in rows]
    for c in ["removals", "eligible", "tweaks", "additions_tx", "distinct_ph_all", "filter_n", "filter_bytes",
              "header_with_filter", "header_no_filter"]:
        print("  %-20s %s" % (c, fmt(stats(col(c)))))
    hb = [r["header_with_filter"] - r["filter_bytes"] for r in rows]
    print("  %-20s %s" % ("H_b (hdr - filter)", fmt(stats(hb))))
    wt = [r for r in rows if r["tweaks"] >= 1]
    print("blocks with >=1 tweak point: %d (%.2f%% of tx blocks, %.2f%% of heights)" % (len(wt), 100 * len(wt) / ntx, 100 * len(wt) / heights))
    for c in ["tweaks", "filter_n", "filter_bytes", "header_with_filter", "header_no_filter"]:
        print("  [tweak blocks] %-20s %s" % (c, fmt(stats([r[c] for r in wt]))))
    print("  [tweak blocks] %-20s %s" % ("H_b (hdr - filter)", fmt(stats([r["header_with_filter"] - r["filter_bytes"] for r in wt]))))

    rem, eli, twk = sum(col("removals")), sum(col("eligible")), sum(col("tweaks"))
    print("removals %d  eligible %d  eligible share %.2f%%" % (rem, eli, 100 * eli / rem if rem else 0))
    print("tweak points %d  from multi-input groups %d (%.3f%%)  blocks with a multi-input group %d (%.2f%% of tx blocks)"
          % (twk, sum(col("tweaks_from_multi")), 100 * sum(col("tweaks_from_multi")) / twk if twk else 0,
             sum(1 for r in rows if r["multi_groups"] > 0), 100 * sum(1 for r in rows if r["multi_groups"] > 0) / ntx))
    print("multi-input groups %d  largest %d  groups emitted %d  dropped single %d  dropped multi %d  duplicates removed %d"
          % (sum(col("multi_groups")), max(col("largest_group")), sum(col("groups_emitted")), sum(col("dropped_single")),
             sum(col("dropped_multi")), sum(col("dup_removed"))))
    for lim in (100, 50):
        a = sum(1 for r in rows if r["distinct_ph_all"] > lim)
        b = sum(1 for r in wt if r["distinct_ph_all"] > lim)
        tw = sum(r["tweaks"] for r in wt if r["distinct_ph_all"] > lim)
        print(">%d distinct addition puzzle hashes: %.2f%% of tx blocks (%d), %.2f%% of blocks with tweak points (%d), holding %.2f%% of tweak points"
              % (lim, 100 * a / ntx, a, 100 * b / len(wt) if wt else 0, b, 100 * tw / twk if twk else 0))
    fb, fn = sum(col("filter_bytes")), sum(col("filter_n"))
    print("filter bytes per element: %.3f (sum bytes %d / sum N %d)" % (fb / fn, fb, fn))
    viol = sum(1 for r in rows if r["tweaks"] > (3 * r["filter_n"]) // 2)
    print("blocks with tweaks > floor(3N/2): %d" % viol)
    print("max tweak list %d = %.2f%% of MAX_TWEAKS_PER_BLOCK (%d); headroom factor %.1fx; max cost %d (%.1f%% of 11e9)"
          % (max(col("tweaks")), 100 * max(col("tweaks")) / MAX_TWEAKS, MAX_TWEAKS, MAX_TWEAKS / max(1, max(col("tweaks"))),
             max(col("cost")), 100 * max(col("cost")) / 11e9))
    big = max(rows, key=lambda r: r["tweaks"])
    print("  block with max tweaks: height %d removals %d eligible %d cost %d" % (big["height"], big["removals"], big["eligible"], big["cost"]))

    # Bandwidth (derived): per height, scaled to 4608 heights/day.
    tb = sum(col("tweak_resp_bytes"))
    hbytes = sum(r["header_with_filter"] for r in wt)
    hnof = sum(r["header_no_filter"] for r in wt)
    fbytes = sum(r["filter_bytes"] for r in wt)
    pages = max(math.ceil(len(wt) / 1024), math.ceil(tb / (1048576 - 41)))
    scale = BLOCKS_PER_DAY / heights
    kb = lambda x: x / 1e3
    print("bandwidth per day at %d heights/day (derived):" % BLOCKS_PER_DAY)
    print("  tweak points      %10.1f kB/day  %8.2f MB/30d   (+41 B x %d responses in window)" % (kb(tb * scale), tb * scale * 30 / 1e6, pages))
    print("  headers+filter    %10.1f kB/day  %8.2f MB/30d   (of which filters %.1f kB/day; headers alone %.1f kB/day)"
          % (kb(hbytes * scale), hbytes * scale * 30 / 1e6, kb(fbytes * scale), kb((hbytes - fbytes) * scale)))
    print("  sum               %10.1f kB/day  %8.2f MB/30d" % (kb((tb + hbytes) * scale), (tb + hbytes) * scale * 30 / 1e6))
    print("  (headers without filter for the same blocks: %.1f kB/day)" % kb(hnof * scale))
    print("  tweak points/day %.0f; blocks with tweak points/day %.0f; tx blocks/day %.0f" % (twk * scale, len(wt) * scale, ntx * scale))
    if rows[0]["ct_omitted"] is not None:
        om = sum(col("ct_omitted"))
        print("cut-through (omit_spent, peak %s): %d of %d tweak points omitted (%.2f%%); blocks left with none: %d of %d; -1 fallbacks %s"
              % (meta["db_peak"], om, twk, 100 * om / twk, sum(1 for r in wt if r["ct_omitted"] == r["tweaks"]), len(wt),
                 meta["cut_through_single_coin_fallback_unspent"]))
        tb2 = sum(40 + 48 * (r["tweaks"] - r["ct_omitted"]) for r in wt if r["tweaks"] > r["ct_omitted"])
        hb2 = sum(r["header_with_filter"] for r in wt if r["tweaks"] > r["ct_omitted"])
        print("  with omit_spent: tweaks %.1f kB/day, headers+filter %.1f kB/day, sum %.1f kB/day"
              % (kb(tb2 * scale), kb(hb2 * scale), kb((tb2 + hb2) * scale)))
    print("server-side time per tx block (this machine): generator %.1f ms mean, group_spends %.1f ms mean"
          % (sum(col("gen_us")) / ntx / 1e3, sum(col("group_us")) / ntx / 1e3))
    if cpu_us:
        for labels, us in cpu_us:
            per_day = twk * scale * us / 1e6
            print("  CPU %3d labels: %.1f us/point -> %.2f s per day of chain, %.1f s (%.2f min) per 30 d, %.1f min per year"
                  % (labels, us, per_day, per_day * 30, per_day * 30 / 60, per_day * 365 / 60))


if __name__ == "__main__":
    cpu = None
    args = sys.argv[1:]
    if args and args[0].startswith("--cpu="):
        cpu = [(int(a.split(":")[0]), float(a.split(":")[1])) for a in args[0][6:].split(",")]
        args = args[1:]
    for p in args:
        analyze(p, cpu)
