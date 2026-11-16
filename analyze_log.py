#!/usr/bin/env python3
"""
Post-processing of logs/security_events.jsonl for the Performance Evaluation
rubric item (D2). Prints:
  * events per type and per source IP
  * alert delivery latency (controller -> logger): avg / p95 / max
  * block response time, if the controller supplies 'first_seen_ts' on BLOCK
    events (time from first suspicious packet to the block rule being installed)
  * recovery time: BLOCK -> next UNBLOCK for the same source IP
Optionally exports a CSV for plotting in Excel / matplotlib.

  python3 analyze_log.py logs/security_events.jsonl --csv results.csv
"""
import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict


def pct(values, q):
    if not values:
        return None
    v = sorted(values)
    return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def summarize(name, values, unit):
    if not values:
        print(f"  {name}: no data")
        return
    print(f"  {name}: n={len(values)} avg={statistics.mean(values):.2f}{unit} "
          f"p95={pct(values, 0.95):.2f}{unit} max={max(values):.2f}{unit}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--csv", help="write a flat CSV of all events")
    a = ap.parse_args()

    events = []
    with open(a.jsonl, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    if not events:
        print("no events found")
        return 1

    print(f"Total events: {len(events)}")
    print("By type  :", dict(Counter(e["event"] for e in events)))
    print("By source:", dict(Counter(e.get("src_ip", "-") for e in events)))

    print("\nTiming")
    summarize("alert delivery latency", [e["alert_latency_ms"] for e in events
                                         if "alert_latency_ms" in e], " ms")
    block_resp = [(e["ts"] - e["first_seen_ts"]) * 1000 for e in events
                  if e["event"] == "BLOCK" and "ts" in e and "first_seen_ts" in e]
    summarize("block response time", block_resp, " ms")

    open_blocks, recov = {}, []
    for e in sorted(events, key=lambda x: x["recv_ts"]):
        ip = e.get("src_ip")
        if e["event"] == "BLOCK":
            open_blocks.setdefault(ip, e["recv_ts"])
        elif e["event"] == "UNBLOCK" and ip in open_blocks:
            recov.append(e["recv_ts"] - open_blocks.pop(ip))
    summarize("recovery (BLOCK->UNBLOCK)", recov, " s")
    if open_blocks:
        print(f"  still blocked at end of log: {sorted(open_blocks)}")

    if a.csv:
        cols = ["id", "recv_time", "event", "src_ip", "dst_ip", "dst_port", "proto",
                "reason", "timeout", "alert_latency_ms", "sender"]
        with open(a.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(events)
        print(f"\nCSV written to {a.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
