"""
Attack-sequence detection: one risk level per source IP.

Each event's `action` (from the parser) gives its stage: scan, read or write.
On top of that, an IP that touches 2+ protocols within `window_s` seconds
(default 60) gets a multi-protocol scan at the moment the second protocol shows up.

    risk     when
    ------   -----------------------------------------------------------------
    High     any write (read -> write, scan -> read -> write, also write-only:
             every write is flagged)
    Medium   reads but no write (scan -> read; a read with no scan also lands here)
    Low      scans only
    Info     traffic, but nothing classified as scan/read/write

`sequence` lists the stages in the order they first appeared, e.g.
"scan -> read -> write".

Usage:
    from analysis.detection import detect
    risk = detect(df)                       # df from parser.parse_log()

    python -m analysis.detection logs/conpot.log [--window 60] [--csv output/risk_by_ip.csv]
"""

import argparse
import sys
from pathlib import Path

import pandas as pd

from parser import DEFAULT_TZ, ParseStats, parse_log

DEFAULT_WINDOW_S = 60
STAGES = ("scan", "read", "write")
RISK_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}

RISK_COLUMNS = [
    "src_ip", "risk", "sequence", "write_flag", "scans", "reads", "writes",
    "multi_protocol_scan", "protocols", "events", "first_seen", "last_seen",
    "is_private", "is_docker_gateway",
]


def multi_protocol_scan_time(events, window_s=DEFAULT_WINDOW_S):
    """First time one IP's events span 2+ protocols within window_s, else None.

    `events` is one IP's rows (timestamp, protocol), any order.
    """
    ev = events[events["protocol"] != "unknown"].sort_values("timestamp")
    times, protos = list(ev["timestamp"]), list(ev["protocol"])
    window = pd.Timedelta(seconds=window_s)
    start = 0
    for i, t in enumerate(times):
        while times[start] < t - window:
            start += 1
        if len(set(protos[start:i + 1])) >= 2:
            return t
    return None


def classify_ip(events, window_s=DEFAULT_WINDOW_S):
    """Risk summary (dict of RISK_COLUMNS) for one IP's events."""
    staged = events.loc[events["action"].isin(STAGES), ["timestamp", "action"]]
    mp_time = multi_protocol_scan_time(events, window_s)
    if mp_time is not None:
        staged = pd.concat([staged, pd.DataFrame({"timestamp": [mp_time], "action": ["scan"]})])
    staged = staged.sort_values("timestamp", kind="stable")

    counts = events["action"].value_counts()
    writes = int(counts.get("write", 0))
    reads = int(counts.get("read", 0))
    scans = int(counts.get("scan", 0)) + (mp_time is not None)

    if writes:
        risk = "High"
    elif reads:
        risk = "Medium"
    elif scans:
        risk = "Low"
    else:
        risk = "Info"

    return {
        "src_ip": events["src_ip"].iloc[0],
        "risk": risk,
        "sequence": " -> ".join(staged["action"].drop_duplicates()),
        "write_flag": writes > 0,
        "scans": scans,
        "reads": reads,
        "writes": writes,
        "multi_protocol_scan": mp_time is not None,
        "protocols": ", ".join(sorted(set(events["protocol"]) - {"unknown"})),
        "events": len(events),
        "first_seen": events["timestamp"].min(),
        "last_seen": events["timestamp"].max(),
        "is_private": bool(events["is_private"].iloc[0]),
        "is_docker_gateway": bool(events["is_docker_gateway"].iloc[0]),
    }


def detect(df, window_s=DEFAULT_WINDOW_S):
    """One row per source IP, highest risk first. Empty input -> empty table."""
    rows = [classify_ip(g, window_s) for _, g in df.groupby("src_ip", sort=False)]
    risk = pd.DataFrame(rows, columns=RISK_COLUMNS)
    if risk.empty:
        return risk
    order = risk["risk"].map(RISK_ORDER)
    return (risk.assign(_order=order)
                .sort_values(["_order", "writes", "events"], ascending=False, kind="stable")
                .drop(columns="_order")
                .reset_index(drop=True))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m analysis.detection",
                                 description="Risk level (Low/Medium/High) per source IP.")
    ap.add_argument("logfile", type=Path)
    ap.add_argument("--window", type=float, default=DEFAULT_WINDOW_S,
                    help=f"multi-protocol scan window in seconds (default {DEFAULT_WINDOW_S})")
    ap.add_argument("--tz", default=DEFAULT_TZ, help=f"log timezone (default {DEFAULT_TZ})")
    ap.add_argument("--csv", type=Path, help="also write the table to this CSV")
    args = ap.parse_args(argv)

    stats = ParseStats()
    risk = detect(parse_log(args.logfile, args.tz, stats), args.window)
    if stats.file_missing:
        print(f"Log file not found or unreadable: {args.logfile}")
        return 1
    if risk.empty:
        print("No attacker events found.")
    else:
        with pd.option_context("display.width", 200):
            print(risk.drop(columns=["first_seen", "last_seen"]).to_string(index=False))
        flagged = risk[risk["write_flag"]]
        if not flagged.empty:
            print(f"\n!! WRITE ATTEMPTS from: {', '.join(flagged['src_ip'])}")
    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        risk.to_csv(args.csv, index=False)
        print(f"\nWrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
