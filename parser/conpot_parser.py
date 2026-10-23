"""
Parse a Conpot log into a pandas DataFrame, one row per attacker event.

Accepts, even mixed in one file:
  * the text log (conpot.log, `docker logs [-t] conpot`, `docker compose logs`)
  * the JSON log (one JSON object per line)
Files saved as UTF-16 (PowerShell's `docker logs conpot > conpot.log`) are fine too.

Never raises on bad input: a missing or empty file gives an empty table, and
lines that can't be parsed are skipped and counted in ParseStats.

Usage as a library:
    from parser import ParseStats, parse_log
    stats = ParseStats()
    df = parse_log("logs/conpot.log", tz="Asia/Kolkata", stats=stats)

Usage from the command line (prints a summary and any lines it couldn't match):
    python -m parser sample_logs/conpot_sample.log
    python -m parser logs/conpot.log --csv output/parsed.csv --tz UTC
"""

import argparse
import ipaddress
import sys
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd

from . import patterns as P
from .classify import classify
from .formats import FORMATS, IGNORED

# Conpot's text log has no timezone; its timestamps are read as this zone.
DEFAULT_TZ = "Asia/Kolkata"
MAX_UNMATCHED = 50

# LAN-side sources (RFC 1918, loopback, link-local, CGNAT). Deliberately not
# ipaddress.is_private, which also counts documentation ranges like 198.51.100.0/24.
PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "100.64.0.0/10")]

COLUMNS = [
    "timestamp", "src_ip", "src_port", "protocol", "event", "request_type",
    "function_code", "action", "details", "is_private", "is_docker_gateway",
    "session_id", "pattern", "raw",
]


@dataclass
class ParseStats:
    lines: int = 0
    blank: int = 0
    parsed: int = 0        # rows in the table (includes fallback rows)
    ignored: int = 0       # known noise: startup banners, responses, disconnects
    fallback: int = 0      # kept as rows, but no pattern fully matched
    unparseable: int = 0   # skipped
    file_missing: bool = False
    unmatched: list = field(default_factory=list)  # first MAX_UNMATCHED fallback/skipped lines

    def note(self, line):
        if len(self.unmatched) < MAX_UNMATCHED:
            self.unmatched.append(line)


def parse_log(path, tz=DEFAULT_TZ, stats=None):
    """Parse a log file. Missing or unreadable file -> empty table (stats.file_missing)."""
    stats = stats if stats is not None else ParseStats()
    try:
        data = Path(path).read_bytes()
    except OSError:
        stats.file_missing = True
        return _to_frame([], tz)
    return parse_bytes(data, tz, stats)


def parse_bytes(data, tz=DEFAULT_TZ, stats=None):
    """Parse raw log bytes (e.g. an uploaded file); handles UTF-8/UTF-16 and BOMs."""
    return parse_lines(_decode(data).splitlines(), tz, stats)


def parse_lines(lines, tz=DEFAULT_TZ, stats=None):
    stats = stats if stats is not None else ParseStats()
    rows = []
    for line in lines:
        stats.lines += 1
        line = line.rstrip("\r\n")
        if not line.strip():
            stats.blank += 1
            continue
        try:
            row = parse_line(line)
        except Exception:  # one malformed line must never take the whole parse down
            row = None
        if row is IGNORED:
            stats.ignored += 1
        elif row is None:
            stats.unparseable += 1
            stats.note(line)
        else:
            if row["pattern"] == "fallback":
                stats.fallback += 1
                stats.note(line)
            rows.append(row)

    df = _to_frame(rows, tz)
    stats.unparseable += len(rows) - len(df)  # rows dropped for an invalid timestamp
    stats.parsed += len(df)
    return df


def parse_line(line):
    """Return a row dict, IGNORED for known noise, or None if nothing understood it."""
    clean = P.ANSI_RE.sub("", line)
    clean = P.COMPOSE_PREFIX_RE.sub("", clean, count=1)
    clean = P.DOCKER_TS_PREFIX_RE.sub("", clean, count=1)

    fmt = next((f for f in FORMATS if f.sniff(clean)), None)
    raw = fmt.parse(clean) if fmt else None
    if raw is None or raw is IGNORED:
        return raw

    protocol = _protocol(raw["proto"])
    row = {"timestamp": raw["ts"], "src_ip": raw["ip"], "src_port": raw["port"],
           "protocol": protocol, "event": raw["event"], "session_id": raw["session_id"],
           "pattern": raw["pattern"], "raw": line}
    row.update(classify(protocol, raw["event"], raw["fields"]))
    return row


def _protocol(text):
    text = text.lower().replace(" ", "_")
    for alias, name in P.PROTOCOL_ALIASES.items():
        if alias in text:
            return name
    return "unknown"


def _decode(data):
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def _to_timestamps(values, tz):
    """Naive timestamps are local time in `tz`; ones with Z/offset are converted to `tz`."""
    s = values.astype(str).str.replace(",", ".", regex=False)
    aware = s.str.contains(r"(?:Z|[+-]\d{2}:?\d{2})$", regex=True)
    naive = pd.to_datetime(s[~aware], format="ISO8601", errors="coerce").dt.tz_localize(
        tz, ambiguous="NaT", nonexistent="NaT")
    converted = pd.to_datetime(s[aware], format="ISO8601", utc=True, errors="coerce").dt.tz_convert(tz)
    return pd.concat([naive, converted]).reindex(values.index).astype(f"datetime64[ns, {tz}]")


def _is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in PRIVATE_NETS)


def _to_frame(rows, tz):
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["timestamp"] = _to_timestamps(df["timestamp"], tz)
    df = df[df["timestamp"].notna()].copy()
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").astype("Int64")
    df["function_code"] = pd.to_numeric(df["function_code"], errors="coerce").astype("Int64")
    df["src_ip"] = df["src_ip"].astype(str)
    df["is_private"] = df["src_ip"].map(_is_private).astype(bool)
    df["is_docker_gateway"] = df["src_ip"].str.match(P.DOCKER_GATEWAY_RE).astype(bool)

    # Requests rarely carry the client port; inherit it from the session's connect line.
    has_sid = df["session_id"].notna()
    df.loc[has_sid, "src_port"] = (
        df[has_sid].groupby("session_id")["src_port"].transform("first"))

    # A session that connected but never sent a request is a port probe -> scan.
    # (While tailing a live log, a session that is still open looks like this too.)
    sessions_with_requests = set(df.loc[df["event"] == "request", "session_id"].dropna())
    probe = (df["event"] == "connect") & has_sid & ~df["session_id"].isin(sessions_with_requests)
    df.loc[probe, "action"] = "scan"
    df.loc[probe, "request_type"] = "Connect only (port probe)"

    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def _tz(name):
    try:
        ZoneInfo(name)
    except Exception:
        raise argparse.ArgumentTypeError(f"unknown timezone {name!r} (try Asia/Kolkata or UTC)")
    return name


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m parser", description="Parse a Conpot log into a table.")
    ap.add_argument("logfile", type=Path)
    ap.add_argument("--csv", type=Path, help="also write the parsed table to this CSV")
    ap.add_argument("--tz", type=_tz, default=DEFAULT_TZ,
                    help=f"timezone of the log's timestamps (default {DEFAULT_TZ})")
    args = ap.parse_args(argv)

    stats = ParseStats()
    df = parse_log(args.logfile, args.tz, stats)
    if stats.file_missing:
        print(f"Log file not found or unreadable: {args.logfile}")
        return 1

    print(f"{stats.lines} lines: {stats.parsed} events ({stats.fallback} fallback), "
          f"{stats.ignored} ignored, {stats.unparseable} unparseable, {stats.blank} blank")
    if df.empty:
        print("No attacker events found.")
    else:
        print(f"{df['src_ip'].nunique()} source IPs, "
              f"{df['timestamp'].min()} -> {df['timestamp'].max()}\n")
        print(df.groupby(["protocol", "action"]).size().unstack(fill_value=0), "\n")
        with pd.option_context("display.width", 200, "display.max_colwidth", 40):
            print(df.drop(columns=["raw", "session_id"]).to_string(index=False))

    if stats.unmatched:
        print(f"\n!! {stats.fallback + stats.unparseable} line(s) not fully understood "
              f"(add/adjust a pattern in parser/patterns.py):")
        for line in stats.unmatched[:20]:
            print("   ", line[:200])
    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(args.csv, index=False)
        print(f"\nWrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
