"""
Data side of the dashboard, kept free of Streamlit so it can be tested.

load() turns a log path (or uploaded bytes) into a Snapshot: the parsed
events, the per-IP risk table, parse stats, KPI numbers and the share of
traffic that came from a Docker gateway IP. It never raises on a missing,
empty or garbled log.
"""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from analysis.detection import DEFAULT_WINDOW_S, detect
from parser import DEFAULT_TZ, ParseStats, parse_bytes, parse_log

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = "logs/conpot.log"
DEFAULT_CONTAINER = "conpot"
DOCKER_TIMEOUT = 10  # seconds to wait for `docker logs` before giving up
# Warn when more than this share of events comes from a Docker gateway IP.
GATEWAY_WARN_SHARE = 0.5


@dataclass
class Snapshot:
    df: pd.DataFrame
    risk: pd.DataFrame
    stats: ParseStats
    source: str
    kpis: dict
    gateway_share: float
    gateway_ips: list
    docker_error: str = None  # set when the source was Docker but it couldn't be read

    @property
    def gateway_warning(self):
        return self.gateway_share > GATEWAY_WARN_SHARE


def resolve(path):
    """Relative paths are tried from the current folder, then from the repo root."""
    p = Path(path).expanduser()
    if p.is_absolute() or p.exists():
        return p
    return ROOT / p


def _assemble(df, stats, source, window_s):
    """Build a Snapshot (risk, KPIs, gateway share) from an events table."""
    risk = detect(df, window_s)
    gw = df[df["is_docker_gateway"]]
    return Snapshot(
        df=df, risk=risk, stats=stats, source=source, kpis=kpis(df, risk),
        gateway_share=len(gw) / len(df) if len(df) else 0.0,
        gateway_ips=sorted(gw["src_ip"].unique()),
    )


def load(path=None, data=None, name=None, tz=DEFAULT_TZ, window_s=DEFAULT_WINDOW_S):
    """Parse `data` (uploaded bytes) if given, else the file at `path`."""
    stats = ParseStats()
    if data is not None:
        df = parse_bytes(data, tz, stats)
        source = name or "uploaded file"
    else:
        p = resolve(path or DEFAULT_LOG)
        df = parse_log(p, tz, stats)
        source = str(p)
    return _assemble(df, stats, source, window_s)


def filter_since(snap, since, window_s=DEFAULT_WINDOW_S):
    """Return a new Snapshot keeping only events strictly after `since`.

    Used by the dashboard's "reset" button: a non-destructive baseline that zeroes
    the view from a moment in time (works for any source — file, upload or Docker)
    without touching the log. `since` is a pandas Timestamp; None returns `snap`
    unchanged. `stats` is kept as-is (it describes the whole log, not the view).
    """
    if since is None or snap is None or not len(snap.df):
        return snap
    df = snap.df[snap.df["timestamp"] > since].reset_index(drop=True)
    out = _assemble(df, snap.stats, snap.source, window_s)
    out.docker_error = snap.docker_error
    return out


def docker_logs(container=DEFAULT_CONTAINER, timeout=DOCKER_TIMEOUT):
    """Run `docker logs <container>` and return (log_bytes, error).

    `error` is None on success, otherwise a short human-readable reason (Docker
    not installed, daemon down, no such container, timeout). Never raises, so the
    dashboard can fall back gracefully when Docker isn't running.
    """
    if shutil.which("docker") is None:
        return b"", "Docker CLI not found on PATH."
    try:
        proc = subprocess.run(["docker", "logs", container],
                              capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return b"", f"`docker logs {container}` timed out after {timeout}s."
    except OSError as exc:
        return b"", f"Could not run docker: {exc}"
    if proc.returncode != 0:
        reason = proc.stderr.decode("utf-8", "replace").strip() or f"exit code {proc.returncode}"
        return b"", f"`docker logs {container}` failed: {reason}"
    # Conpot logs to stderr, other containers to stdout; `docker logs` emits each
    # on the matching stream, so combine them to be sure we catch the log lines.
    return proc.stdout + proc.stderr, None


def load_docker(container=DEFAULT_CONTAINER, tz=DEFAULT_TZ, window_s=DEFAULT_WINDOW_S,
                timeout=DOCKER_TIMEOUT):
    """Snapshot built from live `docker logs <container>` output.

    If Docker can't be read, returns an empty Snapshot with `docker_error` set
    instead of raising.
    """
    data, error = docker_logs(container, timeout)
    snap = load(data=data, name=f"docker logs {container}", tz=tz, window_s=window_s)
    snap.docker_error = error
    return snap


def kpis(df, risk):
    return {
        "Total events": len(df),
        "Unique source IPs": int(df["src_ip"].nunique()),
        "Write attempts": int((df["action"] == "write").sum()),
        "High-risk IPs": int((risk["risk"] == "High").sum()) if len(risk) else 0,
    }


def file_signature(path):
    """(mtime, size) of the resolved log, or None if missing; used as a cache key."""
    try:
        st = resolve(path).stat()
    except OSError:
        return None
    return st.st_mtime_ns, st.st_size
