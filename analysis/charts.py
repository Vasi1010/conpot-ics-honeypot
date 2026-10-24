"""
Report / PPT charts from the parsed table (matplotlib, PNG, 16:9).

    attacks_per_protocol   events per protocol (bar)
    event_timeline         events over time, stacked by stage (scan/read/write)
    actions_by_protocol    scans vs reads vs writes per protocol (stacked bar)
    top_source_ips         busiest source IPs, labelled with their risk level

Each function takes the parser's DataFrame (top_source_ips also takes the
detection table) and returns a matplotlib Figure, so the dashboard can reuse
them. An empty table gives a "No events yet" figure instead of an error.

    python -m analysis.charts logs/conpot.log --out output/
writes the four PNGs plus parsed_events.csv and risk_by_ip.csv.
"""

import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless: render straight to PNG
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from parser import DEFAULT_TZ, ParseStats, parse_log  # noqa: E402

from .detection import DEFAULT_WINDOW_S, detect  # noqa: E402

# Validated categorical slots 1-3 (blue, orange, aqua) for the three stages,
# always shown with a legend. "Other" (connects, unclassified) is neutral gray.
STAGES = ["scan", "read", "write", "other"]
STAGE_COLORS = {"scan": "#2a78d6", "read": "#eb6834", "write": "#1baf7a", "other": "#c3c2b7"}
STAGE_LABELS = {"scan": "Scan", "read": "Read", "write": "Write", "other": "Connect / other"}
# Risk is a status, so it uses the status palette, always with its text label.
RISK_COLORS = {"High": "#d03b3b", "Medium": "#ec835a", "Low": "#fab219", "Info": "#c3c2b7"}
PROTOCOL_NAMES = {"modbus": "Modbus", "s7comm": "S7comm", "snmp": "SNMP", "http": "HTTP"}

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
BAR = "#2a78d6"

FIGSIZE = (10, 5.625)  # 16:9, fills a PPT slide
DPI = 200
BAR_MAX_IN = 0.25      # ~24 px on screen: bars never fill their slot

STYLE = {
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "font.family": ["Segoe UI", "DejaVu Sans", "sans-serif"], "font.size": 10,
    "text.color": INK, "axes.labelcolor": INK_2, "xtick.color": MUTED, "ytick.color": INK_2,
    "axes.edgecolor": AXIS, "axes.linewidth": 0.8, "axes.grid": False,
    "grid.color": GRID, "grid.linewidth": 0.8, "grid.linestyle": "-",
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.titlesize": 14, "axes.titleweight": "bold", "axes.titlelocation": "left",
    "axes.titlepad": 26, "legend.frameon": False,
}

CHARTS = {
    "attacks_per_protocol": "attacks_per_protocol.png",
    "event_timeline": "event_timeline.png",
    "actions_by_protocol": "reads_vs_writes.png",
    "top_source_ips": "top_source_ips.png",
}

# Candidate timeline bin sizes; the smallest giving <= ~60 bins is used.
BIN_SIZES = ["1s", "5s", "10s", "30s", "1min", "5min", "10min", "15min", "30min",
             "1h", "3h", "6h", "12h", "1D"]


def _figure(title, subtitle=None):
    with plt.rc_context(STYLE):
        fig, ax = plt.subplots(figsize=FIGSIZE, layout="constrained")
        ax.set_title(title)
        if subtitle:
            ax.text(0, 1.015, subtitle, transform=ax.transAxes, color=INK_2, fontsize=9.5, va="bottom")
    return fig, ax


def _empty(fig, ax):
    ax.axis("off")
    ax.text(0.5, 0.5, "No events yet", transform=ax.transAxes, ha="center", va="center",
            color=MUTED, fontsize=14)
    return fig


def _bar_height(n):
    """Bar thickness in slot units, capped at BAR_MAX_IN."""
    slot_in = FIGSIZE[1] * 0.75 / max(n, 1)
    return min(0.6, BAR_MAX_IN / slot_in)


def _protocol_name(p):
    return PROTOCOL_NAMES.get(p, p)


def _hbar_axes(ax):
    ax.tick_params(axis="y", length=0)
    ax.spines["left"].set_visible(False)
    ax.xaxis.grid(True)
    ax.set_axisbelow(True)
    ax.xaxis.set_major_locator(plt.MaxNLocator(integer=True))


def _tip_labels(ax, totals):
    """Value at each bar tip (bars listed top to bottom)."""
    pad = max(totals) * 0.012
    for yi, v in zip(range(len(totals))[::-1], totals):
        ax.text(v + pad, yi, f"{v:,}", va="center", ha="left", color=INK, fontsize=9.5)
    ax.set_xlim(0, max(totals) * 1.1)


def attacks_per_protocol(df):
    fig, ax = _figure("Attacker events per protocol",
                      f"{len(df):,} events from {df['src_ip'].nunique()} source IPs" if len(df) else None)
    if df.empty:
        return _empty(fig, ax)
    with plt.rc_context(STYLE):
        counts = df["protocol"].value_counts()
        y = list(range(len(counts)))[::-1]
        ax.barh(y, counts.values, height=_bar_height(len(counts)), color=BAR)
        ax.set_yticks(y, [_protocol_name(p) for p in counts.index])
        _hbar_axes(ax)
        _tip_labels(ax, counts.tolist())
        ax.set_xlabel("Events (connections + requests)")
    return fig


def _bin_size(span):
    for size in BIN_SIZES:
        if span / pd.Timedelta(size) <= 60:
            return size
    return BIN_SIZES[-1]


def event_timeline(df):
    if df.empty:
        fig, ax = _figure("Event timeline")
        return _empty(fig, ax)
    size = _bin_size(df["timestamp"].max() - df["timestamp"].min())
    fig, ax = _figure("Event timeline", f"Events per {size.replace('min', ' min').replace('1D', 'day')}, "
                                        "stacked by stage")
    with plt.rc_context(STYLE):
        stage = df["action"].where(df["action"].isin(STAGES[:3]), "other")
        binned = (df.assign(stage=stage, bin=df["timestamp"].dt.floor(size))
                    .groupby(["bin", "stage"]).size().unstack(fill_value=0)
                    .reindex(columns=STAGES, fill_value=0))
        width = pd.Timedelta(size) * 0.8
        bottom = pd.Series(0, index=binned.index)
        for s in STAGES:
            if binned[s].sum() == 0:
                continue
            ax.bar(binned.index, binned[s], bottom=bottom, width=width, align="edge",
                   color=STAGE_COLORS[s], label=STAGE_LABELS[s], edgecolor=SURFACE, linewidth=0.8)
            bottom += binned[s]
        ax.yaxis.grid(True)
        ax.set_axisbelow(True)
        ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="y", length=0)
        tz = df["timestamp"].dt.tz
        loc = mdates.AutoDateLocator(tz=tz, maxticks=8)
        ax.xaxis.set_major_locator(loc)
        ax.xaxis.set_major_formatter(mdates.ConciseDateFormatter(loc, tz=tz))
        ax.set_xlabel(f"Time ({tz})")
        ax.set_ylabel("Events")
        ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), labelcolor=INK_2)
    return fig


def actions_by_protocol(df):
    fig, ax = _figure("Scans vs reads vs writes", "Classified requests per protocol")
    staged = df[df["action"].isin(STAGES[:3])]
    if staged.empty:
        return _empty(fig, ax)
    with plt.rc_context(STYLE):
        table = (staged.groupby(["protocol", "action"]).size().unstack(fill_value=0)
                 .reindex(columns=STAGES[:3], fill_value=0))
        table = table.loc[table.sum(axis=1).sort_values(ascending=False).index]
        y = list(range(len(table)))[::-1]
        left = pd.Series(0, index=table.index)
        for s in STAGES[:3]:
            ax.barh(y, table[s], left=left, height=_bar_height(len(table)), color=STAGE_COLORS[s],
                    edgecolor=SURFACE, linewidth=2, label=STAGE_LABELS[s])
            left += table[s]
        ax.set_yticks(y, [_protocol_name(p) for p in table.index])
        _hbar_axes(ax)
        _tip_labels(ax, left.tolist())
        writes = int(table["write"].sum())
        ax.text(1, 1.015, f"{writes} write attempt{'s' if writes != 1 else ''}", transform=ax.transAxes,
                ha="right", va="bottom", color=INK, fontsize=10, weight="bold")
        ax.set_xlabel("Requests")
        ax.legend(loc="upper left", bbox_to_anchor=(1.01, 1), labelcolor=INK_2)
    return fig


def top_source_ips(df, risk=None, n=10):
    fig, ax = _figure("Top source IPs", "Bar colour and label show the detected risk level")
    if df.empty:
        return _empty(fig, ax)
    with plt.rc_context(STYLE):
        risk = detect(df) if risk is None else risk
        level = risk.set_index("src_ip")["risk"]
        counts = df["src_ip"].value_counts().head(n)
        gateway = set(df.loc[df["is_docker_gateway"], "src_ip"])
        y = list(range(len(counts)))[::-1]
        ax.barh(y, counts.values, height=_bar_height(len(counts)),
                color=[RISK_COLORS.get(level.get(ip), MUTED) for ip in counts.index])
        ax.set_yticks(y, [f"{ip} (Docker gateway)" if ip in gateway else ip for ip in counts.index])
        _hbar_axes(ax)
        pad = counts.max() * 0.012
        for yi, ip, v in zip(y, counts.index, counts):
            ax.text(v + pad, yi, f"{v:,}  ·  {level.get(ip, '')}", va="center", ha="left",
                    color=INK, fontsize=9.5)
        ax.set_xlim(0, counts.max() * 1.2)
        ax.set_xlabel("Events")
    return fig


def save_all(df, out_dir, risk=None, window_s=DEFAULT_WINDOW_S):
    """Write the four PNGs, parsed_events.csv and risk_by_ip.csv. Returns the paths."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    risk = detect(df, window_s) if risk is None else risk
    figures = {
        "attacks_per_protocol": attacks_per_protocol(df),
        "event_timeline": event_timeline(df),
        "actions_by_protocol": actions_by_protocol(df),
        "top_source_ips": top_source_ips(df, risk),
    }
    paths = []
    for name, fig in figures.items():
        path = out_dir / CHARTS[name]
        fig.savefig(path, dpi=DPI)
        plt.close(fig)
        paths.append(path)
    for name, table in (("parsed_events.csv", df), ("risk_by_ip.csv", risk)):
        table.to_csv(out_dir / name, index=False)
        paths.append(out_dir / name)
    return paths


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m analysis.charts",
                                 description="Render report charts (PNG) and CSVs from a Conpot log.")
    ap.add_argument("logfile", type=Path)
    ap.add_argument("--out", type=Path, default=Path("output"), help="output folder (default output/)")
    ap.add_argument("--tz", default=DEFAULT_TZ, help=f"log timezone (default {DEFAULT_TZ})")
    ap.add_argument("--window", type=float, default=DEFAULT_WINDOW_S,
                    help=f"multi-protocol scan window in seconds (default {DEFAULT_WINDOW_S})")
    args = ap.parse_args(argv)

    stats = ParseStats()
    df = parse_log(args.logfile, args.tz, stats)
    if stats.file_missing:
        print(f"Log file not found or unreadable: {args.logfile}")
        return 1
    for path in save_all(df, args.out, window_s=args.window):
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
