"""
Interactive Plotly versions of the four report charts, for the live dashboard.

These mirror the aggregations in analysis/charts.py (same stage/risk colours and
protocol names, imported from there) but render as interactive Plotly figures on
a transparent dark background that blends with the SOC theme. The matplotlib
PNGs in analysis/charts.py are untouched — they're still what the report uses.

Each function takes the parser's DataFrame (top_source_ips also takes the risk
table) and returns a plotly.graph_objects.Figure; an empty table gives a
"No events yet" figure instead of an error.
"""

import pandas as pd
import plotly.graph_objects as go

from analysis.charts import (PROTOCOL_NAMES, RISK_COLORS, STAGE_COLORS, STAGE_LABELS,
                             _bin_size, _protocol_name)
from analysis.detection import detect

STAGES3 = ["scan", "read", "write"]
MUTED = "#8b98a9"
GRID = "#263040"

# Layout shared by every chart: transparent so the app's dark background shows
# through, muted grid, monospace-ish SOC feel.
LAYOUT = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#c9d4e0", family="IBM Plex Sans, system-ui, sans-serif", size=13),
    margin=dict(l=10, r=10, t=64, b=10),
    legend=dict(bgcolor="rgba(0,0,0,0)", orientation="h", yanchor="bottom", y=1.02,
                xanchor="right", x=1),
    hoverlabel=dict(font_size=12),
)


def _base(title, subtitle=None):
    text = f"<b>{title}</b>"
    if subtitle:
        text += f"<br><span style='font-size:12px;color:{MUTED}'>{subtitle}</span>"
    fig = go.Figure()
    fig.update_layout(title=dict(text=text, x=0, xanchor="left", font=dict(size=17)), **LAYOUT)
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID)
    return fig


def _empty(title):
    fig = _base(title)
    fig.add_annotation(text="No events yet", showarrow=False,
                       font=dict(size=16, color=MUTED), x=0.5, y=0.5, xref="paper", yref="paper")
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return fig


def attacks_per_protocol(df):
    if df.empty:
        return _empty("Attacker events per protocol")
    counts = df["protocol"].value_counts()
    fig = _base("Attacker events per protocol",
                f"{len(df):,} events from {df['src_ip'].nunique()} source IPs")
    fig.add_bar(y=[_protocol_name(p) for p in counts.index], x=counts.values,
                orientation="h", marker_color="#2a78d6",
                text=[f"{v:,}" for v in counts.values], textposition="outside",
                hovertemplate="%{y}: %{x:,} events<extra></extra>")
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(title="Events (connections + requests)")
    return fig


def actions_by_protocol(df):
    staged = df[df["action"].isin(STAGES3)]
    if staged.empty:
        return _empty("Scans vs reads vs writes")
    table = (staged.groupby(["protocol", "action"]).size().unstack(fill_value=0)
             .reindex(columns=STAGES3, fill_value=0))
    table = table.loc[table.sum(axis=1).sort_values(ascending=False).index]
    writes = int(table["write"].sum())
    fig = _base("Scans vs reads vs writes",
                f"Classified requests per protocol · {writes} write attempt{'s' if writes != 1 else ''}")
    protocols = [_protocol_name(p) for p in table.index]
    for stage in STAGES3:
        fig.add_bar(y=protocols, x=table[stage], orientation="h", name=STAGE_LABELS[stage],
                    marker_color=STAGE_COLORS[stage],
                    hovertemplate="%{y} · " + STAGE_LABELS[stage] + ": %{x:,}<extra></extra>")
    fig.update_layout(barmode="stack")
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(title="Requests")
    return fig


def event_timeline(df):
    if df.empty:
        return _empty("Event timeline")
    size = _bin_size(df["timestamp"].max() - df["timestamp"].min())
    stage = df["action"].where(df["action"].isin(STAGES3), "other")
    binned = (df.assign(stage=stage, bin=df["timestamp"].dt.floor(size))
                .groupby(["bin", "stage"]).size().unstack(fill_value=0)
                .reindex(columns=STAGES3 + ["other"], fill_value=0))
    label = size.replace("min", " min").replace("1D", "day")
    fig = _base("Event timeline", f"Events per {label}, stacked by stage")
    for stage_name in STAGES3 + ["other"]:
        if binned[stage_name].sum() == 0:
            continue
        fig.add_bar(x=binned.index, y=binned[stage_name], name=STAGE_LABELS[stage_name],
                    marker_color=STAGE_COLORS[stage_name],
                    hovertemplate="%{x}<br>" + STAGE_LABELS[stage_name] + ": %{y:,}<extra></extra>")
    fig.update_layout(barmode="stack", bargap=0.1)
    fig.update_xaxes(title=f"Time ({df['timestamp'].dt.tz})")
    fig.update_yaxes(title="Events")
    return fig


def top_source_ips(df, risk=None, n=10):
    if df.empty:
        return _empty("Top source IPs")
    risk = detect(df) if risk is None else risk
    level = risk.set_index("src_ip")["risk"]
    counts = df["src_ip"].value_counts().head(n)
    gateway = set(df.loc[df["is_docker_gateway"], "src_ip"])
    labels = [f"{ip} (Docker gateway)" if ip in gateway else ip for ip in counts.index]
    colours = [RISK_COLORS.get(level.get(ip), MUTED) for ip in counts.index]
    fig = _base("Top source IPs", "Bar colour and label show the detected risk level")
    fig.add_bar(y=labels, x=counts.values, orientation="h", marker_color=colours,
                text=[f"{v:,} · {level.get(ip, '')}" for ip, v in counts.items()],
                textposition="outside",
                hovertemplate="%{y}: %{x:,} events<extra></extra>")
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(title="Events")
    return fig
