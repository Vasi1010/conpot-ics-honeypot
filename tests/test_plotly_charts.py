"""
Tests for the interactive Plotly dashboard charts (dashboard/plotly_charts.py).

They mirror analysis/charts.py but render Plotly figures on a transparent dark
background. These check the figures build for a real sample, stay empty-safe,
and keep the risk/stage colours consistent with the report charts.
"""

from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import pytest

from analysis.charts import RISK_COLORS, STAGE_COLORS
from dashboard import plotly_charts as pc
from dashboard.data import load

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_logs"

SNAP = load(SAMPLES / "conpot_sample.log")
DF, RISK = SNAP.df, SNAP.risk

BUILDERS = [pc.attacks_per_protocol, pc.actions_by_protocol, pc.event_timeline, pc.top_source_ips]


def _call(builder, df):
    # top_source_ips takes the risk table too.
    return builder(df, RISK) if builder is pc.top_source_ips else builder(df)


@pytest.mark.parametrize("builder", BUILDERS)
def test_builds_a_figure_with_traces(builder):
    fig = _call(builder, DF)
    assert isinstance(fig, go.Figure)
    assert len(fig.data) >= 1
    # Transparent background so the SOC dark theme shows through.
    assert fig.layout.paper_bgcolor == "rgba(0,0,0,0)"


@pytest.mark.parametrize("builder", BUILDERS)
def test_empty_df_is_safe(builder):
    empty = DF.iloc[0:0]
    fig = _call(builder, empty)
    assert isinstance(fig, go.Figure)
    assert any("No events yet" in (a.text or "") for a in fig.layout.annotations)


def test_actions_by_protocol_is_stacked_with_stage_colours():
    fig = pc.actions_by_protocol(DF)
    assert fig.layout.barmode == "stack"
    used = {bar.marker.color for bar in fig.data}
    assert used <= set(STAGE_COLORS.values())


def test_top_source_ips_colours_reflect_risk():
    fig = pc.top_source_ips(DF, RISK)
    bar_colours = set(fig.data[0].marker.color)
    # Every bar colour is a known risk colour (or the muted fallback).
    assert bar_colours <= set(RISK_COLORS.values()) | {pc.MUTED}
    # The sample has High-risk writers, so the High colour must appear.
    assert RISK_COLORS["High"] in bar_colours


def test_event_timeline_has_a_time_axis_title():
    fig = pc.event_timeline(DF)
    assert "Time" in fig.layout.xaxis.title.text
