from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import pytest

from analysis import charts
from parser import parse_lines, parse_log

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"
CHART_FUNCS = [charts.attacks_per_protocol, charts.event_timeline,
               charts.actions_by_protocol, charts.top_source_ips]


@pytest.fixture(scope="module")
def df():
    return parse_log(SAMPLES / "conpot_sample.log")


@pytest.mark.parametrize("func", CHART_FUNCS)
def test_charts_render_on_sample_and_empty(func, df):
    for data in (df, df.iloc[0:0]):
        fig = func(data)
        assert fig.axes
        plt.close(fig)


def test_empty_chart_says_so(df):
    fig = charts.event_timeline(df.iloc[0:0])
    assert "No events yet" in [t.get_text() for t in fig.axes[0].texts]
    plt.close(fig)


def test_save_all_writes_pngs_and_csvs(df, tmp_path):
    paths = charts.save_all(df, tmp_path / "out")
    names = sorted(p.name for p in paths)
    assert names == sorted(list(charts.CHARTS.values()) + ["parsed_events.csv", "risk_by_ip.csv"])
    for p in paths:
        assert p.stat().st_size > 0
    assert (tmp_path / "out" / "attacks_per_protocol.png").read_bytes()[:4] == b"\x89PNG"
    assert len(pd.read_csv(tmp_path / "out" / "parsed_events.csv")) == len(df)
    assert set(pd.read_csv(tmp_path / "out" / "risk_by_ip.csv")["risk"]) == {"High", "Medium", "Low"}


def test_save_all_on_missing_log(tmp_path):
    paths = charts.save_all(parse_log(tmp_path / "missing.log"), tmp_path)
    assert all(p.exists() for p in paths)


def test_top_ips_labels_risk_and_docker_gateway():
    fig = charts.top_source_ips(parse_log(SAMPLES / "docker_logs_sample.txt"))
    ax = fig.axes[0]
    assert "172.17.0.1 (Docker gateway)" in [t.get_text() for t in ax.get_yticklabels()]
    assert any(t.get_text().endswith("High") for t in ax.texts)
    plt.close(fig)


@pytest.mark.parametrize("span, size", [
    ("30s", "1s"), ("40min", "1min"), ("3h", "5min"), ("2D", "1h"), ("400D", "1D"),
])
def test_timeline_bin_size(span, size):
    assert charts._bin_size(pd.Timedelta(span)) == size


def test_cli(tmp_path, capsys):
    assert charts.main([str(SAMPLES / "conpot_sample.log"), "--out", str(tmp_path)]) == 0
    assert (tmp_path / "event_timeline.png").exists()
    assert charts.main([str(tmp_path / "nope.log"), "--out", str(tmp_path)]) == 1
