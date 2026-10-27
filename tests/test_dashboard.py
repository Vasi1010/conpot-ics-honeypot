from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from dashboard.data import load

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_logs"
APP = str(ROOT / "dashboard" / "app.py")

WRITE = ("2026-10-21 10:23:10,829 Modbus traffic from 10.0.0.9: "
         "{'request': b'0005000000060106000004d2', 'slave_id': 1, 'function_code': 6, 'response': b''}\n")


# --------------------------------------------------------------------------- data layer

def test_load_sample_kpis():
    snap = load(SAMPLES / "conpot_sample.log")
    assert snap.kpis == {"Total events": 40, "Unique source IPs": 4, "Write attempts": 3, "High-risk IPs": 2}
    assert not snap.gateway_warning


def test_load_docker_logs_triggers_gateway_warning():
    snap = load(SAMPLES / "docker_logs_sample.txt")
    assert snap.gateway_warning and snap.gateway_ips == ["172.17.0.1"]
    assert snap.gateway_share == pytest.approx(5 / 6)


def test_load_upload_bytes_utf16():
    snap = load(data=WRITE.encode("utf-16"), name="up.log")
    assert snap.source == "up.log" and snap.kpis["Write attempts"] == 1


@pytest.mark.parametrize("content", [None, "", "garbage\nmore garbage\n"])
def test_load_never_raises(tmp_path, content):
    log = tmp_path / "conpot.log"
    if content is not None:
        log.write_text(content)
    snap = load(log)
    assert snap.df.empty and snap.risk.empty
    assert snap.kpis == {"Total events": 0, "Unique source IPs": 0, "Write attempts": 0, "High-risk IPs": 0}
    assert snap.stats.file_missing == (content is None)


def test_filter_since_keeps_only_later_events():
    from dashboard.data import filter_since
    snap = load(SAMPLES / "conpot_sample.log")
    assert len(snap.df) == 40
    cutoff = snap.df["timestamp"].sort_values().iloc[20]
    fewer = filter_since(snap, cutoff)
    assert 0 < len(fewer.df) < len(snap.df)
    assert (fewer.df["timestamp"] > cutoff).all()
    assert fewer.kpis["Total events"] == len(fewer.df)
    assert filter_since(snap, None) is snap  # no baseline -> unchanged


# --------------------------------------------------------------------------- Streamlit app

def run_app(monkeypatch, log):
    monkeypatch.setenv("CONPOT_LOG", str(log))
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    assert not at.exception
    return at


def test_app_sample_log(monkeypatch):
    at = run_app(monkeypatch, SAMPLES / "conpot_sample.log")
    assert [m.label for m in at.metric] == ["Total events", "Unique source IPs", "Write attempts", "High-risk IPs"]
    assert [m.value for m in at.metric] == ["40", "4", "3", "2"]
    assert any("Write attempts" in e.value for e in at.error)
    assert not at.warning
    assert len(at.dataframe) >= 1


def test_app_docker_gateway_warning(monkeypatch):
    at = run_app(monkeypatch, SAMPLES / "docker_logs_sample.txt")
    assert any("Docker gateway" in w.value and "172.17.0.1" in w.value for w in at.warning)


def test_app_missing_log(monkeypatch, tmp_path):
    at = run_app(monkeypatch, tmp_path / "nope.log")
    assert any("Waiting for the log file" in w.value for w in at.warning)


def test_app_empty_log_then_traffic_arrives(monkeypatch, tmp_path):
    log = tmp_path / "conpot.log"
    log.write_text("")
    at = run_app(monkeypatch, log)
    assert any("No attacker events" in i.value for i in at.info)

    log.write_text(WRITE)  # the log grows while the dashboard is open
    at.run()
    assert not at.exception
    assert at.metric[0].value == "1" and at.metric[2].value == "1"


def test_app_bad_timezone_is_reported(monkeypatch):
    at = run_app(monkeypatch, SAMPLES / "conpot_sample.log")
    at.text_input(key="tz").set_value("Mars/Base").run()
    assert not at.exception
    assert any("Could not load the log" in e.value for e in at.error)
