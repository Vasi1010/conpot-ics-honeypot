"""
Tests for the Attack Simulator (dashboard/simulator.py) and its tab.

Pure helpers (chain status, PLC state, colours, writer diffing, network SVG)
are tested directly. The attack runner is tested via the real refusal path and
one live run against localhost (closed ports -> fast, offline). App-level tests
stub the runner so no subprocess is spawned.
"""

from pathlib import Path

import pandas as pd
from streamlit.testing.v1 import AppTest

from dashboard import simulator
from dashboard.data import load

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_logs"
APP = str(ROOT / "dashboard" / "app.py")

RISK = load(SAMPLES / "conpot_sample.log").risk  # real risk table: has writers


# --------------------------------------------------------------------------- attack runner

def test_attack_command_shape():
    cmd = simulator.attack_command("127.0.0.1", "scan", 0.5, python="py", script="a.py")
    assert cmd == ["py", "a.py", "--target", "127.0.0.1", "--phase", "scan", "--delay", "0.5"]


def test_iter_refuses_public_target_without_spawning():
    out = list(simulator.iter_attack_output("8.8.8.8", "all"))
    assert len(out) == 1 and out[0].startswith("REFUSED")


def test_run_attack_against_localhost_produces_summary():
    # Nothing is listening on localhost in CI, so recon ports refuse instantly;
    # this exercises the real subprocess + UTF-8 round-trip of rich's output.
    text = simulator.run_attack("127.0.0.1", "scan", delay=0.0)
    assert "Attack summary" in text


# --------------------------------------------------------------------------- chain / status

def test_chain_status_for_a_writer():
    writer = simulator.writers(RISK)[0]
    chain = simulator.chain_status(RISK, writer)
    assert chain["write"] is True


def test_chain_status_unknown_ip_is_all_false():
    assert simulator.chain_status(RISK, "203.0.113.200") == {"scan": False, "read": False, "write": False}


def test_plc_state_and_colour_transitions():
    df = pd.DataFrame([
        {"src_ip": "10.0.0.1", "scans": 0, "reads": 0, "writes": 0, "write_flag": False},
        {"src_ip": "10.0.0.2", "scans": 3, "reads": 1, "writes": 0, "write_flag": False},
        {"src_ip": "10.0.0.3", "scans": 1, "reads": 1, "writes": 2, "write_flag": True},
    ])
    assert simulator.plc_state(df, "10.0.0.1") == "idle"
    assert simulator.plc_state(df, "10.0.0.2") == "busy"
    assert simulator.plc_state(df, "10.0.0.3") == "write"
    assert simulator.stage_colour(df, "10.0.0.1") == simulator.COLOUR_IDLE
    assert simulator.stage_colour(df, "10.0.0.2") == simulator.COLOUR_BUSY
    assert simulator.stage_colour(df, "10.0.0.3") == simulator.COLOUR_WRITE


def test_plc_state_empty_risk_is_idle():
    assert simulator.plc_state(pd.DataFrame(), None) == "idle"


def test_new_writers_only_reports_fresh_ones():
    assert simulator.new_writers(["a", "b", "c"], ["a"]) == ["b", "c"]
    assert simulator.new_writers(["a"], ["a", "b"]) == []
    assert simulator.new_writers(["a"], None) == ["a"]


def test_network_svg_uses_the_stage_colour():
    svg = simulator.network_svg(simulator.COLOUR_WRITE, attacker_label="10.0.0.9")
    assert simulator.COLOUR_WRITE in svg and "10.0.0.9" in svg and "<svg" in svg


# --------------------------------------------------------------------------- app tab

def run_app(monkeypatch, log):
    monkeypatch.setenv("CONPOT_LOG", str(log))
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    assert not at.exception
    return at


def test_app_has_both_tabs(monkeypatch):
    at = run_app(monkeypatch, SAMPLES / "conpot_sample.log")
    labels = [t.label for t in at.tabs]
    assert any("Dashboard" in lbl for lbl in labels)
    assert any("Attack Simulator" in lbl for lbl in labels)


def test_simulator_buttons_exist(monkeypatch):
    at = run_app(monkeypatch, SAMPLES / "conpot_sample.log")
    keys = {b.key for b in at.button}
    assert {"sim_btn_scan", "sim_btn_read", "sim_btn_write", "sim_btn_all"} <= keys


def test_clicking_scan_streams_stubbed_output(monkeypatch):
    # Stub the runner so the button click streams fake lines (no subprocess).
    monkeypatch.setattr(simulator, "iter_attack_output",
                        lambda *a, **k: iter(["=== attack ===", "Recon  TCP 502 open", "Attack summary"]))
    at = run_app(monkeypatch, SAMPLES / "conpot_sample.log")
    at.button(key="sim_btn_scan").click().run()
    assert not at.exception
    assert "Attack summary" in at.session_state["sim_output"]
