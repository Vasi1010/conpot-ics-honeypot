"""
Tests for the "Live from Docker" dashboard source.

docker_logs() shells out to `docker logs <container>`; these fake the
subprocess so the tests never need a real Docker daemon, and one app-level
test drives the sidebar radio to confirm the graceful fallback renders.
"""

import subprocess
from pathlib import Path

from streamlit.testing.v1 import AppTest

from dashboard import data

ROOT = Path(__file__).resolve().parent.parent
APP = str(ROOT / "dashboard" / "app.py")

SAMPLE = ("2026-10-21 10:23:10,829 Modbus traffic from 10.0.0.9: "
          "{'request': b'0005000000060106000004d2', 'slave_id': 1, 'function_code': 6, 'response': b''}\n")


class FakeProc:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


# --------------------------------------------------------------------------- docker_logs

def test_docker_missing_binary(monkeypatch):
    monkeypatch.setattr(data.shutil, "which", lambda _: None)
    out, err = data.docker_logs("conpot")
    assert out == b"" and "not found" in err.lower()


def test_docker_logs_success_combines_streams(monkeypatch):
    monkeypatch.setattr(data.shutil, "which", lambda _: "/usr/bin/docker")
    # Conpot writes to stderr; make sure we still pick those lines up.
    monkeypatch.setattr(data.subprocess, "run",
                        lambda *a, **k: FakeProc(0, stdout=b"", stderr=SAMPLE.encode()))
    out, err = data.docker_logs("conpot")
    assert err is None and b"Modbus traffic" in out


def test_docker_logs_no_such_container(monkeypatch):
    monkeypatch.setattr(data.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(data.subprocess, "run",
                        lambda *a, **k: FakeProc(1, stderr=b"Error: No such container: conpot"))
    out, err = data.docker_logs("conpot")
    assert out == b"" and "No such container" in err


def test_docker_logs_timeout(monkeypatch):
    monkeypatch.setattr(data.shutil, "which", lambda _: "/usr/bin/docker")

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=10)

    monkeypatch.setattr(data.subprocess, "run", boom)
    out, err = data.docker_logs("conpot", timeout=10)
    assert out == b"" and "timed out" in err


# --------------------------------------------------------------------------- load_docker

def test_load_docker_parses_live_output(monkeypatch):
    monkeypatch.setattr(data, "docker_logs", lambda c, t=10: (SAMPLE.encode(), None))
    snap = data.load_docker("conpot")
    assert snap.docker_error is None
    assert snap.kpis["Write attempts"] == 1
    assert "docker logs conpot" in snap.source


def test_load_docker_surfaces_error_without_raising(monkeypatch):
    monkeypatch.setattr(data, "docker_logs", lambda c, t=10: (b"", "Docker CLI not found on PATH."))
    snap = data.load_docker("conpot")
    assert snap.docker_error == "Docker CLI not found on PATH."
    assert snap.df.empty  # empty, but no exception


# --------------------------------------------------------------------------- app fallback

def test_app_docker_source_falls_back_gracefully(monkeypatch):
    # Simulate Docker being unavailable and confirm the app warns instead of crashing.
    monkeypatch.setattr(data, "docker_logs", lambda c, t=10: (b"", "Docker daemon is not running."))
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    at.radio[0].set_value("Live from Docker").run()
    assert not at.exception
    assert any("Docker daemon is not running" in w.value for w in at.warning)


def test_app_docker_source_shows_live_events(monkeypatch):
    monkeypatch.setattr(data, "docker_logs", lambda c, t=10: (SAMPLE.encode(), None))
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    at.radio[0].set_value("Live from Docker").run()
    assert not at.exception
    assert at.metric[0].value == "1"  # one event parsed from the live logs
