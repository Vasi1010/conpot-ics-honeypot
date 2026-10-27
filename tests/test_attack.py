"""
Tests for scripts/attack.py — the visual attack console.

These never touch the network: they cover the safety gate, phase planning,
CLI parsing and the summary table. The one end-to-end check runs main()
against a public target and asserts it refuses before sending anything.
"""

import io

import pytest
from rich.console import Console

from scripts import attack


# --------------------------------------------------------------------------- safety gate

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.5.5.5", "10.0.0.9", "192.168.1.50", "172.16.3.4",
    "169.254.1.1", "100.64.0.1",
])
def test_lab_targets_allowed(ip):
    assert attack.is_lab_target(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "not-an-ip"])
def test_public_or_bad_targets_rejected(ip):
    assert not attack.is_lab_target(ip)


def test_check_target_accepts_loopback():
    ip, reason = attack.check_target("127.0.0.1")
    assert ip == "127.0.0.1" and reason is None


def test_check_target_refuses_public_ip():
    ip, reason = attack.check_target("8.8.8.8")
    assert ip is None and "refusing" in reason.lower()


def test_check_target_refuses_unresolvable_host():
    ip, reason = attack.check_target("no-such-host.invalid")
    assert ip is None and "resolve" in reason.lower()


# --------------------------------------------------------------------------- phase planning

def test_scan_runs_recon_and_fingerprint_only():
    assert attack.plan_stages("scan") == ["recon", "fingerprint"]


def test_read_and_write_are_single_stages():
    assert attack.plan_stages("read") == ["read"]
    assert attack.plan_stages("write") == ["write"]


def test_all_runs_the_full_chain():
    assert attack.plan_stages("all") == ["recon", "fingerprint", "read", "write"]


# --------------------------------------------------------------------------- CLI

def test_defaults():
    args = attack.build_parser().parse_args([])
    assert args.target == "127.0.0.1" and args.phase == "all" and args.delay == 0.5


def test_bad_phase_rejected():
    with pytest.raises(SystemExit):
        attack.build_parser().parse_args(["--phase", "nuke"])


def test_main_refuses_public_target_without_touching_network():
    # A public target must be refused with exit code 2, before any stage runs.
    assert attack.main(["--target", "8.8.8.8", "--phase", "all"]) == 2


def test_main_rejects_negative_delay():
    assert attack.main(["--target", "127.0.0.1", "--delay", "-1"]) == 2


# --------------------------------------------------------------------------- summary table

def test_summary_table_has_a_row_per_result():
    results = [
        attack.Result("Recon", "TCP 502 (Modbus)", "open", "connection accepted"),
        attack.Result("Write", "Modbus FC6 addr=0 value=1234", "accepted", "honeypot accepted"),
    ]
    table = attack.summary_table(results)
    assert table.row_count == 2


def test_run_against_closed_port_reports_results(monkeypatch):
    # Point recon at a definitely-closed local port and stub out Modbus so run()
    # exercises the recon path (connection refused) and the no-Modbus fallbacks,
    # fast and offline. StringIO sidesteps any console encoding on Windows.
    monkeypatch.setattr(attack, "PORTS", {"Modbus": 1})  # reserved port -> refused
    monkeypatch.setattr(attack, "_modbus_client", lambda host: None)
    console = Console(file=io.StringIO())
    results = attack.run("127.0.0.1", "all", 0.0, console)
    assert results  # produced Result rows for every stage without raising
    statuses = {r.status for r in results}
    assert statuses <= {"open", "closed", "accepted", "rejected", "no-response", "error"}
