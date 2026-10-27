from pathlib import Path

import pytest

from analysis.detection import RISK_COLUMNS, detect
from parser import parse_lines, parse_log

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"

SID = "5b1e2c7a-3f4d-4e8a-9c21-7d6f0a9b3e11"


def modbus(ts, fc, ip="1.2.3.4"):
    req = {1: "000100000006010100000008", 3: "000100000006010300000005",
           6: "0005000000060106000004d2", 43: "133700000005012b0e0100"}[fc]
    return (f"2026-10-21 {ts},000 Modbus traffic from {ip}: "
            f"{{'request': b'{req}', 'slave_id': 1, 'function_code': {fc}, 'response': b''}} ({SID})")


def snmp_sysdescr(ts, ip="1.2.3.4"):
    return f"2026-10-21 {ts},000 SNMPv2c Get request from ('{ip}', 61334): 1.3.6.1.2.1.1.1.0 "


def risk_of(lines, **kw):
    risk = detect(parse_lines(lines), **kw)
    assert len(risk) == 1
    return risk.iloc[0]


@pytest.mark.parametrize("lines, risk, sequence", [
    ([modbus("10:00:00", 43)], "Low", "scan"),
    ([modbus("10:00:00", 43), modbus("10:00:05", 3)], "Medium", "scan -> read"),
    ([modbus("10:00:00", 3)], "Medium", "read"),
    ([modbus("10:00:00", 3), modbus("10:00:05", 6)], "High", "read -> write"),
    ([modbus("10:00:00", 43), modbus("10:00:05", 1), modbus("10:00:09", 6)], "High", "scan -> read -> write"),
    ([modbus("10:00:00", 6)], "High", "write"),                      # any write is flagged
    ([modbus("10:00:00", 43), modbus("10:00:05", 6)], "High", "scan -> write"),
])
def test_sequences(lines, risk, sequence):
    row = risk_of(lines)
    assert (row["risk"], row["sequence"]) == (risk, sequence)
    assert row["write_flag"] == ("write" in sequence)


def test_multi_protocol_scan_within_window():
    # Two plain reads on different protocols, 30 s apart: the second protocol makes it a scan.
    lines = [modbus("10:00:00", 3),
             "2026-10-21 10:00:30,000 HTTP/1.1 GET request from ('1.2.3.4', 5000): "
             "('/data.xml', [], None). 16ac4191-a26a-40ae-844f-1574f037afc6"]
    row = risk_of(lines)
    assert row["multi_protocol_scan"] and row["sequence"] == "read -> scan"
    assert row["scans"] == 1 and row["protocols"] == "http, modbus"


def test_window_is_configurable():
    lines = [snmp_sysdescr("10:00:00"), modbus("10:01:30", 3)]       # 90 s apart
    assert not risk_of(lines)["multi_protocol_scan"]
    assert risk_of(lines, window_s=120)["multi_protocol_scan"]


def test_connect_only_traffic_is_info():
    sid = "a6a3a450-6513-470e-a69e-0d37f2a74de4"
    lines = [f"2026-10-21 10:00:00,000 New Modbus connection from 1.2.3.4:4000. ({sid})",
             f"2026-10-21 10:00:01,000 Modbus traffic from 1.2.3.4: {{'function_code': 99}} ({sid})"]
    row = risk_of(lines)
    assert (row["risk"], row["sequence"]) == ("Info", "")


def test_ips_are_separated_and_sorted_by_risk():
    risk = detect(parse_lines([modbus("10:00:00", 43, ip="9.9.9.9"),
                               modbus("10:00:01", 6, ip="8.8.8.8"),
                               modbus("10:00:02", 3, ip="7.7.7.7")]))
    assert list(risk["src_ip"]) == ["8.8.8.8", "7.7.7.7", "9.9.9.9"]
    assert list(risk["risk"]) == ["High", "Medium", "Low"]


def test_empty_input():
    risk = detect(parse_log(SAMPLES / "does_not_exist.log"))
    assert risk.empty and list(risk.columns) == RISK_COLUMNS


def test_sample_log_attackers():
    risk = detect(parse_log(SAMPLES / "conpot_sample.log")).set_index("src_ip")
    assert risk.loc["198.51.100.77", ["risk", "sequence"]].tolist() == ["Low", "scan"]
    assert risk.loc["198.51.100.200", ["risk", "sequence"]].tolist() == ["Medium", "scan -> read"]
    assert risk.loc["192.168.1.23", ["risk", "sequence"]].tolist() == ["High", "scan -> read -> write"]
    assert risk.loc["203.0.113.45", ["risk", "sequence"]].tolist() == ["High", "scan -> read -> write"]
    assert risk["write_flag"].sum() == 2


def test_docker_gateway_is_carried_through():
    risk = detect(parse_log(SAMPLES / "docker_logs_sample.txt")).set_index("src_ip")
    assert risk.loc["172.17.0.1", "is_docker_gateway"] and risk.loc["172.17.0.1", "risk"] == "High"
    assert not risk.loc["192.168.56.1", "is_docker_gateway"]
