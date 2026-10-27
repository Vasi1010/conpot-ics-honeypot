"""Parser tests against the realistic sample logs in sample_logs/."""

from pathlib import Path

import pandas as pd
import pytest

from parser import COLUMNS, ParseStats, parse_log

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"


@pytest.fixture(scope="module")
def text_df():
    stats = ParseStats()
    df = parse_log(SAMPLES / "conpot_sample.log", stats=stats)
    assert (stats.unparseable, stats.fallback) == (0, 0)
    return df


def test_sample_has_expected_shape(text_df):
    assert list(text_df.columns) == COLUMNS
    assert len(text_df) == 40
    assert set(text_df["protocol"]) == {"modbus", "s7comm", "snmp", "http"}
    assert set(text_df["src_ip"]) == {"198.51.100.77", "192.168.1.23", "203.0.113.45", "198.51.100.200"}
    assert text_df["timestamp"].is_monotonic_increasing
    assert text_df["timestamp"].notna().all()


def test_actions_per_attacker(text_df):
    """Each sample attacker exercises a different attack sequence for the detection step."""
    acts = text_df[text_df["action"] != "connect"].groupby("src_ip")["action"].agg(set)
    assert acts["198.51.100.77"] == {"scan"}                     # recon only
    assert {"scan", "read", "write"} <= acts["192.168.1.23"]     # scan -> read -> write
    assert {"read", "write"} <= acts["203.0.113.45"]             # (scan ->) read -> write
    assert acts["198.51.100.200"] == {"scan", "read"}  # scan -> read, no write


def test_modbus_write_is_decoded(text_df):
    write = text_df[(text_df["function_code"] == 6)].iloc[0]
    assert write["action"] == "write"
    assert write["request_type"] == "Write Single Register"
    assert write["details"] == "addr=0 value=1234"
    assert write["src_port"] == 51802  # inherited from the session's connect line


def test_modbus_exception_is_flagged(text_df):
    fc16 = text_df[text_df["function_code"] == 16].iloc[0]
    assert fc16["details"] == "addr=10 count=2 values=[0, 500] exception=2"


def test_connect_without_requests_is_a_port_probe(text_df):
    probes = text_df[text_df["request_type"] == "Connect only (port probe)"]
    assert len(probes) == 4
    assert (probes["action"] == "scan").all()


def test_s7_and_snmp_identification_are_scans(text_df):
    s7 = text_df[(text_df["protocol"] == "s7comm") & (text_df["event"] == "request")]
    assert list(s7["request_type"]) == ["Setup Communication", "Read SZL", "Read SZL"]
    assert list(s7["details"])[1:] == ["szl=0x001C (component identification)", "szl=0x0424 (CPU mode/status)"]
    assert (s7["action"] == "scan").all()
    assert (text_df.loc[text_df["protocol"] == "snmp", "action"] == "scan").all()


def test_http_methods(text_df):
    http = text_df[text_df["protocol"] == "http"]
    assert list(http["action"]) == ["scan", "scan", "scan", "write"]  # GET / and /index.html are scans
    assert http.iloc[-1]["details"] == "path=/index.html"


def test_json_log_matches_text_log(text_df):
    stats = ParseStats()
    json_df = parse_log(SAMPLES / "conpot_sample.jsonl", stats=stats)
    assert stats.unparseable == 0
    cols = ["timestamp", "src_ip", "protocol", "request_type", "action", "details"]
    same = text_df["protocol"].isin(["modbus", "s7comm"]) & text_df["src_ip"].isin(json_df["src_ip"])
    assert json_df[cols].reset_index(drop=True).equals(text_df.loc[same, cols].reset_index(drop=True))


def test_docker_logs_sample():
    stats = ParseStats()
    df = parse_log(SAMPLES / "docker_logs_sample.txt", stats=stats)
    # Warnings and the traceback are skipped and counted; the Conpot lines all parse.
    assert (stats.parsed, stats.ignored, stats.unparseable, stats.blank) == (6, 6, 5, 1)
    # Conpot's local time is used, not docker's UTC prefix.
    assert str(df.iloc[0]["timestamp"]) == "2026-10-22 11:01:10.100000+05:30"
    gw = df[df["src_ip"] == "172.17.0.1"]
    assert len(gw) == 5 and gw["is_docker_gateway"].all()
    assert gw["action"].tolist() == ["connect", "read", "write", "connect", "scan"]
    assert not df.loc[df["src_ip"] == "192.168.56.1", "is_docker_gateway"].any()


def test_conpot_060_real_log():
    """Anonymized excerpt of a real Conpot 0.6.0 `docker logs` capture."""
    stats = ParseStats()
    df = parse_log(SAMPLES / "conpot_0.6.0_real.log", tz="UTC", stats=stats)
    # Startup lines, stderr copies, session/response bookkeeping: all ignored, none unknown.
    assert (stats.parsed, stats.ignored, stats.unparseable, stats.fallback) == (4, 11, 0, 0)
    assert df["pattern"].tolist() == ["http_request", "connect", "modbus_traffic", "modbus_traffic"]
    assert df["action"].tolist() == ["scan", "connect", "scan", "read"]
    assert df.iloc[0]["details"] == "path=/favicon.ico"
    # 0.6.0 logs the response as a bare PDU (b'8302'), not with the MBAP header.
    assert df.iloc[3]["details"] == "addr=0 count=5 exception=2"
    assert (df["src_port"] == pd.Series([33620, 48510, 48510, 48510])).all()
