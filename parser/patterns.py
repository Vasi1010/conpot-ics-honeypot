"""
Log-format definitions for conpot.log.

This is the file to edit when the real log arrives and some lines don't match.
Run the parser CLI on the real file first; it prints the lines it could not
match, so you know exactly which pattern to add or loosen:

    python -m parser logs/conpot.log

Everything protocol-specific about *meaning* (function codes, read vs write)
lives in classify.py; this file only knows how lines are *shaped*.
"""

import re

IP = r"(?:\d{1,3}\.){3}\d{1,3}"
UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

# --------------------------------------------------------------------------- line prefixes
# Stripped (in this order) before a line is handed to a format, so conpot.log,
# `docker logs conpot`, `docker logs -t conpot` and `docker compose logs` all
# look the same to the formats.

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# "conpot_1  | " / "conpot-1  | " from `docker compose logs`
COMPOSE_PREFIX_RE = re.compile(r"^[\w.-]+\s+\|\s?")
# "2026-10-21T04:53:10.609123456Z " from `docker logs -t`, only when Conpot's own
# timestamp follows it (Conpot's local time is the one we keep).
DOCKER_TS_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+(?=\d{4}-\d{2}-\d{2}[ T]\d)")

# --------------------------------------------------------------------------- text log

# Timestamp near the start of a line. Accepts Python logging's default
# "2026-10-21 10:23:10,609" as well as ISO-8601 ("2026-10-21T10:23:10.609Z"),
# and tolerates a short unknown prefix before it.
TIMESTAMP_RE = re.compile(
    r"^.{0,40}?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
)

# Optional log-level / logger-name tokens between the timestamp and the message,
# e.g. "INFO conpot.protocols.modbus.modbus_server: ". Stripped before matching.
PREFIX_RE = re.compile(r"^(?:\[?(?:DEBUG|INFO|WARNING|ERROR|CRITICAL)\]?\s+)?(?:[\w.]+:\s+)?")

SESSION_RE = re.compile(UUID)
ANY_IP_RE = re.compile(rf"(?<![\d.])({IP})(?![\d.])")


def _p(pattern):
    return re.compile(pattern.replace("{IP}", IP))


# (name, protocol, event, regex) -- tried in order against the message, first
# match wins. protocol=None means "take it from the (?P<proto>) group".
# Named groups the parser understands: ip, port, proto, payload, op, oid, version.
LINE_PATTERNS = [
    ("connect", None, "connect",
     _p(r"New (?P<proto>[\w/ ]+?) connection from \(?'?(?P<ip>{IP})'?(?:[:,] ?(?P<port>\d+))?")),
    ("modbus_traffic", "modbus", "request",
     _p(r"Modbus traffic from (?P<ip>{IP}): (?P<payload>.*)")),
    ("s7_traffic", "s7comm", "request",
     _p(r"S7(?:comm)? traffic from (?P<ip>{IP}): (?P<payload>.*)")),
    ("snmp_request", "snmp", "request",
     _p(r"SNMPv(?P<version>\S+) (?P<op>\w+) request from \('?(?P<ip>{IP})'?, ?(?P<port>\d+)\)\s*:\s*(?P<oid>[\d.]*)")),
    ("http_request", "http", "request",
     _p(r"(?P<version>HTTP/[\d.]+) (?P<op>[A-Z]+) request from \('?(?P<ip>{IP})'?, ?(?P<port>\d+)\)\s*:\s*(?P<payload>.*)")),
]

# Lines that are known and deliberately skipped: honeypot housekeeping, and
# server *responses* (we count the attacker's request, not our reply).
IGNORE_PATTERNS = [re.compile(p) for p in (
    r"^Starting Conpot",
    r"server started on",
    r"as external ip",
    r"client disconnected",
    r"\bresponse to\b",
    r"(?i)session (?:timed out|ended)",
    # Conpot 0.6.0 startup / configuration
    r"--force option specified",
    r"^Found and enabled \w+ protocol",
    r"^(?:Conpot \w+|IPMI BMC) initialized",
    r"^Class\s+\d+/0x[0-9a-fA-F]+, Instance",       # ENIP object table dump
    r"^Using default FS path",
    r"^Initializing Virtual File System",
    r"^Creating persistent data store",
    r"T?FTP Serving File System",
    r"^Starting TFTP server",
    r"^No proxy template found",
    r"^handle server PID",                           # ENIP server
    # Session bookkeeping. The attacker's activity is the connect/traffic line
    # next to each of these, so counting them would double-count it.
    r"^New \w+ session from",
    r"^Modbus response sent to",
    r"^Exception caught: Modbus Error",              # also shown as exception= in details
)]

# Known noise with no timestamp: Python logging's stderr copies of lines that
# are also logged with a timestamp ("WARNING:root:...", "ERROR:conpot....:"),
# and Conpot's VFS banner.
BARE_IGNORE_PATTERNS = [re.compile(p) for p in (
    r"^(?:DEBUG|INFO|WARNING|ERROR|CRITICAL):[\w.]+:",
    r"^\s*Please wait while the system copies",
)]

# --------------------------------------------------------------------------- JSON log

# Conpot's JSON logger (one JSON object per line). Each output field lists the
# keys to try, in order, so slightly different JSON shapes still work.
JSON_FIELDS = {
    "ts": ("timestamp", "@timestamp", "time"),
    "ip": ("src_ip", "remote_ip", "source_ip"),
    "port": ("src_port", "remote_port", "source_port"),
    "proto": ("data_type", "protocol"),
    "session_id": ("id", "session_id", "session"),
    "event_type": ("event_type", "type"),
}
JSON_EVENT_TYPES = {"NEW_CONNECTION": "connect", "CONNECTION_LOST": None}  # None -> ignore

# --------------------------------------------------------------------------- protocols / IPs

# Canonical protocol names. Keys are lowercase text seen in the log (or the
# JSON "data_type" field); values are what ends up in the `protocol` column.
PROTOCOL_ALIASES = {
    "modbus": "modbus",
    "s7": "s7comm",
    "s7comm": "s7comm",
    "snmp": "snmp",
    "http": "http",
    "bacnet": "bacnet",
    "ipmi": "ipmi",
    "enip": "enip",
    "ftp": "ftp",
    "tftp": "tftp",
    "guardian_ast": "guardian_ast",
    "kamstrup": "kamstrup",
}

# Docker bridge gateways: 172.17.0.1 (default bridge) and 172.18-31.0.1 (compose
# networks). When Conpot sees these as the source, Docker NAT hid the real attacker.
DOCKER_GATEWAY_RE = re.compile(r"^172\.(?:1[6-9]|2\d|3[01])\.0\.1$")
