"""
Turn a matched log line into meaning: request type, function code, and an
`action` that the analysis and attack-sequence detection work from.

    action   meaning
    ------   ---------------------------------------------------------------
    scan     discovery / fingerprinting: identification requests (Modbus 8/17/43,
             S7 SZL reads, SNMP system-group OIDs, HTTP GET of /, /index.html
             or /favicon.ico)
             and connections that never sent a request (port probes; set
             later in conpot_parser.py)
    read     reads process data
    write    changes PLC state (registers, coils, variables, setpoints, stop/start)
    connect  a TCP session opened (its requests are separate rows)
    other    anything not covered above

Edit the tables below to change how a request is classified.
"""

import ast
import json
import re
import struct

# Modbus function code -> (name, action)
MODBUS_FUNCTIONS = {
    1: ("Read Coils", "read"),
    2: ("Read Discrete Inputs", "read"),
    3: ("Read Holding Registers", "read"),
    4: ("Read Input Registers", "read"),
    5: ("Write Single Coil", "write"),
    6: ("Write Single Register", "write"),
    7: ("Read Exception Status", "read"),
    8: ("Diagnostics", "scan"),
    11: ("Get Comm Event Counter", "read"),
    12: ("Get Comm Event Log", "read"),
    15: ("Write Multiple Coils", "write"),
    16: ("Write Multiple Registers", "write"),
    17: ("Report Server ID", "scan"),
    20: ("Read File Record", "read"),
    21: ("Write File Record", "write"),
    22: ("Mask Write Register", "write"),
    23: ("Read/Write Multiple Registers", "write"),
    24: ("Read FIFO Queue", "read"),
    43: ("Read Device Identification", "scan"),
}

# S7comm "Job" function byte -> (name, action)
S7_JOB_FUNCTIONS = {
    0xF0: ("Setup Communication", "scan"),
    0x04: ("Read Variable", "read"),
    0x05: ("Write Variable", "write"),
    0x1A: ("Request Download", "write"),
    0x1B: ("Download Block", "write"),
    0x1C: ("Download Ended", "write"),
    0x1D: ("Start Upload", "read"),
    0x1E: ("Upload Block", "read"),
    0x1F: ("End Upload", "read"),
    0x28: ("PI Service (PLC start/control)", "write"),
    0x29: ("PLC Stop", "write"),
}

# S7comm "Userdata" (function group, subfunction) -> (name, action)
S7_USERDATA_FUNCTIONS = {
    (4, 1): ("Read SZL", "scan"),
    (3, 1): ("List Blocks", "scan"),
    (3, 2): ("List Blocks of Type", "scan"),
    (3, 3): ("Get Block Info", "scan"),
    (7, 1): ("Read Clock", "read"),
    (7, 2): ("Set Clock", "write"),
}

SZL_NAMES = {
    0x0011: "module identification",
    0x001C: "component identification",
    0x0424: "CPU mode/status",
}

SNMP_SYSTEM_GROUP = "1.3.6.1.2.1.1"   # sysDescr, sysName, ... = device fingerprinting
HTTP_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Fetching the landing page is what scanners (zgrab, masscan banners, Shodan) do;
# the favicon is a common web-server fingerprint (e.g. Shodan's favicon hash).
HTTP_SCAN_PATHS = {"/", "/index.html", "/favicon.ico"}


def classify(protocol, event, fields):
    """Return dict(request_type, function_code, action, details) for one event."""
    if event == "connect":
        return _result("Connect", None, "connect")
    handler = {"modbus": _modbus, "s7comm": _s7, "snmp": _snmp, "http": _http}.get(protocol)
    if handler:
        result = handler(fields)
        if result:
            return result
    return _result(fields.get("op") or "Unknown request", None, "other")


def _result(request_type, function_code, action, details=""):
    return {"request_type": request_type, "function_code": function_code,
            "action": action, "details": details}


# --------------------------------------------------------------------------- Modbus

def _modbus(fields):
    req = to_bytes(fields.get("request"))
    fc = _int(fields.get("function_code"))
    if fc is None and req and len(req) >= 8:
        fc = req[7]  # MBAP header is 7 bytes; the function code follows it
    if fc is None:
        return None
    name, action = MODBUS_FUNCTIONS.get(fc, (f"Function {fc}", "other"))

    details = []
    data = req[8:] if req and len(req) >= 8 else b""
    if fc in (1, 2, 3, 4, 15, 16, 23) and len(data) >= 4:
        addr, count = struct.unpack(">HH", data[:4])
        details.append(f"addr={addr} count={count}")
        if fc == 16 and len(data) >= 5 + 2 * count:
            values = struct.unpack(f">{count}H", data[5:5 + 2 * count])
            details.append(f"values={list(values)}")
    elif fc in (5, 6) and len(data) >= 4:
        addr, value = struct.unpack(">HH", data[:4])
        details.append(f"addr={addr} value={value}")

    # The response is logged with its MBAP header, or (Conpot 0.6.0) as a bare
    # PDU like b'8302'. Either way an exception reply is fc|0x80 + code.
    resp = to_bytes(fields.get("response")) or b""
    pdu = resp[7:] if len(resp) >= 9 and resp[7] in (fc, fc | 0x80) else resp
    if len(pdu) >= 2 and pdu[0] == fc | 0x80:
        details.append(f"exception={pdu[1]}")  # honeypot rejected the request
    return _result(name, fc, action, " ".join(details))


# --------------------------------------------------------------------------- S7comm

def _s7(fields):
    req = to_bytes(fields.get("request"))
    fc = _int(fields.get("function_code") or fields.get("function"))
    if req and len(req) >= 7:
        cotp_type = req[5]
        if cotp_type == 0xE0:
            return _result("COTP Connection Request", None, "scan")
        s7 = req[5 + req[4]:]  # skip TPKT (4 bytes) + COTP (1 + length indicator)
        if len(s7) >= 10 and s7[0] == 0x32:
            rosctr, params = s7[1], s7[10:]
            if rosctr == 1 and params:
                fc = params[0]
            elif rosctr == 7 and len(params) >= 7:
                group, sub = params[5] & 0x0F, params[6]
                name, action = S7_USERDATA_FUNCTIONS.get(
                    (group, sub), (f"Userdata group {group} sub {sub}", "other"))
                details = ""
                param_len = struct.unpack(">H", s7[6:8])[0]
                data = params[param_len:]
                if (group, sub) == (4, 1) and len(data) >= 6:
                    szl = struct.unpack(">H", data[4:6])[0]
                    details = f"szl=0x{szl:04X} ({SZL_NAMES.get(szl, 'unknown')})"
                return _result(name, None, action, details)
    if fc is not None:
        name, action = S7_JOB_FUNCTIONS.get(fc, (f"Function 0x{fc:02X}", "other"))
        return _result(name, fc, action)
    return None


# --------------------------------------------------------------------------- SNMP / HTTP

def _snmp(fields):
    op = fields.get("op") or "Request"
    oid = fields.get("oid") or ""
    if op.lower().startswith("set"):
        action = "write"
    elif oid == SNMP_SYSTEM_GROUP or oid.startswith(SNMP_SYSTEM_GROUP + "."):
        action = "scan"
    else:
        action = "read"
    return _result(f"SNMP {op}", None, action, f"oid={oid}" if oid else "")


_HTTP_PATH_RE = re.compile(r"'(?:[A-Z]+ )?(/[^'\s]*)")


def _http(fields):
    method = (fields.get("op") or "").upper()
    if not method:
        return None
    m = _HTTP_PATH_RE.search(str(fields.get("payload") or fields.get("request") or ""))
    path = m.group(1) if m else ""
    if method in HTTP_WRITE_METHODS:
        action = "write"
    elif method in ("GET", "HEAD") and path in HTTP_SCAN_PATHS:
        action = "scan"
    else:
        action = "read"
    return _result(f"HTTP {method}", None, action, f"path={path}" if path else "")


# --------------------------------------------------------------------------- helpers

def parse_payload(text):
    """Best-effort parse of the "{...}" blob Conpot logs after 'traffic from IP:'."""
    text = (text or "").strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        blob = text[start:end + 1]
        for loader in (ast.literal_eval, json.loads):
            try:
                value = loader(blob)
                if isinstance(value, dict):
                    return value
            except (ValueError, SyntaxError):
                pass
    # Fallback: scrape key=value / 'key': value pairs out of whatever is there.
    fields = {}
    for key, value in re.findall(r"'?(\w+)'?\s*[:=]\s*b?'?([\w.]+)'?", text):
        fields.setdefault(key, value)
    return fields


def to_bytes(value):
    """Hex in any of the shapes Conpot uses (b'0a0b', '0a0b', "b'0a0b'") -> bytes."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    value = str(value).strip()
    if value[:2] in ("b'", 'b"'):
        value = value[2:-1]
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
