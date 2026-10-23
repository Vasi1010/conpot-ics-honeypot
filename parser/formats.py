"""
Pluggable line formats.

Each format is a small class with two methods:

    sniff(line) -> bool               cheap check: is this line in my format?
    parse(line) -> dict | IGNORED | None

parse() returns a dict of raw fields
    ts, ip, port, proto, event, session_id, pattern, fields
which conpot_parser turns into a table row; IGNORED for known noise; or None if
the line is in this format but not understood (it gets counted as unparseable).

FORMATS is tried in order and the first format whose sniff() says yes owns the
line. To support a new log shape, write a class here and add it to FORMATS.
"""

import json

from . import patterns as P
from .classify import parse_payload

IGNORED = object()


class JsonFormat:
    """Conpot's JSON logger: one JSON object per line."""

    name = "json"

    def sniff(self, line):
        return line.lstrip().startswith("{")

    def parse(self, line):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None

        def pick(field):
            return next((obj[k] for k in P.JSON_FIELDS[field] if obj.get(k) is not None), None)

        ts, ip = pick("ts"), pick("ip")
        if ts is None or ip is None:
            return None
        event_type = pick("event_type")
        if event_type in P.JSON_EVENT_TYPES:
            event = P.JSON_EVENT_TYPES[event_type]
            if event is None:
                return IGNORED
        else:
            event = "request"

        fields = {"request": obj.get("request"), "response": obj.get("response")}
        if isinstance(obj.get("request"), dict):
            fields.update(obj["request"])
        return {"ts": str(ts), "ip": str(ip), "port": pick("port"),
                "proto": str(pick("proto") or ""), "event": event,
                "session_id": pick("session_id"), "pattern": "json", "fields": fields}


class TextFormat:
    """Conpot's text log (`default` template): '<timestamp> <message>', matched by regex."""

    name = "text"

    def sniff(self, line):
        return P.TIMESTAMP_RE.match(line) is not None

    def parse(self, line):
        m = P.TIMESTAMP_RE.match(line)
        if not m:
            return None
        message = P.PREFIX_RE.sub("", line[m.end():], count=1)
        if any(p.search(message) for p in P.IGNORE_PATTERNS):
            return IGNORED

        sid = P.SESSION_RE.search(message)
        sid = sid.group(0) if sid else None
        for name, protocol, event, regex in P.LINE_PATTERNS:
            hit = regex.search(message)
            if not hit:
                continue
            fields = {k: v for k, v in hit.groupdict().items() if v is not None}
            if "payload" in fields:
                fields.update(parse_payload(fields["payload"]))
            return {"ts": m.group("ts"), "ip": fields["ip"], "port": fields.get("port"),
                    "proto": protocol or fields.get("proto", ""), "event": event,
                    "session_id": sid, "pattern": name, "fields": fields}

        # Nothing matched. If the line still names an attacker IP, keep it as a
        # low-confidence "fallback" row so data isn't silently lost.
        ips = [ip for ip in P.ANY_IP_RE.findall(message) if ip != "0.0.0.0"]
        if not ips:
            return None
        return {"ts": m.group("ts"), "ip": ips[0], "port": None, "proto": message,
                "event": "request", "session_id": sid, "pattern": "fallback", "fields": {}}


class BareNoiseFormat:
    """Known noise lines that carry no timestamp (stderr warnings, banners)."""

    name = "bare_noise"

    def sniff(self, line):
        return any(p.search(line) for p in P.BARE_IGNORE_PATTERNS)

    def parse(self, line):
        return IGNORED


FORMATS = [JsonFormat(), TextFormat(), BareNoiseFormat()]
