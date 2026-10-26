#!/usr/bin/env python3
"""
attack.py  —  a small, visual attack console for our Conpot honeypot lab.

This drives *labelled* ICS traffic at a Conpot honeypot so the log-analysis
half of the project has something to show. It walks four phases, the same
scan -> read -> write chain the dashboard scores:

    Recon        TCP connect to 8080 (HTTP), 102 (S7comm), 502 (Modbus)
    Fingerprint  Modbus FC 43 (Read Device Identification) + HTTP GET /
    Read         Modbus FC 3 (Read Holding Registers) on a few addresses
    Write        Modbus FC 6 (Write Single Register)

Each request's result is coloured (accepted / rejected / open / closed /
no-response) and a summary table is printed at the end.

    python scripts/attack.py --target 127.0.0.1 --phase all

SAFETY
------
This is for our own lab honeypot only. The target must resolve to a loopback
(127.0.0.0/8) or a private LAN address (RFC 1918 / CGNAT / link-local). Any
public address is refused before a single packet is sent.
"""

import argparse
import ipaddress
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Ports we knock on, in the order Recon tries them.
PORTS = {"HTTP": 8080, "S7comm": 102, "Modbus": 502}
MODBUS_PORT = 502
HTTP_PORT = 8080
SLAVE = 1
READ_ADDRESSES = (0, 1, 10, 100)
WRITE_ADDRESS = 0
WRITE_VALUE = 1234
TIMEOUT = 3.0  # seconds per request; the honeypot is local, so this is generous

# The only addresses we'll ever probe: loopback and private LAN. Defined
# explicitly (rather than leaning on ipaddress.is_private, which varies by
# Python version for CGNAT) so the safety gate is stable. Mirrors the parser.
LAB_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "100.64.0.0/10")]

BANNER = r"""
   __ _ _| |_ __ _  ___| | __  ___ ___  _ __  ___  ___ | | ___
  / _` / __| __/ _` |/ __| |/ / / __/ _ \| '_ \/ __|/ _ \| |/ _ \
 | (_| \__ \ || (_| | (__|   < | (_| (_) | | | \__ \ (_) | |  __/
  \__,_|___/\__\__,_|\___|_|\_\ \___\___/|_| |_|___/\___/|_|\___|
"""

# phase name -> the stage functions it runs, in order.
# Matches the dashboard's Scan -> Read -> Write attack chain.
PHASE_PLANS = {
    "scan": ("recon", "fingerprint"),
    "read": ("read",),
    "write": ("write",),
    "all": ("recon", "fingerprint", "read", "write"),
}

# result status -> rich colour/style
STATUS_STYLE = {
    "open": "bold green",
    "closed": "dim",
    "accepted": "bold green",
    "rejected": "yellow",
    "no-response": "dim red",
    "error": "red",
}


@dataclass
class Result:
    phase: str
    label: str
    status: str
    detail: str = ""


# --------------------------------------------------------------------------- safety

def resolve_target(host):
    """Return the IP `host` resolves to (host may already be an IP). Raises on failure."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    return socket.gethostbyname(host)


def is_lab_target(ip_str):
    """True only for loopback / private-LAN addresses we're allowed to probe."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in LAB_NETS)


def check_target(host):
    """(ip, None) if `host` is an allowed lab target, else (None, reason)."""
    try:
        ip = resolve_target(host)
    except OSError as exc:
        return None, f"could not resolve {host!r}: {exc}"
    if not is_lab_target(ip):
        return None, (f"refusing to attack {host} ({ip}): not a loopback or private-LAN "
                      "address. This tool is only for our local lab honeypot.")
    return ip, None


# --------------------------------------------------------------------------- stages

def phase_recon(host, delay):
    results = []
    for name, port in PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            try:
                s.connect((host, port))
                results.append(Result("Recon", f"TCP {port} ({name})", "open", "connection accepted"))
            except OSError as exc:
                results.append(Result("Recon", f"TCP {port} ({name})", "closed", str(exc)))
        time.sleep(delay)
    return results


def phase_fingerprint(host, delay):
    results = [_modbus_device_id(host)]
    time.sleep(delay)
    results.append(_http_get(host, "/"))
    time.sleep(delay)
    return results


def phase_read(host, delay):
    results = []
    client = _modbus_client(host)
    if client is None:
        return [Result("Read", f"Modbus FC3 addr={a}", "no-response", "no Modbus connection")
                for a in READ_ADDRESSES]
    try:
        for addr in READ_ADDRESSES:
            results.append(_modbus_read(client, addr))
            time.sleep(delay)
    finally:
        client.close()
    return results


def phase_write(host, delay):
    client = _modbus_client(host)
    if client is None:
        return [Result("Write", f"Modbus FC6 addr={WRITE_ADDRESS}", "no-response", "no Modbus connection")]
    try:
        return [_modbus_write(client, WRITE_ADDRESS, WRITE_VALUE)]
    finally:
        client.close()


STAGES = {
    "recon": phase_recon,
    "fingerprint": phase_fingerprint,
    "read": phase_read,
    "write": phase_write,
}


# --------------------------------------------------------------------------- Modbus / HTTP helpers

def _modbus_client(host):
    """A connected pymodbus client, or None if the handshake fails."""
    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        return None
    client = ModbusTcpClient(host=host, port=MODBUS_PORT, timeout=TIMEOUT)
    try:
        if client.connect():
            return client
    except OSError:
        pass
    client.close()
    return None


def _modbus_device_id(host):
    client = _modbus_client(host)
    if client is None:
        return Result("Fingerprint", "Modbus FC43 (device id)", "no-response", "no Modbus connection")
    try:
        rr = client.read_device_information(slave=SLAVE)
        if getattr(rr, "isError", lambda: True)():
            return Result("Fingerprint", "Modbus FC43 (device id)", "rejected", str(rr))
        info = getattr(rr, "information", {}) or {}
        vendor = info.get(0)
        if isinstance(vendor, (bytes, bytearray)):
            vendor = vendor.decode("latin-1", "replace")
        return Result("Fingerprint", "Modbus FC43 (device id)", "accepted",
                      f"vendor={vendor}" if vendor else "device info returned")
    except Exception as exc:  # pymodbus raises a variety of errors for bad replies
        return Result("Fingerprint", "Modbus FC43 (device id)", "error", str(exc))
    finally:
        client.close()


def _http_get(host, path):
    url = f"http://{host}:{HTTP_PORT}{path}"
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:  # noqa: S310 (lab-only, validated host)
            server = resp.headers.get("Server", "")
            return Result("Fingerprint", f"HTTP GET {path}", "accepted",
                          f"{resp.status} {server}".strip())
    except urllib.error.HTTPError as exc:
        # An HTTP error status is still a reply from the honeypot's web server.
        return Result("Fingerprint", f"HTTP GET {path}", "accepted",
                      f"{exc.code} {exc.headers.get('Server', '')}".strip())
    except (urllib.error.URLError, OSError) as exc:
        return Result("Fingerprint", f"HTTP GET {path}", "no-response", str(exc))


def _modbus_read(client, addr):
    try:
        rr = client.read_holding_registers(address=addr, count=5, slave=SLAVE)
        if rr.isError():
            return Result("Read", f"Modbus FC3 addr={addr}", "rejected", str(rr))
        return Result("Read", f"Modbus FC3 addr={addr}", "accepted", f"registers={rr.registers}")
    except Exception as exc:
        return Result("Read", f"Modbus FC3 addr={addr}", "error", str(exc))


def _modbus_write(client, addr, value):
    try:
        wr = client.write_register(address=addr, value=value, slave=SLAVE)
        if wr.isError():
            return Result("Write", f"Modbus FC6 addr={addr} value={value}", "rejected", str(wr))
        return Result("Write", f"Modbus FC6 addr={addr} value={value}", "accepted",
                      "honeypot accepted the write")
    except Exception as exc:
        return Result("Write", f"Modbus FC6 addr={addr} value={value}", "error", str(exc))


# --------------------------------------------------------------------------- orchestration / output

def plan_stages(phase):
    """The ordered list of stage names for a --phase value."""
    return list(PHASE_PLANS[phase])


def _styled_status(status):
    return Text(status, style=STATUS_STYLE.get(status, ""))


def run(target, phase, delay, console):
    """Run the chosen phases against `target`, printing progress, and return all Results."""
    console.print(Text(BANNER, style="bold cyan"))
    console.print(f"Target [bold]{target}[/bold] · phase [bold]{phase}[/bold] · "
                  f"{delay:g}s between requests\n")

    all_results = []
    for stage in plan_stages(phase):
        # "line" spinner is plain ASCII, so it's safe on a classic cp1252 console.
        with console.status(f"[bold]{stage.capitalize()}[/bold] in progress...", spinner="line"):
            results = STAGES[stage](target, delay)
        all_results.extend(results)
        for r in results:
            console.print(Text("  • ", style="dim")
                          + Text(f"{r.label:<28} ", style="white")
                          + _styled_status(r.status)
                          + (Text(f"  {r.detail}", style="dim") if r.detail else Text("")))
    console.print()
    console.print(summary_table(all_results))
    return all_results


def summary_table(results):
    table = Table(title="Attack summary", title_style="bold", header_style="bold")
    table.add_column("Phase")
    table.add_column("Request")
    table.add_column("Result")
    table.add_column("Detail", overflow="fold")
    for r in results:
        table.add_row(r.phase, r.label, _styled_status(r.status), r.detail)
    return table


def build_parser():
    p = argparse.ArgumentParser(
        prog="attack.py",
        description="Visual attack console for the Conpot honeypot lab (loopback / private LAN only).")
    p.add_argument("--target", default="127.0.0.1", help="honeypot host or IP (default 127.0.0.1)")
    p.add_argument("--phase", choices=sorted(PHASE_PLANS), default="all",
                   help="scan (recon+fingerprint), read, write, or all (default all)")
    p.add_argument("--delay", type=float, default=0.5,
                   help="seconds to pause between requests (default 0.5)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    console = Console()

    if args.delay < 0:
        console.print("[red]--delay must not be negative.[/red]")
        return 2

    ip, reason = check_target(args.target)
    if ip is None:
        console.print(Panel(reason, title="Refused", border_style="red"))
        return 2

    run(ip, args.phase, args.delay, console)
    return 0


if __name__ == "__main__":
    sys.exit(main())
