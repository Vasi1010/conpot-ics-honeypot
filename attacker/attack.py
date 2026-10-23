#!/usr/bin/env python3
"""
attack.py  —  one-shot combined attack against our Conpot honeypot.

Runs all five probes back-to-back, the same sequence we demo live:

    Modbus -> SNMP -> S7comm -> FTP -> BACnet   (connect, scan, read, write)

Conpot logs every request, and the analysis side then scores this source as
*High* risk (scan -> read -> write across multiple protocols).

This is a convenience wrapper: it imports and calls the existing probe scripts
(modbus_probe.py, snmp_query.py, s7_read.py, ftp_probe.py, bacnet_probe.py), so
there is no duplicated logic — edit the target/ports in those files and this
follows along.

Run it from the attacker/ folder with the venv active:

    python attack.py

It targets whatever the probes target (127.0.0.1 by default — the Conpot
container's ports published on localhost). Make sure the honeypot container is
running first:  docker start conpot
"""

import asyncio
import socket
import sys
import time

import modbus_probe
import snmp_query
import s7_read
import ftp_probe
import bacnet_probe

# Stay in sync with the Modbus probe's target so there is one source of truth.
HOST = modbus_probe.VM_IP
READY_PORT = modbus_probe.PORT   # if Modbus/502 answers, the honeypot is up
READY_TIMEOUT = 60               # seconds to wait for the honeypot after start
WARMUP_GRACE = 3                 # let Conpot's handlers finish starting


def rule(char="="):
    print(char * 60)


def wait_for_honeypot(host, port, timeout):
    """Block until the honeypot accepts a TCP connection, or time out."""
    print(f"[*] Waiting for the honeypot at {host}:{port} (up to {timeout}s) ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                print(f"[+] Honeypot is reachable on {host}:{port}.")
                return True
        except OSError:
            time.sleep(2)
    return False


def run_step(label, func):
    print(f"\n{'>' * 3} {label}")
    try:
        func()
    except Exception as exc:  # a probe blowing up should not abort the whole attack
        print(f"[!] {label} error: {exc}")


def main():
    rule()
    print(f"  COMBINED ICS HONEYPOT ATTACK  ->  {HOST}")
    print("  Modbus + SNMP + S7comm + FTP + BACnet   (scan -> read -> write)")
    rule()

    if not wait_for_honeypot(HOST, READY_PORT, READY_TIMEOUT):
        print(f"[!] Honeypot not reachable on {HOST}:{READY_PORT} after {READY_TIMEOUT}s.")
        print("[!] Is the container running?  docker start conpot  then re-run:  python attack.py")
        return 1

    # Right after the container starts, Conpot's protocol handlers can lag a few
    # seconds behind the open port, so give them a moment before we hit Modbus.
    time.sleep(WARMUP_GRACE)

    run_step("[1/5] MODBUS", modbus_probe.main)
    run_step("[2/5] SNMP", lambda: asyncio.run(snmp_query.main()))
    run_step("[3/5] S7comm", s7_read.main)
    run_step("[4/5] FTP", ftp_probe.main)
    run_step("[5/5] BACnet", bacnet_probe.main)

    rule()
    print("  ATTACK COMPLETE.")
    print("  Scanned, read and wrote across 5 protocols -> scored High risk.")
    print("  Capture the log:  docker logs conpot > ../logs/conpot.log 2>&1")
    rule()
    return 0


if __name__ == "__main__":
    sys.exit(main())
