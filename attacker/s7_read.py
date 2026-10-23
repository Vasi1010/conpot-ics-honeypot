#!/usr/bin/env python3
"""
s7_read.py  —  (optional) S7comm identification read against Conpot.

Conpot emulates a Siemens S7-200/300-style PLC speaking the S7comm protocol.
It does NOT expose real data blocks, but it DOES answer the "identification"
(SZL — System Status List) requests that tools like `get_cpu_info()` send.
So the realistic, reliable S7 probe is to connect and ask the PLC to identify
itself, which is exactly what a real recon tool (e.g. PLCScan) would do first.

Target  : Conpot S7comm service, exposed on the VM at TCP/102
Library  : python-snap7

----------------------------------------------------------------------------
NOTE (Windows): the modern python-snap7 wheel (we use 3.3.0) BUNDLES the native
snap7 library, so `pip install python-snap7` is all you need — no manual
snap7.dll to download or place on PATH. Verified to import on Python 3.13.
This script is still marked OPTIONAL because S7 is a bonus probe for the project.
----------------------------------------------------------------------------

Edit VM_IP below, then:  python s7_read.py
"""

# ---------------------------------------------------------------------------
# CONFIG — change this to your VM's IP address
# ---------------------------------------------------------------------------
VM_IP = "127.0.0.1"       # 127.0.0.1 if NAT port-forwarding on this PC; else the VM's LAN IP
PORT = 102                # VM host port mapped to Conpot's S7comm (container 10201)
RACK = 0                  # S7 rack number (0 is standard)
SLOT = 2                  # S7 slot number (2 is typical for S7-300; try 1 if needed)

# ---------------------------------------------------------------------------
import snap7


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def main():
    banner(f"S7comm identification probe  ->  {VM_IP}:{PORT}  (rack={RACK}, slot={SLOT})")

    client = snap7.client.Client()
    try:
        # connect(address, rack, slot, tcpport) — opens the S7 ISO-on-TCP session
        client.connect(VM_IP, RACK, SLOT, PORT)
    except Exception as exc:
        print(f"[!] Could not connect: {exc}")
        print("    Check: container up (docker ps), port 102 published on 127.0.0.1, try slot=1.")
        return

    if not client.get_connected():
        print("[!] Connect returned but session is not established.")
        return

    print(f"[+] S7 session established to {VM_IP}:{PORT}")

    # get_cpu_info() issues SZL identification reads — Conpot answers these with
    # its emulated Siemens module/serial/AS-name strings.
    try:
        info = client.get_cpu_info()
        print("\n[+] CPU / module identification (from the honeypot):")
        print(f"    Module type name : {info.ModuleTypeName}")
        print(f"    Serial number    : {info.SerialNumber}")
        print(f"    AS name          : {info.ASName}")
        print(f"    Module name      : {info.ModuleName}")
        print(f"    Copyright        : {info.Copyright}")
    except Exception as exc:
        print(f"[-] get_cpu_info() failed: {exc}")

    # get_cpu_state() asks whether the (emulated) CPU is RUN/STOP.
    try:
        print(f"\n[+] CPU state: {client.get_cpu_state()}")
    except Exception as exc:
        print(f"[-] get_cpu_state() failed: {exc}")

    client.disconnect()
    client.destroy()
    banner("Done. Check the container log (docker logs conpot) for the logged S7 requests.")


if __name__ == "__main__":
    main()
