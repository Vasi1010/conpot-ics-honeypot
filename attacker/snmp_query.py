#!/usr/bin/env python3
"""
snmp_query.py  —  SNMP probe against our Conpot honeypot.

Conpot runs an SNMP agent (default community string "public", SNMP v2c) that
answers standard system OIDs with Siemens-like identity strings. This script
issues an SNMP GET for a few well-known OIDs and then a WALK of the system
subtree, so the honeypot logs the queries.

Target    : Conpot SNMP service, reachable on <VM_IP>:161/udp
Community  : public   (read-only, Conpot default)
Version    : SNMP v2c
Library    : pysnmp 7.x  (modern async API — works on Python 3.11/3.12/3.13)

----------------------------------------------------------------------------
pysnmp 7.x is async, so this script is written with asyncio. You do NOT need to
understand asyncio to run it — just `python snmp_query.py`.

If pysnmp ever gives you trouble, the Net-SNMP command-line tools do the same
thing without any Python at all:

    snmpget  -v2c -c public <VM_IP> 1.3.6.1.2.1.1.1.0
    snmpwalk -v2c -c public <VM_IP> 1.3.6.1.2.1.1

(Windows Net-SNMP binaries: https://sourceforge.net/projects/net-snmp/ ;
 on the Ubuntu VM it's `sudo apt install snmp`.)
----------------------------------------------------------------------------

Edit VM_IP below, then:  python snmp_query.py
"""

# ---------------------------------------------------------------------------
# CONFIG — set this to the address where the honeypot is reachable FROM THIS PC:
#   * "127.0.0.1"     if you used VirtualBox NAT port-forwarding on THIS machine
#   * the VM's LAN IP  (e.g. 192.168.10.x) if the VM uses a Bridged adapter
# ---------------------------------------------------------------------------
VM_IP = "127.0.0.1"       # <-- change if your VM is reached by a LAN IP
PORT = 161                # VM host port mapped to Conpot's SNMP (container 16100/udp)
COMMUNITY = "public"      # Conpot default read community
TIMEOUT = 3               # seconds
RETRIES = 1

# A few standard "system" OIDs worth asking for:
OIDS_TO_GET = {
    "1.3.6.1.2.1.1.1.0": "sysDescr   (device description)",
    "1.3.6.1.2.1.1.3.0": "sysUpTime  (uptime)",
    "1.3.6.1.2.1.1.4.0": "sysContact (contact)",
    "1.3.6.1.2.1.1.5.0": "sysName    (hostname)",
    "1.3.6.1.2.1.1.6.0": "sysLocation(location)",
}
SYSTEM_SUBTREE = "1.3.6.1.2.1.1"   # walk the whole 'system' group

# ---------------------------------------------------------------------------
import asyncio
import sys

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, get_cmd, walk_cmd,
)

# On Windows, use the selector event loop — it's the most reliable for the UDP
# sockets SNMP relies on.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def _community():
    # mpModel=1 selects SNMP v2c (mpModel=0 would be v1).
    return CommunityData(COMMUNITY, mpModel=1)


async def _target():
    # UdpTransportTarget.create(...) is a coroutine in pysnmp 7.x.
    return await UdpTransportTarget.create((VM_IP, PORT), timeout=TIMEOUT, retries=RETRIES)


async def snmp_get(engine, oid):
    """Issue a single SNMP GET for one OID; return 'OID = value' as a string."""
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        engine, _community(), await _target(), ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    if errorIndication:
        return f"ERROR: {errorIndication}"
    if errorStatus:
        return f"ERROR: {errorStatus.prettyPrint()}"
    return " = ".join(x.prettyPrint() for x in varBinds[0])


async def snmp_walk(engine, subtree):
    """Walk an OID subtree, printing each 'OID = value' it returns."""
    found = False
    async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
        engine, _community(), await _target(), ContextData(),
        ObjectType(ObjectIdentity(subtree)),
        lexicographicMode=False,   # stop at the end of the subtree
    ):
        if errorIndication:
            print(f"  ERROR: {errorIndication}")
            return
        if errorStatus:
            print(f"  ERROR: {errorStatus.prettyPrint()}")
            return
        for varBind in varBinds:
            found = True
            print("  " + " = ".join(x.prettyPrint() for x in varBind))
    if not found:
        print("  (no response — check community string / that SNMP is UDP-forwarded)")


async def main():
    banner(f"SNMP v2c probe  ->  {VM_IP}:{PORT}  (community='{COMMUNITY}')")
    engine = SnmpEngine()

    print("[*] SNMP GET on well-known system OIDs:\n")
    for oid, label in OIDS_TO_GET.items():
        print(f"  {label}")
        print(f"    {await snmp_get(engine, oid)}\n")

    banner(f"SNMP WALK of system subtree {SYSTEM_SUBTREE}")
    await snmp_walk(engine, SYSTEM_SUBTREE)

    banner("Done. Check the container log (docker logs conpot) for the logged SNMP requests.")


if __name__ == "__main__":
    asyncio.run(main())
