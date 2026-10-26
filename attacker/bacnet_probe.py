#!/usr/bin/env python3
"""
bacnet_probe.py  —  BACnet/IP probe against our Conpot honeypot.

BACnet is the building-automation protocol (HVAC, lighting, access control).
A scanner's first move is a broadcast "Who-Is" to enumerate devices. This probe
sends one Who-Is to Conpot's BACnet/IP service; Conpot logs the connection as an
attacker contact (it may or may not reply with an I-Am — either way it's logged).

Target  : Conpot BACnet service, published on <HOST>:47808/udp
Library  : socket (Python standard library — no extra dependency)

Edit HOST below, then:  python bacnet_probe.py
"""

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
VM_IP = "127.0.0.1"
HOST = VM_IP
PORT = 47808          # host port published to Conpot's BACnet (container 47808/udp)
TIMEOUT = 4

# ---------------------------------------------------------------------------
import socket

# A standard BACnet/IP "Who-Is" (global broadcast), built from:
#   BVLC : 81 0b 00 0c          Original-Broadcast-NPDU, total length 12
#   NPDU : 01 20 ff ff 00 ff    version 1, dest = global broadcast (DNET 0xFFFF)
#   APDU : 10 08                unconfirmed-request, service 8 = Who-Is
WHO_IS = bytes([0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08])


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def main():
    banner(f"BACnet/IP Who-Is probe  ->  {HOST}:{PORT}/udp")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(WHO_IS, (HOST, PORT))
        print(f"[+] sent Who-Is ({len(WHO_IS)} bytes) to {HOST}:{PORT}/udp")
    except OSError as exc:
        print(f"[!] Could not send to {HOST}:{PORT}/udp: {exc}")
        print("    Check: container up (docker ps), port 47808/udp published on 127.0.0.1.")
        sock.close()
        return

    try:
        data, addr = sock.recvfrom(1500)
        print(f"[+] reply from {addr[0]}:{addr[1]} ({len(data)} bytes) -> {data[:32].hex()}")
    except socket.timeout:
        # No I-Am is fine — Conpot still logged the BACnet contact, which is the point.
        print("[*] no I-Am reply (expected); the honeypot still logged the contact.")
    finally:
        sock.close()
    banner("Done. Check the container log (docker logs conpot) for the logged BACnet contact.")


if __name__ == "__main__":
    main()
