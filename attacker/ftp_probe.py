#!/usr/bin/env python3
"""
ftp_probe.py  —  FTP probe against our Conpot honeypot.

Conpot emulates an FTP control service (it answers USER/PASS/SYST/… but has no
real data channel, so PASV/LIST fail — that's expected). This probe opens the
control connection, logs in anonymously, and issues a few read-only control
commands so the honeypot logs an FTP session for the analysis side.

Target  : Conpot FTP service, published on <HOST>:2121/tcp
Library  : ftplib (Python standard library — no extra dependency)

Edit HOST below, then:  python ftp_probe.py
"""

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
VM_IP = "127.0.0.1"   # kept as VM_IP so attack.py can read one target from any probe
HOST = VM_IP
PORT = 2121           # host port published to Conpot's FTP (container 2121)
USER = "anonymous"
PASSWORD = "scanner@example.com"
TIMEOUT = 5

# ---------------------------------------------------------------------------
import ftplib


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def main():
    banner(f"FTP probe  ->  {HOST}:{PORT}  (user={USER})")

    ftp = ftplib.FTP()
    try:
        ftp.connect(HOST, PORT, timeout=TIMEOUT)
        print(f"[+] TCP connected to {HOST}:{PORT}")
        print(f"[+] banner: {ftp.getwelcome()}")
    except OSError as exc:
        print(f"[!] Could not open FTP control connection to {HOST}:{PORT}: {exc}")
        print("    Check: container up (docker ps), port 2121 published on 127.0.0.1.")
        return

    try:
        ftp.login(USER, PASSWORD)
        print(f"[+] login OK as {USER}")
    except ftplib.all_errors as exc:
        print(f"[-] login -> {exc}")

    # Read-only control commands. Conpot answers these even though it has no real
    # data channel; each one is logged as attacker FTP activity.
    for cmd in ("SYST", "PWD", "STAT", "HELP"):
        try:
            print(f"[+] {cmd:4} -> {ftp.sendcmd(cmd)!r}")
        except ftplib.all_errors as exc:
            print(f"[-] {cmd:4} -> {exc}")

    try:
        ftp.quit()
    except ftplib.all_errors:
        ftp.close()
    banner("Done. Check the container log (docker logs conpot) for the logged FTP session.")


if __name__ == "__main__":
    main()
