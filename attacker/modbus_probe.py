#!/usr/bin/env python3
"""
modbus_probe.py  —  Modbus/TCP probe against our Conpot honeypot.

Runs from the Windows laptop against the VM. It performs a set of standard
Modbus *reads* (coils, discrete inputs, holding registers, input registers)
and then attempts a single *write* to a holding register. Conpot logs every
one of these requests — that is the whole point: generate clean, labelled
traffic for the log-analysis half of the project.

Target  : Conpot Modbus service, exposed on the VM at TCP/502
Unit ID : slave=1  (Conpot's default Modbus slave/unit id)
Library : pymodbus==3.6.9   (API note: reads/writes take slave= as a keyword)

Edit VM_IP below, then:  python modbus_probe.py
"""

# ---------------------------------------------------------------------------
# CONFIG — change this to your VM's IP address (e.g. the VirtualBox bridged IP)
# ---------------------------------------------------------------------------
VM_IP = "127.0.0.1"      # 127.0.0.1 if NAT port-forwarding on this PC; else the VM's LAN IP
PORT = 502               # VM host port mapped to Conpot's Modbus (container 5020)
SLAVE = 1                # Modbus unit id Conpot answers on
TIMEOUT = 5              # seconds

# ---------------------------------------------------------------------------
from pymodbus.client import ModbusTcpClient


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def main():
    banner(f"Modbus/TCP probe  ->  {VM_IP}:{PORT}  (slave={SLAVE})")

    # In pymodbus 3.x the client is constructed with host/port and then
    # explicitly connected. connect() returns True on a successful TCP handshake.
    client = ModbusTcpClient(host=VM_IP, port=PORT, timeout=TIMEOUT)

    if not client.connect():
        print(f"[!] Could not open TCP connection to {VM_IP}:{PORT}")
        print("    Check: Docker container up (docker ps), port 502 published on 127.0.0.1.")
        return

    print(f"[+] TCP connected to {VM_IP}:{PORT}")

    # -- READS ---------------------------------------------------------------
    # Each call targets a starting address with a count. pymodbus 3.6.x expects
    # the unit/slave id as the `slave=` keyword. .isError() tells us whether the
    # honeypot returned a Modbus exception instead of data.

    # 1) Read coils (function code 1) — on/off outputs
    rr = client.read_coils(address=0, count=8, slave=SLAVE)
    if rr.isError():
        print(f"[-] read_coils          -> Modbus error: {rr}")
    else:
        print(f"[+] read_coils(0..7)    -> {rr.bits}")

    # 2) Read discrete inputs (function code 2) — read-only inputs
    rr = client.read_discrete_inputs(address=0, count=8, slave=SLAVE)
    if rr.isError():
        print(f"[-] read_discrete_inputs-> Modbus error: {rr}")
    else:
        print(f"[+] read_discrete(0..7) -> {rr.bits}")

    # 3) Read holding registers (function code 3) — 16-bit read/write registers
    rr = client.read_holding_registers(address=0, count=10, slave=SLAVE)
    if rr.isError():
        print(f"[-] read_holding_regs   -> Modbus error: {rr}")
    else:
        print(f"[+] read_holding(0..9)  -> {rr.registers}")

    # 4) Read input registers (function code 4) — 16-bit read-only registers
    rr = client.read_input_registers(address=0, count=10, slave=SLAVE)
    if rr.isError():
        print(f"[-] read_input_regs     -> Modbus error: {rr}")
    else:
        print(f"[+] read_input(0..9)    -> {rr.registers}")

    # -- WRITE ATTEMPT -------------------------------------------------------
    # Attempt to write value 1234 into holding register 0 (function code 6).
    # On a real PLC this would change a setpoint; against Conpot it is logged as
    # an attacker write attempt. Conpot may accept it, ignore it, or return an
    # exception depending on the template — any of those is a valid result to
    # record. We read the register back afterwards to show before/after.
    banner("Write attempt: holding register 0 <- 1234  (function code 6)")

    wr = client.write_register(address=0, value=1234, slave=SLAVE)
    if wr.isError():
        print(f"[-] write_register(0,1234) -> Modbus error: {wr}")
    else:
        print(f"[+] write_register(0,1234) -> OK ({wr})")

    # Read it back
    rr = client.read_holding_registers(address=0, count=1, slave=SLAVE)
    if not rr.isError():
        print(f"[+] read-back holding[0]   -> {rr.registers}")

    client.close()
    banner("Done. Check the container log (docker logs conpot) for the logged requests.")


if __name__ == "__main__":
    main()
