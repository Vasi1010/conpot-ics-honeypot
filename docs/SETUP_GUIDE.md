# Conpot Honeypot — Full Setup & Attack Guide (Docker)

A numbered, copy-paste walkthrough to stand up the Conpot ICS/PLC honeypot in
**Docker Desktop on this Windows laptop** and probe it from the same laptop.
Written so it can be reproduced from scratch for a viva. **Run every command
exactly as shown.** Commands are labelled with **where** to run them:

- 🪟 **[Laptop]** = type it in Windows **PowerShell** on this laptop
- 🐳 **[Docker Desktop]** = do it in the Docker Desktop app window

Network design: Conpot runs inside a Docker container; Docker **publishes** its
ICS ports to the laptop's loopback, so from the laptop you always attack
**`127.0.0.1`**. No VM, no VirtualBox, no port-forward rules.

```
 [Laptop] 127.0.0.1:502  ──Docker -p 127.0.0.1:502:5020──▶  [container] :5020  Conpot Modbus
```

> **Moved off the VM.** An earlier version of this project ran Conpot in Docker
> *inside* an Ubuntu VirtualBox VM. Docker Desktop now works on the laptop, so the
> honeypot runs directly here — simpler, faster, nothing to boot. The old VM path
> is retired. For the big picture, the file-by-file repo map, and the analysis
> pipeline, see **`docs/PROJECT_WALKTHROUGH.md`**; this guide is the detailed
> *install + run the honeypot + probe it* reference.

---

## What to download / install (shopping list)

| Where | Software | How to get it | Needed? |
|-------|----------|---------------|---------|
| This laptop | **Docker Desktop** (Windows) | <https://www.docker.com/products/docker-desktop/> | Yes — install first (Part 0). |
| This laptop | **Conpot image** | built from the repo `Dockerfile` with `docker build` (Part A) — extends `honeynet/conpot` with a custom template | Yes |
| This laptop | **Python 3.x** | <https://www.python.org/downloads/> (tick "Add to PATH") | Already installed (3.13). |
| This laptop | **Probe deps** (pymodbus, pysnmp, snap7) | `pip install -r requirements.txt` in `attacker\` (Part C) | Yes |
| This laptop | **Analysis deps** (pandas, matplotlib, streamlit) | `pip install -r requirements.txt` at the repo root | For the analysis side (see PROJECT_WALKTHROUGH.md) |
| This laptop | **Nmap** (optional, for verifying) | <https://nmap.org/download.html> | Optional |
| This laptop | **Net-SNMP** (only if pysnmp fails) | <https://sourceforge.net/projects/net-snmp/files/> | Fallback only |

Nothing here needs a specific old version. The one trap we already hit and fixed:
the SNMP library **must be the modern pysnmp** (`attacker/requirements.txt` pins 7.x) —
the old pysnmp 4.4 is broken on Python 3.12+.

---

## Part 0 — Install Docker Desktop (on this laptop)

0.1 🪟 **[Laptop]** Download Docker Desktop for Windows from
    <https://www.docker.com/products/docker-desktop/> and run the installer with
    the defaults (it enables the WSL2 backend). Reboot if it asks you to.

0.2 🐳 **[Docker Desktop]** Launch Docker Desktop and wait until the whale icon in
    the system tray is steady and the app says **"Engine running"**.

0.3 🪟 **[Laptop]** Confirm the engine answers (prints client + server versions):
    ```powershell
    docker version
    ```
    > If this says the daemon isn't running, open Docker Desktop and wait for
    > "Engine running", then retry. Every command below is plain `docker ...` in
    > PowerShell — no `sudo`, because Docker Desktop runs the engine for you.

---

## Part A — Build & run Conpot in Docker

This project ships a **custom Conpot template** (`conpot_template/`, baked into the image
by the repo `Dockerfile`) so the Modbus slave returns realistic process data — a small
pumping/water-treatment station — instead of `IllegalAddress`. Build the image, then run it.

1. 🪟 **[Laptop]** Build the image from the repo root (pulls `honeynet/conpot` the first
   time, then layers the custom template on top):
   ```powershell
   docker build -t conpot-ics:latest .
   ```

2. 🪟 **[Laptop]** Start Conpot **detached**, named `conpot`, publishing the
   container's internal ports (8800/10201/5020/16100) to the laptop's ICS ports
   on **`127.0.0.1`**:
   ```powershell
   docker run -d --name conpot --restart unless-stopped `
     -p 127.0.0.1:502:5020/tcp `
     -p 127.0.0.1:102:10201/tcp `
     -p 127.0.0.1:161:16100/udp `
     -p 127.0.0.1:8080:8800/tcp `
     -p 127.0.0.1:2121:2121/tcp `
     -p 127.0.0.1:47808:47808/udp `
     conpot-ics:latest
   ```
   | Laptop (127.0.0.1) port | Container port | Service |
   |-------------------------|----------------|---------|
   | 502                     | 5020           | Modbus  |
   | 102                     | 10201          | S7comm  |
   | 161/udp                 | 16100/udp      | SNMP    |
   | 8080                    | 8800           | HTTP    |
   | 2121                    | 2121           | FTP     |
   | 47808/udp               | 47808/udp      | BACnet  |

   > **Why 8080 for HTTP?** This laptop already has something on port 80 (another
   > project's container), so we map HTTP to **8080**. The probes don't use HTTP,
   > so this only matters for the browser check in Part B — adjust if yours differs.
   >
   > **Why high container ports (5020 etc.)?** The base honeynet/conpot image runs Conpot
   > as a non-root user, so it binds high ports inside the container. `-p` maps them
   > down to the familiar 502/102/161 on the laptop.
   >
   > `--restart unless-stopped` makes the container come back automatically when
   > Docker Desktop starts (e.g. after a reboot). Start it by hand any time with
   > `docker start conpot`.

3. 🪟 **[Laptop]** Check the container is running:
   ```powershell
   docker ps
   ```
   You should see a `conpot` row with `Up ...` and the mappings reading
   **`127.0.0.1:502->5020/tcp`** etc.

4. 🪟 **[Laptop]** Watch the honeypot's live log (Ctrl-C stops *watching*, not the
   container):
   ```powershell
   docker logs -f conpot
   ```
   Confirm it started its handlers — you'll see lines like
   `Modbus server started on: ('0.0.0.0', 5020)`, and the same for S7Comm (10201),
   HTTP (8800) and SNMP (16100).

---

## Part B — Verify from the laptop (ports, browser, optional Nmap)

5. 🪟 **[Laptop]** Confirm the published TCP ports answer:
   ```powershell
   foreach ($p in 502,102,8080) { Test-NetConnection 127.0.0.1 -Port $p | Select-Object RemotePort, TcpTestSucceeded }
   ```
   Three `TcpTestSucceeded : True` = the honeypot is reachable.

6. 🪟 **[Laptop]** Open the honeypot's fake device web page in a browser:
   ```
   http://127.0.0.1:8080
   ```
   You should see Conpot's emulated ICS device page (Siemens-style).

7. 🪟 **[Laptop]** *(Optional)* Nmap scan with ICS scripts. Install Nmap from
   <https://nmap.org/download.html> first, then:
   ```powershell
   nmap -sV -p 502,102,8080 127.0.0.1
   nmap -sU -p 161 --script snmp-info 127.0.0.1
   nmap -p 502 --script modbus-discover 127.0.0.1
   nmap -p 102 --script s7-info 127.0.0.1
   ```

---

## Part C — Install the attacker scripts (laptop)

8. 🪟 **[Laptop]** Go to the project's attacker folder:
   ```powershell
   cd C:\Users\wahee\honeypot\attacker
   ```

9. 🪟 **[Laptop]** Create and activate a Python virtual environment:
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```
   > If PowerShell blocks the activation script, run once:
   > `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` then try again.

10. 🪟 **[Laptop]** Install the dependencies:
    ```powershell
    pip install -r requirements.txt
    ```

> This is the **attacker** venv. The analysis/dashboard side uses a **separate**
> venv at the repo root — don't mix them. See `docs/PROJECT_WALKTHROUGH.md`.

---

## Part D — Run the probes

The scripts already target `127.0.0.1` (the published ports). Keep the
`docker logs -f conpot` window visible so you can watch requests land.

11. 🪟 **[Laptop]** **Easiest — all five at once** (waits for the honeypot, then
    runs Modbus → SNMP → S7comm → FTP → BACnet):
    ```powershell
    python attack.py
    ```

    > There's also a second, coloured **terminal console** at `scripts/attack.py` (run from
    > the repo root: `python scripts/attack.py --phase all`). It walks Recon → Fingerprint →
    > Read → Write with a live summary, refuses any non-loopback/private target, and is what
    > the dashboard's **Attack Simulator** tab drives.

    Or run them **individually**:

12. 🪟 **[Laptop]** Modbus — reads (coils/inputs/registers) + a write attempt:
    ```powershell
    python modbus_probe.py
    ```
    > With the custom template, slave 1 returns **real values**: coils (pump/valve
    > states), discrete inputs (status contacts), holding registers (setpoints, e.g.
    > `[1480, 1465, 85, 20, 650, 0, 500, 0, ...]`) and input registers (sensors, e.g.
    > `[412, 538, 1260, 236, 74, ...]`), and the **write to holding register 0 is
    > accepted** (read-back shows `1234`) — a realistic tamper. (On the *stock* template
    > these all return `IllegalAddress`, which is also fine — just less convincing.)

13. 🪟 **[Laptop]** SNMP — GET on system OIDs + a WALK (community `public`):
    ```powershell
    python snmp_query.py
    ```
    > Returns the fake Siemens identity (`Siemens, SIMATIC, S7-200` / `CP 443-1 EX40`).
    > If pysnmp ever misbehaves, the no-Python fallback is Net-SNMP:
    > `snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.2.1.1`

14. 🪟 **[Laptop]** *(Optional)* S7comm identification read:
    ```powershell
    python s7_read.py
    ```
    > The session establishes and is logged; `get_cpu_info()` then erroring out is
    > a known Conpot/snap7 mismatch, not a failure. S7 is the bonus probe —
    > Modbus + SNMP already demonstrate the honeypot.

    *Also available, run the same way* — more protocol breadth in the capture:
    ```powershell
    python ftp_probe.py       # FTP: anonymous control session (SYST/PWD/STAT/HELP)
    python bacnet_probe.py    # BACnet/IP: a broadcast Who-Is
    ```
    > Both use only the Python standard library. They need the FTP (2121) and BACnet
    > (47808/udp) ports published — already in the Part A run command.

---

## Part E — Produce the clean `conpot.log`

15. 🪟 **[Laptop]** After running the probes, dump the honeypot's full log straight
    into the project (no VM transfer needed — it's all local now):
    ```powershell
    cd C:\Users\wahee\honeypot
    docker logs conpot > logs\conpot.log 2>&1
    ```

16. 🪟 **[Laptop]** Have a quick look — it should contain the Modbus/SNMP/S7
    requests you just sent, from source `172.17.0.1` (the Docker bridge gateway):
    ```powershell
    docker logs --tail 40 conpot
    ```

17. **Don't commit `conpot.log`.** It can contain the honeypot's public IP
    ("Fetched <ip> as external ip"), and `.gitignore` excludes `logs/*.log` for
    that reason. If a real excerpt is useful for tests, anonymize it (replace
    public IPs with documentation addresses like `203.0.113.10`) and put it in
    `sample_logs/`.

> From here, the analysis side (parse → risk score → charts → dashboard) takes
> over. Those steps, the repo map and the two-venv rule are in
> **`docs/PROJECT_WALKTHROUGH.md`** (Section 4 onward).

---

## Managing the container

- Stop:    🪟 `docker stop conpot`
- Start:   🪟 `docker start conpot`
- Restart (fresh session/log): 🪟 `docker restart conpot`
- Remove:  🪟 `docker rm -f conpot`  (then re-run Part A step 2 to recreate)

---

## Troubleshooting

| # | Symptom | Likely cause & fix |
|---|---------|--------------------|
| T1 | `docker version` says the daemon isn't running | Open **Docker Desktop** and wait for "Engine running", then retry. |
| T2 | `Test-NetConnection` = False / scripts time out | Container not up. `docker ps`; if missing, `docker start conpot` (or recreate with Part A step 2). It can lag a couple of seconds after start. |
| T3 | Browser `127.0.0.1:8080` won't load | HTTP not published, or host 8080 also busy — change the host port in the `-p ...:8800` mapping (recreate the container) and in the URL. |
| T4 | `docker ps` shows no `conpot` | Container exited. `docker logs conpot` to see why, or `docker start conpot`. |
| T5 | Port 502/102/161 "address already in use" on `docker run` | Something else holds that loopback port. Find it (`netstat -ano -p tcp | findstr :502`) or pick a different host port in the `-p` mapping (and update the probe's `PORT`). |
| T6 | SNMP returns nothing | Wrong community or template. Confirm `public`; try `snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.2.1.1`. |
| T7 | SNMP errors / `No module named 'imp'` | You have the OLD pysnmp 4.4 (dead on Python 3.12+). Fix: `pip uninstall -y pysnmp && pip install "pysnmp==7.1.30"`. Last resort: the `snmpwalk` CLI. |
| T8 | S7 script import error (e.g. `No module named 'pkg_resources'`) | You have the old python-snap7 1.x. Fix: `pip install "python-snap7==3.3.0"` (modern wheel bundles the native lib; no DLL). S7 is optional. |
| T9 | Attacker shows as `172.17.0.1`, not a real IP | Expected — the Docker bridge gateway rewrites the source on localhost. The parser flags `is_docker_gateway`. A real deployment would use host networking to see true source IPs. |
| T10 | Pulled image is very old / won't start | Build from source instead: `git clone https://github.com/mushorg/conpot.git` then build its Docker image per the repo's README. |

---

## Attacking from a different machine (optional)

Everything above keeps the honeypot on loopback (`127.0.0.1`) — safe, and all on
one laptop. If you *want* another machine on your LAN to probe it, recreate the
container publishing on all interfaces (drop the `127.0.0.1:` prefix, e.g.
`-p 502:5020/tcp`), open those ports in Windows Firewall, and point the probes'
`VM_IP` at this laptop's LAN IP. Only do this on a private, trusted network.
