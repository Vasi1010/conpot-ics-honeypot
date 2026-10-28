# Project Walkthrough — from zero to a live attack

This is the **complete orientation + operations guide** for the Conpot honeypot
project. Read it top to bottom once and you'll know what every file does and the
exact order of commands to (1) stand the honeypot up, (2) attack it live, and
(3) turn the resulting log into risk intelligence and a dashboard.

- For **presentation day** (what to click and say), see `docs/VIVA_WALKTHROUGH.md`.
- `docs/SETUP_GUIDE.md` is the **old VM-based** install (VirtualBox + Ubuntu). We
  have since moved the honeypot to **Docker on the laptop**, which is what this
  guide describes. Prefer this guide.

---

## 1. The big picture

The project has **two halves** that meet at one file — the honeypot's log.

```
  ┌─────────────────────┐        ICS protocols          ┌──────────────────────┐
  │  ATTACKER (half 1)  │  Modbus / SNMP / S7comm        │  HONEYPOT             │
  │  Python probes on   │ ─────────────────────────────▶ │  Conpot in Docker     │
  │  the Windows laptop │   127.0.0.1:502 / 161 / 102    │  (fake Siemens PLC)   │
  └─────────────────────┘                                └───────────┬──────────┘
                                                                      │ logs every request
                                                                      ▼
                                       logs\conpot.log  ◀── docker logs conpot
                                                                      │
  ┌─────────────────────┐                                            ▼
  │  ANALYSIS (half 2)  │   parse → score risk → charts → dashboard
  │  Python on the      │ ◀──────────────────────────────────────────
  │  laptop (from root) │
  └─────────────────────┘
```

- **Conpot** is a *low-interaction* honeypot: it emulates ICS/SCADA protocols
  (Modbus, SNMP, S7comm, HTTP, …) and answers as a **Siemens SIMATIC S7-200**
  PLC, but there's no real device behind it. It is purpose-built to be scanned
  and attacked, and it **logs every request**.
- The **attacker** side is three small Python scripts that act like a real
  recon-to-tamper attack: fingerprint the device, read its data, then write to it.
- The **analysis** side reads the honeypot's log and produces: a clean per-event
  table, a per-source-IP **risk score**, report **charts**, and a live
  **Streamlit dashboard**.

> **The honeypot runs in Docker directly on this laptop — there is no VM.** The
> attacker and the honeypot are on the same machine; Docker publishes the honeypot's
> ports on `127.0.0.1`, so the probes just target localhost.

---

## 2. Repository map — which file has what

```
honeypot/
├─ Dockerfile                ← builds conpot-ics:latest (honeynet/conpot + custom template)
├─ conpot_template/          ← custom Conpot template: slave 1 returns REAL Modbus data
│
├─ attacker/                 ← HALF 1: the attack scripts (own venv)
│  ├─ attack.py              ← one-shot COMBINED attack: runs all 5 probes in order
│  ├─ modbus_probe.py        ← Modbus/TCP: reads coils/registers, then a WRITE
│  ├─ snmp_query.py          ← SNMP v2c: GET + WALK the system tree (the "identity")
│  ├─ s7_read.py             ← S7comm: connect + identification read (optional/bonus)
│  ├─ ftp_probe.py           ← FTP: anonymous control session (SYST/PWD/STAT/HELP)
│  ├─ bacnet_probe.py        ← BACnet/IP: a broadcast Who-Is (building-automation recon)
│  ├─ requirements.txt       ← attacker deps: pymodbus, pysnmp, python-snap7
│  └─ .venv/                 ← attacker Python env (NOT the analysis one)
│
├─ scripts/                  ← second attacker
│  └─ attack.py              ← rich coloured TERMINAL console (Recon/Fingerprint/Read/Write)
│
├─ parser/                   ← HALF 2a: raw log → structured events
│  ├─ __main__.py            ← lets you run `python -m parser <log>`
│  ├─ conpot_parser.py       ← main parse loop → pandas DataFrame, one row per event
│  ├─ formats.py             ← detects text-log vs JSON-log lines (pluggable)
│  ├─ patterns.py            ← the regexes for log line SHAPES (edit here if a line won't match)
│  └─ classify.py            ← turns a matched line into MEANING: scan / read / write / connect
│
├─ analysis/                 ← HALF 2b: scoring + charts
│  ├─ detection.py           ← per-IP RISK score from the attack sequence (High/Medium/Low/Info)
│  └─ charts.py              ← 4 PNG charts + 2 CSVs from the parsed table
│
├─ dashboard/                ← HALF 2c: the live view
│  ├─ app.py                 ← Streamlit UI: Dashboard tab + Attack Simulator tab
│  ├─ data.py                ← log → Snapshot (parse + score + KPIs); load_docker() live source
│  ├─ plotly_charts.py       ← interactive dashboard charts
│  └─ simulator.py           ← drives scripts/attack.py + reads the attack chain back
│
├─ tests/                    ← pytest suite covering parser/detection/charts/dashboard/simulator
├─ sample_logs/              ← anonymised example logs so the analysis runs without a live capture
├─ slides/                   ← LaTeX Beamer deck (presentation.tex/.pdf) + figures/
├─ docs/                     ← this guide, SETUP_GUIDE, VIVA_WALKTHROUGH, ATTACK_VIEW_PROMPT
├─ output/                   ← generated charts + CSVs land here (gitignored)
├─ logs/                     ← conpot.log lands here (gitignored — it can contain real IPs)
├─ requirements.txt          ← ANALYSIS deps: pandas, matplotlib, streamlit, plotly, rich, …
└─ README.md                 ← short project overview
```

**Two golden rules that trip people up:**

1. **Two separate Python environments. Don't mix them.**
   - `attacker\.venv` → the probes (pymodbus, pysnmp, snap7).
   - repo-root `.venv` → the analysis/dashboard (pandas, matplotlib, streamlit).
2. **Run the analysis commands from the repo ROOT** (`C:\Users\wahee\honeypot`).
   `parser`, `analysis`, and `dashboard` are Python *packages* — running them from
   inside `attacker\` gives `ModuleNotFoundError: No module named 'analysis'`.

---

## 3. One-time setup (only needed once per machine)

> If the container `conpot` and both `.venv` folders already exist (they do on this
> laptop), **skip to Section 4** — this is only for a fresh machine.

**3.1 Install Docker Desktop** (Windows) and make sure it's running (whale icon in
the tray, "Engine running").

**3.2 Build the honeypot image** (pulls `honeynet/conpot` the first time, then bakes in
the repo's custom template so Modbus returns real process data). From the repo root:

```powershell
docker build -t conpot-ics:latest .
```

**3.3 Create the honeypot container:**

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

What this does: Conpot inside the container listens on high ports (5020/16100/10201/8800
because it runs unprivileged); `-p 127.0.0.1:502:5020` **publishes** container port 5020
to the laptop's `127.0.0.1:502`, which is exactly where `modbus_probe.py` points. Same
idea for the others. `--restart unless-stopped` means it comes back on reboot / Docker
restart.

**3.3 Create the two Python environments** (from `C:\Users\wahee\honeypot`):

```powershell
# Analysis side (repo root)
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
deactivate

# Attacker side
cd attacker
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
deactivate
cd ..
```

(If `Activate.ps1` is blocked, run once per terminal:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`.)

---

## 4. Run a live attack — the full sequence

This is the part you asked for: the exact order to make a live attack work and
light up the whole pipeline. Do it from `C:\Users\wahee\honeypot` in PowerShell.

### Step 1 — Start the honeypot

```powershell
docker start conpot          # (auto-starts with Docker; this is just to be sure)
docker ps                    # confirm the `conpot` row shows "Up" with the 127.0.0.1 ports
```

Expected: one `conpot` row, `Up …`, ports
`127.0.0.1:502->5020/tcp, 127.0.0.1:102->10201/tcp, 127.0.0.1:161->16100/udp, 127.0.0.1:8080->8800/tcp` (plus `2121->2121/tcp` for FTP and `47808->47808/udp` for BACnet).

Confirm the ports actually answer:

```powershell
foreach ($p in 502,102,8080) { Test-NetConnection 127.0.0.1 -Port $p | Select RemotePort, TcpTestSucceeded }
```

Expected: three `True`s.

### Step 2 — Fire the attack

**Easiest — the combined runner** (waits for the honeypot, then runs all three probes):

```powershell
cd attacker
.\.venv\Scripts\python.exe attack.py
cd ..
```

Or run the probes **individually** (same effect, more explanation on screen):

```powershell
cd attacker
.\.venv\Scripts\python.exe modbus_probe.py   # reads + a write
.\.venv\Scripts\python.exe snmp_query.py     # the Siemens "identity" GET + WALK
.\.venv\Scripts\python.exe s7_read.py         # optional S7 identification probe
cd ..
```

**What "working" looks like (these are NOT errors):**
- **SNMP** prints a full Siemens identity — `sysDescr = Siemens, SIMATIC, S7-200`,
  `sysName = CP 443-1 EX40`, `sysLocation = Venus`, plus a system WALK. This is the
  money shot: a scanner now believes this is a real PLC.
- **Modbus** connects and returns **real values** from the custom template's slave 1:
  coils (pump/valve states), discrete inputs (status), holding registers (setpoints,
  e.g. `[1480, 1465, 85, 20, 650, 0, 500, 0, ...]`) and input registers (sensors,
  e.g. `[412, 538, 1260, 236, 74, ...]`). The **write to holding register 0 is accepted**
  and the read-back shows `1234` — a realistic tamper. (On the stock template these all
  return `IllegalAddress`; still logged, just less convincing.)
- **S7comm** establishes a session, then `get_cpu_info()` fails to parse
  ("…must contain exactly 12 bytes" / "request not implemented"). Also expected —
  it's an emulation-vs-library mismatch; the connection is still logged. S7 is a bonus.

### Step 3 — Capture the honeypot's log

The honeypot logged every request *inside the container*. Export it to the file the
analysis side reads:

```powershell
docker logs conpot > logs\conpot.log 2>&1
```

Peek at it:

```powershell
docker logs --tail 20 conpot
```

You'll see the requests arriving from **`172.17.0.1`** — that's the Docker bridge
gateway (your laptop reaching the container through Docker's NAT), not a bug.

### Step 4 — Turn the log into intelligence

Run these **from the repo root**, with the **analysis** venv:

```powershell
# 1) Structured events (and a count of anything it couldn't parse)
.\.venv\Scripts\python.exe -m parser logs\conpot.log

# 2) Per-source-IP risk score
.\.venv\Scripts\python.exe -m analysis.detection logs\conpot.log

# 3) Charts + CSVs into output\
.\.venv\Scripts\python.exe -m analysis.charts logs\conpot.log --out output\
```

Expected from step 2: one row for `172.17.0.1`, risk **High**, sequence
**`scan -> read -> write`**, protocols `modbus, s7comm, snmp`, with the write flagged.
That's the classic recon-to-tamper pattern — a write + multi-protocol scan = High.

### Step 5 — The live dashboard

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py
```

A browser opens `http://localhost:8501`. It shows a threat-level posture banner, KPI
tiles (events, source IPs, write attempts, High-risk IPs), interactive Plotly charts, the
colour-coded per-IP risk table, and the latest events. Stop it with `Ctrl+C`.

- **Log source (sidebar):** a file path (default `logs\conpot.log`), an upload, or
  **Live from Docker** — which runs `docker logs conpot` on every refresh, so you don't
  need to re-export the log by hand (Step 3) at all. Pick that for a live demo.
- **Attack Simulator tab:** run the attack *from the dashboard* (Scan / Read / Write / Full
  buttons), watch its output stream into a terminal panel, and see the **scan → read →
  write** chain light up with a PLC-status card and an attacker → honeypot network view.

> **Nuance (file source only):** when the source is the **file** `logs\conpot.log`, re-run
> Step 3 to refresh it after a new probe. The **Live from Docker** source skips that.

---

## 5. Don't have the honeypot up? You can still run everything

The whole analysis half works on the committed sample logs — no Docker needed:

```powershell
.\.venv\Scripts\python.exe -m analysis.detection sample_logs\conpot_0.6.0_real.log
.\.venv\Scripts\python.exe -m analysis.charts    sample_logs\conpot_0.6.0_real.log --out output\
```

Run the test suite the same way (from the root):

```powershell
.\.venv\Scripts\python.exe -m pytest -q      # expect: 79 passed
```

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `ModuleNotFoundError: No module named 'analysis'` (or `parser`) | You ran it from `attacker\` or the wrong venv. `cd C:\Users\wahee\honeypot` and use the **root** `.venv`. |
| `TcpTestSucceeded : False` on 502/102/8080 | Container not up. `docker start conpot`; check Docker Desktop is running; `docker ps`. |
| Probes hang / "Honeypot not reachable" | Same as above — start the container; it can lag a couple of seconds after `docker start`. |
| Modbus reads say `IllegalAddress` | You're on the **stock** template. Build/run the custom image (`docker build -t conpot-ics:latest .`) so slave 1 has register data. On stock it's harmless — requests are still logged. |
| S7 `get_cpu_info()` error | **Normal** — Conpot/snap7 mismatch; the session is still logged. S7 is optional. |
| Attacker shows as `172.17.0.1` not a real IP | Docker gateway rewrites the source (the parser flags `is_docker_gateway`). Expected on localhost. |
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` in that terminal. |
| Dashboard numbers didn't change after a live probe | Re-export the log: `docker logs conpot > logs\conpot.log`. |

**Reset / teardown:**

```powershell
docker restart conpot     # fresh honeypot (clears its in-memory session, keeps the container)
docker stop conpot        # stop it (keeps it; `docker start conpot` to resume)
docker rm -f conpot       # remove it entirely (recreate with the Section 3.2 command)
```

---

## 7. One-page cheat sheet

```powershell
# from C:\Users\wahee\honeypot

# 1. honeypot up
docker start conpot ; docker ps

# 2. attack  (attacker venv)
cd attacker ; .\.venv\Scripts\python.exe attack.py ; cd ..

# 3. capture
docker logs conpot > logs\conpot.log 2>&1

# 4. analyse  (root venv)
.\.venv\Scripts\python.exe -m analysis.detection logs\conpot.log
.\.venv\Scripts\python.exe -m analysis.charts    logs\conpot.log --out output\

# 5. dashboard
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py
```
