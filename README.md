# Conpot ICS/PLC Honeypot — Project

An ICS/SCADA honeypot built on [Conpot](https://github.com/mushorg/conpot), run in
**Docker on the laptop** (ports published on `127.0.0.1`) and probed locally. A custom
Conpot template makes the Modbus slave return realistic process data. This is a
two-person university project:

- **Attacker + deployment:** build/run Conpot in Docker, probe it over Modbus, SNMP and
  S7comm (plus a `rich` attack console), and produce a clean `conpot.log`.
- **Analysis + dashboard:** parse the log, score per-IP risk, and show it live — including
  an **Attack Simulator** tab that drives the attack from the UI.

New here? Read **`docs/PROJECT_WALKTHROUGH.md`** (from zero to a live attack) or
**`docs/SETUP_GUIDE.md`** (numbered install). The honeypot ran in a VirtualBox VM in an
earlier phase; it now runs directly in Docker Desktop on the laptop.

> ⚠️ **Scope / ethics.** Everything here targets *our own* honeypot on localhost, for a
> university assignment. Conpot is purpose-built to be probed, and the attack console
> refuses any non-loopback / non-private target. Do not point these scripts at a host you
> do not own or have written permission to test.

## Layout

```
conpot-honeypot/
├── Dockerfile             # builds conpot-ics:latest = honeynet/conpot + custom template
├── conpot_template/       # custom Conpot template (slave 1 returns real Modbus data)
├── attacker/              # probe scripts, run locally against 127.0.0.1
│   ├── attack.py          # one-shot combined attack (modbus→snmp→s7comm→ftp→bacnet)
│   ├── modbus_probe.py    # Modbus reads + a write (pymodbus 3.6.9, slave=1)
│   ├── snmp_query.py      # SNMP GET/WALK (pysnmp, with snmpwalk fallback in comments)
│   ├── s7_read.py         # optional S7comm identification read (python-snap7)
│   ├── ftp_probe.py       # FTP control-session probe (ftplib, stdlib)
│   ├── bacnet_probe.py    # BACnet/IP Who-Is probe (socket, stdlib)
│   └── requirements.txt
├── scripts/
│   └── attack.py          # rich coloured attack console (Recon/Fingerprint/Read/Write)
├── docs/                  # SETUP_GUIDE, PROJECT_WALKTHROUGH, VIVA_WALKTHROUGH, ...
├── logs/                  # captured conpot.log lands here (git-ignored)
│
├── parser/                # analysis: conpot.log -> pandas DataFrame
│   ├── patterns.py        #   line shapes (edit this if real lines don't match)
│   ├── formats.py         #   pluggable formats: TextFormat (regex), JsonFormat
│   ├── classify.py        #   function codes -> request type + scan/read/write
│   └── conpot_parser.py   #   parse_log() + CLI
├── analysis/
│   ├── detection.py       # Low/Medium/High risk per source IP
│   └── charts.py          # report/PPT charts (PNG) + CSV export
├── dashboard/
│   ├── app.py             # Streamlit dashboard + Attack Simulator tab
│   ├── data.py            # log -> snapshot (KPIs, risk, gateway share); load_docker()
│   ├── plotly_charts.py   # interactive dashboard charts
│   └── simulator.py       # drives scripts/attack.py + reads the attack chain back
└── tests/                 # pytest suite
```

## Analysis side

```bash
py -3 -m venv .venv
.venv\Scripts\Activate.ps1          # or .venv\Scripts\activate.bat in cmd
pip install -r requirements.txt

python -m parser logs/conpot.log --csv output/parsed.csv   # summary + parsed table
python -m parser logs/conpot.log --tz UTC                  # if the VM logs in UTC
pytest
```

```python
from parser import ParseStats, parse_log
stats = ParseStats()
df = parse_log("logs/conpot.log", tz="Asia/Kolkata", stats=stats)
```

Each row is one attacker event: `timestamp, src_ip, src_port, protocol, event,
request_type, function_code, action, details, is_private, is_docker_gateway,
session_id, pattern, raw`. `action` is `scan`, `read`, `write`, `connect` or
`other` (rules in `parser/classify.py`). `is_docker_gateway` marks 172.17.0.1-style
sources, where Docker NAT hid the real attacker IP.

Input can be `conpot.log`, `docker logs [-t] conpot` output (also when saved as
UTF-16 by PowerShell) or Conpot's JSON log. Timestamps without a timezone are read
as `--tz` (default `Asia/Kolkata`). A missing or empty file gives an empty table.
Unparseable lines are skipped and counted, and lines that only partly match but
contain an IP are kept as `pattern == "fallback"` rows. The CLI lists both kinds,
so if the real log has any, adjust `parser/patterns.py`.

### Attack-sequence detection

```bash
python -m analysis.detection logs/conpot.log --csv output/risk_by_ip.csv   # --window 60
```

One row per source IP with `risk`, `sequence` (stages in first-seen order, e.g.
`scan -> read -> write`), `write_flag`, scan/read/write counts, and whether the IP hit 2+
protocols within `--window` seconds (a multi-protocol scan).

| risk   | when |
|--------|------|
| High   | any write (read -> write, scan -> read -> write; every write is flagged) |
| Medium | reads, no write (scan -> read) |
| Low    | scans only |
| Info   | traffic, but nothing classified as scan/read/write |

Scans are: port probes (connect, no request), Modbus FC 8/17/43, S7 SZL / COTP
connect, SNMP system-group OIDs, HTTP GET of `/` or `/index.html`, and multi-protocol
contact within the window.

### Charts and CSVs for the report

```bash
python -m analysis.charts logs/conpot.log --out output/
```

Writes 16:9 PNGs (200 dpi, slide-ready) and the tables to `output/` (git-ignored):

| file | shows |
|------|-------|
| `attacks_per_protocol.png` | events per protocol |
| `event_timeline.png` | events over time, stacked by stage (scan / read / write) |
| `reads_vs_writes.png` | scans vs reads vs writes per protocol, with the write-attempt count |
| `top_source_ips.png` | busiest source IPs, coloured and labelled by risk level |
| `parsed_events.csv` | the full parsed table |
| `risk_by_ip.csv` | the detection table |

### Live dashboard (for the demo)

```bash
.venv\Scripts\Activate.ps1
streamlit run dashboard/app.py          # opens http://localhost:8501
```

- **Log source:** the sidebar takes a file path (default `logs/conpot.log`, or set the
  `CONPOT_LOG` environment variable), an uploaded file, or **Live from Docker** — which runs
  `docker logs conpot` on every refresh, so no manual export is needed.
- **Live view:** it re-reads the source every few seconds (adjustable, or pause it), so new
  events show up within seconds.
- **What it shows:** a threat-level posture banner, KPI cards (total events, unique IPs,
  write attempts, High-risk IPs), interactive Plotly charts, the colour-coded risk-per-IP
  table, and the latest events.
- **Attack Simulator tab:** drive the attack from the UI (Scan / Read / Write / Full), watch
  its output stream into a terminal panel, and see the **scan → read → write** chain light up
  with a PLC-status card and an attacker → honeypot network view.
- **Warnings:** a red alert lists the IPs that attempted writes. A yellow warning appears
  when more than half the traffic comes from a Docker gateway IP (`172.17.0.1`), which means
  Docker NAT is hiding the real attackers; run Conpot with `--network host`.
- **Bad input:** a missing, empty or garbled log (or an unreachable container) shows a
  waiting/empty state instead of crashing.

## Port map (published on 127.0.0.1)

| Service | Conpot container port | Laptop port |
|---------|-----------------------|-------------|
| HTTP    | 8800                  | 8080        |
| S7comm  | 10201                 | 102         |
| Modbus  | 5020                  | 502         |
| SNMP    | 16100/udp             | 161/udp     |
| FTP     | 2121                  | 2121        |
| BACnet  | 47808/udp             | 47808/udp   |

## Quick start

```powershell
# 1. build + run the honeypot (from the repo root)
docker build -t conpot-ics:latest .
docker run -d --name conpot --restart unless-stopped `
  -p 127.0.0.1:502:5020/tcp -p 127.0.0.1:102:10201/tcp `
  -p 127.0.0.1:161:16100/udp -p 127.0.0.1:8080:8800/tcp `
  -p 127.0.0.1:2121:2121/tcp -p 127.0.0.1:47808:47808/udp conpot-ics:latest

# 2. attack it (scripts already target 127.0.0.1)
cd attacker
python -m venv .venv ; .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python attack.py            # or modbus_probe.py / snmp_query.py / s7_read.py
```

See `docs/PROJECT_WALKTHROUGH.md` (from zero to a live attack) or `docs/SETUP_GUIDE.md`
(numbered install) for the full walkthrough.
