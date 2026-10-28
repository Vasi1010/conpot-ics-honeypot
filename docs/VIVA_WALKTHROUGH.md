# Viva Walkthrough & Live Demo Script

A presentation-day runbook: what to have ready, what to click, what to say, who
speaks, and what to do if something breaks. Pairs with the slide deck
(`slides/presentation.pdf`) and the setup guide (`docs/SETUP_GUIDE.md`).

> **Two environments, two Python venvs — don't mix them up:**
> - **Attacker/probes:** `attacker\.venv` (pymodbus, pysnmp, snap7)
> - **Analysis/dashboard:** repo-root `.venv` (pandas, matplotlib, streamlit)
>
> **The honeypot now runs in a local Docker container (`conpot`) on this laptop — no
> VM.** The analysis + dashboard run on Windows from the already-captured
> `logs\conpot.log` and need nothing live. You only need the container running if you
> want to fire a probe *live*.

---

## 0. Pre-flight checklist (do this ~15 min before the viva)

1. **(Only if doing a live probe) Start the honeypot container.**
   - Make sure Docker Desktop is running, then: `docker start conpot` (it also
     auto-starts with Docker via `--restart unless-stopped`). Check with `docker ps`.
   - Verify the honeypot is reachable from Windows (PowerShell):
     ```powershell
     foreach ($p in 502,102,8080) { Test-NetConnection 127.0.0.1 -Port $p | Select RemotePort, TcpTestSucceeded }
     ```
     Three `True`s = the honeypot is live.
2. **Confirm the analysis side works (nothing live needed):**
   ```powershell
   cd C:\Users\wahee\honeypot
   .\.venv\Scripts\python.exe -m analysis.detection logs\conpot.log
   ```
   Should print `172.17.0.1 ... High ... scan -> read -> write`.
3. **Open the deck:** `slides\presentation.pdf` (full-screen).
4. **Pre-stage a terminal** in `C:\Users\wahee\honeypot` and have the dashboard
   command copied (Section 2E).
5. **Safety net:** the `output\` folder already has the charts and the compiled PDF —
   if anything live fails, you present from those.

---

## 1. Slides (~6–8 min)

| Slide | Talking point | Speaker |
|-------|---------------|---------|
| Title | Project + who did which half | Both |
| Background | ICS/SCADA use legacy, unauthenticated protocols; honeypots observe attackers safely | A |
| Conpot | Low-interaction honeypot emulating a Siemens S7-200 PLC | A |
| Architecture | Laptop → Docker (publishes to `127.0.0.1`) → Conpot; port table | A |
| Attack methodology | Three probes: Modbus, SNMP, S7comm | A |
| Results | 25 events, 1 source, 3 protocols (point at the chart) | A |
| SNMP identity | Honeypot answers as "Siemens, SIMATIC, S7-200" / "CP 443-1 EX40" | A |
| Log analysis | Raw log → structured events (parser), 79 passing tests | B |
| Detection | Per-IP risk; our capture scored **High** (`scan → read → write`) | B |
| Dashboard | Live Streamlit view with KPIs + risk table | B |
| Ethics & scope | Own honeypot, private LAN, authorised | B |
| Conclusion | What we built + future work | B |

---

## 2. Live demo (~4–5 min)

> If the container is up, do A–E. If not (or if anything is flaky), skip A–C and jump to
> **D–E**, which run entirely on the captured log — that's the robust core of the demo.

**A. "The honeypot is running."** On the **laptop** (any terminal):
```powershell
docker ps
```
Point out the `conpot` row — `Up`, ports `127.0.0.1:502/102/161/8080` mapped.

**B. "Let's scan it like an attacker would."** On the **laptop** (attacker venv):
```powershell
cd C:\Users\wahee\honeypot\attacker
.\.venv\Scripts\python.exe snmp_query.py
```
It prints the fake Siemens identity (sysDescr = *Siemens, SIMATIC, S7-200*, sysName =
*CP 443-1 EX40*). Great visual: "a scanner now believes this is a real PLC."
*(Optional second probe — the write attempt:)*
```powershell
.\.venv\Scripts\python.exe modbus_probe.py
```

**C. "The honeypot logged every request."** On the **laptop**:
```powershell
docker logs --tail 20 conpot
```
Show the requests arriving from `172.17.0.1` (= your laptop through the Docker gateway).

**D. "Now we turn the log into intelligence."** On the **laptop** (analysis venv):
```powershell
cd C:\Users\wahee\honeypot
.\.venv\Scripts\python.exe -m parser logs\conpot.log
.\.venv\Scripts\python.exe -m analysis.detection logs\conpot.log
```
Call out: 131 lines → 25 events; source `172.17.0.1` scored **High** — sequence
**`scan → read → write`** across modbus/s7comm/snmp, with the write flagged.

**E. "And a live dashboard for an operator."**
```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py
```
A browser opens `http://localhost:8501`. Point at:
- the **KPI tiles** (events, source IPs, write attempts),
- the red **"Write attempts (High risk) from: 172.17.0.1"** banner,
- the **Risk per source IP** table and the charts.

> **Important nuance:** the dashboard reads the *captured* `logs\conpot.log` (your
> recorded session). A probe you run *live* in step B lands in the container's log,
> not in this file — so don't expect the live probe to change the dashboard numbers
> unless you re-export it (`docker logs conpot > logs\conpot.log`). Present the live
> probe as "watch the honeypot respond," and the dashboard as "here's the analysis of
> the session we captured."

---

## 3. Likely questions (and crisp answers)

- **Why does the attacker show as `172.17.0.1`?** That's the Docker bridge *gateway*
  address — traffic from the host reaches the container through Docker's NAT, which
  rewrites the source. The parser flags this (`is_docker_gateway`); on a real deployment
  you'd run Conpot with host networking to see true source IPs. (Our earlier VM-based runs
  showed `10.0.2.2`, the VirtualBox NAT gateway, for the same reason.)
- **Why did the Modbus reads return "IllegalAddress"?** The stock Conpot template
  defines no register values, so it answers like a PLC with those addresses empty. The
  requests are still fully logged — which is what we needed.
- **Why did the S7 CPU-info read error out?** Conpot's S7comm handler replies "request
  not implemented"; the S7 *session* still established and was logged. S7 was the bonus
  probe.
- **Low- vs high-interaction honeypot?** Conpot is low-interaction — it emulates
  protocols without a real OS/PLC behind them, so it's safe and easy to run, at the cost
  of not fooling a very determined attacker for long.
- **How does the risk score work?** From the per-IP attack *sequence* (scan→read→write),
  whether it scanned multiple protocols, and whether it attempted a write. Write +
  multi-protocol = High.
- **Is this legal/ethical?** Everything targets our own honeypot on a private LAN for a
  university assignment; Conpot exists to be probed. Nothing external is touched.

---

## 4. If something breaks (fallbacks)

| Problem | Fallback |
|---------|----------|
| Container won't start / Docker down | Skip live probe (steps A–C). Do D–E on the captured log — nothing live required. |
| Dashboard won't start | Show the static charts in `output\*.png` and the `analysis.detection` text output. |
| Analysis venv broken | Everything is already in the **compiled PDF** (`slides\presentation.pdf`) — present from it. |
| Projector/resolution issues | The PDF is 16:9; the dashboard is browser-zoomable (Ctrl +/–). |

**Golden rule:** the compiled PDF + `output\` charts + `logs\conpot.log` are a complete,
self-contained demo that needs nothing live. Treat the live probe as a bonus, not a
dependency.

---

## 5. Speaking split (two presenters)

- **Presenter A (honeypot & attacker):** Background → Conpot → Architecture → Attack
  methodology → Results/SNMP → live demo steps A–C.
- **Presenter B (analysis & dashboard):** Log analysis → Detection → Dashboard → Ethics
  → Conclusion → live demo steps D–E.

Hand-off line after the attack demo: *"We've generated the attack traffic — now [Awez]
will show how we turn that raw log into risk intelligence."*
