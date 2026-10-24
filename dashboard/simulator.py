"""
Attack Simulator: run the attack console and read the attack chain back out of
the parsed log.

Everything here is Streamlit-free so it can be tested; dashboard/app.py does the
widget wiring. The attack runner shells out to scripts/attack.py, which enforces
the loopback/private-LAN safety rule — we also pre-check here so a bad target is
refused without spawning anything.
"""

import os
import subprocess
import sys
from pathlib import Path

from scripts import attack

ROOT = Path(__file__).resolve().parent.parent
ATTACK_SCRIPT = ROOT / "scripts" / "attack.py"

# Button label -> scripts/attack.py --phase value. Mirrors the Scan -> Read ->
# Write attack chain.
PHASES = {"Scan": "scan", "Read": "read", "Write": "write", "Full Attack": "all"}

# Attack-chain stages, in order.
STAGES = ("scan", "read", "write")

# Colours shared by the chain tracker, PLC card, and network edge.
COLOUR_IDLE = "#2ecc71"   # green
COLOUR_BUSY = "#f1c40f"   # amber: being scanned / read
COLOUR_WRITE = "#e74c3c"  # red: write attempted

# PLC state key -> (colour, label).
PLC_STATES = {
    "idle": (COLOUR_IDLE, "IDLE"),
    "busy": (COLOUR_BUSY, "BEING SCANNED / READ"),
    "write": (COLOUR_WRITE, "WRITE ATTEMPTED"),
}


# --------------------------------------------------------------------------- attack runner

def attack_command(target, phase, delay=0.0, python=None, script=ATTACK_SCRIPT):
    """The argv that runs the attack console for one phase."""
    python = python or sys.executable
    return [python, str(script), "--target", str(target), "--phase", phase, "--delay", str(delay)]


def iter_attack_output(target, phase, delay=0.0, python=None, script=ATTACK_SCRIPT):
    """Yield the attack console's output line by line, for a terminal-style panel.

    Refuses a non-lab target before spawning anything (yields one REFUSED line).
    """
    ip, reason = attack.check_target(target)
    if ip is None:
        yield f"REFUSED: {reason}"
        return
    # Force UTF-8 on the child so rich's box-drawing output round-trips on Windows.
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.Popen(
        attack_command(target, phase, delay, python, script),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1, env=env)
    try:
        for line in proc.stdout:
            yield line.rstrip("\n")
    finally:
        proc.stdout.close()
        proc.wait()


def run_attack(target, phase, delay=0.0, python=None, script=ATTACK_SCRIPT):
    """All of the attack console's output as one string."""
    return "\n".join(iter_attack_output(target, phase, delay, python, script))


# --------------------------------------------------------------------------- chain / status

def chain_status(risk, ip):
    """Which stages `ip` has reached, read from the risk table: {scan, read, write} -> bool."""
    empty = {stage: False for stage in STAGES}
    if risk is None or risk.empty or ip is None:
        return empty
    row = risk[risk["src_ip"] == ip]
    if row.empty:
        return empty
    r = row.iloc[0]
    return {"scan": int(r["scans"]) > 0, "read": int(r["reads"]) > 0, "write": int(r["writes"]) > 0}


def plc_state(risk, ip):
    """PLC status key for `ip`: 'write' > 'busy' (scan/read) > 'idle'."""
    c = chain_status(risk, ip)
    if c["write"]:
        return "write"
    if c["scan"] or c["read"]:
        return "busy"
    return "idle"


def stage_colour(risk, ip):
    """Colour for the network edge / PLC, from the current PLC state."""
    return PLC_STATES[plc_state(risk, ip)][0]


def writers(risk):
    """Source IPs that have attempted a write, sorted."""
    if risk is None or risk.empty:
        return []
    return sorted(risk.loc[risk["write_flag"], "src_ip"])


def new_writers(current, previous):
    """Writer IPs in `current` not seen in `previous` — what to toast about."""
    prev = set(previous or [])
    return [ip for ip in current if ip not in prev]


# --------------------------------------------------------------------------- network view

def network_svg(colour, attacker_label="attacker", honeypot_label="Conpot", animate=True):
    """A small Attacker -> Honeypot diagram with an animated dashed edge in `colour`.

    Returns an inline SVG string; the edge colour encodes the current stage.
    """
    dash = ('<animate attributeName="stroke-dashoffset" from="28" to="0" '
            'dur="0.7s" repeatCount="indefinite"/>') if animate else ""
    return f"""<svg viewBox="0 0 420 120" width="100%" height="120"
     xmlns="http://www.w3.org/2000/svg" role="img" aria-label="attack path">
  <defs>
    <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3"
            orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="{colour}"/></marker>
  </defs>
  <line x1="110" y1="60" x2="300" y2="60" stroke="{colour}" stroke-width="4"
        stroke-dasharray="7 7" marker-end="url(#arrow)">{dash}</line>
  <g>
    <rect x="20" y="35" width="90" height="50" rx="8" fill="#1b2330" stroke="{colour}"/>
    <text x="65" y="56" fill="#e6edf3" font-size="13" text-anchor="middle"
          font-family="monospace">attacker</text>
    <text x="65" y="74" fill="#8b98a9" font-size="11" text-anchor="middle"
          font-family="monospace">{attacker_label}</text>
  </g>
  <g>
    <rect x="300" y="35" width="100" height="50" rx="8" fill="#1b2330" stroke="{colour}"/>
    <text x="350" y="56" fill="#e6edf3" font-size="13" text-anchor="middle"
          font-family="monospace">honeypot</text>
    <text x="350" y="74" fill="#8b98a9" font-size="11" text-anchor="middle"
          font-family="monospace">{honeypot_label}</text>
  </g>
</svg>"""
