"""
Live Conpot honeypot dashboard.

    streamlit run dashboard/app.py

Reads the log (path or upload) and refreshes every few seconds. The default
path is logs/conpot.log, or set CONPOT_LOG to point somewhere else.
"""

import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root, for parser/analysis

import streamlit as st  # noqa: E402
import streamlit.components.v1 as components  # noqa: E402

from analysis.detection import DEFAULT_WINDOW_S  # noqa: E402
from dashboard import plotly_charts as charts  # noqa: E402  (report PNGs still use analysis.charts)
from dashboard import simulator  # noqa: E402
from dashboard.data import DEFAULT_CONTAINER, DEFAULT_LOG, file_signature, filter_since, load, load_docker  # noqa: E402
from parser import DEFAULT_TZ  # noqa: E402

st.set_page_config(page_title="Conpot honeypot dashboard", page_icon="🛡️", layout="wide")

# Risk → (background, text) colours for the SOC dark theme, shared by the
# posture banner and the risk-table badges. Saturated chips on a dark page.
RISK_STYLE = {
    "High": ("#e74c3c", "#180a08"),
    "Medium": ("#e6a817", "#1b1403"),
    "Low": ("#2ecc71", "#07251a"),
    "Info": ("#46566a", "#e6edf3"),
}

# The Dockerized Conpot logs timestamps in UTC; show them in the viewer's local
# time so they line up with the wall clock during a demo.
LOCAL_TZ = datetime.now().astimezone().tzinfo


def to_local(series):
    """Convert a tz-aware timestamp Series to local time (no-op if not tz-aware)."""
    try:
        return series.dt.tz_convert(LOCAL_TZ)
    except (TypeError, AttributeError):
        return series


def inject_css():
    st.markdown(
        """
        <style>
          @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
          html, body, [class*="css"] { font-family: 'IBM Plex Sans', system-ui, sans-serif; }
          .block-container { padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1320px; }
          #MainMenu, footer, .stDeployButton { visibility: hidden; }

          /* header band */
          .hp-head { display:flex; align-items:center; gap:14px; padding:18px 22px; border-radius:14px;
            background: linear-gradient(100deg,#0e2a33 0%, #12313c 55%, #0e1f27 100%); color:#eaf5f8;
            box-shadow: 0 6px 22px rgba(11,34,42,.18); margin-bottom:18px; }
          .hp-head .dot { width:12px; height:12px; border-radius:50%; background:#49d39a;
            box-shadow:0 0 0 4px rgba(73,211,154,.25); flex:none; }
          .hp-head h1 { font-size:1.45rem; font-weight:700; margin:0; letter-spacing:-.01em; color:#fff; }
          .hp-head .sub { font-family:'IBM Plex Mono',monospace; font-size:.72rem; letter-spacing:.12em;
            text-transform:uppercase; color:#8fc6d4; margin-top:2px; }
          .hp-head .spacer { flex:1; }
          .hp-head .meta { font-family:'IBM Plex Mono',monospace; font-size:.72rem; color:#9fd0dc; text-align:right; }

          /* posture banner */
          .hp-posture { border-radius:14px; padding:16px 20px; margin-bottom:12px; display:flex; align-items:center;
            gap:16px; border:1px solid rgba(0,0,0,.06); }
          .hp-posture .lvl { font-family:'IBM Plex Mono',monospace; font-weight:600; font-size:1.7rem;
            letter-spacing:.02em; line-height:1; }
          .hp-posture .txt { font-size:.9rem; }
          .hp-posture .txt b { font-weight:600; }

          /* metric tiles (dark SOC panels) */
          div[data-testid="stMetric"] { background:#161b22; border:1px solid #30363d; border-radius:12px;
            padding:14px 16px; box-shadow:0 1px 2px rgba(0,0,0,.35); }
          div[data-testid="stMetricLabel"] p { font-family:'IBM Plex Mono',monospace; font-size:.7rem;
            letter-spacing:.08em; text-transform:uppercase; color:#8b98a9; }
          div[data-testid="stMetricValue"] { font-weight:700; color:#e6edf3; }

          /* tabs: SOC-style pill row */
          .stTabs [data-baseweb="tab-list"] { gap:6px; }
          .stTabs [data-baseweb="tab"] { font-family:'IBM Plex Mono',monospace; letter-spacing:.04em; }

          /* terminal-style code panels (attack output) */
          .stCode, pre { background:#0b0f14 !important; border:1px solid #1e2631; border-radius:10px; }
          code, pre, .stCode span { font-family:'IBM Plex Mono',monospace !important; }

          /* section headings */
          h2, h3 { letter-spacing:-.01em; color:#e6edf3; }
          .stDataFrame { border-radius:10px; overflow:hidden; border:1px solid #30363d; }
          hr { margin:1.1rem 0; border-color:#1e2631; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header():
    st.markdown(
        '<div class="hp-head"><span class="dot"></span>'
        '<div><h1>Conpot ICS Honeypot</h1>'
        '<div class="sub">Live threat monitor · Modbus · S7comm · SNMP · HTTP</div></div>'
        '<span class="spacer"></span>'
        '<div class="meta">Siemens SIMATIC S7-200<br>per-IP attack-sequence risk</div></div>',
        unsafe_allow_html=True,
    )


@st.cache_data(show_spinner=False, max_entries=8)
def load_path(path, signature, tz, window_s):
    # `signature` (mtime, size) is only part of the cache key: a changed log re-parses.
    return load(path=path, tz=tz, window_s=window_s)


@st.cache_data(show_spinner=False, max_entries=4)
def load_upload(data, name, tz, window_s):
    return load(data=data, name=name, tz=tz, window_s=window_s)


# --------------------------------------------------------------------------- sidebar

with st.sidebar:
    st.header("Log source")
    mode = st.radio("Source", ["File path", "Upload", "Live from Docker"],
                    label_visibility="collapsed")
    path = upload = container = None
    if mode == "File path":
        path = st.text_input("Log file path", value=os.environ.get("CONPOT_LOG", DEFAULT_LOG), key="path",
                             help="conpot.log, `docker logs conpot` output, or a JSON log")
    elif mode == "Upload":
        upload = st.file_uploader("Upload a log file", type=None, key="upload")
    else:
        container = st.text_input("Container name", value=DEFAULT_CONTAINER, key="container",
                                  help="Runs `docker logs <name>` on every refresh — no manual export needed.")

    st.header("Refresh")
    live = st.toggle("Auto-refresh", value=True, key="live")
    interval = st.slider("Every (seconds)", 2, 60, 5, key="interval", disabled=not live)

    st.header("Detection")
    window_s = st.number_input("Multi-protocol scan window (s)", 1, 3600, int(DEFAULT_WINDOW_S), key="window")
    tz = st.text_input("Log timezone", value="UTC", key="tz",
                       help="Timezone the log's timestamps are in. The Dockerized Conpot logs "
                            "in UTC; the dashboard then shows them in your local time.")

    st.header("View")
    if st.button("🔄 Reset events", key="reset_btn", width="stretch",
                 help="Zero the counts and charts from now. New attacks climb from zero. "
                      "Non-destructive — the honeypot and its log are untouched."):
        st.session_state["reset_pending"] = True
    _ra = st.session_state.get("reset_at")
    if _ra is not None:
        st.caption(f"Counting events since the reset at {_ra.tz_convert(LOCAL_TZ):%H:%M:%S}.")
        if st.button("Clear reset", key="clear_reset_btn", width="stretch"):
            st.session_state.pop("reset_at", None)
            st.session_state.pop("reset_pending", None)


inject_css()
render_header()


def apply_reset(snap):
    """Apply the sidebar 'Reset events' baseline: a non-destructive view filter.

    On the click we record the latest event time as the baseline; from then on only
    events after it are shown, so the view starts at zero and climbs with new attacks.
    Works for every source and never touches the log.
    """
    if snap is None or snap.docker_error or snap.stats.file_missing:
        return snap
    if st.session_state.pop("reset_pending", False):
        st.session_state["reset_at"] = snap.df["timestamp"].max() if len(snap.df) else None
    return filter_since(snap, st.session_state.get("reset_at"), window_s)


def get_snapshot():
    try:
        if upload is not None:
            snap = load_upload(upload.getvalue(), upload.name, tz, window_s)
        elif container is not None:
            # Not cached: we want a fresh `docker logs` read on every refresh.
            snap = load_docker(container.strip() or DEFAULT_CONTAINER, tz, window_s)
        elif path is not None:
            snap = load_path(path, file_signature(path), tz, window_s)
        else:
            return None
    except Exception as exc:  # e.g. an unknown timezone typed in the sidebar
        st.error(f"Could not load the log: {exc}")
        return None
    return apply_reset(snap)


def show_posture(snap):
    """A single at-a-glance threat level derived from the worst per-IP risk."""
    counts = snap.risk["risk"].value_counts().to_dict() if len(snap.risk) else {}
    if counts.get("High"):
        level, blurb = "High", f"{counts['High']} source IP(s) attempted a write or multi-protocol attack."
    elif counts.get("Medium"):
        level, blurb = "Medium", f"{counts['Medium']} source IP(s) read process data after scanning."
    elif counts.get("Low"):
        level, blurb = "Low", f"{counts['Low']} source IP(s) scanned but did not read or write."
    else:
        level, blurb = "Info", "Traffic seen, but nothing classified as scan, read or write yet."
    bg, fg = RISK_STYLE[level]
    st.markdown(
        f'<div class="hp-posture" style="background:{bg};border-color:{fg}33">'
        f'<span class="lvl" style="color:{fg}">{level.upper()}</span>'
        f'<span class="txt"><b style="color:{fg}">Threat level</b><br>{blurb}</span></div>',
        unsafe_allow_html=True,
    )


def show_kpis(snap):
    prev = st.session_state.get("prev_kpis", {})
    for col, (label, value) in zip(st.columns(4), snap.kpis.items()):
        delta = value - prev[label] if label in prev and value != prev[label] else None
        col.metric(label, f"{value:,}", delta=delta, border=True)
    st.session_state["prev_kpis"] = snap.kpis


def show_chart(col, fig):
    with col:
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def show_risk_table(risk):
    st.subheader("Risk per source IP")
    table = risk.copy()
    for c in ("first_seen", "last_seen"):
        table[c] = to_local(table[c]).dt.strftime("%Y-%m-%d %H:%M:%S")
    order = ["src_ip", "risk", "sequence", "write_flag", "scans", "reads", "writes",
             "multi_protocol_scan", "protocols", "events", "first_seen", "last_seen",
             "is_private", "is_docker_gateway"]

    def colour_risk(column):
        return [f"background-color:{RISK_STYLE.get(v, RISK_STYLE['Info'])[0]};"
                f"color:{RISK_STYLE.get(v, RISK_STYLE['Info'])[1]};font-weight:600" for v in column]

    styler = table.style.apply(colour_risk, subset=["risk"])
    st.dataframe(
        styler, hide_index=True, width="stretch", column_order=order,
        column_config={
            "src_ip": "Source IP", "risk": "Risk", "sequence": "Sequence",
            "write_flag": st.column_config.CheckboxColumn("Write!"),
            "multi_protocol_scan": st.column_config.CheckboxColumn("Multi-proto scan"),
            "is_private": st.column_config.CheckboxColumn("Private"),
            "is_docker_gateway": st.column_config.CheckboxColumn("Docker GW"),
            "first_seen": "First seen", "last_seen": "Last seen",
        },
    )


def show_parse_stats(snap):
    s = snap.stats
    suffix = f" · showing {len(snap.df):,} since reset" if st.session_state.get("reset_at") is not None else ""
    st.caption(f"Source: `{snap.source}` · {s.lines:,} lines · {s.parsed:,} events{suffix} · "
               f"{s.ignored:,} ignored · {s.unparseable:,} unparseable · "
               f"refreshed {datetime.now():%H:%M:%S}")
    if s.unmatched:
        with st.expander(f"{s.fallback + s.unparseable} line(s) not fully understood"):
            st.code("\n".join(line[:300] for line in s.unmatched), language=None)


@st.fragment(run_every=interval if live else None)
def dashboard():
    snap = get_snapshot()
    if snap is None:
        if mode == "Upload":
            st.info("Upload a Conpot log to start.")
        return
    if snap.docker_error:
        st.warning(f"Live Docker source unavailable: {snap.docker_error}  "
                   "Start the honeypot container (e.g. `docker start conpot`) or switch to a "
                   "file/upload source in the sidebar.", icon="🐳")
        return
    if snap.stats.file_missing:
        st.warning(f"Waiting for the log file: `{snap.source}`. "
                   "The dashboard will pick it up automatically once it exists.")
        return

    if snap.df.empty:
        show_kpis(snap)
        st.info("No attacker events in the log yet. Waiting for traffic.")
        show_parse_stats(snap)
        return

    show_posture(snap)
    show_kpis(snap)

    if snap.gateway_warning:
        st.warning(
            f"**{snap.gateway_share:.0%} of events come from a Docker gateway IP** "
            f"({', '.join(snap.gateway_ips)}). Docker NAT is hiding the real attacker addresses, so "
            "per-IP results lump everyone together. Run the Conpot container with `--network host` "
            "so it sees real source IPs.", icon="⚠️")
    writers = snap.risk.loc[snap.risk["write_flag"], "src_ip"].tolist()
    if writers:
        st.error(f"**Write attempts** (High risk) from: {', '.join(writers)}", icon="🚨")

    st.divider()
    left, right = st.columns(2)
    show_chart(left, charts.attacks_per_protocol(snap.df))
    show_chart(right, charts.actions_by_protocol(snap.df))
    left, right = st.columns(2)
    show_chart(left, charts.event_timeline(snap.df))
    show_chart(right, charts.top_source_ips(snap.df, snap.risk))

    st.divider()
    show_risk_table(snap.risk)
    with st.expander("Latest events"):
        latest = snap.df.drop(columns=["raw", "session_id", "pattern"]).tail(50).iloc[::-1].copy()
        if "timestamp" in latest.columns:
            latest["timestamp"] = to_local(latest["timestamp"])
        st.dataframe(latest, hide_index=True, width="stretch")
    show_parse_stats(snap)


# --------------------------------------------------------------------------- Attack Simulator tab

def show_attack_chain(chain):
    """Three pills — Scan -> Read -> Write — lit for the stages reached."""
    cols = st.columns([3, 1, 3, 1, 3])
    pills = [("scan", "🔍 Scan"), ("read", "📖 Read"), ("write", "✍️ Write")]
    for col, (stage, label) in zip((cols[0], cols[2], cols[4]), pills):
        lit = chain[stage]
        colour = simulator.COLOUR_WRITE if stage == "write" and lit else (
            simulator.COLOUR_BUSY if lit else "#3a4553")
        fg = "#0d1117" if lit else "#8b98a9"
        col.markdown(
            f"<div style='background:{colour};color:{fg};border-radius:8px;"
            f"padding:10px 4px;text-align:center;font-weight:700;font-family:monospace'>"
            f"{label}</div>", unsafe_allow_html=True)
    for arrow_col in (cols[1], cols[3]):
        arrow_col.markdown("<div style='text-align:center;font-size:22px;"
                           "padding-top:6px;color:#8b98a9'>→</div>", unsafe_allow_html=True)


def show_plc_card(state_key):
    colour, label = simulator.PLC_STATES[state_key]
    st.markdown(
        f"<div style='background:{colour};border-radius:10px;padding:16px;text-align:center;"
        f"color:#0d1117'><div style='font-size:12px;letter-spacing:2px'>PLC STATUS</div>"
        f"<div style='font-size:20px;font-weight:800;margin-top:4px'>{label}</div></div>",
        unsafe_allow_html=True)


def stream_attack(target, phase):
    """Run the attack console and stream its output into a terminal-style panel."""
    panel = st.empty()
    lines = []
    with st.spinner(f"Running **{phase}** against `{target}` ..."):
        for line in simulator.iter_attack_output(target, phase):
            lines.append(line)
            panel.code("\n".join(lines[-400:]) or " ", language=None)
    st.session_state["sim_output"] = "\n".join(lines)


def simulator_tab():
    st.subheader("Attack Simulator")
    st.caption("Drive labelled traffic at the lab honeypot and watch the attack chain light up. "
               "Targets are restricted to loopback / private-LAN addresses.")

    target = st.text_input("Attack target", value="127.0.0.1", key="sim_target",
                           help="Loopback or private-LAN only — the attack console refuses anything else.")

    cols = st.columns(len(simulator.PHASES))
    clicked = None
    for col, (label, phase) in zip(cols, simulator.PHASES.items()):
        kind = "primary" if label == "Full Attack" else "secondary"
        if col.button(label, key=f"sim_btn_{phase}", width="stretch", type=kind):
            clicked = phase
    if clicked:
        stream_attack(target.strip() or "127.0.0.1", clicked)
    elif st.session_state.get("sim_output"):
        st.code(st.session_state["sim_output"][-6000:], language=None)

    # Read the (now-updated) log and visualise the chain for one IP.
    snap = get_snapshot()
    st.divider()
    if snap is None or snap.df.empty:
        st.info("Run an attack above (with a live honeypot source) to populate the attack chain.")
        return

    ips = list(snap.risk["src_ip"])
    default = simulator.writers(snap.risk) or ips
    chosen = st.selectbox("Source IP to track", ips,
                          index=ips.index(default[0]) if default else 0, key="sim_ip")

    chain = simulator.chain_status(snap.risk, chosen)
    state = simulator.plc_state(snap.risk, chosen)
    colour = simulator.stage_colour(snap.risk, chosen)

    left, right = st.columns([2, 1])
    with left:
        st.markdown("**Attack chain**")
        show_attack_chain(chain)
        st.markdown("**Network view**")
        components.html(simulator.network_svg(colour, attacker_label=chosen), height=130)
    with right:
        show_plc_card(state)

    # Toast when a brand-new write attempt shows up since the last run.
    current = simulator.writers(snap.risk)
    fresh = simulator.new_writers(current, st.session_state.get("sim_prev_writers", []))
    for ip in fresh:
        st.toast(f"🚨 New WRITE attempt from {ip}", icon="🚨")
    st.session_state["sim_prev_writers"] = current


tab_dashboard, tab_simulator = st.tabs(["📊 Dashboard", "🎯 Attack Simulator"])
with tab_dashboard:
    dashboard()
with tab_simulator:
    simulator_tab()
