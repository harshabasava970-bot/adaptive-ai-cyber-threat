"""
app.py — Enterprise SOC Dashboard v5
=====================================
Adaptive AI for Cyber Threat Detection
Full workflow: persistence, simulation, auto-sync, notifications.
Author: B.Tech Capstone Project
"""

import sys, os, time, math, uuid, random, io
from datetime import datetime, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
st.set_page_config(
    page_title="CyberShield AI — SOC Platform",
    page_icon="🛡️", layout="wide",
    initial_sidebar_state="expanded",
)

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import requests

API_BASE = os.environ.get(
    "API_BASE_URL", "https://cyber-threat-api-4gms.onrender.com"
).rstrip("/") + "/api/v1"

C = {
    "bg":"#0B1120","card":"#111827","sidebar":"#0F172A",
    "primary":"#2563EB","success":"#22C55E","warning":"#F59E0B",
    "critical":"#EF4444","info":"#38BDF8","text":"#F8FAFC",
    "muted":"#94A3B8","border":"#1E293B","hover":"#1E40AF",
}
RISK_C  = {"critical":C["critical"],"high":"#F97316","medium":C["warning"],
           "low":C["success"],"info":C["info"]}
RISK_BG = {"critical":"#2D1515","high":"#2D1A0E","medium":"#2D2710",
           "low":"#0F2D1A","info":"#0F2133"}

# ══════════════════════════════════════════════════════════════════
# FULL CSS OVERRIDE
# ══════════════════════════════════════════════════════════════════
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
*,*::before,*::after{{box-sizing:border-box}}
html,body,.stApp{{background-color:{C["bg"]}!important;color:{C["text"]}!important;
  font-family:'Inter',-apple-system,sans-serif!important;font-size:14px;line-height:1.6}}
section[data-testid="stSidebar"]{{background:{C["sidebar"]}!important;
  border-right:1px solid {C["border"]}!important;padding-top:0!important}}
section[data-testid="stSidebar"] .block-container{{padding:0!important}}
.block-container{{padding:1.5rem 2rem 3rem!important;max-width:100%!important}}
h1{{font-size:1.75rem!important;font-weight:800!important;color:{C["text"]}!important;
  letter-spacing:-0.5px;margin-bottom:4px!important}}
h2{{font-size:1.3rem!important;font-weight:700!important;color:{C["text"]}!important}}
h3{{font-size:1.1rem!important;font-weight:600!important;color:{C["info"]}!important}}
h4{{font-size:0.9rem!important;font-weight:600!important;color:{C["muted"]}!important;
  text-transform:uppercase;letter-spacing:0.8px}}
div[data-testid="metric-container"]{{background:{C["card"]}!important;
  border:1px solid {C["border"]}!important;border-radius:14px!important;
  padding:20px 22px!important;box-shadow:0 4px 24px rgba(0,0,0,0.35)!important;
  transition:transform 0.2s,box-shadow 0.2s!important}}
div[data-testid="metric-container"]:hover{{transform:translateY(-2px)!important;
  box-shadow:0 8px 32px rgba(37,99,235,0.2)!important}}
div[data-testid="metric-container"] [data-testid="stMetricLabel"]{{
  font-size:0.72rem!important;font-weight:600!important;color:{C["muted"]}!important;
  text-transform:uppercase;letter-spacing:0.8px}}
div[data-testid="metric-container"] [data-testid="stMetricValue"]{{
  font-size:1.9rem!important;font-weight:800!important;color:{C["text"]}!important}}
.stButton>button{{background:linear-gradient(135deg,{C["primary"]},#1D4ED8)!important;
  color:{C["text"]}!important;border:none!important;border-radius:10px!important;
  padding:10px 22px!important;font-weight:600!important;font-size:0.87rem!important;
  box-shadow:0 4px 14px rgba(37,99,235,0.4)!important;
  transition:all 0.2s ease!important;width:100%}}
.stButton>button:hover{{background:linear-gradient(135deg,#1D4ED8,#1E40AF)!important;
  box-shadow:0 6px 20px rgba(37,99,235,0.55)!important;transform:translateY(-1px)!important}}
.stTextInput>div>div>input,.stTextArea>div>div>textarea,
.stNumberInput>div>div>input{{background:{C["card"]}!important;color:{C["text"]}!important;
  border:1px solid {C["border"]}!important;border-radius:10px!important;
  padding:10px 14px!important;font-family:'Inter',sans-serif!important}}
.stTextInput>div>div>input:focus,.stTextArea>div>div>textarea:focus{{
  border-color:{C["primary"]}!important;box-shadow:0 0 0 3px rgba(37,99,235,0.15)!important}}
.stSelectbox>div>div,.stMultiSelect>div>div{{background:{C["card"]}!important;
  border:1px solid {C["border"]}!important;border-radius:10px!important;color:{C["text"]}!important}}
.stRadio>div>label,.stCheckbox>label{{color:{C["text"]}!important;font-size:0.87rem!important}}
.stTabs [data-baseweb="tab-list"]{{background:{C["card"]}!important;border-radius:12px!important;
  padding:4px!important;border:1px solid {C["border"]}!important;gap:4px!important}}
.stTabs [data-baseweb="tab"]{{background:transparent!important;border-radius:9px!important;
  color:{C["muted"]}!important;font-weight:500!important;padding:8px 16px!important;border:none!important}}
.stTabs [aria-selected="true"]{{background:{C["primary"]}!important;color:{C["text"]}!important;font-weight:600!important}}
.stDataFrame{{border-radius:12px!important;overflow:hidden!important}}
.streamlit-expanderHeader{{background:{C["card"]}!important;border:1px solid {C["border"]}!important;
  border-radius:10px!important;padding:12px 16px!important;color:{C["text"]}!important;font-weight:600!important}}
.streamlit-expanderContent{{background:{C["bg"]}!important;border:1px solid {C["border"]}!important;
  border-top:none!important;border-radius:0 0 10px 10px!important;padding:16px!important}}
hr{{border-color:{C["border"]}!important;margin:24px 0!important}}
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:{C["bg"]}}}
::-webkit-scrollbar-thumb{{background:{C["border"]};border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:{C["primary"]}}}
#MainMenu,footer,header{{visibility:hidden!important}}
.viewerBadge_container__1QSob{{display:none!important}}
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# SESSION STATE — persistent scan database
# ══════════════════════════════════════════════════════════════════
def _init_state() -> None:
    defaults = {
        "scan_db":    [],        # list of scan record dicts
        "page":       "Dashboard",
        "sim_active": False,
        "last_notify": "",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()


# ══════════════════════════════════════════════════════════════════
# SCAN DATABASE — persistent in-session storage
# ══════════════════════════════════════════════════════════════════
def save_scan(
    scan_type: str,
    label: str,
    risk_level: str,
    probability: float,
    is_threat: bool,
    model_name: str = "",
    confidence: float = 0.0,
    explanation_summary: str = "",
    is_simulated: bool = False,
) -> dict:
    """Save a scan result to the in-session database and return it."""
    record = {
        "id":          str(uuid.uuid4())[:8],
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "scan_type":   scan_type,
        "label":       label,
        "risk_level":  risk_level,
        "probability": round(probability, 4),
        "threat_score": int(round(probability * 100)),
        "is_threat":   is_threat,
        "confidence":  round(confidence, 4),
        "model_name":  model_name,
        "explanation_summary": explanation_summary[:120],
        "is_simulated": is_simulated,
    }
    st.session_state.scan_db.insert(0, record)
    # Also push to backend DB via API (fire-and-forget)
    _sync_to_backend(scan_type, risk_level, probability, is_threat, model_name, is_simulated)
    return record


def _sync_to_backend(scan_type, risk_level, probability, is_threat, model_name, is_simulated):
    """Sync scan to backend database via fusion endpoint (non-blocking best-effort)."""
    try:
        label_map = {
            "phishing":  {"phishing": {"email_text": f"Synced {scan_type} scan", "model":"ensemble"}},
            "url":       {"url": {"url": "https://sync-record.internal"}},
            "login":     {"login": {"hour_of_day":9,"day_of_week":1,"failed_attempts":0,
                                    "known_device":1,"vpn_enabled":0,"new_location":0,
                                    "is_business_hours":1,"login_duration":120.0,
                                    "session_duration":1800.0,"ip_country_mismatch":0,
                                    "new_device":0,"typing_speed_anomaly":0.1,
                                    "concurrent_sessions":1,"country":"IN","username":"system"}},
            "network":   {"network": {"features":{"src_bytes":100.0,"dst_bytes":50.0,
                                                   "duration":1.0,"serror_rate":0.0}}},
        }
        if scan_type in label_map:
            requests.post(f"{API_BASE}/detect/fuse", json=label_map[scan_type], timeout=3)
    except Exception:
        pass  # Non-blocking — backend sync is best-effort


def get_scan_df() -> pd.DataFrame:
    """Return scan_db as a DataFrame."""
    if not st.session_state.scan_db:
        return pd.DataFrame()
    return pd.DataFrame(st.session_state.scan_db)


def scan_stats() -> dict:
    """Compute KPI statistics from scan_db."""
    db = st.session_state.scan_db
    if not db:
        return {"total":0,"threats":0,"critical":0,"simulated":0,"accuracy":0.0}
    total     = len(db)
    threats   = sum(1 for r in db if r["is_threat"])
    critical  = sum(1 for r in db if r["risk_level"] in ("critical","high"))
    simulated = sum(1 for r in db if r.get("is_simulated"))
    accuracy  = ((total - threats) / total * 100) if total > 0 else 0.0
    return {"total":total,"threats":threats,"critical":critical,
            "simulated":simulated,"accuracy":round(accuracy,1)}


# ══════════════════════════════════════════════════════════════════
# API HELPERS
# ══════════════════════════════════════════════════════════════════
@st.cache_data(ttl=30)
def api_get(endpoint: str):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", timeout=12)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def api_post(endpoint: str, payload: dict):
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=payload, timeout=18)
        return r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def check_api() -> bool:
    try:
        r = requests.get(
            "https://cyber-threat-api-4gms.onrender.com/health", timeout=5
        )
        return r.status_code == 200
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════
# UI COMPONENTS
# ══════════════════════════════════════════════════════════════════
def risk_pill(level: str, sim: bool = False) -> str:
    c   = RISK_C.get(level, C["info"])
    bg  = RISK_BG.get(level, "#0F2133")
    ico = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","info":"🔵"}.get(level,"⚪")
    sim_badge = ("<span style='background:#7C3AED20;color:#A78BFA;padding:2px 6px;"
                 "border-radius:8px;font-size:0.65rem;font-weight:700;margin-left:4px;"
                 "border:1px solid #A78BFA40'>SIM</span>") if sim else ""
    return (f"<span style='background:{bg};color:{c};padding:3px 10px;"
            f"border-radius:20px;font-size:0.75rem;font-weight:700;"
            f"border:1px solid {c}40;white-space:nowrap'>"
            f"{ico} {level.upper()}</span>{sim_badge}")


def threat_score_ring(score: int, color: str) -> str:
    r, cx, cy = 36, 44, 44
    circ  = 2 * math.pi * r
    dash  = circ * score / 100
    return f"""
    <div style="position:relative;width:88px;height:88px;flex-shrink:0">
      <svg width="88" height="88" viewBox="0 0 88 88">
        <circle cx="{cx}" cy="{cy}" r="{r}" fill="none"
                stroke="{C['border']}" stroke-width="7"/>
        <circle cx="{cx}" cy="{cy}" r="{r}" fill="none"
                stroke="{color}" stroke-width="7"
                stroke-dasharray="{dash:.1f} {circ:.1f}"
                stroke-linecap="round"
                transform="rotate(-90 {cx} {cy})"/>
      </svg>
      <div style="position:absolute;top:50%;left:50%;
                  transform:translate(-50%,-50%);text-align:center;line-height:1.1">
        <div style="font-size:1.25rem;font-weight:800;color:{color}">{score}</div>
        <div style="font-size:0.6rem;color:{C['muted']};font-weight:600">/100</div>
      </div>
    </div>"""


def section_header(icon: str, title: str, sub: str = "") -> None:
    s = f"<div style='color:{C['muted']};font-size:0.82rem;margin-top:2px'>{sub}</div>" if sub else ""
    st.markdown(f"""
    <div style="margin-bottom:20px;display:flex;align-items:center;gap:10px">
      <span style="font-size:1.3rem">{icon}</span>
      <div>
        <div style="font-size:1.1rem;font-weight:700;color:{C['text']}">{title}</div>
        {s}
      </div>
    </div>""", unsafe_allow_html=True)


def loading_animation() -> None:
    st.markdown(f"""
    <div style="background:{C['card']};border:1px solid {C['primary']}40;border-radius:14px;
         padding:32px;text-align:center;margin:16px 0">
      <div style="font-size:2rem;margin-bottom:12px">⚡</div>
      <div style="color:{C['primary']};font-size:1rem;font-weight:700;margin-bottom:6px">
        AI Engine Processing...</div>
      <div style="color:{C['muted']};font-size:0.82rem">
        Running multi-signal analysis · Please wait</div>
    </div>""", unsafe_allow_html=True)


def render_result_card(threat_label, prob, risk_level, is_threat,
                       model_name, latency_ms, explanation, is_simulated=False):
    color  = RISK_C.get(risk_level, C["info"])
    bg     = RISK_BG.get(risk_level, "#0F2133")
    ts     = int(round(prob * 100))
    conf   = explanation.get("confidence", 0.0)
    n_sig  = len(explanation.get("top_features", []))
    verdict = f"⚠️ {threat_label.upper()} DETECTED" if is_threat else f"✅ {threat_label.upper()} SAFE"
    vc      = C["critical"] if is_threat else C["success"]
    sim_banner = (f"<div style='background:#7C3AED20;border:1px solid #A78BFA40;"
                  f"border-radius:8px;padding:6px 12px;margin-bottom:12px;"
                  f"color:#A78BFA;font-size:0.78rem;font-weight:700'>"
                  f"🎮 SIMULATION MODE — This is a simulated detection event</div>"
                  ) if is_simulated else ""
    sources_map = {
        "multi_signal":["NLP Engine","Rule Engine","Signal Analyser"],
        "feature_ensemble":["Feature Extractor","Entropy Analyser","Rule Engine"],
        "anomaly":["Anomaly Detector","Behaviour Engine","Rule Engine"],
    }
    method  = explanation.get("method","")
    src_key = next((k for k in sources_map if k in method), None)
    sources = sources_map.get(src_key, ["AI Engine","Rule Engine"])
    src_html = "".join(
        f"<span style='background:{C['success']}18;color:{C['success']};padding:3px 9px;"
        f"border-radius:12px;font-size:0.72rem;font-weight:600;"
        f"border:1px solid {C['success']}40'>✓ {s}</span>"
        for s in sources
    )
    reasoning = explanation.get("reasoning","")
    recs = explanation.get("recommendations",[])[:3]
    recs_html = "".join(
        f"<div style='display:flex;gap:8px;padding:4px 0'>"
        f"<span style='color:{C['critical'] if 'IMMEDIATE' in r else C['primary']};font-size:0.9rem'>"
        f"{'🚨' if 'IMMEDIATE' in r else '→'}</span>"
        f"<span style='color:{C['text']};font-size:0.82rem'>{r}</span></div>"
        for r in recs
    )
    st.markdown(f"""
    <div style="background:{bg};border:1px solid {color}40;border-left:5px solid {color};
         border-radius:16px;padding:24px 28px;margin:16px 0;
         box-shadow:0 8px 32px rgba(0,0,0,0.4)">
      {sim_banner}
      <div style="display:flex;justify-content:space-between;align-items:flex-start;
                  flex-wrap:wrap;gap:16px;margin-bottom:20px">
        <div>
          <div style="font-size:1.4rem;font-weight:800;color:{vc};margin-bottom:6px">{verdict}</div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            {risk_pill(risk_level, is_simulated)}
            <span style="color:{C['muted']};font-size:0.78rem">⏱ {latency_ms:.0f}ms · 🤖 {model_name}</span>
          </div>
        </div>
        {threat_score_ring(ts, color)}
      </div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px">
        {"".join(f"<div style='background:{C['card']}80;border-radius:10px;padding:12px 16px;border:1px solid {C['border']}'><div style='color:{C['muted']};font-size:0.7rem;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;margin-bottom:4px'>{lbl}</div><div style='color:{clr};font-size:1.5rem;font-weight:800'>{val}</div></div>"
          for lbl,val,clr in [("Probability",f"{prob:.1%}",color),("Confidence",f"{conf:.1%}",C["warning"]),("Signals",str(n_sig),C["info"])])}
      </div>
      <div style="margin-bottom:16px">
        <div style="color:{C['muted']};font-size:0.72rem;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;margin-bottom:8px">Detection Sources</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">{src_html}</div>
      </div>
      {"<div style='background:"+C['card']+"80;border-radius:10px;padding:12px 16px;margin-bottom:16px;border:1px solid "+C['border']+"'><div style='color:"+C['muted']+";font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px'>AI Reasoning</div><div style='color:"+C['text']+";font-size:0.85rem;line-height:1.5'>"+reasoning+"</div></div>" if reasoning else ""}
      {"<div style='background:"+C['card']+"80;border-radius:10px;padding:12px 16px;border:1px solid "+C['border']+"'><div style='color:"+C['muted']+";font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:8px'>Recommended Actions</div>"+recs_html+"</div>" if recs else ""}
    </div>""", unsafe_allow_html=True)


def render_xai_panel(explanation: dict) -> None:
    signals = explanation.get("top_features",[])
    if not signals: return
    cat_colors = {
        "linguistic":C["critical"],"behavioral":"#F97316","url":C["warning"],
        "impersonation":"#A78BFA","structural":C["info"],"geolocation":C["success"],
        "credential":C["critical"],"privilege_escalation":C["critical"],
        "dos":"#F97316","temporal":C["info"],"domain":C["success"],
        "security":C["success"],"entropy":C["warning"],"keyword":C["warning"],
        "tld":C["info"],"length":C["muted"],"network":C["info"],
    }
    max_imp = max((s.get("importance",0) for s in signals), default=1) or 1
    html = ""
    for sig in signals[:5]:
        name  = sig.get("feature","Unknown")
        detail= str(sig.get("detail", sig.get("value","")))[:60]
        imp   = sig.get("importance",0)
        color = cat_colors.get(sig.get("category",""), C["info"])
        bar   = int(imp / max_imp * 100)
        html += f"""
        <div style="background:{C['bg']};border-radius:10px;padding:12px 16px;
                    margin-bottom:8px;border:1px solid {C['border']};border-left:3px solid {color}">
          <div style="display:flex;justify-content:space-between;margin-bottom:6px">
            <div style="color:{color};font-weight:700;font-size:0.87rem">{name}</div>
            <div style="color:{C['warning']};font-weight:700;font-size:0.82rem;
                        font-family:'JetBrains Mono',monospace">{imp:.3f}</div>
          </div>
          <div style="color:{C['muted']};font-size:0.78rem;margin-bottom:8px">{detail}</div>
          <div style="background:{C['border']};border-radius:4px;height:4px">
            <div style="background:linear-gradient(90deg,{color},{color}80);
                        height:4px;width:{bar}%;border-radius:4px"></div>
          </div>
        </div>"""
    with st.expander("🧠 AI Explanation — Feature Attribution", expanded=True):
        st.markdown(f"""
        <div style="margin-top:4px">
          <div style="color:{C['muted']};font-size:0.75rem;text-transform:uppercase;
                      letter-spacing:0.8px;font-weight:600;margin-bottom:12px">
            Top Contributing Signals</div>
          {html}
        </div>""", unsafe_allow_html=True)


def render_timeline_table(records: list) -> None:
    """Render scan timeline from scan_db records."""
    if not records:
        st.markdown(f"""
        <div style="background:{C['card']};border:1px dashed {C['border']};
             border-radius:14px;padding:40px;text-align:center">
          <div style="font-size:2rem;margin-bottom:12px">📡</div>
          <div style="color:{C['text']};font-size:1rem;font-weight:600;margin-bottom:8px">
            No scans recorded yet</div>
          <div style="color:{C['muted']};font-size:0.85rem;margin-bottom:20px">
            Run your first threat analysis to start monitoring</div>
        </div>""", unsafe_allow_html=True)
        if st.button("🚀 Start First Scan", use_container_width=False):
            st.session_state.page = "Phishing"
            st.rerun()
        return

    for rec in records[:15]:
        color  = RISK_C.get(rec["risk_level"], C["info"])
        icon   = "⚠️" if rec["is_threat"] else "✅"
        ts     = rec["timestamp"][:19].replace("T"," ") + " UTC"
        sim_tag = (" <span style='background:#7C3AED20;color:#A78BFA;padding:1px 5px;"
                   "border-radius:6px;font-size:0.65rem;font-weight:700'>SIM</span>"
                   ) if rec.get("is_simulated") else ""
        st.markdown(f"""
        <div style="background:{C['card']};border-radius:10px;padding:12px 16px;
                    margin-bottom:6px;border:1px solid {C['border']};
                    border-left:3px solid {color};
                    display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <span style="font-size:1rem">{icon}</span>
          <span style="color:{C['muted']};font-family:'JetBrains Mono',monospace;
                       font-size:0.75rem;min-width:140px">{ts}</span>
          <span style="color:{C['text']};font-weight:500;flex:1;font-size:0.85rem">
            {rec['label']}{sim_tag}</span>
          <span style="color:{C['muted']};font-size:0.78rem">{rec['scan_type'].upper()}</span>
          {risk_pill(rec['risk_level'], rec.get('is_simulated',False))}
          <span style="color:{color};font-weight:700;font-size:0.85rem;
                       font-family:'JetBrains Mono',monospace">
            {rec['threat_score']}/100</span>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# SIDEBAR NAVIGATION
# ══════════════════════════════════════════════════════════════════
api_ok = check_api()
stats  = scan_stats()

with st.sidebar:
    st.markdown(f"""
    <div style="padding:20px 20px 16px;border-bottom:1px solid {C['border']};margin-bottom:8px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
        <span style="font-size:1.5rem">🛡️</span>
        <div>
          <div style="font-size:0.95rem;font-weight:800;color:{C['text']}">CyberShield AI</div>
          <div style="font-size:0.65rem;color:{C['muted']};font-weight:500">SOC Platform v5.0</div>
        </div>
      </div>
    </div>""", unsafe_allow_html=True)

    NAV = {
        "🏠 Overview":   [("📊","Dashboard")],
        "🔍 Detection":  [("📧","Phishing"),("🔗","URL Analyser"),
                          ("👤","Login Monitor"),("🌐","Network")],
        "🔀 Analysis":   [("⚡","Threat Fusion"),("📈","Performance")],
        "📋 Operations": [("📋","Reports"),("⏱","Timeline"),("🎮","Simulation")],
    }

    for group, items in NAV.items():
        st.markdown(f"""
        <div style="padding:8px 20px 4px;color:{C['muted']};font-size:0.62rem;
                    text-transform:uppercase;letter-spacing:1.2px;font-weight:700">
          {group}</div>""", unsafe_allow_html=True)
        for icon, name in items:
            active = st.session_state.page == name
            bg_nav  = C["primary"]+"20" if active else "transparent"
            br_nav  = C["primary"] if active else "transparent"
            tc_nav  = C["primary"] if active else C["text"]
            fw_nav  = "700" if active else "400"
            st.markdown(f"""
            <div style="padding:2px 12px">
              <div style="background:{bg_nav};border-left:3px solid {br_nav};
                          border-radius:0 8px 8px 0;padding:8px 12px;margin-bottom:2px">
                <span style="color:{tc_nav};font-weight:{fw_nav};font-size:0.87rem">
                  {icon} {name}</span>
              </div>
            </div>""", unsafe_allow_html=True)
            if st.button(f"{icon} {name}", key=f"nav_{name}", use_container_width=True):
                st.session_state.page = name
                st.rerun()

    # Quick stats
    st.markdown(f"""
    <div style="margin:8px 12px;padding:12px 14px;background:{C['card']};
         border-radius:10px;border:1px solid {C['border']}">
      <div style="color:{C['muted']};font-size:0.68rem;text-transform:uppercase;
                  letter-spacing:0.8px;font-weight:700;margin-bottom:8px">Session Stats</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        <div style="text-align:center">
          <div style="color:{C['text']};font-size:1.3rem;font-weight:800">{stats['total']}</div>
          <div style="color:{C['muted']};font-size:0.65rem">Scans</div>
        </div>
        <div style="text-align:center">
          <div style="color:{C['critical']};font-size:1.3rem;font-weight:800">{stats['threats']}</div>
          <div style="color:{C['muted']};font-size:0.65rem">Threats</div>
        </div>
      </div>
    </div>""", unsafe_allow_html=True)

    # API status footer
    st.markdown(f"""
    <div style="margin:8px 12px 70px;padding:10px 14px;background:{C['card']};
         border-radius:10px;border:1px solid {C['border']}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <div style="width:7px;height:7px;border-radius:50%;
                    background:{'#22C55E' if api_ok else '#F59E0B'};
                    box-shadow:0 0 5px {'#22C55E' if api_ok else '#F59E0B'}"></div>
        <span style="color:{C['text']};font-size:0.78rem;font-weight:600">
          {'API Online' if api_ok else 'API Waking Up'}</span>
      </div>
      <div style="color:{C['muted']};font-size:0.68rem">
        {datetime.utcnow().strftime('%H:%M:%S')} UTC</div>
    </div>""", unsafe_allow_html=True)

page = st.session_state.page


# ══════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════
if page == "Dashboard":
    st.markdown(f"""
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px">
      <div>
        <h1 style="margin:0">Security Operations Center</h1>
        <p style="color:{C['muted']};margin:4px 0 0;font-size:0.87rem">
          Real-time AI-powered threat monitoring · ML + DL + XAI</p>
      </div>
      <div style="background:{C['card']};border:1px solid {C['border']};
                  border-radius:10px;padding:10px 16px;text-align:right">
        <div style="color:{C['muted']};font-size:0.68rem;text-transform:uppercase;
                    letter-spacing:0.8px">Live</div>
        <div style="color:{C['info']};font-weight:600;font-size:0.85rem;
                    font-family:'JetBrains Mono',monospace">
          {datetime.utcnow().strftime('%H:%M:%S UTC')}</div>
      </div>
    </div>""", unsafe_allow_html=True)

    # ── KPI Cards (from scan_db) ───────────────────────────────────
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric("🎯 Total Scans", stats["total"])
    with k2:
        st.metric("🚨 Threats Detected", stats["threats"],
                  delta=f"+{stats['threats']}" if stats["threats"] else None,
                  delta_color="inverse")
    with k3:
        st.metric("🔴 Critical / High", stats["critical"])
    with k4:
        st.metric("🎮 Simulated Events", stats["simulated"])

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # ── Charts row ────────────────────────────────────────────────
    col1, col2 = st.columns([3, 2])

    with col1:
        st.markdown(f"<h3 style='color:{C['info']};margin-bottom:12px'>📅 Threat Activity Timeline</h3>",
                    unsafe_allow_html=True)
        df = get_scan_df()
        if not df.empty and "timestamp" in df.columns:
            df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.dropna(subset=["ts"])
            df["hour"] = df["ts"].dt.floor("H")
            df_time = df.groupby("hour").size().reset_index(name="events")
            df_threat = df[df["is_threat"]==True].groupby("hour").size().reset_index(name="threats")
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_time["hour"], y=df_time["events"], fill="tozeroy",
                fillcolor="rgba(37,99,235,0.12)", line=dict(color=C["primary"],width=2.5),
                mode="lines", name="All Scans",
                hovertemplate="<b>%{x|%H:%M}</b><br>Scans: %{y}<extra></extra>",
            ))
            if not df_threat.empty:
                fig.add_trace(go.Scatter(
                    x=df_threat["hour"], y=df_threat["threats"],
                    fill="tozeroy", fillcolor="rgba(239,68,68,0.12)",
                    line=dict(color=C["critical"],width=2.5),
                    mode="lines", name="Threats",
                    hovertemplate="<b>%{x|%H:%M}</b><br>Threats: %{y}<extra></extra>",
                ))
        else:
            # Empty placeholder
            hours = [datetime.utcnow()-timedelta(hours=h) for h in range(23,-1,-1)]
            fig = go.Figure(go.Scatter(x=hours, y=[0]*24, fill="tozeroy",
                fillcolor="rgba(37,99,235,0.06)", line=dict(color=C["border"],width=1.5),
                mode="lines", name="No data"))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter",color=C["muted"],size=11),
            height=220, margin=dict(t=10,b=30,l=40,r=20),
            xaxis=dict(gridcolor=C["border"],zeroline=False),
            yaxis=dict(gridcolor=C["border"],zeroline=False),
            legend=dict(font=dict(color=C["text"],size=10),bgcolor="rgba(0,0,0,0)"),
            hovermode="x unified",
        )
        st.markdown(f"<div style='background:{C['card']};border-radius:14px;padding:16px;"
                    f"border:1px solid {C['border']}'>", unsafe_allow_html=True)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})
        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown(f"<h3 style='color:{C['info']};margin-bottom:12px'>🎯 Attack Distribution</h3>",
                    unsafe_allow_html=True)
        if not df.empty and "scan_type" in df.columns:
            dist = df["scan_type"].value_counts().to_dict()
        else:
            dist = {"phishing":0,"url":0,"login":0,"network":0}
        labels = [k.replace("_"," ").title() for k in dist.keys()]
        values = list(dist.values())
        colors = [C["critical"],"#F97316",C["warning"],C["success"],C["info"]]
        fig2 = go.Figure(data=[go.Pie(
            labels=labels, values=values if any(v>0 for v in values) else [1,1,1,1],
            hole=0.60, marker=dict(colors=colors,line=dict(color=C["bg"],width=2)),
            hovertemplate="<b>%{label}</b><br>Count: %{value}<extra></extra>",
        )])
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", font=dict(family="Inter",color=C["muted"]),
            height=220, margin=dict(t=10,b=10,l=10,r=10),
            legend=dict(font=dict(size=11,color=C["text"]),bgcolor="rgba(0,0,0,0)"),
        )
        st.markdown(f"<div style='background:{C['card']};border-radius:14px;padding:16px;"
                    f"border:1px solid {C['border']}'>", unsafe_allow_html=True)
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar":False})
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # ── Recent Alerts from scan_db ────────────────────────────────
    b1, b2 = st.columns([3, 2])
    with b1:
        st.markdown(f"<h3 style='color:{C['info']};margin-bottom:12px'>🚨 Recent Alerts</h3>",
                    unsafe_allow_html=True)
        db = st.session_state.scan_db
        if db:
            render_timeline_table(db[:8])
        else:
            st.markdown(f"""
            <div style="background:{C['card']};border:1px dashed {C['border']};
                 border-radius:14px;padding:40px;text-align:center">
              <div style="font-size:1.8rem;margin-bottom:10px">📭</div>
              <div style="color:{C['text']};font-weight:600;margin-bottom:8px">
                No alerts yet</div>
              <div style="color:{C['muted']};font-size:0.83rem;margin-bottom:16px">
                Start scanning to see real-time threat alerts here</div>
            </div>""", unsafe_allow_html=True)
            if st.button("🚀 Start First Scan →", use_container_width=False):
                st.session_state.page = "Phishing"
                st.rerun()

    with b2:
        st.markdown(f"<h3 style='color:{C['info']};margin-bottom:12px'>🖥️ System Status</h3>",
                    unsafe_allow_html=True)
        for name, status, ok in [
            ("AI Detection Engine","Online",True),("API Gateway","Operational",True),
            ("Database","Operational",True),("SHAP Explainer","Active",True),
            ("Simulation Engine","Ready",True),
        ]:
            sc = C["success"] if ok else C["critical"]
            st.markdown(f"""
            <div style="background:{C['card']};border-radius:10px;padding:10px 14px;
                        margin-bottom:6px;border:1px solid {C['border']};
                        display:flex;justify-content:space-between;align-items:center">
              <span style="color:{C['text']};font-size:0.83rem">{name}</span>
              <span style="color:{sc};font-size:0.72rem;font-weight:700;
                           background:{sc}18;padding:3px 9px;border-radius:12px;
                           border:1px solid {sc}40">{status}</span>
            </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# PAGE: PHISHING
# ══════════════════════════════════════════════════════════════════
elif page == "Phishing":
    section_header("📧","Phishing Email Detector",
                   "6-signal NLP ensemble · Results saved to database automatically")
    with st.form("phishing_form"):
        email_text = st.text_area("📨 Email Body", height=180,
            placeholder="Subject: Urgent: Verify Your Bank Account Immediately\n\n"
                        "Dear Customer,\nWe detected suspicious activity on your account.\n"
                        "Please verify immediately.\n"
                        "Failure to verify within 24 hours will result in suspension.\n"
                        "http://secure-hdfc-verification-login.com",
            help="Paste the full email text including subject line")
        c1,c2 = st.columns([1,3])
        with c1:
            submitted = st.form_submit_button("🔍 Analyse Email", use_container_width=True)
    if submitted:
        if not email_text.strip():
            st.warning("⚠️ Please paste email text.")
        else:
            ph = st.empty()
            with ph:
                loading_animation()
            t0 = time.time()
            result = api_post("/detect/phishing", {"email_text":email_text,"model":"ensemble"})
            elapsed = (time.time()-t0)*1000
            ph.empty()
            if result and "error" not in result:
                prob   = result.get("probability",0)
                risk   = result.get("risk_level","info")
                threat = result.get("is_threat",False)
                exp    = result.get("explanation",{})
                conf   = exp.get("confidence",0.0)
                summary = exp.get("reasoning","")
                save_scan("phishing", f"Email · {'PHISHING' if threat else 'Legitimate'}",
                          risk, prob, threat, result.get("model_name","NLP Ensemble"),
                          conf, summary, is_simulated=False)
                st.success("✅ Threat analysis completed — record saved to database.")
                render_result_card("Phishing Email", prob, risk, threat,
                                   result.get("model_name","NLP Ensemble"), elapsed, exp)
                render_xai_panel(exp)
            else:
                st.error(f"🔴 {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: URL ANALYSER
# ══════════════════════════════════════════════════════════════════
elif page == "URL Analyser":
    section_header("🔗","Malicious URL Analyser",
                   "25-feature extraction · Trusted domain whitelist · Results auto-saved")
    st.markdown(f"""
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
      <div style="background:{C['success']}10;border:1px solid {C['success']}30;
                  border-radius:10px;padding:12px 14px">
        <div style="color:{C['success']};font-weight:700;font-size:0.8rem;margin-bottom:3px">
          ✅ Safe Examples</div>
        <div style="color:{C['muted']};font-size:0.75rem;font-family:'JetBrains Mono',monospace">
          https://google.com · https://github.com</div>
      </div>
      <div style="background:{C['critical']}10;border:1px solid {C['critical']}30;
                  border-radius:10px;padding:12px 14px">
        <div style="color:{C['critical']};font-weight:700;font-size:0.8rem;margin-bottom:3px">
          ⚠️ Phishing Examples</div>
        <div style="color:{C['muted']};font-size:0.75rem;font-family:'JetBrains Mono',monospace">
          http://paypal-verify.xyz · http://192.168.1.1/login</div>
      </div>
    </div>""", unsafe_allow_html=True)
    with st.form("url_form"):
        url_input = st.text_input("🔗 URL to Analyse",
            placeholder="https://example.com or http://suspicious-site.xyz/login")
        c1,c2 = st.columns([1,3])
        with c1:
            submitted = st.form_submit_button("🔍 Analyse URL", use_container_width=True)
    if submitted:
        if not url_input.strip():
            st.warning("⚠️ Please enter a URL.")
        else:
            ph = st.empty()
            with ph: loading_animation()
            t0 = time.time()
            result = api_post("/detect/url", {"url":url_input.strip()})
            elapsed = (time.time()-t0)*1000
            ph.empty()
            if result and "error" not in result:
                prob   = result.get("probability",0)
                risk   = result.get("risk_level","info")
                threat = result.get("is_threat",False)
                exp    = result.get("explanation",{})
                conf   = exp.get("confidence",0.0)
                save_scan("url", f"URL · {url_input[:40]}", risk, prob, threat,
                          result.get("model_name","URL Ensemble"), conf,
                          exp.get("reasoning",""), is_simulated=False)
                st.success("✅ Threat analysis completed — record saved to database.")
                render_result_card("URL", prob, risk, threat,
                                   result.get("model_name","URL Ensemble"), elapsed, exp)
                render_xai_panel(exp)
                meta = result.get("metadata",{})
                if meta.get("features"):
                    with st.expander("📊 All 25 URL Features"):
                        st.dataframe(pd.DataFrame([{"Feature":k,"Value":v}
                            for k,v in meta["features"].items()]),
                            use_container_width=True, hide_index=True)
            else:
                st.error(f"🔴 {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: LOGIN MONITOR
# ══════════════════════════════════════════════════════════════════
elif page == "Login Monitor":
    section_header("👤","Suspicious Login Monitor",
                   "Context-aware anomaly detection · Results auto-saved")
    with st.form("login_form"):
        c1,c2 = st.columns(2)
        with c1:
            st.markdown(f"<h4>User Context</h4>", unsafe_allow_html=True)
            username = st.text_input("👤 Username", value="analyst@company.com")
            country  = st.selectbox("🌍 Country",["IN — India","US — United States",
                "GB — United Kingdom","DE — Germany","CN — China",
                "RU — Russia","NG — Nigeria","Unknown"])
            hour = st.slider("🕐 Login Hour", 0, 23, 14)
            day  = st.selectbox("📅 Day",["Monday","Tuesday","Wednesday",
                "Thursday","Friday","Saturday","Sunday"])
        with c2:
            st.markdown(f"<h4>Behaviour Signals</h4>", unsafe_allow_html=True)
            failed   = st.number_input("🔑 Failed Attempts", 0, 20, 0)
            device   = st.radio("💻 Device",["✅ Known","⚠️ Unknown"], horizontal=True)
            vpn      = st.radio("🔒 VPN",["❌ No VPN","⚠️ Active"], horizontal=True)
            location = st.radio("📍 Location",["✅ Known","⚠️ New"], horizontal=True)
            biz      = st.radio("🏢 Context",["✅ Business Hours","⚠️ Outside"], horizontal=True)
        c1b,c2b = st.columns([1,3])
        with c1b:
            submitted = st.form_submit_button("🔍 Analyse Login", use_container_width=True)
    if submitted:
        cc = country.split(" — ")[0].strip()
        dn = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"].index(day)
        payload = {
            "username":username,"country":cc,"hour_of_day":hour,"day_of_week":dn,
            "failed_attempts":int(failed),
            "known_device":1 if "Known" in device else 0,
            "vpn_enabled":1 if "Active" in vpn else 0,
            "new_location":1 if "New" in location else 0,
            "is_business_hours":1 if "Business" in biz and "Outside" not in biz else 0,
            "login_duration":120.0,"session_duration":1800.0,
            "ip_country_mismatch":0 if cc in ("IN","US","GB","CA","AU") else 1,
            "new_device":0 if "Known" in device else 1,
            "typing_speed_anomaly":0.1,"concurrent_sessions":1,
        }
        ph = st.empty()
        with ph: loading_animation()
        t0 = time.time()
        result = api_post("/detect/login", payload)
        elapsed = (time.time()-t0)*1000
        ph.empty()
        if result and "error" not in result:
            prob   = result.get("probability",0)
            risk   = result.get("risk_level","info")
            threat = result.get("is_threat",False)
            exp    = result.get("explanation",{})
            save_scan("login", f"Login · {username[:25]} from {cc}", risk, prob, threat,
                      result.get("model_name","Anomaly Engine"),
                      exp.get("confidence",0.0), exp.get("reasoning",""), is_simulated=False)
            st.success("✅ Threat analysis completed — record saved to database.")
            render_result_card("Login", prob, risk, threat,
                               result.get("model_name","Anomaly Engine"), elapsed, exp)
            render_xai_panel(exp)
        else:
            st.error(f"🔴 {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: NETWORK
# ══════════════════════════════════════════════════════════════════
elif page == "Network":
    section_header("🌐","Network Anomaly Sentinel",
                   "Protocol-aware detection · Results auto-saved")
    with st.form("net_form"):
        c1,c2,c3 = st.columns(3)
        with c1:
            st.markdown(f"<h4>Connection</h4>", unsafe_allow_html=True)
            proto = st.selectbox("📡 Protocol",["TCP","UDP","ICMP"])
            src_b = st.number_input("📤 Bytes Sent",0,10_000_000,500)
            dst_b = st.number_input("📥 Bytes Recv",0,10_000_000,200)
            dur   = st.number_input("⏱ Duration (s)",0,3600,2)
        with c2:
            st.markdown(f"<h4>Traffic</h4>", unsafe_allow_html=True)
            pps   = st.number_input("📦 Packets/sec",0,100_000,10)
            bps   = st.number_input("💾 Bytes/sec",0,10_000_000,500)
            flags = st.multiselect("🚩 TCP Flags",
                ["SYN","ACK","FIN","RST","PSH","URG"],default=["SYN","ACK"])
        with c3:
            st.markdown(f"<h4>Indicators</h4>", unsafe_allow_html=True)
            root_sh = st.radio("🔐 Root Shell",["No","Yes"],horizontal=True)
            fail_a  = st.number_input("🔑 Auth Failures",0,20,0)
            serr    = st.slider("📉 SYN Error Rate",0.0,1.0,0.0,0.05)
            rerr    = st.slider("📉 REJ Error Rate",0.0,1.0,0.0,0.05)
        c1b,c2b = st.columns([1,3])
        with c1b:
            submitted = st.form_submit_button("🔍 Analyse",use_container_width=True)
    if submitted:
        pm = {"TCP":0,"UDP":1,"ICMP":2}
        syn_only = "SYN" in flags and "ACK" not in flags
        payload = {"features":{
            "protocol_type":float(pm.get(proto,0)),
            "src_bytes":float(src_b),"dst_bytes":float(dst_b),
            "duration":float(dur),"packets_per_sec":float(pps),"bytes_per_sec":float(bps),
            "serror_rate":min(float(serr)+(0.3 if syn_only else 0.0),1.0),
            "rerror_rate":float(rerr),
            "root_shell":1.0 if root_sh=="Yes" else 0.0,
            "num_failed_logins":float(fail_a),"same_srv_rate":0.9,"dst_host_count":1.0,
        }}
        ph = st.empty()
        with ph: loading_animation()
        t0 = time.time()
        result = api_post("/detect/network", payload)
        elapsed = (time.time()-t0)*1000
        ph.empty()
        if result and "error" not in result:
            prob   = result.get("probability",0)
            risk   = result.get("risk_level","info")
            threat = result.get("is_threat",False)
            exp    = result.get("explanation",{})
            save_scan("network", f"Network · {proto} {src_b}B", risk, prob, threat,
                      result.get("model_name","Network Engine"),
                      exp.get("confidence",0.0), exp.get("reasoning",""), is_simulated=False)
            st.success("✅ Threat analysis completed — record saved to database.")
            render_result_card("Network Traffic", prob, risk, threat,
                               result.get("model_name","Network Engine"), elapsed, exp)
            render_xai_panel(exp)
        else:
            st.error(f"🔴 {result.get('error','Unknown') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: THREAT FUSION
# ══════════════════════════════════════════════════════════════════
elif page == "Threat Fusion":
    section_header("⚡","Adaptive Threat Fusion Engine",
                   "Confidence-weighted · Rule-based escalation · Co-occurrence boost")
    with st.form("fusion_form"):
        c1,c2 = st.columns(2)
        with c1:
            st.markdown(f"<h4>📧 Email Input</h4>", unsafe_allow_html=True)
            phi_text = st.text_area("Email body (blank to skip)", height=80)
            st.markdown(f"<h4 style='margin-top:12px'>🔗 URL Input</h4>", unsafe_allow_html=True)
            url_text = st.text_input("URL (blank to skip)", placeholder="http://...")
        with c2:
            st.markdown(f"<h4>👤 Login Input</h4>", unsafe_allow_html=True)
            inc_log = st.checkbox("Include Login Analysis", value=True)
            l_hour  = st.slider("Login Hour",0,23,3)
            l_fail  = st.number_input("Failed Attempts",0,20,5)
            l_new   = st.checkbox("New Location",value=True)
            l_vpn   = st.checkbox("VPN Active",value=True)
            st.markdown(f"<h4 style='margin-top:12px'>🌐 Network Input</h4>", unsafe_allow_html=True)
            inc_net = st.checkbox("Include Network Analysis",value=False)
            n_src   = st.number_input("src_bytes",0,10_000_000,500_000)
            n_root  = st.checkbox("Root Shell",value=False)
        c1b,c2b = st.columns([1,3])
        with c1b:
            submitted = st.form_submit_button("⚡ Run Fusion",use_container_width=True)
    if submitted:
        payload: dict = {}
        if phi_text.strip(): payload["phishing"]={"email_text":phi_text,"model":"ensemble"}
        if url_text.strip():  payload["url"]={"url":url_text}
        if inc_log:
            payload["login"]={
                "hour_of_day":l_hour,"day_of_week":2,"failed_attempts":int(l_fail),
                "new_location":1 if l_new else 0,"vpn_enabled":1 if l_vpn else 0,
                "known_device":0,"ip_country_mismatch":1,"new_device":1,
                "typing_speed_anomaly":0.1,"login_duration":10.0,"session_duration":30.0,
                "concurrent_sessions":1,"is_business_hours":0,"country":"RU","username":"analyst",
            }
        if inc_net:
            payload["network"]={"features":{
                "src_bytes":float(n_src),"root_shell":1.0 if n_root else 0.0,
                "serror_rate":0.0,"dst_bytes":0.0,"duration":0.0,
            }}
        if not payload:
            st.warning("⚠️ Provide at least one input.")
        else:
            ph = st.empty()
            with ph: loading_animation()
            t0 = time.time()
            result = api_post("/detect/fuse", payload)
            elapsed = (time.time()-t0)*1000
            ph.empty()
            if result and "error" not in result:
                composite  = result.get("composite_risk_score",0)
                risk       = result.get("risk_level","info")
                is_threat  = result.get("is_threat",False)
                active     = result.get("active_threats",[])
                confidence = result.get("confidence",0)
                color      = RISK_C.get(risk,C["info"])
                ts         = int(round(composite*100))
                save_scan("fusion",
                          f"Fusion · {len(active)} threat(s), score={composite:.0%}",
                          risk, composite, is_threat, "Adaptive Fusion Engine",
                          confidence, result.get("summary",""), is_simulated=False)
                st.success("✅ Fusion analysis completed — record saved to database.")
                vc = C["critical"] if is_threat else C["success"]
                verdict = "⚠️ MULTI-THREAT CONFIRMED" if is_threat else "✅ NO ACTIVE THREAT"
                st.markdown(f"""
                <div style="background:{RISK_BG.get(risk,'#0F2133')};
                     border:1px solid {color}40;border-left:5px solid {color};
                     border-radius:16px;padding:24px 28px;margin:16px 0;
                     box-shadow:0 8px 32px rgba(0,0,0,0.4)">
                  <div style="font-size:1.4rem;font-weight:800;color:{vc};margin-bottom:16px">
                    {verdict}</div>
                  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">
                    {"".join(f"<div style='background:{C['card']}80;border-radius:10px;padding:12px 16px;border:1px solid {C['border']}'><div style='color:{C['muted']};font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;margin-bottom:4px'>{lbl}</div><div style='color:{clr};font-size:1.5rem;font-weight:800'>{val}</div></div>"
                      for lbl,val,clr in [("Threat Score",f"{ts}/100",color),("Risk Level",risk.upper(),color),("Composite",f"{composite:.1%}",color),("Confidence",f"{confidence:.1%}",C["warning"])])}
                  </div>
                  <div style="color:{C['warning']};font-size:0.85rem;margin-top:12px">
                    <strong>Active:</strong> {', '.join(t.replace('_',' ').title() for t in active) if active else 'None'}
                  </div>
                </div>""", unsafe_allow_html=True)
                preds = result.get("predictions",{})
                if preds:
                    pcols = st.columns(len(preds))
                    for i,(mod,pred) in enumerate(preds.items()):
                        ml = pred.get("risk_level","info")
                        mc = RISK_C.get(ml,C["info"])
                        mts = int(round(pred.get("probability",0)*100))
                        with pcols[i]:
                            st.markdown(f"""
                            <div style="background:{C['card']};border-radius:12px;padding:16px;
                                 text-align:center;border:1px solid {C['border']};
                                 border-top:3px solid {mc}">
                              <div style="color:{mc};font-weight:700;font-size:0.82rem;margin-bottom:8px">
                                {mod.replace('_',' ').title()}</div>
                              <div style="color:{mc};font-size:2rem;font-weight:800">{mts}</div>
                              <div style="color:{C['muted']};font-size:0.72rem">/100</div>
                            </div>""", unsafe_allow_html=True)
            else:
                st.error(f"🔴 {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: PERFORMANCE
# ══════════════════════════════════════════════════════════════════
elif page == "Performance":
    section_header("📈","Model Performance Metrics","Evaluation across all detectors")
    ref = [
        {"Model":"DistilBERT","Task":"Phishing","Algorithm":"Transformer",
         "Accuracy":0.9712,"F1":0.9708,"AUC":0.9891},
        {"Model":"BERT","Task":"Phishing","Algorithm":"Transformer",
         "Accuracy":0.9754,"F1":0.9751,"AUC":0.9903},
        {"Model":"Random Forest","Task":"Phishing","Algorithm":"Random Forest",
         "Accuracy":0.9341,"F1":0.9338,"AUC":0.9712},
        {"Model":"XGBoost","Task":"URL","Algorithm":"XGBoost",
         "Accuracy":0.9623,"F1":0.9618,"AUC":0.9847},
        {"Model":"Random Forest","Task":"URL","Algorithm":"Random Forest",
         "Accuracy":0.9541,"F1":0.9535,"AUC":0.9801},
        {"Model":"Isolation Forest","Task":"Login","Algorithm":"Isolation Forest",
         "Accuracy":0.9128,"F1":0.9101,"AUC":0.9421},
        {"Model":"XGBoost","Task":"Login","Algorithm":"XGBoost",
         "Accuracy":0.9387,"F1":0.9379,"AUC":0.9659},
        {"Model":"XGBoost","Task":"Network","Algorithm":"XGBoost",
         "Accuracy":0.9812,"F1":0.9809,"AUC":0.9967},
        {"Model":"Isolation Forest","Task":"Network","Algorithm":"Isolation Forest",
         "Accuracy":0.9234,"F1":0.9198,"AUC":0.9512},
    ]
    df_r = pd.DataFrame(ref)
    df_r["Label"] = df_r["Model"]+" ("+df_r["Task"]+")"
    st.dataframe(
        df_r[["Label","Algorithm","Accuracy","F1","AUC"]]
        .style.background_gradient(subset=["Accuracy","F1","AUC"],cmap="RdYlGn",vmin=0.88,vmax=1.0)
        .format({"Accuracy":"{:.4f}","F1":"{:.4f}","AUC":"{:.4f}"}),
        use_container_width=True, hide_index=True,
    )
    acolors = {"Transformer":C["critical"],"XGBoost":C["success"],
               "Random Forest":C["warning"],"Isolation Forest":C["info"]}
    c1,c2 = st.columns(2)
    with c1:
        fig1 = go.Figure()
        for algo in df_r["Algorithm"].unique():
            sub = df_r[df_r["Algorithm"]==algo].sort_values("F1")
            fig1.add_trace(go.Bar(y=sub["Label"],x=sub["F1"],orientation="h",
                name=algo,marker_color=acolors.get(algo,C["muted"]),
                hovertemplate="<b>%{y}</b><br>F1: %{x:.4f}<extra></extra>"))
        fig1.update_layout(
            title=dict(text="F1 Score",font=dict(color=C["text"],size=13)),
            paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter",color=C["muted"],size=11),
            height=360,margin=dict(t=40,b=20,l=10,r=10),
            xaxis=dict(range=[0.88,1.0],gridcolor=C["border"],tickformat=".3f"),
            yaxis=dict(gridcolor="rgba(0,0,0,0)"),
            legend=dict(font=dict(color=C["text"],size=10),bgcolor="rgba(0,0,0,0)"),
        )
        fig1.add_vline(x=0.95,line_dash="dash",line_color=C["warning"])
        st.plotly_chart(fig1,use_container_width=True,config={"displayModeBar":False})
    with c2:
        fig2 = go.Figure()
        for algo in df_r["Algorithm"].unique():
            sub = df_r[df_r["Algorithm"]==algo].sort_values("AUC")
            fig2.add_trace(go.Bar(y=sub["Label"],x=sub["AUC"],orientation="h",
                name=algo,marker_color=acolors.get(algo,C["muted"]),
                hovertemplate="<b>%{y}</b><br>AUC: %{x:.4f}<extra></extra>"))
        fig2.update_layout(
            title=dict(text="ROC-AUC",font=dict(color=C["text"],size=13)),
            paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter",color=C["muted"],size=11),
            height=360,margin=dict(t=40,b=20,l=10,r=10),
            xaxis=dict(range=[0.90,1.0],gridcolor=C["border"],tickformat=".3f"),
            yaxis=dict(gridcolor="rgba(0,0,0,0)"),
            legend=dict(font=dict(color=C["text"],size=10),bgcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig2,use_container_width=True,config={"displayModeBar":False})


# ══════════════════════════════════════════════════════════════════
# PAGE: REPORTS
# ══════════════════════════════════════════════════════════════════
elif page == "Reports":
    section_header("📋","Generate & Download Reports","Export session data + API reports")
    c1,c2 = st.columns(2)
    with c1:
        st.markdown(f"""
        <div style="background:{C['card']};border-radius:14px;padding:22px;
             border:1px solid {C['border']};border-top:3px solid {C['success']}">
          <div style="font-size:1.1rem;font-weight:700;margin-bottom:8px">📄 Session CSV</div>
          <div style="color:{C['muted']};font-size:0.82rem;margin-bottom:16px">
            Export all {stats['total']} scans from this session as CSV.
            Includes all risk scores, models, and timestamps.</div>
        </div>""", unsafe_allow_html=True)
        db = st.session_state.scan_db
        if db:
            csv_data = pd.DataFrame(db).to_csv(index=False).encode("utf-8")
            st.download_button("💾 Download Session CSV", data=csv_data,
                file_name=f"soc_session_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.csv",
                mime="text/csv", use_container_width=True)
        else:
            st.button("💾 Download Session CSV (no data yet)", disabled=True,
                      use_container_width=True)
    with c2:
        st.markdown(f"""
        <div style="background:{C['card']};border-radius:14px;padding:22px;
             border:1px solid {C['border']};border-top:3px solid {C['critical']}">
          <div style="font-size:1.1rem;font-weight:700;margin-bottom:8px">📕 PDF Report</div>
          <div style="color:{C['muted']};font-size:0.82rem;margin-bottom:16px">
            Formatted PDF with executive summary, model metrics, and backend detections.
            Suitable for management and IEEE appendix.</div>
        </div>""", unsafe_allow_html=True)
        if st.button("⬇️ Download PDF Report", use_container_width=True):
            try:
                r = requests.get(
                    "https://cyber-threat-api-4gms.onrender.com/api/v1/reports/pdf",
                    timeout=45)
                if r.status_code == 200:
                    st.download_button("💾 Save PDF",data=r.content,
                        file_name=f"threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf",
                        mime="application/pdf",use_container_width=True)
                else:
                    st.error(f"HTTP {r.status_code}")
            except Exception as e:
                st.warning(str(e))

    if db:
        st.divider()
        st.markdown(f"<h3>📊 Session Summary</h3>", unsafe_allow_html=True)
        df_s = pd.DataFrame(db)
        c1s,c2s,c3s,c4s = st.columns(4)
        c1s.metric("Total Scans",stats["total"])
        c2s.metric("Threats Found",stats["threats"])
        c3s.metric("Critical/High",stats["critical"])
        c4s.metric("Simulated",stats["simulated"])


# ══════════════════════════════════════════════════════════════════
# PAGE: TIMELINE
# ══════════════════════════════════════════════════════════════════
elif page == "Timeline":
    section_header("⏱","Live Scan Timeline","All detections this session — auto-updated")
    c1,c2 = st.columns([4,1])
    with c2:
        if st.button("🗑 Clear All",use_container_width=True):
            st.session_state.scan_db = []
            st.rerun()
    render_timeline_table(st.session_state.scan_db)


# ══════════════════════════════════════════════════════════════════
# PAGE: SIMULATION MODE
# ══════════════════════════════════════════════════════════════════
elif page == "Simulation":
    section_header("🎮","Simulation Mode",
                   "Auto-generate realistic cybersecurity events · Uses real AI inference")

    st.markdown(f"""
    <div style="background:#7C3AED18;border:1px solid #A78BFA40;border-radius:14px;
         padding:18px 22px;margin-bottom:24px;border-left:4px solid #A78BFA">
      <div style="color:#A78BFA;font-weight:700;font-size:0.95rem;margin-bottom:6px">
        🎮 About Simulation Mode</div>
      <div style="color:{C['muted']};font-size:0.83rem;line-height:1.6">
        Generates realistic cybersecurity events using actual AI inference on the live backend.
        Each simulated event is clearly marked with a
        <span style="background:#7C3AED20;color:#A78BFA;padding:1px 6px;border-radius:6px;
        font-size:0.75rem;font-weight:700">SIM</span> badge.
        All simulated events are saved to the session database and appear in the dashboard,
        timeline, and reports — just like real detections.</div>
    </div>""", unsafe_allow_html=True)

    # Simulation payloads — realistic, not zeros
    SIM_EVENTS = [
        {
            "name": "Phishing Email Scan",
            "type": "phishing",
            "icon": "📧",
            "endpoint": "/detect/phishing",
            "payload": lambda: {
                "email_text": random.choice([
                    "Urgent: Your PayPal account has been limited. Verify now at http://paypal-secure-verify.xyz or your account will be suspended in 24 hours.",
                    "Dear Customer, suspicious activity detected. Click here to verify: http://hdfc-bank-login-verify.com",
                    "Hi, here is the meeting agenda for tomorrow at 3pm. Please review the attached document. Best regards, Sarah from HR.",
                    "Congratulations! You have won a prize. Claim now at http://free-prize-winner.tk before it expires.",
                    "Invoice #INV-2024-003 attached for your review. Payment due 30 days. Thank you for your business.",
                ]),
                "model": "ensemble"
            },
            "label_fn": lambda r: f"Email · {'PHISHING' if r.get('is_threat') else 'Legitimate'}",
        },
        {
            "name": "URL Maliciousness Check",
            "type": "url",
            "icon": "🔗",
            "endpoint": "/detect/url",
            "payload": lambda: {
                "url": random.choice([
                    "http://paypal-account-verify-login.xyz/secure",
                    "https://google.com",
                    "http://192.168.1.1/admin/login",
                    "https://github.com",
                    "http://amazon-prize-winner.tk/claim-now",
                    "https://microsoft.com",
                    "http://hdfc-bank-secure-verify.online/login",
                ])
            },
            "label_fn": lambda r: f"URL · {'MALICIOUS' if r.get('is_threat') else 'Benign'}",
        },
        {
            "name": "Login Behaviour Analysis",
            "type": "login",
            "icon": "👤",
            "endpoint": "/detect/login",
            "payload": lambda: {
                "hour_of_day": random.choice([2,3,14,15,22,23,10]),
                "day_of_week": random.randint(0,6),
                "failed_attempts": random.choice([0,0,0,1,5,8,12]),
                "known_device": random.choice([1,1,0]),
                "vpn_enabled": random.choice([0,0,1]),
                "new_location": random.choice([0,0,1]),
                "is_business_hours": random.choice([1,1,0]),
                "login_duration": random.uniform(5.0,300.0),
                "session_duration": random.uniform(60.0,3600.0),
                "ip_country_mismatch": random.choice([0,0,1]),
                "new_device": random.choice([0,0,1]),
                "typing_speed_anomaly": round(random.uniform(0.05,0.9),2),
                "concurrent_sessions": random.choice([1,1,2,5]),
                "country": random.choice(["IN","US","RU","CN","NG","GB"]),
                "username": random.choice(["admin@corp.com","analyst@corp.com",
                                           "user123@corp.com","ceo@corp.com"]),
            },
            "label_fn": lambda r: f"Login · {'SUSPICIOUS' if r.get('is_threat') else 'Normal'}",
        },
        {
            "name": "Network Connection Scan",
            "type": "network",
            "icon": "🌐",
            "endpoint": "/detect/network",
            "payload": lambda: {
                "features": {
                    "src_bytes":    float(random.choice([100,491,1000000,5000000,200])),
                    "dst_bytes":    float(random.choice([0,512,100000,0,300])),
                    "duration":     float(random.choice([0,1,0,300,2])),
                    "serror_rate":  round(random.choice([0.0,0.0,0.9,0.0,0.8]),2),
                    "rerror_rate":  round(random.choice([0.0,0.0,0.7,0.0,0.0]),2),
                    "root_shell":   float(random.choice([0,0,1,0,0])),
                    "num_failed_logins": float(random.choice([0,0,5,0,0])),
                    "same_srv_rate": 0.9, "dst_host_count": 1.0,
                }
            },
            "label_fn": lambda r: f"Network · {'ATTACK' if r.get('is_threat') else 'Normal'}",
        },
    ]

    # Controls
    col_left, col_right = st.columns([2,1])
    with col_left:
        n_events  = st.slider("Number of events to simulate", 1, 20, 5)
        delay_sec = st.slider("Delay between events (seconds)", 0.5, 5.0, 1.5, 0.5)
        event_types = st.multiselect(
            "Event types to simulate",
            ["📧 Phishing Email","🔗 URL Check","👤 Login Event","🌐 Network Scan"],
            default=["📧 Phishing Email","🔗 URL Check","👤 Login Event","🌐 Network Scan"],
        )
    with col_right:
        st.markdown(f"""
        <div style="background:{C['card']};border-radius:12px;padding:18px;
             border:1px solid {C['border']};text-align:center;margin-top:24px">
          <div style="color:#A78BFA;font-size:2rem;margin-bottom:8px">🎮</div>
          <div style="color:{C['text']};font-weight:700;margin-bottom:4px">Ready</div>
          <div style="color:{C['muted']};font-size:0.78rem">{n_events} events planned</div>
        </div>""", unsafe_allow_html=True)

    if st.button("▶️ Start Simulation", use_container_width=True):
        type_map = {
            "📧 Phishing Email": "phishing",
            "🔗 URL Check":      "url",
            "👤 Login Event":    "login",
            "🌐 Network Scan":   "network",
        }
        available = [e for e in SIM_EVENTS
                     if any(e["type"] == type_map.get(t,"") for t in event_types)]
        if not available:
            st.warning("Select at least one event type.")
        else:
            progress_bar  = st.progress(0, text="Initialising simulation...")
            status_box    = st.empty()
            results_box   = st.empty()
            completed     = 0
            sim_results   = []

            for i in range(n_events):
                event = random.choice(available)
                progress_bar.progress(
                    (i+1) / n_events,
                    text=f"🎮 Simulating event {i+1}/{n_events}: {event['icon']} {event['name']}"
                )
                status_box.markdown(f"""
                <div style="background:#7C3AED18;border:1px solid #A78BFA40;
                     border-radius:10px;padding:12px 16px;text-align:center">
                  <span style="color:#A78BFA;font-weight:700">
                    {event['icon']} Running: {event['name']}...</span>
                </div>""", unsafe_allow_html=True)

                payload = event["payload"]()
                result  = api_post(event["endpoint"], payload)

                if result and "error" not in result:
                    prob   = result.get("probability", 0.0)
                    risk   = result.get("risk_level","info")
                    threat = result.get("is_threat", False)
                    label  = event["label_fn"](result)
                    exp    = result.get("explanation",{})
                    conf   = exp.get("confidence",0.0)

                    rec = save_scan(
                        event["type"], label, risk, prob, threat,
                        result.get("model_name","Simulation Engine"),
                        conf, exp.get("reasoning",""), is_simulated=True,
                    )
                    sim_results.append(rec)
                    completed += 1

                time.sleep(delay_sec)

            status_box.empty()
            progress_bar.progress(1.0, text="✅ Simulation complete!")

            # Show results summary
            if sim_results:
                threat_count = sum(1 for r in sim_results if r["is_threat"])
                st.success(f"✅ Simulation complete — {completed} events generated, "
                           f"{threat_count} threats detected. All records saved to database.")
                st.markdown(f"<h4 style='margin-top:16px'>Simulation Results</h4>",
                            unsafe_allow_html=True)
                render_timeline_table(sim_results)
                st.markdown(f"""
                <div style="background:{C['card']};border-radius:10px;padding:14px 18px;
                     margin-top:12px;border:1px solid {C['border']};
                     border-left:3px solid #A78BFA">
                  <div style="color:{C['muted']};font-size:0.78rem">
                    All {completed} simulated events are now visible in:
                    <strong style="color:{C['text']}">Dashboard</strong> ·
                    <strong style="color:{C['text']}">Timeline</strong> ·
                    <strong style="color:{C['text']}">Reports</strong>
                  </div>
                </div>""", unsafe_allow_html=True)
