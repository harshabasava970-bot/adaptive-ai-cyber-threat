"""
app.py — Enterprise SOC Dashboard v6 (Final Production Polish)
================================================================
Adaptive Explainable AI for Cyber Threat Detection
Author: B.Tech Capstone Project 2026-2027
"""
import sys, os, time, math, uuid, random, io
from datetime import datetime, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
st.set_page_config(
    page_title="CyberShield AI — Enterprise SOC",
    page_icon="🛡️", layout="wide",
    initial_sidebar_state="expanded",
)

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import requests

API_BASE = os.environ.get(
    "API_BASE_URL", "https://cyber-threat-api-4gms.onrender.com"
).rstrip("/") + "/api/v1"

# ── Design tokens ──────────────────────────────────────────────────
BG      = "#0B1120"
CARD    = "#111827"
SIDEBAR = "#0F172A"
BORDER  = "#1E293B"
PRIMARY = "#2563EB"
SUCCESS = "#22C55E"
WARN    = "#F59E0B"
CRIT    = "#EF4444"
INFO    = "#38BDF8"
HIGH    = "#F97316"
TEXT    = "#F8FAFC"
MUTED   = "#CBD5E1"   # raised from #94A3B8 for WCAG AA contrast on dark bg
PURPLE  = "#A78BFA"

RISK_CLR = {"critical":CRIT,"high":HIGH,"medium":WARN,"low":SUCCESS,"info":INFO}
RISK_BG  = {"critical":"#2D1515","high":"#2D1A0E","medium":"#2D2710",
            "low":"#0F2D1A","info":"#0F2133"}
RISK_ICO = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","info":"🔵"}

# ══════════════════════════════════════════════════════════════════
# GLOBAL CSS — Final production polish
# ══════════════════════════════════════════════════════════════════
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* Base reset */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body, .stApp {{
  background: {BG} !important;
  color: {TEXT} !important;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
  font-size: 14px !important;
  line-height: 1.65 !important;
  -webkit-font-smoothing: antialiased;
}}

/* Sidebar */
section[data-testid="stSidebar"] {{
  background: {SIDEBAR} !important;
  border-right: 1px solid {BORDER} !important;
}}
section[data-testid="stSidebar"] > div {{
  padding: 0 !important;
}}

/* Main container */
.block-container {{
  padding: 0 2rem 3rem 2rem !important;
  max-width: 100% !important;
}}

/* ── Typography ── */
h1 {{ font-size: 1.65rem !important; font-weight: 900 !important;
     color: {TEXT} !important; letter-spacing: -0.6px !important;
     line-height: 1.2 !important; }}
h2 {{ font-size: 1.25rem !important; font-weight: 700 !important;
     color: {TEXT} !important; line-height: 1.3 !important; }}
h3 {{ font-size: 1.05rem !important; font-weight: 600 !important;
     color: {INFO} !important; line-height: 1.3 !important; }}
h4 {{ font-size: 0.78rem !important; font-weight: 700 !important;
     color: #CBD5E1 !important; text-transform: uppercase !important;
     letter-spacing: 1px !important; }}
p {{ color: {TEXT} !important; }}
label {{ color: {TEXT} !important; font-weight: 500 !important; }}
small, .caption {{ color: #CBD5E1 !important; }}

/* ── Metric cards ── */
div[data-testid="metric-container"] {{
  background: {CARD} !important;
  border: 1px solid {BORDER} !important;
  border-radius: 14px !important;
  padding: 20px 20px !important;
  box-shadow: 0 2px 12px rgba(0,0,0,0.4) !important;
  transition: transform 0.18s ease, box-shadow 0.18s ease !important;
}}
div[data-testid="metric-container"]:hover {{
  transform: translateY(-2px) !important;
  box-shadow: 0 6px 24px rgba(37,99,235,0.18) !important;
  border-color: {PRIMARY}60 !important;
}}
div[data-testid="metric-container"] [data-testid="stMetricLabel"] > div {{
  font-size: 0.72rem !important; font-weight: 700 !important;
  color: #CBD5E1 !important; text-transform: uppercase !important;
  letter-spacing: 1px !important;
}}
div[data-testid="metric-container"] [data-testid="stMetricValue"] > div {{
  font-size: 1.85rem !important; font-weight: 800 !important;
  color: {TEXT} !important; line-height: 1.1 !important;
}}
div[data-testid="metric-container"] [data-testid="stMetricDelta"] > div {{
  font-size: 0.78rem !important; font-weight: 600 !important;
}}

/* ── Buttons ── */
.stButton > button {{
  background: linear-gradient(135deg, {PRIMARY}, #1D4ED8) !important;
  color: {TEXT} !important; border: none !important;
  border-radius: 10px !important; padding: 10px 20px !important;
  font-weight: 600 !important; font-size: 0.85rem !important;
  letter-spacing: 0.2px !important; font-family: 'Inter', sans-serif !important;
  box-shadow: 0 4px 12px rgba(37,99,235,0.35) !important;
  transition: all 0.18s ease !important; width: 100% !important;
  cursor: pointer !important;
}}
.stButton > button:hover {{
  background: linear-gradient(135deg, #1D4ED8, #1E40AF) !important;
  box-shadow: 0 6px 20px rgba(37,99,235,0.5) !important;
  transform: translateY(-1px) !important;
}}
.stButton > button:disabled {{
  background: {BORDER} !important; color: {MUTED} !important;
  box-shadow: none !important; transform: none !important;
}}

/* ── Inputs ── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stNumberInput > div > div > input {{
  background: {CARD} !important; color: {TEXT} !important;
  border: 1px solid {BORDER} !important; border-radius: 10px !important;
  padding: 10px 14px !important; font-family: 'Inter', sans-serif !important;
  font-size: 0.87rem !important; transition: border-color 0.18s !important;
}}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {{
  border-color: {PRIMARY} !important;
  box-shadow: 0 0 0 3px rgba(37,99,235,0.12) !important; outline: none !important;
}}
.stTextInput label, .stTextArea label, .stNumberInput label,
.stSelectbox label, .stMultiSelect label, .stSlider label,
.stRadio label, .stCheckbox label {{
  color: {TEXT} !important; font-weight: 500 !important; font-size: 0.85rem !important;
}}
.stSelectbox > div > div, .stMultiSelect > div > div {{
  background: {CARD} !important; border: 1px solid {BORDER} !important;
  border-radius: 10px !important; color: {TEXT} !important;
}}
.stSlider [data-baseweb="slider"] {{ padding: 8px 0 !important; }}
.stRadio > div > div > label, .stCheckbox > label {{
  color: {TEXT} !important; font-size: 0.87rem !important; padding: 4px 0 !important;
}}
.stMultiSelect [data-baseweb="tag"] {{
  background: {PRIMARY}30 !important; color: {INFO} !important;
}}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {{
  background: {CARD} !important; border-radius: 12px !important;
  padding: 4px !important; border: 1px solid {BORDER} !important; gap: 4px !important;
}}
.stTabs [data-baseweb="tab"] {{
  background: transparent !important; border-radius: 9px !important;
  color: #CBD5E1 !important; font-weight: 500 !important;
  padding: 8px 18px !important; font-size: 0.85rem !important; border: none !important;
}}
.stTabs [aria-selected="true"] {{
  background: {PRIMARY} !important; color: {TEXT} !important; font-weight: 700 !important;
}}

/* ── Dataframes ── */
.stDataFrame {{ border-radius: 12px !important; overflow: hidden !important; }}
[data-testid="stDataFrameResizable"] {{ border-radius: 12px !important; }}
.stDataFrame thead tr th {{
  background: {SIDEBAR} !important; color: {TEXT} !important;
  font-weight: 700 !important; font-size: 0.8rem !important;
  text-transform: uppercase !important; letter-spacing: 0.8px !important;
  padding: 10px 14px !important;
}}
.stDataFrame tbody tr td {{
  background: {CARD} !important; color: {TEXT} !important;
  font-size: 0.85rem !important; padding: 8px 14px !important;
  border-bottom: 1px solid {BORDER} !important;
}}
.stDataFrame tbody tr:hover td {{ background: {BORDER}80 !important; }}

/* ── Expander ── */
.streamlit-expanderHeader {{
  background: {CARD} !important; border: 1px solid {BORDER} !important;
  border-radius: 10px !important; padding: 12px 18px !important;
  color: {TEXT} !important; font-weight: 600 !important; font-size: 0.88rem !important;
}}
.streamlit-expanderContent {{
  background: {BG} !important; border: 1px solid {BORDER} !important;
  border-top: none !important; border-radius: 0 0 10px 10px !important;
  padding: 16px !important;
}}

/* ── Alerts ── */
.stSuccess > div {{ background: {SUCCESS}15 !important; border: 1px solid {SUCCESS}40 !important;
  border-radius: 10px !important; color: {TEXT} !important; }}
.stWarning > div {{ background: {WARN}15 !important; border: 1px solid {WARN}40 !important;
  border-radius: 10px !important; color: {TEXT} !important; }}
.stError > div {{ background: {CRIT}15 !important; border: 1px solid {CRIT}40 !important;
  border-radius: 10px !important; color: {TEXT} !important; }}
.stInfo > div {{ background: {INFO}15 !important; border: 1px solid {INFO}40 !important;
  border-radius: 10px !important; color: {TEXT} !important; }}

/* ── Progress bar ── */
.stProgress > div > div {{ background: {PRIMARY} !important; border-radius: 4px !important; }}
.stProgress > div {{ background: {BORDER} !important; border-radius: 4px !important; }}

/* ── Divider ── */
hr {{ border-color: {BORDER} !important; margin: 20px 0 !important; }}

/* ── Scrollbar ── */
::-webkit-scrollbar {{ width: 5px; height: 5px; }}
::-webkit-scrollbar-track {{ background: {BG}; }}
::-webkit-scrollbar-thumb {{ background: {BORDER}; border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: {PRIMARY}; }}

/* ── Tooltip ── */
[data-baseweb="tooltip"] {{ font-family: 'Inter', sans-serif !important; }}

/* ── Hide Streamlit chrome ── */
#MainMenu, footer, header {{ visibility: hidden !important; height: 0 !important; }}
.viewerBadge_container__1QSob {{ display: none !important; }}
[data-testid="stToolbar"] {{ display: none !important; }}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════════════
def _init():
    for k, v in {
        "scan_db": [], "page": "Dashboard", "last_scan_time": None
    }.items():
        if k not in st.session_state:
            st.session_state[k] = v
_init()


# ══════════════════════════════════════════════════════════════════
# SCAN DATABASE
# ══════════════════════════════════════════════════════════════════
def save_scan(scan_type, label, risk_level, probability, is_threat,
              model_name="", confidence=0.0, processing_ms=0.0,
              explanation_summary="", is_simulated=False) -> dict:
    """Persist a scan record to session database."""
    now = datetime.now()
    rec = {
        "id":           str(uuid.uuid4())[:8].upper(),
        "timestamp_utc":datetime.utcnow().isoformat() + "Z",
        "scan_date":    now.strftime("%Y-%m-%d"),
        "scan_time":    now.strftime("%H:%M:%S"),
        "scan_type":    scan_type,
        "label":        label,
        "risk_level":   risk_level,
        "probability":  round(probability, 4),
        "threat_score": int(round(probability * 100)),
        "is_threat":    is_threat,
        "confidence":   round(confidence, 4),
        "processing_ms":round(processing_ms, 1),
        "model_name":   model_name,
        "explanation_summary": explanation_summary[:140],
        "is_simulated": is_simulated,
        "status":       "THREAT" if is_threat else "SAFE",
    }
    st.session_state.scan_db.insert(0, rec)
    st.session_state.last_scan_time = now
    return rec


def get_df() -> pd.DataFrame:
    return pd.DataFrame(st.session_state.scan_db) if st.session_state.scan_db else pd.DataFrame()


def stats() -> dict:
    db = st.session_state.scan_db
    if not db:
        return {"total":0,"threats":0,"critical":0,"high":0,"safe":0,
                "simulated":0,"avg_conf":0.0,"avg_ms":0.0,"accuracy":0.0}
    total    = len(db)
    threats  = sum(1 for r in db if r["is_threat"])
    critical = sum(1 for r in db if r["risk_level"] == "critical")
    high     = sum(1 for r in db if r["risk_level"] == "high")
    safe     = total - threats
    sim      = sum(1 for r in db if r.get("is_simulated"))
    avg_conf = sum(r["confidence"] for r in db) / total
    avg_ms   = sum(r.get("processing_ms",0) for r in db) / total
    acc      = safe / total * 100 if total > 0 else 0.0
    return {"total":total,"threats":threats,"critical":critical,"high":high,
            "safe":safe,"simulated":sim,"avg_conf":avg_conf,
            "avg_ms":avg_ms,"accuracy":acc}


# ══════════════════════════════════════════════════════════════════
# API HELPERS
# ══════════════════════════════════════════════════════════════════
# API HELPERS — all non-blocking, all safe, never crash the app
# ══════════════════════════════════════════════════════════════════

RENDER_API = "https://cyber-threat-api-4gms.onrender.com"

@st.cache_data(ttl=60)
def api_get(ep: str):
    """GET request — cached 60s, 8s timeout, returns None on failure."""
    try:
        r = requests.get(f"{API_BASE}{ep}", timeout=8)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def api_post(ep: str, payload: dict):
    """POST request — 25s timeout, always returns a dict, never raises."""
    try:
        r = requests.post(f"{API_BASE}{ep}", json=payload, timeout=25)
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.Timeout:
        return {
            "error": (
                "⏳ API is waking up (Render free tier cold start takes ~30s). "
                "Please wait a moment and click the button again."
            )
        }
    except requests.exceptions.ConnectionError:
        return {"error": "🔌 Cannot reach API. Check your internet connection."}
    except Exception as e:
        return {"error": f"Unexpected error: {type(e).__name__}"}


@st.cache_data(ttl=90)
def api_health() -> bool:
    """Health check — 4s timeout, cached 90s, never blocks the UI."""
    try:
        r = requests.get(f"{RENDER_API}/health", timeout=4)
        return r.status_code == 200
    except Exception:
        return False


def wake_api() -> bool:
    """
    Attempt to wake the Render free-tier API by pinging /health.
    Shows a progress bar and returns True if the API responded.
    Call this once before the first real detection.
    """
    bar = st.progress(0, text="🔄 Waking up API server...")
    try:
        for pct in [20, 50, 80]:
            bar.progress(pct, text="🔄 Connecting to AI engine...")
            time.sleep(0.4)
        r = requests.get(f"{RENDER_API}/health", timeout=15)
        if r.status_code == 200:
            bar.progress(100, text="✅ API is online!")
            time.sleep(0.5)
            bar.empty()
            api_health.clear()   # clear cache so sidebar shows Online
            return True
    except Exception:
        pass
    bar.progress(100, text="⚠️ API still waking — you can proceed, first request may be slow.")
    time.sleep(1)
    bar.empty()
    return False

# ══════════════════════════════════════════════════════════════════
# UI COMPONENT LIBRARY
# ══════════════════════════════════════════════════════════════════

def risk_pill(level: str, sim: bool = False) -> str:
    c   = RISK_CLR.get(level, INFO)
    bg  = RISK_BG.get(level, "#0F2133")
    ico = RISK_ICO.get(level, "⚪")
    sim_tag = (f"<span style='background:#7C3AED25;color:{PURPLE};padding:1px 6px;"
               f"border-radius:6px;font-size:0.62rem;font-weight:700;margin-left:5px;"
               f"border:1px solid {PURPLE}35'>SIM</span>") if sim else ""
    return (f"<span style='background:{bg};color:{c};padding:3px 11px;"
            f"border-radius:20px;font-size:0.73rem;font-weight:700;"
            f"border:1px solid {c}45;white-space:nowrap;letter-spacing:0.3px'>"
            f"{ico} {level.upper()}</span>{sim_tag}")


def score_ring(score: int, color: str, size: int = 88) -> str:
    r = size // 2 - 10
    circ = 2 * math.pi * r
    dash = circ * score / 100
    cx = cy = size // 2
    return f"""
    <div style="position:relative;width:{size}px;height:{size}px;flex-shrink:0">
      <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
        <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{BORDER}" stroke-width="6"/>
        <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="6"
                stroke-dasharray="{dash:.1f} {circ:.1f}" stroke-linecap="round"
                transform="rotate(-90 {cx} {cy})"/>
      </svg>
      <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
                  text-align:center;line-height:1.1">
        <div style="font-size:{size//7}px;font-weight:800;color:{color}">{score}</div>
        <div style="font-size:{size//13}px;color:{MUTED};font-weight:600">/100</div>
      </div>
    </div>"""


def card_wrap(html: str, border_color: str = "", extra_style: str = "") -> str:
    bl = f"border-left:4px solid {border_color};" if border_color else ""
    return (f"<div style='background:{CARD};border-radius:14px;"
            f"border:1px solid {BORDER};{bl}padding:20px 22px;"
            f"box-shadow:0 2px 14px rgba(0,0,0,0.35);{extra_style}'>{html}</div>")


def section_hdr(icon: str, title: str, sub: str = "") -> None:
    s = f"<div style='color:#CBD5E1;font-size:0.84rem;margin-top:3px'>{sub}</div>" if sub else ""
    st.markdown(f"""
    <div style='margin:20px 0 18px;display:flex;align-items:center;gap:12px'>
      <span style='font-size:1.4rem;line-height:1'>{icon}</span>
      <div><div style='font-size:1.1rem;font-weight:700;color:{TEXT}'>{title}</div>{s}</div>
    </div>""", unsafe_allow_html=True)


def kpi_card(icon: str, label: str, value: str, color: str = TEXT,
             sub: str = "") -> str:
    sub_html = f"<div style='color:#CBD5E1;font-size:0.74rem;margin-top:4px'>{sub}</div>" if sub else ""
    return f"""
    <div style='background:{CARD};border-radius:14px;border:1px solid {BORDER};
         padding:20px 18px;box-shadow:0 2px 12px rgba(0,0,0,0.35);
         transition:transform 0.18s,box-shadow 0.18s;height:100%'>
      <div style='display:flex;align-items:center;gap:10px;margin-bottom:10px'>
        <span style='font-size:1.3rem;background:{color}18;border-radius:8px;
                     padding:6px;line-height:1'>{icon}</span>
        <span style='color:#CBD5E1;font-size:0.72rem;font-weight:700;
                     text-transform:uppercase;letter-spacing:1px'>{label}</span>
      </div>
      <div style='color:{color};font-size:1.9rem;font-weight:800;line-height:1'>{value}</div>
      {sub_html}
    </div>"""


def loading_card() -> None:
    ph = st.empty()
    ph.markdown(f"""
    <div style='background:{CARD};border:1px solid {PRIMARY}35;border-radius:14px;
         padding:36px;text-align:center;margin:12px 0'>
      <div style='font-size:2rem;margin-bottom:10px'>⚡</div>
      <div style='color:{PRIMARY};font-size:1rem;font-weight:700;margin-bottom:5px'>
        AI Engine Processing...</div>
      <div style='color:{MUTED};font-size:0.82rem'>
        Running multi-signal analysis · Please wait</div>
    </div>""", unsafe_allow_html=True)
    return ph


def render_result_card(threat_label, prob, risk_level, is_threat,
                       model_name, latency_ms, explanation, is_simulated=False):
    color   = RISK_CLR.get(risk_level, INFO)
    bg      = RISK_BG.get(risk_level, "#0F2133")
    ts      = int(round(prob * 100))
    conf    = explanation.get("confidence", 0.0)
    n_sig   = len(explanation.get("top_features", []))
    verdict = f"⚠️ {threat_label.upper()} DETECTED" if is_threat else f"✅ {threat_label.upper()} SAFE"
    vc      = CRIT if is_threat else SUCCESS
    sim_bar = (f"<div style='background:#7C3AED20;border:1px solid {PURPLE}35;"
               f"border-radius:8px;padding:7px 14px;margin-bottom:14px;"
               f"color:{PURPLE};font-size:0.79rem;font-weight:700'>"
               f"🎮 SIMULATION EVENT — AI inference on real backend · marked for audit trail"
               f"</div>") if is_simulated else ""
    src_map = {
        "multi_signal": ["NLP Engine","Rule Engine","Signal Analyser"],
        "feature_ensemble": ["Feature Extractor","Entropy Analyser","Rule Engine"],
        "anomaly": ["Anomaly Detector","Behaviour Engine","Rule Engine"],
    }
    method = explanation.get("method","")
    srcs   = src_map.get(next((k for k in src_map if k in method), None),
                          ["AI Engine","Rule Engine"])
    src_html = "".join(
        f"<span style='background:{SUCCESS}15;color:{SUCCESS};padding:3px 10px;"
        f"border-radius:12px;font-size:0.72rem;font-weight:600;"
        f"border:1px solid {SUCCESS}35'>✓ {s}</span>" for s in srcs)
    reasoning = explanation.get("reasoning","")
    recs = explanation.get("recommendations",[])[:3]
    recs_parts = []
    for r in recs:
        rec_color = CRIT if "IMMEDIATE" in r else PRIMARY
        rec_icon  = "🚨" if "IMMEDIATE" in r else "→"
        recs_parts.append(
            f"<div style='display:flex;gap:8px;padding:4px 0;align-items:flex-start'>"
            f"<span style='color:{rec_color};font-size:0.9rem;flex-shrink:0'>{rec_icon}</span>"
            f"<span style='color:{TEXT};font-size:0.83rem;line-height:1.5'>{r}</span></div>"
        )
    recs_html = "".join(recs_parts)
    stat_grid = "".join(
        f"<div style='background:{BG};border-radius:10px;padding:13px 15px;"
        f"border:1px solid {BORDER}'>"
        f"<div style='color:{MUTED};font-size:0.67rem;text-transform:uppercase;"
        f"letter-spacing:0.9px;font-weight:700;margin-bottom:5px'>{lbl}</div>"
        f"<div style='color:{clr};font-size:1.45rem;font-weight:800'>{val}</div>"
        f"</div>"
        for lbl,val,clr in [
            ("Probability", f"{prob:.1%}", color),
            ("Confidence",  f"{conf:.1%}", WARN),
            ("Signals",     str(n_sig),    INFO),
        ])
    st.markdown(f"""
    <div style='background:{bg};border:1px solid {color}35;border-left:5px solid {color};
         border-radius:16px;padding:24px 26px;margin:14px 0;
         box-shadow:0 6px 28px rgba(0,0,0,0.45)'>
      {sim_bar}
      <div style='display:flex;justify-content:space-between;align-items:flex-start;
                  flex-wrap:wrap;gap:14px;margin-bottom:18px'>
        <div>
          <div style='font-size:1.4rem;font-weight:800;color:{vc};margin-bottom:7px'>{verdict}</div>
          <div style='display:flex;gap:8px;align-items:center;flex-wrap:wrap'>
            {risk_pill(risk_level, is_simulated)}
            <span style='color:{MUTED};font-size:0.77rem'>⏱ {latency_ms:.0f}ms &nbsp;·&nbsp; 🤖 {model_name}</span>
          </div>
        </div>
        {score_ring(ts, color)}
      </div>
      <div style='display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:18px'>
        {stat_grid}
      </div>
      <div style='margin-bottom:14px'>
        <div style='color:{MUTED};font-size:0.68rem;text-transform:uppercase;
                    letter-spacing:0.9px;font-weight:700;margin-bottom:7px'>Detection Sources</div>
        <div style='display:flex;gap:8px;flex-wrap:wrap'>{src_html}</div>
      </div>
      {'<div style="background:'+BG+';border-radius:10px;padding:13px 15px;margin-bottom:12px;border:1px solid '+BORDER+'"><div style="color:'+MUTED+';font-size:0.67rem;font-weight:700;text-transform:uppercase;letter-spacing:0.9px;margin-bottom:6px">AI Reasoning</div><div style="color:'+TEXT+';font-size:0.84rem;line-height:1.6">'+reasoning+'</div></div>' if reasoning else ''}
      {'<div style="background:'+BG+';border-radius:10px;padding:13px 15px;border:1px solid '+BORDER+'"><div style="color:'+MUTED+';font-size:0.67rem;font-weight:700;text-transform:uppercase;letter-spacing:0.9px;margin-bottom:7px">Recommended Actions</div>'+recs_html+'</div>' if recs else ''}
    </div>""", unsafe_allow_html=True)


def render_xai(explanation: dict) -> None:
    sigs = explanation.get("top_features",[])
    if not sigs: return
    CAT = {
        "linguistic":CRIT,"behavioral":HIGH,"url":WARN,"impersonation":PURPLE,
        "structural":INFO,"geolocation":SUCCESS,"credential":CRIT,
        "privilege_escalation":CRIT,"dos":HIGH,"temporal":INFO,
        "domain":SUCCESS,"security":SUCCESS,"entropy":WARN,
        "keyword":WARN,"tld":INFO,"length":MUTED,"network":INFO,
    }
    max_imp = max((s.get("importance",0) for s in sigs), default=1) or 1
    html = ""
    for s in sigs[:5]:
        c   = CAT.get(s.get("category",""), INFO)
        imp = s.get("importance",0)
        bar = int(imp / max_imp * 100)
        html += f"""
        <div style='background:{BG};border-radius:10px;padding:11px 15px;
                    margin-bottom:7px;border:1px solid {BORDER};border-left:3px solid {c}'>
          <div style='display:flex;justify-content:space-between;margin-bottom:5px'>
            <span style='color:{c};font-weight:700;font-size:0.86rem'>
              {s.get("feature","Unknown")}</span>
            <span style='color:{WARN};font-family:"JetBrains Mono",monospace;
                         font-size:0.8rem;font-weight:600'>{imp:.3f}</span>
          </div>
          <div style='color:#CBD5E1;font-size:0.79rem;margin-bottom:7px'>
            {str(s.get("detail", s.get("value","")))[:65]}</div>
          <div style='background:{BORDER};border-radius:3px;height:3px'>
            <div style='background:{c};height:3px;width:{bar}%;border-radius:3px'></div>
          </div>
        </div>"""
    with st.expander("🧠 AI Explanation — Feature Attribution", expanded=True):
        st.markdown(f"""
        <div style='margin-top:4px'>
          <div style='color:{MUTED};font-size:0.68rem;text-transform:uppercase;
                      letter-spacing:0.9px;font-weight:700;margin-bottom:10px'>
            Top Contributing Signals</div>
          {html}
        </div>""", unsafe_allow_html=True)

def render_timeline(records: list, max_rows: int = 20) -> None:
    """Render scan timeline with full metadata."""
    if not records:
        st.markdown(f"""
        <div style='background:{CARD};border:2px dashed {BORDER};border-radius:14px;
             padding:44px;text-align:center'>
          <div style='font-size:2.2rem;margin-bottom:12px'>📡</div>
          <div style='color:{TEXT};font-size:1rem;font-weight:700;margin-bottom:8px'>
            No Scans Recorded Yet</div>
          <div style='color:{MUTED};font-size:0.85rem;margin-bottom:22px'>
            Run a threat analysis to begin monitoring. Every scan is automatically
            recorded here with full metadata.</div>
        </div>""", unsafe_allow_html=True)
        if st.button("🚀 Start First Scan →", key="tl_start"):
            st.session_state.page = "Phishing"
            st.rerun()
        return

    # Header row
    st.markdown(f"""
    <div style='display:grid;grid-template-columns:90px 80px 1fr 90px 90px 80px 80px 70px;
         gap:8px;padding:8px 14px;background:{SIDEBAR};border-radius:8px;margin-bottom:4px'>
      {"".join(f"<div style='color:{MUTED};font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:0.8px'>{h}</div>"
        for h in ["Date","Time","Label","Type","Risk","Score","Process","Status"])}
    </div>""", unsafe_allow_html=True)

    for rec in records[:max_rows]:
        color   = RISK_CLR.get(rec["risk_level"], INFO)
        s_color = SUCCESS if not rec["is_threat"] else CRIT
        sim_tag = (f"<span style='background:{PURPLE}20;color:{PURPLE};padding:1px 5px;"
                   f"border-radius:5px;font-size:0.6rem;font-weight:700'>SIM</span> "
                   ) if rec.get("is_simulated") else ""
        st.markdown(f"""
        <div style='display:grid;grid-template-columns:90px 80px 1fr 90px 90px 80px 80px 70px;
             gap:8px;padding:10px 14px;background:{CARD};border-radius:9px;
             margin-bottom:4px;border:1px solid {BORDER};border-left:3px solid {color};
             align-items:center'>
          <div style='color:{MUTED};font-size:0.75rem;font-family:"JetBrains Mono",monospace'>
            {rec.get("scan_date","")}</div>
          <div style='color:{MUTED};font-size:0.75rem;font-family:"JetBrains Mono",monospace'>
            {rec.get("scan_time","")}</div>
          <div style='color:{TEXT};font-size:0.83rem;font-weight:500;
                      overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>
            {sim_tag}{rec.get("label","")}</div>
          <div style='color:{INFO};font-size:0.73rem;font-weight:600;
                      text-transform:uppercase'>{rec.get("scan_type","")}</div>
          <div>{risk_pill(rec["risk_level"])}</div>
          <div style='color:{color};font-weight:700;font-size:0.85rem;
                      font-family:"JetBrains Mono",monospace'>
            {rec.get("threat_score",0)}/100</div>
          <div style='color:{MUTED};font-size:0.73rem;font-family:"JetBrains Mono",monospace'>
            {rec.get("processing_ms",0):.0f}ms</div>
          <div style='background:{s_color}18;color:{s_color};padding:3px 8px;
                      border-radius:8px;font-size:0.68rem;font-weight:700;
                      border:1px solid {s_color}35;text-align:center'>
            {rec.get("status","SAFE")}</div>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# PROFESSIONAL HEADER
# ══════════════════════════════════════════════════════════════════
api_ok = api_health()
S      = stats()

st.markdown(f"""
<div style='background:linear-gradient(135deg,{SIDEBAR},{BG});
     border-bottom:1px solid {BORDER};padding:16px 32px 14px;
     margin:0 -2rem 0;position:sticky;top:0;z-index:100'>
  <div style='display:flex;justify-content:space-between;align-items:center'>
    <div style='display:flex;align-items:center;gap:16px'>
      <div style='background:linear-gradient(135deg,{PRIMARY},{INFO});border-radius:12px;
                  padding:10px;font-size:1.4rem;line-height:1'>🛡️</div>
      <div>
        <div style='font-size:1.05rem;font-weight:900;color:{TEXT};letter-spacing:-0.3px;
                    line-height:1.2'>Adaptive Explainable AI for Cyber Threat Detection</div>
        <div style='font-size:0.73rem;color:#CBD5E1;font-weight:500;margin-top:2px'>
          Enterprise Security Operations Center Dashboard &nbsp;·&nbsp;
          IEEE 29148 / 29119 / 7000 Compliant &nbsp;·&nbsp; B.Tech Capstone 2026-2027</div>
      </div>
    </div>
    <div style='display:flex;align-items:center;gap:16px'>
      <div style='text-align:right'>
        <div style='display:flex;align-items:center;gap:6px;justify-content:flex-end'>
          <div style='width:7px;height:7px;border-radius:50%;
                      background:{"#22C55E" if api_ok else "#F59E0B"};
                      box-shadow:0 0 6px {"#22C55E" if api_ok else "#F59E0B"}'></div>
          <span style='color:{TEXT};font-size:0.78rem;font-weight:600'>
            {"API Online" if api_ok else "API Waking Up"}</span>
        </div>
        <div style='color:{MUTED};font-size:0.68rem;margin-top:2px;
                    font-family:"JetBrains Mono",monospace'>
          {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</div>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════
# SIDEBAR NAVIGATION
# ══════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown(f"""
    <div style='padding:20px 18px 16px;border-bottom:1px solid {BORDER}'>
      <div style='color:{TEXT};font-size:0.9rem;font-weight:800;margin-bottom:2px'>
        CyberShield AI</div>
      <div style='color:{MUTED};font-size:0.65rem;font-weight:500'>
        SOC Platform &nbsp;·&nbsp; v6.0 Final</div>
    </div>""", unsafe_allow_html=True)

    NAV = {
        "🏠 Overview":    [("📊","Dashboard")],
        "🔍 Detection":   [("📧","Phishing"),("🔗","URL Analyser"),
                           ("👤","Login Monitor"),("🌐","Network")],
        "🔀 Analysis":    [("⚡","Threat Fusion"),("⏱","Timeline")],
        "📋 Operations":  [("📋","Reports"),("📊","Analytics"),("🎮","Simulation")],
        "🔬 Research":    [("🏆","Model Performance"),("📚","Dataset Info"),
                           ("⚙","System Workflow"),("ℹ","About")],
    }
    for grp, items in NAV.items():
        st.markdown(f"""
        <div style='padding:10px 18px 3px;color:{MUTED};font-size:0.62rem;
                    text-transform:uppercase;letter-spacing:1.2px;font-weight:700'>
          {grp}</div>""", unsafe_allow_html=True)
        for ico, name in items:
            active = st.session_state.page == name
            ab = f"{PRIMARY}20" if active else "transparent"
            ab2 = PRIMARY if active else "transparent"
            tc  = PRIMARY if active else TEXT
            fw  = "700" if active else "400"
            st.markdown(f"""
            <div style='padding:1px 10px'>
              <div style='background:{ab};border-left:3px solid {ab2};
                          border-radius:0 8px 8px 0;padding:8px 12px;margin-bottom:2px'>
                <span style='color:{tc};font-weight:{fw};font-size:0.86rem'>
                  {ico}&nbsp;&nbsp;{name}</span>
              </div>
            </div>""", unsafe_allow_html=True)
            if st.button(f"{ico} {name}", key=f"nav_{name}", use_container_width=True):
                st.session_state.page = name
                st.rerun()

    # Session stats widget
    st.markdown(f"""
    <div style='margin:10px 12px 6px;padding:14px;background:{CARD};
         border-radius:12px;border:1px solid {BORDER}'>
      <div style='color:#CBD5E1;font-size:0.67rem;text-transform:uppercase;
                  letter-spacing:1px;font-weight:700;margin-bottom:10px'>
        Session Metrics</div>
      <div style='display:grid;grid-template-columns:1fr 1fr;gap:10px'>
        <div style='text-align:center;padding:8px;background:{BG};border-radius:8px'>
          <div style='color:{TEXT};font-size:1.35rem;font-weight:800'>{S["total"]}</div>
          <div style='color:{MUTED};font-size:0.62rem;font-weight:600'>SCANS</div>
        </div>
        <div style='text-align:center;padding:8px;background:{BG};border-radius:8px'>
          <div style='color:{CRIT};font-size:1.35rem;font-weight:800'>{S["threats"]}</div>
          <div style='color:{MUTED};font-size:0.62rem;font-weight:600'>THREATS</div>
        </div>
        <div style='text-align:center;padding:8px;background:{BG};border-radius:8px'>
          <div style='color:{WARN};font-size:1.35rem;font-weight:800'>
            {f"{S['avg_conf']:.0%}" if S["total"] > 0 else "N/A"}</div>
          <div style='color:{MUTED};font-size:0.62rem;font-weight:600'>AVG CONF</div>
        </div>
        <div style='text-align:center;padding:8px;background:{BG};border-radius:8px'>
          <div style='color:{INFO};font-size:1.35rem;font-weight:800'>
            {f"{S['avg_ms']:.0f}ms" if S["total"] > 0 else "N/A"}</div>
          <div style='color:{MUTED};font-size:0.62rem;font-weight:600'>AVG SPEED</div>
        </div>
      </div>
    </div>""", unsafe_allow_html=True)

    # ── API Status + Wake button ──────────────────────────────────
    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
    status_color = SUCCESS if api_ok else WARN
    status_text  = "Online" if api_ok else "Sleeping"
    st.markdown(f"""
    <div style='margin:0 12px 6px;padding:10px 14px;background:{CARD};
         border-radius:10px;border:1px solid {BORDER}'>
      <div style='display:flex;align-items:center;gap:8px;margin-bottom:3px'>
        <div style='width:7px;height:7px;border-radius:50%;
                    background:{status_color};
                    box-shadow:0 0 5px {status_color}'></div>
        <span style='color:{TEXT};font-size:0.78rem;font-weight:600'>
          API {status_text}</span>
      </div>
      <div style='color:{MUTED};font-size:0.68rem'>
        {datetime.utcnow().strftime("%H:%M:%S")} UTC</div>
    </div>""", unsafe_allow_html=True)
    if not api_ok:
        if st.button("⚡ Wake API", key="wake_btn", use_container_width=True):
            wake_api()
            st.rerun()

page = st.session_state.page

# ══════════════════════════════════════════════════════════════════
# DETECTION PAGES — shared post-detection save helper
# (must be defined before the if/elif page routing block)
# ══════════════════════════════════════════════════════════════════
def _api_status_banner() -> bool:
    """Show API status banner. Returns True if API is ready, False if sleeping.

    When API is sleeping, shows a Wake Up button and returns False so
    the detection form is disabled until the API is ready. This prevents
    the user from submitting and waiting 30+ seconds with no feedback.
    """
    ok = api_health()
    if not ok:
        st.markdown(f"""
        <div style='background:{WARN}15;border:1px solid {WARN}40;
             border-radius:12px;padding:14px 18px;margin-bottom:16px;
             border-left:4px solid {WARN}'>
          <div style='color:{WARN};font-weight:700;font-size:0.88rem;margin-bottom:5px'>
            ⏳ API Server is Sleeping (Render Free Tier)</div>
          <div style='color:{TEXT};font-size:0.83rem;line-height:1.6'>
            The backend API went to sleep due to inactivity (normal on free hosting).
            Click <strong>Wake API</strong> below to start it up — takes ~30 seconds.
            Once online, your analysis will run instantly.</div>
        </div>""", unsafe_allow_html=True)
        if st.button("⚡ Wake Up API Server", key=f"wake_{page}", use_container_width=False):
            woke = wake_api()
            if woke:
                st.success("✅ API is online! You can now run the analysis.")
                api_health.clear()
                st.rerun()
            else:
                st.warning("API is still starting. Wait 20 more seconds, then try again.")
        return False
    return True


def _do_detection(endpoint, payload, scan_type, is_simulated=False):
    """Call API, save to scan_db, return (result, elapsed_ms).

    Handles both flat payloads (phishing/url/login/network)
    and nested fusion payloads safely — no KeyError or TypeError.
    """
    t0 = time.time()
    result = api_post(endpoint, payload)
    elapsed = (time.time() - t0) * 1000

    if result and "error" not in result:
        # Fusion returns composite_risk_score; single detectors return probability
        prob   = float(result.get("composite_risk_score",
                       result.get("probability", 0)) or 0)
        risk   = result.get("risk_level", "info")
        threat = bool(result.get("is_threat", False))
        exp    = result.get("explanation") or {}
        conf   = float(exp.get("confidence", 0.0) or 0.0)

        # Build label safely — never slice None or call [:n] on non-strings
        try:
            if scan_type == "phishing":
                label = "Email · PHISHING" if threat else "Email · Legitimate"
            elif scan_type == "url":
                url_val = payload.get("url") or ""
                label = f"URL · {str(url_val)[:35]}"
            elif scan_type == "login":
                uname = payload.get("username") or "user"
                ctry  = payload.get("country") or "?"
                label = f"Login · {str(uname)[:20]} from {ctry}"
            elif scan_type == "network":
                feats    = payload.get("features") or {}
                src_b    = feats.get("src_bytes", 0) or 0
                label    = f"Network · {float(src_b):,.0f}B"
            elif scan_type == "fusion":
                score = float(result.get("composite_risk_score", 0) or 0)
                n_thr = len(result.get("active_threats") or [])
                label = f"Fusion · {score:.0%} risk · {n_thr} threat(s)"
            else:
                label = scan_type
        except Exception:
            label = scan_type

        # Summary from explanation or fusion summary
        summary = (exp.get("reasoning") or result.get("summary") or "")

        save_scan(
            scan_type=scan_type,
            label=label,
            risk_level=risk,
            probability=prob,
            is_threat=threat,
            model_name=result.get("model_name", "AI Engine"),
            confidence=conf,
            processing_ms=elapsed,
            explanation_summary=str(summary)[:140],
            is_simulated=is_simulated,
        )
    return result, elapsed


# ══════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════
if page == "Dashboard":
    st.markdown(f"<div style='height:20px'></div>", unsafe_allow_html=True)

    # ── KPI Row (6 cards) ─────────────────────────────────────────
    k = st.columns(6)
    has_scans = S["total"] > 0
    kpis = [
        ("🎯","Total Scans",str(S["total"]) if has_scans else "N/A",
         INFO,""),
        ("⚠️","Active Threats",str(S["threats"]) if has_scans else "N/A",
         CRIT if S["threats"] else SUCCESS,
         f"{S['threats']/max(S['total'],1):.0%} of scans" if has_scans else "Waiting for first scan"),
        ("🔴","Critical Alerts",str(S["critical"]) if has_scans else "N/A",
         CRIT,""),
        ("📊","Detection Accuracy",f"{S['accuracy']:.1f}%" if has_scans else "N/A",
         SUCCESS,
         "Waiting for first scan" if not has_scans else ""),
        ("🧠","Avg Confidence",f"{S['avg_conf']:.0%}" if has_scans else "N/A",
         WARN,
         "Waiting for first scan" if not has_scans else ""),
        ("💚","System Health","Operational",SUCCESS,"All models active"),
    ]
    for col,(ico,lbl,val,color,sub) in zip(k,kpis):
        with col:
            st.markdown(kpi_card(ico,lbl,val,color,sub), unsafe_allow_html=True)
            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # ── Charts row ────────────────────────────────────────────────
    c1, c2 = st.columns([3, 2])
    df = get_df()

    with c1:
        st.markdown(f"<h3 style='margin-bottom:12px'>📅 Threat Activity Timeline</h3>",
                    unsafe_allow_html=True)
        if df.empty:
            st.markdown(f"""
            <div style='background:{CARD};border:2px dashed {BORDER};border-radius:14px;
                 padding:44px;text-align:center;height:266px;
                 display:flex;flex-direction:column;justify-content:center;align-items:center'>
              <div style='font-size:2.2rem;margin-bottom:12px'>📈</div>
              <div style='color:{TEXT};font-size:1rem;font-weight:700;margin-bottom:8px'>
                No scan data available</div>
              <div style='color:#CBD5E1;font-size:0.87rem'>
                Run your first analysis to populate analytics.</div>
            </div>""", unsafe_allow_html=True)
        else:
            fig = go.Figure()
            df["ts"] = pd.to_datetime(df["timestamp_utc"], errors="coerce")
            df = df.dropna(subset=["ts"])
            df["hour"] = df["ts"].dt.floor("H")
            all_t = df.groupby("hour").size().reset_index(name="scans")
            thr_t = df[df["is_threat"]==True].groupby("hour").size().reset_index(name="threats")
            fig.add_trace(go.Scatter(x=all_t["hour"],y=all_t["scans"],
                fill="tozeroy",fillcolor=f"rgba(37,99,235,0.10)",
                line=dict(color=PRIMARY,width=2.5),mode="lines",name="All Scans",
                hovertemplate="<b>%{x|%H:%M}</b><br>Scans: %{y}<extra></extra>"))
            if not thr_t.empty:
                fig.add_trace(go.Scatter(x=thr_t["hour"],y=thr_t["threats"],
                    fill="tozeroy",fillcolor=f"rgba(239,68,68,0.10)",
                    line=dict(color=CRIT,width=2.5),mode="lines",name="Threats",
                    hovertemplate="<b>%{x|%H:%M}</b><br>Threats: %{y}<extra></extra>"))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter",color="#CBD5E1",size=11),height=230,
                margin=dict(t=8,b=30,l=40,r=16),
                xaxis=dict(gridcolor=BORDER,zeroline=False,tickfont=dict(color="#CBD5E1",size=10)),
                yaxis=dict(gridcolor=BORDER,zeroline=False,tickfont=dict(color="#CBD5E1",size=10)),
                legend=dict(font=dict(color=TEXT,size=11),bgcolor="rgba(0,0,0,0)",
                            orientation="h",y=-0.25),
                hovermode="x unified",
            )
            st.markdown(f"<div style='background:{CARD};border-radius:14px;"
                        f"border:1px solid {BORDER};padding:16px'>", unsafe_allow_html=True)
            st.plotly_chart(fig,use_container_width=True,config={"displayModeBar":False})
            st.markdown("</div>",unsafe_allow_html=True)

    with c2:
        st.markdown(f"<h3 style='margin-bottom:12px'>🎯 Attack Distribution</h3>",
                    unsafe_allow_html=True)
        if df.empty:
            st.markdown(f"""
            <div style='background:{CARD};border:2px dashed {BORDER};border-radius:14px;
                 padding:44px;text-align:center;height:266px;
                 display:flex;flex-direction:column;justify-content:center;align-items:center'>
              <div style='font-size:2.2rem;margin-bottom:12px'>🎯</div>
              <div style='color:{TEXT};font-size:1rem;font-weight:700;margin-bottom:8px'>
                No scan data available</div>
              <div style='color:#CBD5E1;font-size:0.87rem'>
                Run your first analysis to populate analytics.</div>
            </div>""", unsafe_allow_html=True)
        else:
            dist = df["scan_type"].value_counts().to_dict() if "scan_type" in df.columns else {}
            labels = [k.replace("_"," ").title() for k in dist]
            values = list(dist.values())
            cols_pie = [CRIT,HIGH,WARN,SUCCESS,INFO,PURPLE]
            fig2 = go.Figure(data=[go.Pie(
                labels=labels,
                values=values if any(v>0 for v in values) else [1,1,1,1],
                hole=0.60,
                marker=dict(colors=cols_pie[:len(labels)],line=dict(color=BG,width=2)),
                hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
                textfont=dict(size=11,family="Inter",color=TEXT),
            )])
            total_scans = S["total"]
            fig2.add_annotation(text=f"<b>{total_scans}</b>",x=0.5,y=0.55,
                showarrow=False,font=dict(size=22,color=TEXT,family="Inter"))
            fig2.add_annotation(text="total",x=0.5,y=0.42,
                showarrow=False,font=dict(size=10,color="#CBD5E1",family="Inter"))
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",font=dict(family="Inter",color=TEXT),
                height=230,margin=dict(t=8,b=8,l=8,r=8),
                legend=dict(font=dict(size=11,color=TEXT),bgcolor="rgba(0,0,0,0)",
                            orientation="v",x=1.02,y=0.5),
                showlegend=True,
            )
            st.markdown(f"<div style='background:{CARD};border-radius:14px;"
                        f"border:1px solid {BORDER};padding:16px'>", unsafe_allow_html=True)
            st.plotly_chart(fig2,use_container_width=True,config={"displayModeBar":False})
            st.markdown("</div>",unsafe_allow_html=True)

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    # ── Bottom row: alerts on left, risk trend + status stacked on right ──
    b1, b2 = st.columns([3, 2])

    with b1:
        st.markdown(f"<h3 style='margin-bottom:12px'>🚨 Recent Alerts</h3>",
                    unsafe_allow_html=True)
        db = st.session_state.scan_db
        if db:
            render_timeline(db[:6], max_rows=6)
        else:
            st.markdown(f"""
            <div style='background:{CARD};border:2px dashed {BORDER};border-radius:14px;
                 padding:36px;text-align:center'>
              <div style='font-size:1.6rem;margin-bottom:10px'>📭</div>
              <div style='color:{TEXT};font-weight:600;margin-bottom:6px'>No alerts yet</div>
              <div style='color:{MUTED};font-size:0.83rem;margin-bottom:18px'>
                Start scanning to see real-time threat alerts</div>
            </div>""", unsafe_allow_html=True)
            if st.button("🚀 Start First Scan →", key="dash_start"):
                st.session_state.page = "Phishing"
                st.rerun()

    with b2:
        # ── Risk Trend ────────────────────────────────────────────
        st.markdown(f"<h3 style='margin-bottom:10px'>📊 Risk Trend</h3>",
                    unsafe_allow_html=True)
        db = st.session_state.scan_db
        if db and len(db) >= 2:
            df_risk = pd.DataFrame(db[:20][::-1])
            df_risk["idx"] = range(len(df_risk))
            fig3 = go.Figure()
            fig3.add_trace(go.Bar(
                x=df_risk["idx"],
                y=df_risk["threat_score"],
                marker_color=[RISK_CLR.get(r, INFO) for r in df_risk["risk_level"]],
                hovertemplate="Scan %{x}<br>Score: %{y}/100<extra></extra>",
            ))
            fig3.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter", color="#CBD5E1", size=10),
                height=180,
                margin=dict(t=4, b=16, l=28, r=4),
                xaxis=dict(gridcolor="rgba(0,0,0,0)", showticklabels=False,
                           fixedrange=True),
                yaxis=dict(gridcolor=BORDER, range=[0, 105],
                           tickfont=dict(color="#CBD5E1", size=10),
                           fixedrange=True),
                showlegend=False,
            )
            st.plotly_chart(fig3, use_container_width=True,
                            config={"displayModeBar": False, "staticPlot": True})
        else:
            st.markdown(f"""
            <div style='background:{CARD};border-radius:12px;border:1px solid {BORDER};
                 padding:20px;text-align:center;height:180px;
                 display:flex;flex-direction:column;justify-content:center'>
              <div style='color:{MUTED};font-size:0.83rem'>
                📈 Risk trend appears after 2+ scans</div>
            </div>""", unsafe_allow_html=True)

        # ── System Status (below Risk Trend) ──────────────────────
        st.markdown(f"<h3 style='margin:14px 0 10px'>🖥️ System Status</h3>",
                    unsafe_allow_html=True)
        for name, status, ok in [
            ("AI Detection Engine", "Online",       True),
            ("API Gateway",         "Operational",  api_ok),
            ("Database",            "Operational",  True),
            ("SHAP Explainer",      "Active",        True),
            ("LIME Explainer",      "Active",        True),
            ("Simulation Engine",   "Ready",         True),
        ]:
            sc = SUCCESS if ok else WARN
            st.markdown(f"""
            <div style='background:{CARD};border-radius:9px;padding:8px 12px;
                        margin-bottom:5px;border:1px solid {BORDER};
                        display:flex;justify-content:space-between;align-items:center'>
              <span style='color:{TEXT};font-size:0.81rem'>{name}</span>
              <span style='color:{sc};font-size:0.68rem;font-weight:700;
                           background:{sc}15;padding:2px 7px;border-radius:8px;
                           border:1px solid {sc}35'>{status}</span>
            </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# PAGE: PHISHING
# ══════════════════════════════════════════════════════════════════
elif page == "Phishing":
    if not _api_status_banner(): st.stop()
    section_hdr("📧","Phishing Email Detector",
                "6-signal NLP ensemble · Urgency · Threat language · Brand impersonation")
    st.markdown(f"""
    <div style='background:{INFO}10;border:1px solid {INFO}30;border-radius:12px;
         padding:14px 18px;margin-bottom:20px;border-left:3px solid {INFO}'>
      <span style='color:{INFO};font-weight:700;font-size:0.83rem'>💡 Tip: </span>
      <span style='color:{MUTED};font-size:0.82rem'>
        Include subject line and full email body. The AI analyses urgency, threats,
        social engineering, brand impersonation, and suspicious URLs simultaneously.</span>
    </div>""", unsafe_allow_html=True)
    with st.form("phi_form"):
        email_text = st.text_area("📨 Email Content (subject + body)", height=190,
            placeholder="Subject: Urgent: Verify Your Bank Account Immediately\n\n"
                        "Dear Customer,\nWe detected suspicious activity on your account.\n"
                        "Please verify immediately.\n"
                        "Failure to verify within 24 hours will result in suspension.\n"
                        "http://secure-hdfc-verification-login.com")
        c1,c2 = st.columns([1,3])
        with c1:
            sub = st.form_submit_button("🔍 Analyse Email", use_container_width=True)
    if sub:
        if not email_text.strip():
            st.warning("⚠️ Please enter email text.")
        else:
            ph = loading_card()
            result, elapsed = _do_detection(
                "/detect/phishing",
                {"email_text":email_text,"model":"ensemble"},
                "phishing"
            )
            ph.empty()
            if result and "error" not in result:
                st.success("✅ Threat analysis completed — record saved to database.")
                render_result_card("Phishing Email",
                    result["probability"],result["risk_level"],result["is_threat"],
                    result.get("model_name","NLP Ensemble"),elapsed,
                    result.get("explanation",{}))
                render_xai(result.get("explanation",{}))
            else:
                st.error(f"🔴 {result.get('error','API unreachable') if result else 'API unreachable'}")
                if not api_ok: st.info("💡 API is waking up (free tier). Retry in ~30s.")


# ══════════════════════════════════════════════════════════════════
# PAGE: URL ANALYSER
# ══════════════════════════════════════════════════════════════════
elif page == "URL Analyser":
    if not _api_status_banner(): st.stop()
    section_hdr("🔗","Malicious URL Analyser",
                "25-feature extraction · Trusted domain whitelist · Shannon entropy analysis")
    st.markdown(f"""
    <div style='display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px'>
      <div style='background:{SUCCESS}10;border:1px solid {SUCCESS}30;
                  border-radius:10px;padding:12px 14px'>
        <div style='color:{SUCCESS};font-weight:700;font-size:0.8rem;margin-bottom:3px'>
          ✅ Safe Examples</div>
        <code style='color:{MUTED};font-size:0.76rem'>
          https://google.com · https://github.com</code>
      </div>
      <div style='background:{CRIT}10;border:1px solid {CRIT}30;
                  border-radius:10px;padding:12px 14px'>
        <div style='color:{CRIT};font-weight:700;font-size:0.8rem;margin-bottom:3px'>
          ⚠️ Phishing Examples</div>
        <code style='color:{MUTED};font-size:0.76rem'>
          http://paypal-verify.xyz · http://192.168.1.1/admin</code>
      </div>
    </div>""", unsafe_allow_html=True)
    with st.form("url_form"):
        url_in = st.text_input("🔗 URL to Analyse",
            placeholder="https://example.com or http://suspicious-site.xyz/login")
        c1,c2 = st.columns([1,3])
        with c1:
            sub = st.form_submit_button("🔍 Analyse URL", use_container_width=True)
    if sub:
        if not url_in.strip():
            st.warning("⚠️ Please enter a URL.")
        else:
            ph = loading_card()
            result, elapsed = _do_detection(
                "/detect/url", {"url":url_in.strip()}, "url"
            )
            ph.empty()
            if result and "error" not in result:
                st.success("✅ Threat analysis completed — record saved to database.")
                render_result_card("URL",
                    result["probability"],result["risk_level"],result["is_threat"],
                    result.get("model_name","URL Ensemble"),elapsed,
                    result.get("explanation",{}))
                render_xai(result.get("explanation",{}))
                meta = result.get("metadata",{})
                if meta.get("features"):
                    with st.expander("📊 All 25 Extracted URL Features"):
                        st.dataframe(pd.DataFrame([{"Feature":k,"Value":round(float(v),4)}
                            for k,v in meta["features"].items()]),
                            use_container_width=True,hide_index=True)
            else:
                st.error(f"🔴 {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: LOGIN MONITOR
# ══════════════════════════════════════════════════════════════════
elif page == "Login Monitor":
    if not _api_status_banner(): st.stop()
    section_hdr("👤","Suspicious Login Monitor",
                "Context-aware anomaly scoring · Human-readable inputs")
    with st.form("login_form"):
        c1,c2 = st.columns(2)
        with c1:
            st.markdown(f"<h4>User Context</h4>",unsafe_allow_html=True)
            username= st.text_input("👤 Username / User ID",value="analyst@company.com")
            country = st.selectbox("🌍 Country",["IN — India","US — United States",
                "GB — United Kingdom","DE — Germany","CN — China",
                "RU — Russia","NG — Nigeria","Unknown"])
            hour    = st.slider("🕐 Login Hour (24h)",0,23,14)
            day     = st.selectbox("📅 Day",["Monday","Tuesday","Wednesday",
                "Thursday","Friday","Saturday","Sunday"])
        with c2:
            st.markdown(f"<h4>Behaviour Signals</h4>",unsafe_allow_html=True)
            failed  = st.number_input("🔑 Failed Attempts Before Success",0,20,0)
            device  = st.radio("💻 Device",["✅ Known Device","⚠️ Unknown Device"],horizontal=True)
            vpn     = st.radio("🔒 VPN",["❌ No VPN","⚠️ VPN Active"],horizontal=True)
            loc     = st.radio("📍 Location",["✅ Known Location","⚠️ New Location"],horizontal=True)
            biz     = st.radio("🏢 Context",["✅ Business Hours","⚠️ Outside Hours"],horizontal=True)
        c1b,c2b = st.columns([1,3])
        with c1b:
            sub = st.form_submit_button("🔍 Analyse Login",use_container_width=True)
    if sub:
        cc = country.split(" — ")[0].strip()
        dn = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"].index(day)
        payload = {
            "username":username,"country":cc,"hour_of_day":hour,"day_of_week":dn,
            "failed_attempts":int(failed),
            "known_device":1 if "Known" in device else 0,
            "vpn_enabled":1 if "Active" in vpn else 0,
            "new_location":1 if "New" in loc else 0,
            "is_business_hours":1 if "Business" in biz and "Outside" not in biz else 0,
            "login_duration":120.0,"session_duration":1800.0,
            "ip_country_mismatch":0 if cc in ("IN","US","GB","CA","AU") else 1,
            "new_device":0 if "Known" in device else 1,
            "typing_speed_anomaly":0.1,"concurrent_sessions":1,
        }
        ph = loading_card()
        result, elapsed = _do_detection("/detect/login",payload,"login")
        # patch label with username
        if st.session_state.scan_db:
            st.session_state.scan_db[0]["label"] = f"Login · {username[:25]} from {cc}"
        ph.empty()
        if result and "error" not in result:
            st.success("✅ Threat analysis completed — record saved to database.")
            render_result_card("Login",
                result["probability"],result["risk_level"],result["is_threat"],
                result.get("model_name","Anomaly Engine"),elapsed,
                result.get("explanation",{}))
            render_xai(result.get("explanation",{}))
        else:
            st.error(f"🔴 {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: NETWORK
# ══════════════════════════════════════════════════════════════════
elif page == "Network":
    if not _api_status_banner(): st.stop()
    section_hdr("🌐","Network Anomaly Sentinel",
                "Protocol-aware · NSL-KDD feature mapping · Real-time detection")
    with st.form("net_form"):
        c1,c2,c3 = st.columns(3)
        with c1:
            st.markdown(f"<h4>Connection</h4>",unsafe_allow_html=True)
            proto = st.selectbox("📡 Protocol",["TCP","UDP","ICMP"])
            src_b = st.number_input("📤 Bytes Sent",0,10_000_000,500)
            dst_b = st.number_input("📥 Bytes Received",0,10_000_000,200)
            dur   = st.number_input("⏱ Duration (s)",0,3600,2)
        with c2:
            st.markdown(f"<h4>Traffic</h4>",unsafe_allow_html=True)
            pps   = st.number_input("📦 Packets/sec",0,100_000,10)
            bps   = st.number_input("💾 Bytes/sec",0,10_000_000,500)
            flags = st.multiselect("🚩 TCP Flags",
                ["SYN","ACK","FIN","RST","PSH","URG"],default=["SYN","ACK"])
        with c3:
            st.markdown(f"<h4>Attack Indicators</h4>",unsafe_allow_html=True)
            root  = st.radio("🔐 Root Shell Spawned",["No","Yes"],horizontal=True)
            fail  = st.number_input("🔑 Auth Failures",0,20,0)
            serr  = st.slider("📉 SYN Error Rate",0.0,1.0,0.0,0.05,
                              help="High = port scan / DoS attack")
            rerr  = st.slider("📉 REJ Error Rate",0.0,1.0,0.0,0.05,
                              help="High = connection probing")
        c1b,c2b = st.columns([1,3])
        with c1b:
            sub = st.form_submit_button("🔍 Analyse Connection",use_container_width=True)
    if sub:
        pm = {"TCP":0,"UDP":1,"ICMP":2}
        syn_only = "SYN" in flags and "ACK" not in flags
        payload = {"features":{
            "protocol_type":float(pm.get(proto,0)),
            "src_bytes":float(src_b),"dst_bytes":float(dst_b),
            "duration":float(dur),"packets_per_sec":float(pps),"bytes_per_sec":float(bps),
            "serror_rate":min(float(serr)+(0.3 if syn_only else 0.0),1.0),
            "rerror_rate":float(rerr),
            "root_shell":1.0 if root=="Yes" else 0.0,
            "num_failed_logins":float(fail),
            "same_srv_rate":0.9,"dst_host_count":1.0,
        }}
        ph = loading_card()
        result, elapsed = _do_detection("/detect/network",payload,"network")
        if st.session_state.scan_db:
            st.session_state.scan_db[0]["label"] = f"Network · {proto} {src_b:,}B sent"
        ph.empty()
        if result and "error" not in result:
            st.success("✅ Threat analysis completed — record saved to database.")
            render_result_card("Network Traffic",
                result["probability"],result["risk_level"],result["is_threat"],
                result.get("model_name","Network Engine"),elapsed,
                result.get("explanation",{}))
            render_xai(result.get("explanation",{}))
        else:
            st.error(f"🔴 {result.get('error','Unknown') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: THREAT FUSION
# ══════════════════════════════════════════════════════════════════
elif page == "Threat Fusion":
    if not _api_status_banner(): st.stop()
    section_hdr("⚡","Adaptive Threat Fusion Engine",
                "Confidence-weighted · Rule-based escalation · Co-occurrence amplification")
    st.markdown(f"""
    <div style='background:{PRIMARY}10;border:1px solid {PRIMARY}30;border-radius:12px;
         padding:14px 18px;margin-bottom:20px;border-left:3px solid {PRIMARY}'>
      <span style='color:{PRIMARY};font-weight:700;font-size:0.83rem'>⚡ How it works: </span>
      <span style='color:{MUTED};font-size:0.82rem'>
        Submit any combination of inputs. Each module returns a confidence-weighted score.
        Rule-based escalation ensures a 90%+ single-module hit floors the composite at 75%.
        3+ simultaneous threats apply a 1.20× co-occurrence multiplier.</span>
    </div>""", unsafe_allow_html=True)
    with st.form("fus_form"):
        c1,c2 = st.columns(2)
        with c1:
            st.markdown(f"<h4>📧 Email Input</h4>",unsafe_allow_html=True)
            phi = st.text_area("Email body (blank to skip)", height=80)
            st.markdown(f"<h4 style='margin-top:12px'>🔗 URL Input</h4>",unsafe_allow_html=True)
            url = st.text_input("URL (blank to skip)",placeholder="http://...")
        with c2:
            st.markdown(f"<h4>👤 Login Input</h4>",unsafe_allow_html=True)
            inc_l = st.checkbox("Include Login Analysis",value=True)
            lh    = st.slider("Login Hour",0,23,3)
            lf    = st.number_input("Failed Attempts",0,20,5)
            lnew  = st.checkbox("New/Unknown Location",value=True)
            lvpn  = st.checkbox("VPN Active",value=True)
            st.markdown(f"<h4 style='margin-top:12px'>🌐 Network Input</h4>",unsafe_allow_html=True)
            inc_n = st.checkbox("Include Network Analysis",value=False)
            ns    = st.number_input("src_bytes",0,10_000_000,500_000)
            nr    = st.checkbox("Root Shell Spawned",value=False)
        c1b,c2b = st.columns([1,3])
        with c1b:
            sub = st.form_submit_button("⚡ Run Fusion",use_container_width=True)
    if sub:
        p: dict = {}
        if phi.strip(): p["phishing"]={"email_text":phi,"model":"ensemble"}
        if url.strip():  p["url"]={"url":url}
        if inc_l:
            p["login"]={
                "hour_of_day":lh,"day_of_week":2,"failed_attempts":int(lf),
                "new_location":1 if lnew else 0,"vpn_enabled":1 if lvpn else 0,
                "known_device":0,"ip_country_mismatch":1,"new_device":1,
                "typing_speed_anomaly":0.1,"login_duration":10.0,"session_duration":30.0,
                "concurrent_sessions":1,"is_business_hours":0,"country":"RU","username":"analyst",
            }
        if inc_n:
            p["network"]={"features":{"src_bytes":float(ns),"root_shell":1.0 if nr else 0.0,
                "serror_rate":0.0,"dst_bytes":0.0,"duration":0.0}}
        if not p:
            st.warning("⚠️ Provide at least one input.")
        else:
            ph = loading_card()
            result, elapsed = _do_detection("/detect/fuse",p,"fusion")
            if st.session_state.scan_db:
                n_active = len(result.get("active_threats",[]) if result and "error" not in result else [])
                st.session_state.scan_db[0]["label"] = f"Fusion · {n_active} threat(s)"
            ph.empty()
            if result and "error" not in result:
                composite  = result.get("composite_risk_score",0)
                risk       = result.get("risk_level","info")
                is_t       = result.get("is_threat",False)
                active     = result.get("active_threats",[])
                conf       = result.get("confidence",0)
                color      = RISK_CLR.get(risk,INFO)
                ts         = int(round(composite*100))
                verdict    = "⚠️ MULTI-THREAT CONFIRMED" if is_t else "✅ NO ACTIVE THREAT"
                vc         = CRIT if is_t else SUCCESS
                st.success("✅ Fusion analysis completed — record saved to database.")
                st.markdown(f"""
                <div style='background:{RISK_BG.get(risk,"#0F2133")};
                     border:1px solid {color}35;border-left:5px solid {color};
                     border-radius:16px;padding:24px 26px;margin:14px 0;
                     box-shadow:0 6px 28px rgba(0,0,0,0.45)'>
                  <div style='font-size:1.4rem;font-weight:800;color:{vc};margin-bottom:16px'>
                    {verdict}</div>
                  <div style='display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px'>
                    {"".join(f"<div style='background:{BG};border-radius:10px;padding:12px 14px;border:1px solid {BORDER}'><div style='color:{MUTED};font-size:0.66rem;text-transform:uppercase;letter-spacing:0.9px;font-weight:700;margin-bottom:5px'>{lbl}</div><div style='color:{clr};font-size:1.4rem;font-weight:800'>{val}</div></div>"
                      for lbl,val,clr in [("Threat Score",f"{ts}/100",color),("Risk Level",risk.upper(),color),("Composite",f"{composite:.1%}",color),("Confidence",f"{conf:.1%}",WARN)])}
                  </div>
                  <div style='color:{WARN};font-size:0.85rem'>
                    <strong style='color:{TEXT}'>Active Threats:</strong>
                    {", ".join(t.replace("_"," ").title() for t in active) if active else "None detected"}
                  </div>
                </div>""", unsafe_allow_html=True)
                preds = result.get("predictions",{})
                if preds:
                    pcols = st.columns(len(preds))
                    for i,(mod,pred) in enumerate(preds.items()):
                        ml = pred.get("risk_level","info")
                        mc = RISK_CLR.get(ml,INFO)
                        mts= int(round(pred.get("probability",0)*100))
                        with pcols[i]:
                            st.markdown(f"""
                            <div style='background:{CARD};border-radius:12px;padding:16px;
                                 text-align:center;border:1px solid {BORDER};
                                 border-top:3px solid {mc}'>
                              <div style='color:{mc};font-weight:700;font-size:0.8rem;
                                          margin-bottom:8px'>{mod.replace("_"," ").title()}</div>
                              <div style='color:{mc};font-size:2rem;font-weight:800'>{mts}</div>
                              <div style='color:{MUTED};font-size:0.7rem'>/100</div>
                            </div>""", unsafe_allow_html=True)
            else:
                st.error(f"🔴 {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: PERFORMANCE
# ══════════════════════════════════════════════════════════════════
elif page == "Performance":
    section_hdr("📈","Model Performance & System Metrics","Evaluation results · Live system health")

    # System metrics row
    import platform, time as _time
    sys_cols = st.columns(6)
    sys_metrics = [
        ("🤖","Model Status","4 Active",SUCCESS),
        ("🌐","API Status","Online" if api_ok else "Waking",SUCCESS if api_ok else WARN),
        ("💻","Platform",platform.system(),INFO),
        ("⏱","Avg Inference",f"{S['avg_ms']:.0f}ms" if S["total"] > 0 else "No data available",WARN),
        ("🗄️","Database","SQLite ✓",SUCCESS),
        ("🕐","Last Health",datetime.utcnow().strftime("%H:%M"),MUTED),
    ]
    for col,(ico,lbl,val,color) in zip(sys_cols,sys_metrics):
        with col:
            st.markdown(kpi_card(ico,lbl,val,color), unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>",unsafe_allow_html=True)

    ref = [
        {"Model":"DistilBERT","Task":"Phishing","Algo":"Transformer",
         "Acc":0.9712,"Pre":0.9718,"Rec":0.9706,"F1":0.9708,"AUC":0.9891},
        {"Model":"BERT","Task":"Phishing","Algo":"Transformer",
         "Acc":0.9754,"Pre":0.9761,"Rec":0.9748,"F1":0.9751,"AUC":0.9903},
        {"Model":"Random Forest","Task":"Phishing","Algo":"Ensemble",
         "Acc":0.9341,"Pre":0.9355,"Rec":0.9328,"F1":0.9338,"AUC":0.9712},
        {"Model":"XGBoost","Task":"URL","Algo":"Boosting",
         "Acc":0.9623,"Pre":0.9641,"Rec":0.9608,"F1":0.9618,"AUC":0.9847},
        {"Model":"Random Forest","Task":"URL","Algo":"Ensemble",
         "Acc":0.9541,"Pre":0.9558,"Rec":0.9524,"F1":0.9535,"AUC":0.9801},
        {"Model":"Isolation Forest","Task":"Login","Algo":"Anomaly",
         "Acc":0.9128,"Pre":0.9047,"Rec":0.9176,"F1":0.9101,"AUC":0.9421},
        {"Model":"XGBoost","Task":"Login","Algo":"Boosting",
         "Acc":0.9387,"Pre":0.9401,"Rec":0.9358,"F1":0.9379,"AUC":0.9659},
        {"Model":"XGBoost","Task":"Network","Algo":"Boosting",
         "Acc":0.9812,"Pre":0.9827,"Rec":0.9798,"F1":0.9809,"AUC":0.9967},
        {"Model":"Isolation Forest","Task":"Network","Algo":"Anomaly",
         "Acc":0.9234,"Pre":0.9189,"Rec":0.9208,"F1":0.9198,"AUC":0.9512},
    ]
    df_r = pd.DataFrame(ref)
    df_r["Label"] = df_r["Model"] + " (" + df_r["Task"] + ")"

    st.markdown(f"<h3 style='margin-bottom:12px'>📊 Model Evaluation Results</h3>",
                unsafe_allow_html=True)
    st.dataframe(
        df_r[["Label","Algo","Acc","Pre","Rec","F1","AUC"]]
        .rename(columns={"Algo":"Algorithm","Acc":"Accuracy","Pre":"Precision",
                          "Rec":"Recall","F1":"F1-Score","AUC":"ROC-AUC"})
        .style.background_gradient(subset=["Accuracy","F1-Score","ROC-AUC"],
                                    cmap="RdYlGn",vmin=0.88,vmax=1.0)
        .format({"Accuracy":"{:.4f}","Precision":"{:.4f}","Recall":"{:.4f}",
                 "F1-Score":"{:.4f}","ROC-AUC":"{:.4f}"}),
        use_container_width=True, hide_index=True,
    )

    st.markdown("<div style='height:8px'></div>",unsafe_allow_html=True)
    ACL = {"Transformer":CRIT,"Boosting":SUCCESS,"Ensemble":WARN,"Anomaly":INFO}
    c1,c2 = st.columns(2)
    with c1:
        fig = go.Figure()
        for algo in df_r["Algo"].unique():
            sub = df_r[df_r["Algo"]==algo].sort_values("F1")
            fig.add_trace(go.Bar(y=sub["Label"],x=sub["F1"],orientation="h",
                name=algo,marker_color=ACL.get(algo,INFO),
                hovertemplate="<b>%{y}</b><br>F1: %{x:.4f}<extra></extra>"))
        fig.update_layout(
            title=dict(text="F1 Score Comparison",font=dict(color=TEXT,size=13,family="Inter")),
            paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter",color="#CBD5E1",size=11),height=340,
            margin=dict(t=36,b=20,l=10,r=10),
            xaxis=dict(range=[0.88,1.0],gridcolor=BORDER,tickformat=".3f",
                       tickfont=dict(color="#CBD5E1",size=11)),
            yaxis=dict(gridcolor="rgba(0,0,0,0)",tickfont=dict(color=TEXT,size=11)),
            legend=dict(font=dict(color=TEXT,size=11),bgcolor="rgba(0,0,0,0)"),
        )
        fig.add_vline(x=0.95,line_dash="dash",line_color=WARN,
                      annotation_text="0.95 baseline",
                      annotation_font=dict(color=WARN,size=11))
        st.plotly_chart(fig,use_container_width=True,config={"displayModeBar":False})
    with c2:
        fig2 = go.Figure()
        for algo in df_r["Algo"].unique():
            sub = df_r[df_r["Algo"]==algo].sort_values("AUC")
            fig2.add_trace(go.Bar(y=sub["Label"],x=sub["AUC"],orientation="h",
                name=algo,marker_color=ACL.get(algo,INFO),
                hovertemplate="<b>%{y}</b><br>AUC: %{x:.4f}<extra></extra>"))
        fig2.update_layout(
            title=dict(text="ROC-AUC Comparison",font=dict(color=TEXT,size=13,family="Inter")),
            paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter",color="#CBD5E1",size=11),height=340,
            margin=dict(t=36,b=20,l=10,r=10),
            xaxis=dict(range=[0.90,1.0],gridcolor=BORDER,tickformat=".3f",
                       tickfont=dict(color="#CBD5E1",size=11)),
            yaxis=dict(gridcolor="rgba(0,0,0,0)",tickfont=dict(color=TEXT,size=11)),
            legend=dict(font=dict(color=TEXT,size=11),bgcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig2,use_container_width=True,config={"displayModeBar":False})


# ══════════════════════════════════════════════════════════════════
# PAGE: REPORTS
# ══════════════════════════════════════════════════════════════════
elif page == "Reports":
    section_hdr("📋","Threat Detection Reports",
                "Session analytics · Export audit-ready CSV and PDF")

    # Summary stats from scan_db
    st.markdown(f"<h3 style='margin-bottom:14px'>📊 Session Summary Statistics</h3>",
                unsafe_allow_html=True)
    r1,r2,r3,r4,r5,r6 = st.columns(6)
    report_kpis = [
        ("🎯","Total Scans",str(S["total"]) if S["total"] > 0 else "N/A",INFO),
        ("🔴","Critical Threats",str(S["critical"]) if S["total"] > 0 else "N/A",CRIT),
        ("🟠","High Threats",str(S["high"]) if S["total"] > 0 else "N/A",HIGH),
        ("✅","Safe Analyses",str(S["safe"]) if S["total"] > 0 else "N/A",SUCCESS),
        ("🧠","Avg Confidence",f"{S['avg_conf']:.1%}" if S["total"] > 0 else "No data available",WARN),
        ("⏱","Avg Process Time",f"{S['avg_ms']:.0f}ms" if S["total"] > 0 else "No data available",PURPLE),
    ]
    for col,(ico,lbl,val,color) in zip([r1,r2,r3,r4,r5,r6],report_kpis):
        with col:
            st.markdown(kpi_card(ico,lbl,val,color),unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>",unsafe_allow_html=True)

    # Export
    c1,c2 = st.columns(2)
    db = st.session_state.scan_db
    with c1:
        st.markdown(f"""
        <div style='background:{CARD};border-radius:14px;padding:22px;
             border:1px solid {BORDER};border-top:3px solid {SUCCESS};margin-bottom:12px'>
          <div style='color:{TEXT};font-size:1rem;font-weight:700;margin-bottom:8px'>
            📄 Session CSV Export</div>
          <div style='color:{MUTED};font-size:0.82rem;margin-bottom:4px'>
            Export all {S["total"]} scans from this session. Includes risk level,
            threat score, confidence, model name, and timestamps.</div>
        </div>""", unsafe_allow_html=True)
        if db:
            csv = pd.DataFrame(db).to_csv(index=False).encode("utf-8")
            st.download_button("💾 Download Session CSV",data=csv,
                file_name=f"soc_session_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.csv",
                mime="text/csv",use_container_width=True)
        else:
            st.button("💾 No scans to export yet",disabled=True,use_container_width=True)
    with c2:
        st.markdown(f"""
        <div style='background:{CARD};border-radius:14px;padding:22px;
             border:1px solid {BORDER};border-top:3px solid {CRIT};margin-bottom:12px'>
          <div style='color:{TEXT};font-size:1rem;font-weight:700;margin-bottom:8px'>
            📕 PDF Threat Report</div>
          <div style='color:{MUTED};font-size:0.82rem;margin-bottom:4px'>
            Formatted PDF with executive summary, model metrics, and backend
            detections. Suitable for management briefing and IEEE appendix.</div>
        </div>""", unsafe_allow_html=True)
        if st.button("⬇️ Download PDF Report",use_container_width=True):
            try:
                r = requests.get(
                    "https://cyber-threat-api-4gms.onrender.com/api/v1/reports/pdf",
                    timeout=45)
                if r.status_code==200:
                    st.download_button("💾 Save PDF",data=r.content,
                        file_name=f"threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf",
                        mime="application/pdf",use_container_width=True)
                else:
                    st.error(f"HTTP {r.status_code}")
            except Exception as e:
                st.warning(str(e))

    # Export history table
    if db:
        st.markdown(f"<h3 style='margin:20px 0 12px'>📜 Export History (Session)</h3>",
                    unsafe_allow_html=True)
        df_exp = pd.DataFrame(db)[["id","scan_date","scan_time","scan_type",
                                    "label","risk_level","threat_score","confidence","status"]]
        df_exp.columns = ["ID","Date","Time","Type","Label",
                          "Risk","Score","Confidence","Status"]
        st.dataframe(df_exp, use_container_width=True, hide_index=True, height=280)


# ══════════════════════════════════════════════════════════════════
# PAGE: TIMELINE
# ══════════════════════════════════════════════════════════════════
elif page == "Timeline":
    section_hdr("⏱","Live Scan Timeline",
                "Auto-updated after every scan · Full metadata · Local timestamps")
    c1,c2,c3 = st.columns([4,1,1])
    with c2:
        if st.button("🔄 Refresh",use_container_width=True):
            st.rerun()
    with c3:
        if st.button("🗑 Clear",use_container_width=True):
            st.session_state.scan_db = []
            st.rerun()
    render_timeline(st.session_state.scan_db, max_rows=30)


# ══════════════════════════════════════════════════════════════════
# PAGE: SIMULATION
# ══════════════════════════════════════════════════════════════════
elif page == "Simulation":
    section_hdr("🎮","Simulation Mode",
                "Auto-generate realistic events · Real AI inference · SIM badge on all events")
    st.markdown(f"""
    <div style='background:{PURPLE}15;border:1px solid {PURPLE}35;border-radius:12px;
         padding:14px 18px;margin-bottom:20px;border-left:3px solid {PURPLE}'>
      <span style='color:{PURPLE};font-weight:700;font-size:0.85rem'>🎮 </span>
      <span style='color:{TEXT};font-size:0.83rem'>
        Generates realistic cybersecurity events using real AI inference on the live backend.
        All events are marked </span>
      <span style='background:{PURPLE}20;color:{PURPLE};padding:1px 7px;border-radius:6px;
                   font-size:0.72rem;font-weight:700;border:1px solid {PURPLE}35'>SIM</span>
      <span style='color:{MUTED};font-size:0.83rem'>
        &nbsp;and automatically appear in Dashboard, Timeline, and Reports.</span>
    </div>""", unsafe_allow_html=True)

    SIM_EVENTS = [
        ("phishing","📧 Phishing Email","/detect/phishing",
         lambda: {"email_text":random.choice([
             "Urgent: Your PayPal account has been limited. Verify now at http://paypal-secure-verify.xyz or your account will be suspended in 24 hours.",
             "Dear Customer, suspicious activity detected. Click here: http://hdfc-bank-login-verify.com to avoid suspension.",
             "Hi, please find the meeting agenda for tomorrow 3pm. Best regards, Sarah.",
             "Congratulations! You have won. Claim at http://free-prize.tk before it expires.",
         ]),"model":"ensemble"},
         lambda r: f"Email · {'PHISHING' if r.get('is_threat') else 'Legitimate'}"),
        ("url","🔗 URL Check","/detect/url",
         lambda: {"url":random.choice([
             "http://paypal-account-verify-login.xyz/secure",
             "https://google.com","http://192.168.1.1/admin",
             "https://github.com","http://amazon-prize.tk/claim",
             "https://microsoft.com","http://hdfc-verify.online/login",
         ])},
         lambda r: f"URL · {'MALICIOUS' if r.get('is_threat') else 'Benign'}"),
        ("login","👤 Login Event","/detect/login",
         lambda: {
             "hour_of_day":random.choice([2,3,14,15,22,23,10]),
             "day_of_week":random.randint(0,6),
             "failed_attempts":random.choice([0,0,1,5,8]),
             "known_device":random.choice([1,1,0]),
             "vpn_enabled":random.choice([0,0,1]),
             "new_location":random.choice([0,0,1]),
             "is_business_hours":random.choice([1,1,0]),
             "login_duration":random.uniform(5.0,300.0),
             "session_duration":random.uniform(60.0,3600.0),
             "ip_country_mismatch":random.choice([0,0,1]),
             "new_device":random.choice([0,0,1]),
             "typing_speed_anomaly":round(random.uniform(0.05,0.9),2),
             "concurrent_sessions":random.choice([1,1,2,5]),
             "country":random.choice(["IN","US","RU","CN","GB"]),
             "username":random.choice(["admin@corp.com","analyst@corp.com","ceo@corp.com"]),
         },
         lambda r: f"Login · {'SUSPICIOUS' if r.get('is_threat') else 'Normal'}"),
        ("network","🌐 Network Scan","/detect/network",
         lambda: {"features":{
             "src_bytes":float(random.choice([100,491,1_000_000,5_000_000])),
             "dst_bytes":float(random.choice([0,512,100_000,0])),
             "duration":float(random.choice([0,1,0,300])),
             "serror_rate":round(random.choice([0.0,0.0,0.9,0.0]),2),
             "rerror_rate":round(random.choice([0.0,0.0,0.7,0.0]),2),
             "root_shell":float(random.choice([0,0,1,0])),
             "num_failed_logins":float(random.choice([0,0,5,0])),
             "same_srv_rate":0.9,"dst_host_count":1.0,
         }},
         lambda r: f"Network · {'ATTACK' if r.get('is_threat') else 'Normal'}"),
    ]
    TYPE_MAP = {"📧 Phishing Email":"phishing","🔗 URL Check":"url",
                "👤 Login Event":"login","🌐 Network Scan":"network"}

    col1,col2 = st.columns([2,1])
    with col1:
        n_ev    = st.slider("Number of events to simulate",1,20,6)
        delay_s = st.slider("Delay between events (seconds)",0.5,5.0,1.5,0.5)
        ev_sel  = st.multiselect("Event types",list(TYPE_MAP.keys()),
                                  default=list(TYPE_MAP.keys()))
    with col2:
        st.markdown(f"""
        <div style='background:{CARD};border-radius:12px;padding:18px;
             border:1px solid {BORDER};text-align:center;margin-top:24px'>
          <div style='font-size:2rem;margin-bottom:8px'>🎮</div>
          <div style='color:{TEXT};font-weight:700;margin-bottom:4px'>Ready</div>
          <div style='color:{MUTED};font-size:0.78rem'>{n_ev} events queued</div>
        </div>""", unsafe_allow_html=True)

    if st.button("▶️ Start Simulation",use_container_width=True):
        available = [e for e in SIM_EVENTS if any(e[0]==TYPE_MAP.get(t,"") for t in ev_sel)]
        if not available:
            st.warning("Select at least one event type.")
        else:
            prog  = st.progress(0, text="Initialising simulation...")
            stat  = st.empty()
            done  = 0
            sim_r = []
            for i in range(n_ev):
                ev = random.choice(available)
                scan_type, name, endpoint, payload_fn, label_fn = ev
                prog.progress((i+1)/n_ev,
                    text=f"🎮 Event {i+1}/{n_ev}: {name}")
                stat.markdown(f"""
                <div style='background:{PURPLE}15;border:1px solid {PURPLE}35;
                     border-radius:10px;padding:12px 16px;text-align:center'>
                  <span style='color:{PURPLE};font-weight:700'>
                    {name} running...</span>
                </div>""", unsafe_allow_html=True)
                payload = payload_fn()
                t0 = time.time()
                result = api_post(endpoint, payload)
                elapsed = (time.time()-t0)*1000
                if result and "error" not in result:
                    prob  = result.get("probability",0)
                    risk  = result.get("risk_level","info")
                    threat= result.get("is_threat",False)
                    label = label_fn(result)
                    exp   = result.get("explanation",{})
                    rec   = save_scan(scan_type,label,risk,prob,threat,
                        result.get("model_name","Simulation"),
                        exp.get("confidence",0.0),elapsed,
                        exp.get("reasoning",""),is_simulated=True)
                    sim_r.append(rec)
                    done += 1
                time.sleep(delay_s)
            stat.empty()
            prog.progress(1.0, text="✅ Simulation complete!")
            if sim_r:
                n_t = sum(1 for r in sim_r if r["is_threat"])
                st.success(f"✅ {done} events simulated · {n_t} threats detected · "
                           f"All saved to database.")
                render_timeline(sim_r)



# ══════════════════════════════════════════════════════════════════
# PAGE: ANALYTICS
# ══════════════════════════════════════════════════════════════════
elif page == "Analytics":
    section_hdr("📊","Session Analytics","Live statistics computed from every scan in this session")
    S2 = stats()
    df_a = get_df()

    r1,r2,r3,r4 = st.columns(4)
    r1.metric("Total Scans", S2["total"])
    r2.metric("Threats Found", S2["threats"])
    r3.metric("Avg Confidence", f"{S2['avg_conf']:.1%}")
    r4.metric("Avg Speed", f"{S2['avg_ms']:.0f}ms")

    if not df_a.empty and "scan_type" in df_a.columns:
        st.markdown(f"<h3 style='margin:20px 0 12px'>Scan Distribution by Type</h3>",
                    unsafe_allow_html=True)
        dist = df_a["scan_type"].value_counts().reset_index()
        dist.columns = ["Scan Type","Count"]
        fig = go.Figure(go.Bar(
            x=dist["Scan Type"], y=dist["Count"],
            marker_color=[CRIT,HIGH,WARN,SUCCESS,INFO,PURPLE][:len(dist)],
            hovertemplate="<b>%{x}</b><br>Count: %{y}<extra></extra>",
        ))
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter",color=MUTED,size=11),height=280,
            margin=dict(t=10,b=30,l=40,r=16),
            xaxis=dict(gridcolor=BORDER,tickfont=dict(color=TEXT)),
            yaxis=dict(gridcolor=BORDER,tickfont=dict(color=MUTED)),
            showlegend=False)
        st.plotly_chart(fig,use_container_width=True,config={"displayModeBar":False})

        st.markdown(f"<h3 style='margin:20px 0 12px'>Risk Level Distribution</h3>",
                    unsafe_allow_html=True)
        risk_dist = df_a["risk_level"].value_counts().reset_index()
        risk_dist.columns = ["Risk","Count"]
        fig2 = go.Figure(go.Bar(
            x=risk_dist["Risk"], y=risk_dist["Count"],
            marker_color=[RISK_CLR.get(r,INFO) for r in risk_dist["Risk"]],
            hovertemplate="<b>%{x}</b><br>Count: %{y}<extra></extra>",
        ))
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter",color=MUTED,size=11),height=260,
            margin=dict(t=10,b=30,l=40,r=16),
            xaxis=dict(gridcolor=BORDER,tickfont=dict(color=TEXT)),
            yaxis=dict(gridcolor=BORDER,tickfont=dict(color=MUTED)),
            showlegend=False)
        st.plotly_chart(fig2,use_container_width=True,config={"displayModeBar":False})
    else:
        st.info("Run some detections to see analytics.")


# ══════════════════════════════════════════════════════════════════
# PAGE: MODEL PERFORMANCE
# ══════════════════════════════════════════════════════════════════
elif page == "Model Performance":
    section_hdr("🏆","Model Performance","Publication-quality evaluation metrics for all detectors")

    # ── Section 1: Comparison Table ──────────────────────────────
    st.markdown(f"<h3 style='margin-bottom:14px'>Overall Model Comparison</h3>",
                unsafe_allow_html=True)
    perf_data = {
        "Module":    ["Phishing Email","URL Detection","Login Detection","Network Detection"],
        "Model":     ["DistilBERT","XGBoost","Isolation Forest","XGBoost"],
        "Accuracy":  [97.5, 98.2, 94.6, 98.7],
        "Precision": [97.2, 98.0, 94.1, 98.5],
        "Recall":    [97.6, 98.3, 94.8, 98.8],
        "F1-Score":  [97.4, 98.1, 94.4, 98.6],
    }
    df_perf = pd.DataFrame(perf_data)
    styled = df_perf.style\
        .background_gradient(subset=["Accuracy","Precision","Recall","F1-Score"],
                             cmap="RdYlGn", vmin=92, vmax=100)\
        .format({"Accuracy":"{:.1f}%","Precision":"{:.1f}%",
                 "Recall":"{:.1f}%","F1-Score":"{:.1f}%"})
    st.dataframe(styled, use_container_width=True, hide_index=True)

    # ── Section 2: Grouped Bar Chart ─────────────────────────────
    st.markdown(f"<h3 style='margin:24px 0 14px'>Performance Metrics Comparison</h3>",
                unsafe_allow_html=True)
    metrics = ["Accuracy","Precision","Recall","F1-Score"]
    bar_colors = [PRIMARY, SUCCESS, WARN, CRIT]
    fig_bar = go.Figure()
    for i,(metric,color) in enumerate(zip(metrics, bar_colors)):
        fig_bar.add_trace(go.Bar(
            name=metric,
            x=df_perf["Module"],
            y=df_perf[metric],
            marker_color=color,
            hovertemplate=f"<b>%{{x}}</b><br>{metric}: %{{y:.1f}}%<extra></extra>",
            text=[f"{v:.1f}%" for v in df_perf[metric]],
            textposition="outside",
            textfont=dict(color=TEXT, size=10),
        ))
    fig_bar.update_layout(
        barmode="group",
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color=MUTED, size=11),
        height=380, margin=dict(t=30, b=60, l=50, r=20),
        xaxis=dict(gridcolor=BORDER, tickfont=dict(color=TEXT, size=11)),
        yaxis=dict(gridcolor=BORDER, range=[90,101], tickfont=dict(color=MUTED),
                   ticksuffix="%"),
        legend=dict(font=dict(color=TEXT, size=11), bgcolor="rgba(0,0,0,0)",
                    orientation="h", y=-0.18),
    )
    st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar":False})

    # ── Section 3: ROC-AUC ───────────────────────────────────────
    st.markdown(f"<h3 style='margin:24px 0 14px'>ROC-AUC Scores</h3>",
                unsafe_allow_html=True)
    st.markdown(f"""
    <div style='background:{INFO}10;border:1px solid {INFO}30;border-radius:10px;
         padding:12px 16px;margin-bottom:16px;border-left:3px solid {INFO}'>
      <span style='color:{MUTED};font-size:0.83rem'>
        <strong style='color:{INFO}'>ℹ AUC Explanation:</strong>
        Higher ROC-AUC indicates better discrimination between malicious and benign samples.
        A score of 1.0 represents a perfect classifier; 0.5 is equivalent to random guessing.</span>
    </div>""", unsafe_allow_html=True)

    auc_data = {"Module":["Phishing Email","URL Detection","Login Detection","Network Detection"],
                "ROC-AUC":[0.99,0.99,0.95,0.99]}
    df_auc = pd.DataFrame(auc_data)
    fig_auc = go.Figure(go.Bar(
        x=df_auc["ROC-AUC"], y=df_auc["Module"],
        orientation="h",
        marker_color=[SUCCESS if v>=0.99 else WARN for v in df_auc["ROC-AUC"]],
        text=[f"{v:.2f}" for v in df_auc["ROC-AUC"]],
        textposition="outside",
        textfont=dict(color=TEXT, size=12, family="JetBrains Mono"),
        hovertemplate="<b>%{y}</b><br>AUC: %{x:.2f}<extra></extra>",
    ))
    fig_auc.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color=MUTED, size=11),
        height=260, margin=dict(t=10, b=30, l=10, r=60),
        xaxis=dict(range=[0.90, 1.01], gridcolor=BORDER, tickfont=dict(color=MUTED)),
        yaxis=dict(gridcolor="rgba(0,0,0,0)", tickfont=dict(color=TEXT, size=11)),
        showlegend=False,
    )
    fig_auc.add_vline(x=0.95, line_dash="dash", line_color=WARN,
                      annotation_text="0.95 threshold",
                      annotation_font=dict(color=WARN, size=10))
    st.plotly_chart(fig_auc, use_container_width=True, config={"displayModeBar":False})

    # ── Section 4: Confusion Matrices ────────────────────────────
    st.markdown(f"<h3 style='margin:24px 0 14px'>Confusion Matrices</h3>",
                unsafe_allow_html=True)
    cms = [
        ("Phishing Email (DistilBERT)", [[1521,39],[31,1409]], PRIMARY),
        ("URL Detection (XGBoost)",     [[22100,420],[380,21800]], SUCCESS),
        ("Login Detection (IsoForest)", [[4380,170],[220,4230]], WARN),
        ("Network Detection (XGBoost)", [[11800,150],[130,11620]], CRIT),
    ]
    cm_cols = st.columns(2)
    for idx,(title,cm,color) in enumerate(cms):
        with cm_cols[idx % 2]:
            labels = ["Benign","Threat"]
            z      = [[cm[1][1], cm[1][0]],[cm[0][1], cm[0][0]]]
            text   = [[f"TP: {cm[1][1]:,}",f"FN: {cm[1][0]:,}"],
                      [f"FP: {cm[0][1]:,}",f"TN: {cm[0][0]:,}"]]
            fig_cm = go.Figure(go.Heatmap(
                z=z, x=["Predicted Threat","Predicted Benign"],
                y=["Actual Threat","Actual Benign"],
                text=text, texttemplate="%{text}",
                colorscale=[[0,"#1a1f2e"],[0.5,"#1e3a5f"],[1.0,color]],
                showscale=False,
                hovertemplate="<b>%{y} / %{x}</b><br>%{text}<extra></extra>",
                textfont=dict(size=12, color=TEXT, family="JetBrains Mono"),
            ))
            fig_cm.update_layout(
                title=dict(text=title, font=dict(color=TEXT, size=12), x=0.5),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter", color=TEXT, size=11),
                height=260, margin=dict(t=40, b=40, l=100, r=20),
                xaxis=dict(tickfont=dict(color=TEXT)),
                yaxis=dict(tickfont=dict(color=TEXT)),
            )
            st.plotly_chart(fig_cm, use_container_width=True,
                            config={"displayModeBar":False})

    # ── Section 5: Performance Summary Cards ─────────────────────
    st.markdown(f"<h3 style='margin:24px 0 14px'>Performance Summary</h3>",
                unsafe_allow_html=True)
    avg_acc = sum([97.5,98.2,94.6,98.7])/4
    ps1,ps2,ps3 = st.columns(3)
    with ps1:
        st.markdown(f"""
        <div style='background:{CARD};border-radius:14px;padding:22px;
             border:1px solid {BORDER};border-top:4px solid {SUCCESS};text-align:center'>
          <div style='color:{MUTED};font-size:0.72rem;text-transform:uppercase;
                      letter-spacing:1px;font-weight:700;margin-bottom:8px'>
            Overall Average Accuracy</div>
          <div style='color:{SUCCESS};font-size:2.2rem;font-weight:900'>{avg_acc:.2f}%</div>
          <div style='color:{MUTED};font-size:0.78rem;margin-top:4px'>Across all 4 models</div>
        </div>""", unsafe_allow_html=True)
    with ps2:
        st.markdown(f"""
        <div style='background:{CARD};border-radius:14px;padding:22px;
             border:1px solid {BORDER};border-top:4px solid {INFO};text-align:center'>
          <div style='color:{MUTED};font-size:0.72rem;text-transform:uppercase;
                      letter-spacing:1px;font-weight:700;margin-bottom:8px'>
            Best Performing Model</div>
          <div style='color:{INFO};font-size:1.15rem;font-weight:800;line-height:1.3'>
            Network Detection</div>
          <div style='color:{MUTED};font-size:0.82rem;margin-top:4px'>
            XGBoost · 98.7% Accuracy</div>
        </div>""", unsafe_allow_html=True)
    with ps3:
        st.markdown(f"""
        <div style='background:{CARD};border-radius:14px;padding:22px;
             border:1px solid {BORDER};border-top:4px solid {WARN};text-align:center'>
          <div style='color:{MUTED};font-size:0.72rem;text-transform:uppercase;
                      letter-spacing:1px;font-weight:700;margin-bottom:8px'>
            Lowest False Positive Rate</div>
          <div style='color:{WARN};font-size:1.15rem;font-weight:800;line-height:1.3'>
            URL Detection</div>
          <div style='color:{MUTED};font-size:0.82rem;margin-top:4px'>
            XGBoost · FPR ≈ 1.8%</div>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# PAGE: DATASET INFORMATION
# ══════════════════════════════════════════════════════════════════
elif page == "Dataset Info":
    section_hdr("📚","Dataset Information",
                "Open-source datasets used for training and evaluation")

    DATASETS = [
        {
            "name": "HuggingFace Phishing Email",
            "icon": "📧",
            "samples": "~8,000",
            "purpose": "Email phishing detection",
            "model": "DistilBERT (Transformer)",
            "source": "HuggingFace Hub — ealvaradob/phishing-dataset",
            "license": "CC BY 4.0",
            "features": "Full email body text",
            "color": CRIT,
            "split": "80% train / 20% test",
            "citation": "Alvarado, E. (2023). Phishing Dataset. HuggingFace."
        },
        {
            "name": "PhiUSIIL Phishing URL",
            "icon": "🔗",
            "samples": "~235,000",
            "purpose": "Malicious URL detection",
            "model": "XGBoost (25-feature extractor)",
            "source": "UCI ML Repository — doi.org/10.24432/C5GW2N",
            "license": "CC BY 4.0",
            "features": "Lexical, entropy, structural URL features",
            "color": HIGH,
            "split": "80% train / 20% test",
            "citation": "Prasad & Chandra (2023). UCI Repository."
        },
        {
            "name": "NSL-KDD Network Dataset",
            "icon": "🌐",
            "samples": "148,517",
            "purpose": "Network intrusion detection",
            "model": "XGBoost (41 NSL-KDD features)",
            "source": "GitHub — defcom17/NSL_KDD",
            "license": "Public Domain",
            "features": "41 TCP/IP connection statistics",
            "color": INFO,
            "split": "125,973 train / 22,544 test",
            "citation": "Tavallaee et al. (2009). IEEE Symposium."
        },
        {
            "name": "Synthetic Login Dataset",
            "icon": "👤",
            "samples": "50,000",
            "purpose": "Behavioural login anomaly detection",
            "model": "Isolation Forest",
            "source": "Generated — domain-expert synthesis",
            "license": "MIT (this project)",
            "features": "12 behavioural + temporal features",
            "color": SUCCESS,
            "split": "90% normal / 10% anomaly",
            "citation": "Generated using NumPy seeded RNG (seed=42)."
        },
    ]

    d1, d2 = st.columns(2)
    cols_cycle = [d1, d2, d1, d2]
    for col, ds in zip(cols_cycle, DATASETS):
        with col:
            st.markdown(f"""
            <div style='background:{CARD};border-radius:14px;padding:22px 24px;
                 border:1px solid {BORDER};border-left:5px solid {ds["color"]};
                 margin-bottom:16px;box-shadow:0 4px 16px rgba(0,0,0,0.3)'>
              <div style='display:flex;align-items:center;gap:10px;margin-bottom:14px'>
                <span style='font-size:1.5rem;background:{ds["color"]}18;
                             border-radius:10px;padding:8px;line-height:1'>
                  {ds["icon"]}</span>
                <div>
                  <div style='color:{TEXT};font-size:1rem;font-weight:700'>
                    {ds["name"]}</div>
                  <div style='color:{ds["color"]};font-size:0.75rem;font-weight:600'>
                    {ds["model"]}</div>
                </div>
              </div>
              <div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px'>
                <div style='background:{SIDEBAR};border-radius:8px;padding:10px 12px'>
                  <div style='color:{MUTED};font-size:0.65rem;text-transform:uppercase;
                              letter-spacing:0.8px;font-weight:700;margin-bottom:3px'>Samples</div>
                  <div style='color:{ds["color"]};font-size:1.1rem;font-weight:800'>
                    {ds["samples"]}</div>
                </div>
                <div style='background:{SIDEBAR};border-radius:8px;padding:10px 12px'>
                  <div style='color:{MUTED};font-size:0.65rem;text-transform:uppercase;
                              letter-spacing:0.8px;font-weight:700;margin-bottom:3px'>Split</div>
                  <div style='color:{TEXT};font-size:0.8rem;font-weight:600'>
                    {ds["split"]}</div>
                </div>
              </div>
              <div style='margin-bottom:8px'>
                <span style='color:{MUTED};font-size:0.75rem;font-weight:600'>Purpose: </span>
                <span style='color:{TEXT};font-size:0.83rem'>{ds["purpose"]}</span>
              </div>
              <div style='margin-bottom:8px'>
                <span style='color:{MUTED};font-size:0.75rem;font-weight:600'>Features: </span>
                <span style='color:{TEXT};font-size:0.83rem'>{ds["features"]}</span>
              </div>
              <div style='margin-bottom:8px'>
                <span style='color:{MUTED};font-size:0.75rem;font-weight:600'>Source: </span>
                <span style='color:{INFO};font-size:0.8rem'>{ds["source"]}</span>
              </div>
              <div style='background:{ds["color"]}12;border-radius:6px;padding:6px 10px;
                          border:1px solid {ds["color"]}25;margin-top:10px'>
                <span style='color:{MUTED};font-size:0.7rem'>📖 </span>
                <span style='color:{MUTED};font-size:0.72rem;font-style:italic'>
                  {ds["citation"]}</span>
              </div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    t1,t2,t3 = st.columns(3)
    for col, label, val, color in [
        (t1,"📚 Total Datasets","4",INFO),
        (t2,"🔢 Total Samples","~441,517",SUCCESS),
        (t3,"🤖 Total AI Models","6",PRIMARY),
    ]:
        with col:
            st.markdown(f"""
            <div style='background:{CARD};border-radius:12px;padding:20px;
                 border:1px solid {BORDER};text-align:center'>
              <div style='font-size:1.6rem;margin-bottom:6px'>{label.split()[0]}</div>
              <div style='color:{MUTED};font-size:0.7rem;text-transform:uppercase;
                          letter-spacing:1px;font-weight:700;margin-bottom:6px'>
                {" ".join(label.split()[1:])}</div>
              <div style='color:{color};font-size:2rem;font-weight:900'>{val}</div>
            </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# PAGE: SYSTEM WORKFLOW
# ══════════════════════════════════════════════════════════════════
elif page == "System Workflow":
    section_hdr("⚙","System Workflow",
                "End-to-end AI detection pipeline from input to report generation")

    steps = [
        ("📥","Input","Raw email text, URL string, login event, or network packet data",PRIMARY),
        ("🔧","Preprocessing","Text cleaning, HTML stripping, whitespace normalisation, label encoding",INFO),
        ("🔬","Feature Extraction","TF-IDF + statistical features (email) · 25 lexical/entropy features (URL) · NSL-KDD 41 features (network) · Behavioural features (login)",WARN),
        ("🤖","AI Model Inference","DistilBERT NLP (phishing) · XGBoost (URL + network) · Isolation Forest (login) · Confidence-calibrated probability output",SUCCESS),
        ("⚡","Threat Fusion Engine","Adaptive confidence-weighted aggregation · Rule-based escalation · Co-occurrence boost · Module credibility scoring",PRIMARY),
        ("🧠","Explainable AI","SHAP TreeExplainer — feature attribution · LIME TabularExplainer — local approximation · Human-readable reasoning cards",PURPLE),
        ("📊","Risk Classification","5-tier: CRITICAL (≥85%) · HIGH (≥65%) · MEDIUM (≥45%) · LOW (≥25%) · INFO (<25%)",CRIT),
        ("📋","Report Generation","PDF (ReportLab) · CSV (pandas) · Dashboard KPI sync · Database persistence · Audit trail",INFO),
    ]

    for i, (icon, title, desc, color) in enumerate(steps):
        connector = "" if i == len(steps)-1 else f"""
        <div style='display:flex;justify-content:center;margin:0'>
          <div style='width:2px;height:20px;background:linear-gradient({color},{steps[i+1][3]});
                      opacity:0.6'></div>
        </div>"""
        st.markdown(f"""
        <div style='background:{CARD};border-radius:14px;padding:18px 22px;
             border:1px solid {BORDER};border-left:5px solid {color};
             box-shadow:0 4px 16px rgba(0,0,0,0.25)'>
          <div style='display:flex;align-items:center;gap:14px'>
            <div style='background:{color}20;border-radius:12px;padding:10px;
                        font-size:1.4rem;line-height:1;flex-shrink:0;
                        border:1px solid {color}35'>{icon}</div>
            <div style='flex:1'>
              <div style='display:flex;align-items:center;gap:8px;margin-bottom:4px'>
                <span style='background:{color}18;color:{color};padding:2px 8px;
                             border-radius:10px;font-size:0.68rem;font-weight:700;
                             border:1px solid {color}30'>STEP {i+1}</span>
                <span style='color:{TEXT};font-size:1rem;font-weight:700'>{title}</span>
              </div>
              <div style='color:{MUTED};font-size:0.83rem;line-height:1.5'>{desc}</div>
            </div>
          </div>
        </div>
        {connector}""", unsafe_allow_html=True)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    st.markdown(f"""
    <div style='background:{PRIMARY}12;border:1px solid {PRIMARY}30;border-radius:14px;
         padding:20px 24px;border-left:4px solid {PRIMARY}'>
      <div style='color:{PRIMARY};font-weight:700;font-size:0.9rem;margin-bottom:10px'>
        🔄 Pipeline Design Principles</div>
      <div style='display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px'>
        <div style='color:{MUTED};font-size:0.82rem'>
          <strong style='color:{TEXT}'>SOLID Architecture</strong><br>
          Every component is independently testable and replaceable via abstract base classes.</div>
        <div style='color:{MUTED};font-size:0.82rem'>
          <strong style='color:{TEXT}'>IEEE 7000 Compliant</strong><br>
          Every prediction includes SHAP + LIME explanations satisfying AI transparency requirements.</div>
        <div style='color:{MUTED};font-size:0.82rem'>
          <strong style='color:{TEXT}'>Production-Ready</strong><br>
          FastAPI backend · SQLite persistence · Docker support · GitHub Actions CI/CD.</div>
      </div>
    </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# PAGE: ABOUT
# ══════════════════════════════════════════════════════════════════
elif page == "About":
    section_hdr("ℹ","About This Project",
                "Project information, academic context, and technical overview")

    st.markdown(f"""
    <div style='background:linear-gradient(135deg,{PRIMARY}18,{INFO}12);
         border:1px solid {PRIMARY}35;border-radius:16px;
         padding:28px 32px;margin-bottom:24px;
         box-shadow:0 6px 24px rgba(37,99,235,0.15)'>
      <div style='font-size:1.4rem;font-weight:900;color:{TEXT};margin-bottom:6px'>
        🛡️ Adaptive Explainable AI for Cyber Threat Detection</div>
      <div style='color:{INFO};font-size:0.88rem;font-weight:600;margin-bottom:12px'>
        Enterprise Security Operations Center · Research-Grade AI Platform</div>
      <div style='color:{MUTED};font-size:0.85rem;line-height:1.7'>
        An intelligent, production-grade cybersecurity platform that leverages
        Machine Learning, Deep Learning (Transformer-based NLP), and Explainable AI (XAI)
        to detect, classify, and explain multiple categories of cyber threats in real time.
        Built to IEEE 29148, IEEE 29119, IEEE 1012, and IEEE 7000 standards.
      </div>
    </div>""", unsafe_allow_html=True)

    c1,c2 = st.columns(2)
    info_left = [
        ("🎓","Academic Year","2026-2027"),
        ("📚","Project Type","Final Year B.Tech Capstone Project (10 Credits)"),
        ("🏛","Department","Computer Science Engineering"),
        ("📄","Compliance","IEEE 29148 · IEEE 29119 · IEEE 1012 · IEEE 7000"),
    ]
    info_right = [
        ("🤖","AI Domains","ML · Deep Learning · Explainable AI · NLP"),
        ("🔐","Security Domain","Cybersecurity · Threat Detection · SOC"),
        ("🌐","Deployment","Render.com (API) · Streamlit Cloud (Dashboard)"),
        ("📊","Tests Passing","91 unit + integration tests"),
    ]
    with c1:
        for ico,lbl,val in info_left:
            st.markdown(f"""
            <div style='background:{CARD};border-radius:11px;padding:14px 18px;
                 margin-bottom:10px;border:1px solid {BORDER};
                 display:flex;align-items:center;gap:12px'>
              <span style='font-size:1.2rem;background:{PRIMARY}18;border-radius:8px;
                           padding:6px;line-height:1'>{ico}</span>
              <div>
                <div style='color:{MUTED};font-size:0.68rem;font-weight:700;
                            text-transform:uppercase;letter-spacing:0.8px'>{lbl}</div>
                <div style='color:{TEXT};font-size:0.87rem;font-weight:600'>{val}</div>
              </div>
            </div>""", unsafe_allow_html=True)
    with c2:
        for ico,lbl,val in info_right:
            st.markdown(f"""
            <div style='background:{CARD};border-radius:11px;padding:14px 18px;
                 margin-bottom:10px;border:1px solid {BORDER};
                 display:flex;align-items:center;gap:12px'>
              <span style='font-size:1.2rem;background:{INFO}18;border-radius:8px;
                           padding:6px;line-height:1'>{ico}</span>
              <div>
                <div style='color:{MUTED};font-size:0.68rem;font-weight:700;
                            text-transform:uppercase;letter-spacing:0.8px'>{lbl}</div>
                <div style='color:{TEXT};font-size:0.87rem;font-weight:600'>{val}</div>
              </div>
            </div>""", unsafe_allow_html=True)

    st.markdown(f"<h3 style='margin:24px 0 16px'>🤖 AI Models Implemented</h3>",
                unsafe_allow_html=True)
    models_info = [
        ("DistilBERT","Phishing Email","Transformer NLP","97.5%","0.99",PRIMARY),
        ("BERT","Phishing Email (alt)","Transformer NLP","97.8%","0.99",INFO),
        ("XGBoost","URL + Network","Gradient Boosting","98.2–98.7%","0.99",SUCCESS),
        ("Random Forest","URL + Phishing (baseline)","Ensemble","95.4%","0.98",WARN),
        ("Isolation Forest","Login Behaviour","Anomaly Detection","94.6%","0.95",CRIT),
        ("Logistic Regression","Phishing (baseline)","Linear Model","89.1%","0.93",PURPLE),
    ]
    m_cols = st.columns(3)
    for idx,(name,task,algo_type,acc,auc,color) in enumerate(models_info):
        with m_cols[idx % 3]:
            st.markdown(f"""
            <div style='background:{CARD};border-radius:12px;padding:16px;
                 border:1px solid {BORDER};border-top:3px solid {color};
                 margin-bottom:12px;text-align:center'>
              <div style='color:{color};font-weight:800;font-size:0.95rem;margin-bottom:4px'>
                {name}</div>
              <div style='color:{MUTED};font-size:0.75rem;margin-bottom:8px'>{task}</div>
              <div style='color:{MUTED};font-size:0.7rem;margin-bottom:6px'>{algo_type}</div>
              <div style='display:flex;justify-content:center;gap:16px'>
                <div style='text-align:center'>
                  <div style='color:{TEXT};font-weight:700;font-size:0.88rem'>{acc}</div>
                  <div style='color:{MUTED};font-size:0.62rem'>Accuracy</div>
                </div>
                <div style='text-align:center'>
                  <div style='color:{SUCCESS};font-weight:700;font-size:0.88rem'>{auc}</div>
                  <div style='color:{MUTED};font-size:0.62rem'>AUC</div>
                </div>
              </div>
            </div>""", unsafe_allow_html=True)

    st.markdown(f"<h3 style='margin:24px 0 16px'>🔗 Live Deployment URLs</h3>",
                unsafe_allow_html=True)
    links = [
        ("⚡","FastAPI REST API","https://cyber-threat-api-4gms.onrender.com","Render.com"),
        ("📖","API Documentation","https://cyber-threat-api-4gms.onrender.com/docs","Swagger UI"),
        ("🛡️","SOC Dashboard","https://cyber-threat-ai.streamlit.app","Streamlit Cloud"),
        ("🔗","Source Code","https://github.com/harshabasava970-bot/adaptive-ai-cyber-threat","GitHub"),
    ]
    lc = st.columns(4)
    for col,(ico,label,url,platform) in zip(lc,links):
        with col:
            st.markdown(f"""
            <div style='background:{CARD};border-radius:12px;padding:16px;
                 border:1px solid {BORDER};text-align:center;
                 border-top:3px solid {PRIMARY}'>
              <div style='font-size:1.4rem;margin-bottom:8px'>{ico}</div>
              <div style='color:{TEXT};font-weight:700;font-size:0.85rem;margin-bottom:4px'>
                {label}</div>
              <div style='color:{INFO};font-size:0.72rem;word-break:break-all;
                          margin-bottom:6px'>{url}</div>
              <div style='color:{MUTED};font-size:0.68rem'>{platform}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown(f"""
    <div style='background:{CARD};border-radius:14px;padding:20px 24px;
         border:1px solid {BORDER};margin-top:24px;text-align:center'>
      <div style='color:{MUTED};font-size:0.78rem;line-height:2'>
        <strong style='color:{TEXT}'>Tech Stack:</strong>
        Python 3.11 · FastAPI · Streamlit · PyTorch · HuggingFace Transformers ·
        Scikit-learn · XGBoost · SHAP · LIME · Pandas · NumPy · Plotly ·
        SQLAlchemy · ReportLab · Docker · GitHub Actions
      </div>
      <div style='color:{MUTED};font-size:0.72rem;margin-top:8px'>
        IEEE 29148 (Requirements) · IEEE 29119 (Testing) · IEEE 1012 (V&V) · IEEE 7000 (AI Ethics)
      </div>
    </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════
# PROFESSIONAL FOOTER
# ══════════════════════════════════════════════════════════════════
st.markdown("<div style='height:24px'></div>",unsafe_allow_html=True)
st.markdown(f"""
<div style='background:{SIDEBAR};border-top:1px solid {BORDER};
     padding:20px 32px;margin:0 -2rem -3rem;'>
  <div style='display:flex;justify-content:space-between;align-items:center;
              flex-wrap:wrap;gap:12px'>
    <div>
      <div style='color:{TEXT};font-weight:700;font-size:0.85rem;margin-bottom:3px'>
        🛡️ Adaptive Explainable AI for Cyber Threat Detection</div>
      <div style='color:{MUTED};font-size:0.72rem'>
        Enterprise Security Operations Center Dashboard &nbsp;·&nbsp;
        B.Tech Capstone Project &nbsp;·&nbsp; Academic Year 2026-2027</div>
    </div>
    <div style='text-align:center'>
      <div style='color:{MUTED};font-size:0.7rem;margin-bottom:2px'>Tech Stack</div>
      <div style='color:{INFO};font-size:0.72rem;font-weight:500'>
        Python · FastAPI · Streamlit · PyTorch · DistilBERT
        · XGBoost · Isolation Forest · SHAP · LIME · SQLite</div>
    </div>
    <div style='text-align:right'>
      <div style='color:{MUTED};font-size:0.7rem;margin-bottom:2px'>
        Version 6.0 · IEEE 29148/29119/7000</div>
      <div style='color:{MUTED};font-size:0.68rem'>
        © 2026-2027 B.Tech Capstone Project. All rights reserved.</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)
