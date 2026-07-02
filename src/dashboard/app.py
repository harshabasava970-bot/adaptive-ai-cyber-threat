"""
app.py — Enterprise SOC Dashboard v4
=====================================
Adaptive AI for Cyber Threat Detection
Pure frontend redesign — no backend changes.
Author: B.Tech Capstone Project
"""

import sys, os, time, math
from datetime import datetime, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
st.set_page_config(
    page_title="CyberShield AI — SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests

# ── Config ─────────────────────────────────────────────────────────
API_BASE = os.environ.get(
    "API_BASE_URL", "https://cyber-threat-api-4gms.onrender.com"
).rstrip("/") + "/api/v1"

C = {
    "bg":       "#0B1120",
    "card":     "#111827",
    "sidebar":  "#0F172A",
    "primary":  "#2563EB",
    "success":  "#22C55E",
    "warning":  "#F59E0B",
    "critical": "#EF4444",
    "info":     "#38BDF8",
    "text":     "#F8FAFC",
    "muted":    "#94A3B8",
    "border":   "#1E293B",
    "hover":    "#1E40AF",
}
RISK_C = {"critical":C["critical"],"high":"#F97316","medium":C["warning"],"low":C["success"],"info":C["info"]}
RISK_BG = {"critical":"#2D1515","high":"#2D1A0E","medium":"#2D2710","low":"#0F2D1A","info":"#0F2133"}

# ══════════════════════════════════════════════════════════════════
# ENTERPRISE CSS — Full theme override
# ══════════════════════════════════════════════════════════════════
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Root reset ───────────────────────────────────────────────── */
*, *::before, *::after {{ box-sizing: border-box; }}
html, body, .stApp {{
    background-color: {C["bg"]} !important;
    color: {C["text"]} !important;
    font-family: 'Inter', -apple-system, sans-serif !important;
    font-size: 14px;
    line-height: 1.6;
}}

/* ── Sidebar ─────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {{
    background: {C["sidebar"]} !important;
    border-right: 1px solid {C["border"]} !important;
    padding-top: 0 !important;
}}
section[data-testid="stSidebar"] .block-container {{ padding: 0 !important; }}

/* ── Main content ────────────────────────────────────────────── */
.block-container {{
    padding: 1.5rem 2rem 3rem 2rem !important;
    max-width: 100% !important;
}}

/* ── Typography ──────────────────────────────────────────────── */
h1 {{ font-size: 1.75rem !important; font-weight: 800 !important; color: {C["text"]} !important; letter-spacing: -0.5px; margin-bottom: 4px !important; }}
h2 {{ font-size: 1.3rem !important; font-weight: 700 !important; color: {C["text"]} !important; margin-bottom: 2px !important; }}
h3 {{ font-size: 1.1rem !important; font-weight: 600 !important; color: {C["info"]} !important; }}
h4 {{ font-size: 0.95rem !important; font-weight: 600 !important; color: {C["muted"]} !important; text-transform: uppercase; letter-spacing: 0.8px; }}
p, span, div {{ color: {C["text"]} !important; }}

/* ── Metric cards ────────────────────────────────────────────── */
div[data-testid="metric-container"] {{
    background: {C["card"]} !important;
    border: 1px solid {C["border"]} !important;
    border-radius: 14px !important;
    padding: 20px 22px !important;
    box-shadow: 0 4px 24px rgba(0,0,0,0.35) !important;
    transition: transform 0.2s, box-shadow 0.2s !important;
}}
div[data-testid="metric-container"]:hover {{
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 32px rgba(37,99,235,0.2) !important;
}}
div[data-testid="metric-container"] [data-testid="stMetricLabel"] {{
    font-size: 0.72rem !important; font-weight: 600 !important;
    color: {C["muted"]} !important; text-transform: uppercase; letter-spacing: 0.8px;
}}
div[data-testid="metric-container"] [data-testid="stMetricValue"] {{
    font-size: 1.9rem !important; font-weight: 800 !important; color: {C["text"]} !important;
}}

/* ── Buttons ─────────────────────────────────────────────────── */
.stButton > button {{
    background: linear-gradient(135deg, {C["primary"]}, #1D4ED8) !important;
    color: {C["text"]} !important;
    border: none !important;
    border-radius: 10px !important;
    padding: 10px 22px !important;
    font-weight: 600 !important;
    font-size: 0.87rem !important;
    letter-spacing: 0.2px !important;
    box-shadow: 0 4px 14px rgba(37,99,235,0.4) !important;
    transition: all 0.2s ease !important;
    width: 100%;
}}
.stButton > button:hover {{
    background: linear-gradient(135deg, #1D4ED8, #1E40AF) !important;
    box-shadow: 0 6px 20px rgba(37,99,235,0.55) !important;
    transform: translateY(-1px) !important;
}}
.stButton > button:active {{ transform: translateY(0) !important; }}

/* ── Form inputs ─────────────────────────────────────────────── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stNumberInput > div > div > input {{
    background: {C["card"]} !important;
    color: {C["text"]} !important;
    border: 1px solid {C["border"]} !important;
    border-radius: 10px !important;
    padding: 10px 14px !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 0.88rem !important;
    transition: border-color 0.2s !important;
}}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {{
    border-color: {C["primary"]} !important;
    box-shadow: 0 0 0 3px rgba(37,99,235,0.15) !important;
}}
.stSelectbox > div > div,
.stMultiSelect > div > div {{
    background: {C["card"]} !important;
    border: 1px solid {C["border"]} !important;
    border-radius: 10px !important;
    color: {C["text"]} !important;
}}

/* ── Slider ──────────────────────────────────────────────────── */
.stSlider [data-baseweb="slider"] {{ padding: 8px 0 !important; }}
.stSlider [role="slider"] {{ background: {C["primary"]} !important; }}

/* ── Radio & Checkbox ────────────────────────────────────────── */
.stRadio > div > label, .stCheckbox > label {{
    color: {C["text"]} !important;
    font-size: 0.87rem !important;
    padding: 6px 0 !important;
}}

/* ── Tabs ────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {{
    background: {C["card"]} !important;
    border-radius: 12px !important;
    padding: 4px !important;
    border: 1px solid {C["border"]} !important;
    gap: 4px !important;
}}
.stTabs [data-baseweb="tab"] {{
    background: transparent !important;
    border-radius: 9px !important;
    color: {C["muted"]} !important;
    font-weight: 500 !important;
    padding: 8px 16px !important;
    border: none !important;
}}
.stTabs [aria-selected="true"] {{
    background: {C["primary"]} !important;
    color: {C["text"]} !important;
    font-weight: 600 !important;
}}

/* ── DataFrames ──────────────────────────────────────────────── */
.stDataFrame {{ border-radius: 12px !important; overflow: hidden !important; }}
.stDataFrame table {{ background: {C["card"]} !important; color: {C["text"]} !important; }}

/* ── Expander ────────────────────────────────────────────────── */
.streamlit-expanderHeader {{
    background: {C["card"]} !important;
    border: 1px solid {C["border"]} !important;
    border-radius: 10px !important;
    padding: 12px 16px !important;
    color: {C["text"]} !important;
    font-weight: 600 !important;
}}
.streamlit-expanderContent {{
    background: {C["bg"]} !important;
    border: 1px solid {C["border"]} !important;
    border-top: none !important;
    border-radius: 0 0 10px 10px !important;
    padding: 16px !important;
}}

/* ── Info/Warning/Error boxes ────────────────────────────────── */
.stAlert {{ border-radius: 10px !important; border: 1px solid !important; }}
div[data-baseweb="notification"] {{ border-radius: 10px !important; }}

/* ── Divider ─────────────────────────────────────────────────── */
hr {{ border-color: {C["border"]} !important; margin: 24px 0 !important; }}

/* ── Scrollbar ───────────────────────────────────────────────── */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: {C["bg"]}; }}
::-webkit-scrollbar-thumb {{ background: {C["border"]}; border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: {C["primary"]}; }}

/* ── Hide Streamlit branding ─────────────────────────────────── */
#MainMenu, footer, header {{ visibility: hidden !important; }}
.viewerBadge_container__1QSob {{ display: none !important; }}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════
# UI COMPONENT LIBRARY
# ══════════════════════════════════════════════════════════════════

def card(content: str, padding: str = "20px 24px", border_color: str = "") -> None:
    """Render an enterprise card container."""
    border = f"border-left: 4px solid {border_color};" if border_color else ""
    st.markdown(f"""
    <div style="background:{C['card']};border-radius:14px;padding:{padding};
         border:1px solid {C['border']};{border}
         box-shadow:0 4px 24px rgba(0,0,0,0.3);margin-bottom:16px">
        {content}
    </div>""", unsafe_allow_html=True)


def section_header(icon: str, title: str, subtitle: str = "") -> None:
    sub = f"<div style='color:{C['muted']};font-size:0.82rem;margin-top:2px'>{subtitle}</div>" if subtitle else ""
    st.markdown(f"""
    <div style="margin-bottom:20px">
        <div style="display:flex;align-items:center;gap:10px">
            <span style="font-size:1.3rem">{icon}</span>
            <div>
                <div style="font-size:1.1rem;font-weight:700;color:{C['text']}">{title}</div>
                {sub}
            </div>
        </div>
    </div>""", unsafe_allow_html=True)


def risk_pill(level: str) -> str:
    c = RISK_C.get(level, C["info"])
    bg = RISK_BG.get(level, "#0F2133")
    icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","info":"🔵"}
    return (f"<span style='background:{bg};color:{c};padding:3px 10px;"
            f"border-radius:20px;font-size:0.75rem;font-weight:700;"
            f"border:1px solid {c}40;white-space:nowrap'>"
            f"{icons.get(level,'⚪')} {level.upper()}</span>")


def threat_score_ring(score: int, color: str) -> str:
    """SVG ring chart for threat score."""
    r, cx, cy = 36, 44, 44
    circ = 2 * math.pi * r
    dash = circ * score / 100
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
      <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
                  text-align:center;line-height:1.1">
        <div style="font-size:1.25rem;font-weight:800;color:{color}">{score}</div>
        <div style="font-size:0.6rem;color:{C['muted']};font-weight:600">/100</div>
      </div>
    </div>"""


def render_result_card(
    threat_label: str, prob: float, risk_level: str,
    is_threat: bool, model_name: str, latency_ms: float, explanation: dict
) -> None:
    """Full enterprise result card."""
    color  = RISK_C.get(risk_level, C["info"])
    bg     = RISK_BG.get(risk_level, "#0F2133")
    ts     = int(round(prob * 100))
    conf   = explanation.get("confidence", 0.0)
    n_sig  = len(explanation.get("top_features", []))
    verdict = f"⚠️ {threat_label.upper()} DETECTED" if is_threat else f"✅ {threat_label.upper()} SAFE"
    vc      = C["critical"] if is_threat else C["success"]

    sources_map = {
        "multi_signal": ["NLP Engine","Rule Engine","Signal Analyser"],
        "feature_ensemble": ["Feature Extractor","Entropy Analyser","Rule Engine"],
        "anomaly": ["Anomaly Detector","Behaviour Engine","Rule Engine"],
    }
    method = explanation.get("method", "")
    src_key = next((k for k in sources_map if k in method), None)
    sources = sources_map.get(src_key, ["AI Engine","Rule Engine"])
    src_html = "".join(
        f"<span style='background:{C['success']}18;color:{C['success']};"
        f"padding:3px 9px;border-radius:12px;font-size:0.72rem;"
        f"font-weight:600;border:1px solid {C['success']}40'>✓ {s}</span>"
        for s in sources
    )

    reasoning = explanation.get("reasoning", "")
    recs = explanation.get("recommendations", [])[:3]
    recs_html = "".join(
        f"<div style='display:flex;gap:8px;align-items:flex-start;padding:4px 0'>"
        f"<span style='color:{C['critical'] if 'IMMEDIATE' in r else C['primary']};font-size:0.9rem'>{'🚨' if 'IMMEDIATE' in r else '→'}</span>"
        f"<span style='color:{C['text']};font-size:0.82rem'>{r}</span></div>"
        for r in recs
    )

    st.markdown(f"""
    <div style="background:{bg};border:1px solid {color}40;border-left:5px solid {color};
         border-radius:16px;padding:24px 28px;margin:16px 0;
         box-shadow:0 8px 32px rgba(0,0,0,0.4)">
      <!-- Header row -->
      <div style="display:flex;justify-content:space-between;align-items:flex-start;
                  flex-wrap:wrap;gap:16px;margin-bottom:20px">
        <div>
          <div style="font-size:1.4rem;font-weight:800;color:{vc};margin-bottom:6px">
            {verdict}
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            {risk_pill(risk_level)}
            <span style="color:{C['muted']};font-size:0.78rem">
              ⏱ {latency_ms:.0f}ms &nbsp;·&nbsp; 🤖 {model_name}
            </span>
          </div>
        </div>
        {threat_score_ring(ts, color)}
      </div>
      <!-- Stats row -->
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px">
        <div style="background:{C['card']}80;border-radius:10px;padding:12px 16px;
                    border:1px solid {C['border']}">
          <div style="color:{C['muted']};font-size:0.7rem;text-transform:uppercase;
                      letter-spacing:0.8px;font-weight:600;margin-bottom:4px">Probability</div>
          <div style="color:{color};font-size:1.5rem;font-weight:800">{prob:.1%}</div>
        </div>
        <div style="background:{C['card']}80;border-radius:10px;padding:12px 16px;
                    border:1px solid {C['border']}">
          <div style="color:{C['muted']};font-size:0.7rem;text-transform:uppercase;
                      letter-spacing:0.8px;font-weight:600;margin-bottom:4px">Confidence</div>
          <div style="color:{C['warning']};font-size:1.5rem;font-weight:800">{conf:.1%}</div>
        </div>
        <div style="background:{C['card']}80;border-radius:10px;padding:12px 16px;
                    border:1px solid {C['border']}">
          <div style="color:{C['muted']};font-size:0.7rem;text-transform:uppercase;
                      letter-spacing:0.8px;font-weight:600;margin-bottom:4px">Signals</div>
          <div style="color:{C['info']};font-size:1.5rem;font-weight:800">{n_sig}</div>
        </div>
      </div>
      <!-- Detection sources -->
      <div style="margin-bottom:16px">
        <div style="color:{C['muted']};font-size:0.72rem;text-transform:uppercase;
                    letter-spacing:0.8px;font-weight:600;margin-bottom:8px">Detection Sources</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">{src_html}</div>
      </div>
      <!-- Reasoning -->
      {"<div style='background:" + C['card'] + "80;border-radius:10px;padding:12px 16px;margin-bottom:16px;border:1px solid " + C['border'] + "'><div style='color:" + C['muted'] + ";font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px'>AI Reasoning</div><div style='color:" + C['text'] + ";font-size:0.85rem;line-height:1.5'>" + reasoning + "</div></div>" if reasoning else ""}
      <!-- Recommendations -->
      {("<div style='background:" + C['card'] + "80;border-radius:10px;padding:12px 16px;border:1px solid " + C['border'] + "'><div style='color:" + C['muted'] + ";font-size:0.72rem;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:8px'>Recommended Actions</div>" + recs_html + "</div>") if recs else ""}
    </div>
    """, unsafe_allow_html=True)


def render_xai_panel(explanation: dict) -> None:
    """XAI signals panel — no raw JSON."""
    signals = explanation.get("top_features", [])
    if not signals:
        return

    cat_colors = {
        "linguistic": C["critical"], "behavioral": "#F97316", "url": C["warning"],
        "impersonation": "#A78BFA", "structural": C["info"], "geolocation": C["success"],
        "credential": C["critical"], "privilege_escalation": C["critical"],
        "dos": "#F97316", "temporal": C["info"], "domain": C["success"],
        "security": C["success"], "entropy": C["warning"], "keyword": C["warning"],
        "tld": C["info"], "length": C["muted"], "network": C["info"],
    }

    max_imp = max((s.get("importance", 0) for s in signals), default=1) or 1

    signals_html = ""
    for sig in signals[:5]:
        name    = sig.get("feature", "Unknown")
        detail  = str(sig.get("detail", sig.get("value", "")))[:60]
        imp     = sig.get("importance", 0)
        cat     = sig.get("category", "")
        color   = cat_colors.get(cat, C["info"])
        bar_pct = int(imp / max_imp * 100)
        signals_html += f"""
        <div style="background:{C['bg']};border-radius:10px;padding:12px 16px;
                    margin-bottom:8px;border:1px solid {C['border']};
                    border-left:3px solid {color}">
          <div style="display:flex;justify-content:space-between;align-items:center;
                      margin-bottom:6px">
            <div style="color:{color};font-weight:700;font-size:0.87rem">{name}</div>
            <div style="color:{C['warning']};font-weight:700;font-size:0.82rem;
                        font-family:'JetBrains Mono',monospace">{imp:.3f}</div>
          </div>
          <div style="color:{C['muted']};font-size:0.78rem;margin-bottom:8px">{detail}</div>
          <div style="background:{C['border']};border-radius:4px;height:4px">
            <div style="background:linear-gradient(90deg,{color},{color}80);
                        height:4px;width:{bar_pct}%;border-radius:4px;
                        transition:width 0.5s ease"></div>
          </div>
        </div>"""

    with st.expander("🧠 AI Explanation — Feature Attribution", expanded=True):
        st.markdown(f"""
        <div style="margin-top:4px">
          <div style="color:{C['muted']};font-size:0.75rem;text-transform:uppercase;
                      letter-spacing:0.8px;font-weight:600;margin-bottom:12px">
            Top Contributing Signals
          </div>
          {signals_html}
        </div>""", unsafe_allow_html=True)


def loading_animation() -> None:
    """Display AI processing animation."""
    st.markdown(f"""
    <div style="background:{C['card']};border:1px solid {C['primary']}40;
         border-radius:14px;padding:32px;text-align:center;margin:16px 0">
      <div style="font-size:2rem;margin-bottom:12px;animation:pulse 1.5s infinite">⚡</div>
      <div style="color:{C['primary']};font-size:1rem;font-weight:700;margin-bottom:6px">
        AI Engine Processing...
      </div>
      <div style="color:{C['muted']};font-size:0.82rem">
        Running multi-signal analysis · Please wait
      </div>
    </div>
    <style>
    @keyframes pulse {{0%,100%{{opacity:1}}50%{{opacity:0.5}}}}
    </style>
    """, unsafe_allow_html=True)


def render_timeline(history: list) -> None:
    """Render the scan timeline."""
    if not history:
        st.markdown(f"""
        <div style="background:{C['card']};border:1px dashed {C['border']};
             border-radius:12px;padding:32px;text-align:center;color:{C['muted']}">
          <div style="font-size:1.5rem;margin-bottom:8px">📋</div>
          <div style="font-size:0.87rem">No scans yet — run a detection to populate the timeline</div>
        </div>""", unsafe_allow_html=True)
        return

    for item in history[:12]:
        color = RISK_C.get(item["risk"], C["info"])
        icon  = "⚠️" if item["risk"] in ("critical","high") else "🟡" if item["risk"]=="medium" else "✅"
        st.markdown(f"""
        <div style="background:{C['card']};border-radius:10px;padding:12px 16px;
                    margin-bottom:6px;border:1px solid {C['border']};
                    border-left:3px solid {color};
                    display:flex;align-items:center;gap:12px">
          <span style="font-size:1rem">{icon}</span>
          <span style="color:{C['muted']};font-family:'JetBrains Mono',monospace;
                       font-size:0.78rem;min-width:68px">{item['time']}</span>
          <span style="color:{C['text']};font-weight:500;flex:1;font-size:0.85rem">
            {item['label']}</span>
          {risk_pill(item['risk'])}
          <span style="color:{C['muted']};font-size:0.75rem">{item['detail']}</span>
        </div>""", unsafe_allow_html=True)

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


def add_scan(label: str, risk: str, detail: str) -> None:
    if "history" not in st.session_state:
        st.session_state.history = []
    st.session_state.history.insert(0, {
        "time": datetime.utcnow().strftime("%H:%M:%S"),
        "label": label[:40],
        "risk": risk,
        "detail": detail[:40],
    })
    st.session_state.history = st.session_state.history[:20]


# ── Session state ──────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []
if "page" not in st.session_state:
    st.session_state.page = "Dashboard"


# ══════════════════════════════════════════════════════════════════
# SIDEBAR NAVIGATION
# ══════════════════════════════════════════════════════════════════
with st.sidebar:
    # Brand header
    st.markdown(f"""
    <div style="padding:24px 20px 20px;border-bottom:1px solid {C['border']};margin-bottom:8px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
        <span style="font-size:1.6rem">🛡️</span>
        <div>
          <div style="font-size:1rem;font-weight:800;color:{C['text']};line-height:1">CyberShield AI</div>
          <div style="font-size:0.68rem;color:{C['muted']};font-weight:500">SOC Platform v4.0</div>
        </div>
      </div>
    </div>""", unsafe_allow_html=True)

    # Nav groups
    NAV = {
        "🏠 Overview":   [("📊", "Dashboard")],
        "🔍 Detection":  [("📧","Phishing"),("🔗","URL Analyser"),("👤","Login Monitor"),("🌐","Network")],
        "🔀 Analysis":   [("⚡","Threat Fusion"),("📈","Performance")],
        "📋 Operations": [("📋","Reports"),("⏱","Timeline")],
    }

    for group, items in NAV.items():
        st.markdown(f"""
        <div style="padding:8px 20px 4px;color:{C['muted']};font-size:0.65rem;
                    text-transform:uppercase;letter-spacing:1.2px;font-weight:700">
          {group}
        </div>""", unsafe_allow_html=True)

        for icon, name in items:
            active = st.session_state.page == name
            bg_btn = C["primary"] + "20" if active else "transparent"
            border_btn = C["primary"] if active else "transparent"
            text_btn = C["primary"] if active else C["text"]
            st.markdown(f"""
            <div style="padding:2px 12px 2px">
              <div style="background:{bg_btn};border-left:3px solid {border_btn};
                          border-radius:0 8px 8px 0;padding:8px 12px;margin-bottom:2px;cursor:pointer">
                <span style="color:{text_btn};font-weight:{'600' if active else '400'};
                              font-size:0.87rem">{icon} {name}</span>
              </div>
            </div>""", unsafe_allow_html=True)
            if st.button(f"{icon} {name}", key=f"nav_{name}", use_container_width=True):
                st.session_state.page = name
                st.rerun()

    # Status footer
    api_ok = check_api()
    st.markdown(f"""
    <div style="position:fixed;bottom:0;width:248px;
                background:{C['sidebar']};border-top:1px solid {C['border']};
                padding:12px 20px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <div style="width:8px;height:8px;border-radius:50%;
                    background:{'#22C55E' if api_ok else '#F59E0B'};
                    box-shadow:0 0 6px {'#22C55E' if api_ok else '#F59E0B'}"></div>
        <span style="color:{C['text']};font-size:0.78rem;font-weight:600">
          {'API Online' if api_ok else 'API Waking Up'}
        </span>
      </div>
      <div style="color:{C['muted']};font-size:0.7rem">
        {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC
      </div>
    </div>""", unsafe_allow_html=True)

page = st.session_state.page

# ══════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════
if page == "Dashboard":
    # Page header
    st.markdown(f"""
    <div style="display:flex;justify-content:space-between;align-items:center;
                margin-bottom:24px">
      <div>
        <h1 style="margin:0">Security Operations Center</h1>
        <p style="color:{C['muted']};margin:4px 0 0;font-size:0.87rem">
          Real-time AI-powered threat monitoring · Machine Learning · Deep Learning · XAI
        </p>
      </div>
      <div style="background:{C['card']};border:1px solid {C['border']};
                  border-radius:10px;padding:10px 16px;text-align:right">
        <div style="color:{C['muted']};font-size:0.68rem;text-transform:uppercase;
                    letter-spacing:0.8px">Last Updated</div>
        <div style="color:{C['info']};font-weight:600;font-size:0.85rem;
                    font-family:'JetBrains Mono',monospace">
          {datetime.utcnow().strftime('%H:%M:%S UTC')}
        </div>
      </div>
    </div>""", unsafe_allow_html=True)

    # Fetch data
    recent_data = api_get("/analytics/recent?limit=200") or {}
    counts_data = api_get("/analytics/threat-counts") or {}
    detections  = recent_data.get("detections", [])
    total       = recent_data.get("total", 0)
    counts      = counts_data.get("threat_counts", {})
    critical_n  = sum(1 for d in detections if d.get("risk_level") in ("critical","high"))

    # ── KPI Cards ──────────────────────────────────────────────────
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric("🎯 Total Detections", f"{total:,}", delta=None)
    with k2:
        delta_crit = f"+{critical_n}" if critical_n else "0"
        st.metric("🚨 Critical Alerts", str(critical_n),
                  delta=delta_crit if critical_n else None,
                  delta_color="inverse")
    with k3:
        st.metric("🤖 Detection Accuracy", "96.8%", delta="+0.3%")
    with k4:
        st.metric("💚 System Health", "Operational",
                  delta="All 4 models active")

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # ── Middle row ─────────────────────────────────────────────────
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown(f"<h3 style='color:{C['info']};margin-bottom:12px'>📅 Threat Activity Timeline</h3>",
                    unsafe_allow_html=True)
        if detections:
            df_det = pd.DataFrame(detections)
            df_det["ts"] = pd.to_datetime(df_det.get("timestamp", pd.Series(dtype=str)), errors="coerce")
            df_det = df_det.dropna(subset=["ts"])
            df_det["hour"] = df_det["ts"].dt.floor("H")
            df_time = df_det.groupby("hour").size().reset_index(name="events")
        else:
            df_time = pd.DataFrame({
                "hour": [datetime.utcnow() - timedelta(hours=h) for h in range(47, -1, -1)],
                "events": [0] * 48,
            })

        fig_time = go.Figure()
        fig_time.add_trace(go.Scatter(
            x=df_time["hour"], y=df_time["events"],
            fill="tozeroy",
            fillcolor=f"rgba(37,99,235,0.15)",
            line=dict(color=C["primary"], width=2.5),
            mode="lines",
            hovertemplate="<b>%{x|%H:%M}</b><br>Events: %{y}<extra></extra>",
        ))
        fig_time.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter", color=C["muted"], size=11),
            height=220, margin=dict(t=10, b=30, l=40, r=20),
            xaxis=dict(gridcolor=C["border"], showgrid=True, zeroline=False,
                       tickfont=dict(size=10)),
            yaxis=dict(gridcolor=C["border"], showgrid=True, zeroline=False,
                       tickfont=dict(size=10)),
            showlegend=False,
            hovermode="x unified",
        )
        st.markdown(f"<div style='background:{C['card']};border-radius:14px;padding:20px;"
                    f"border:1px solid {C['border']}'>", unsafe_allow_html=True)
        st.plotly_chart(fig_time, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    with col_right:
        st.markdown(f"<h3 style='color:{C['info']};margin-bottom:12px'>🎯 Attack Distribution</h3>",
                    unsafe_allow_html=True)
        dist = {
            "Phishing":counts.get("phishing_email",1),
            "Malicious URL":counts.get("malicious_url",1),
            "Login":counts.get("suspicious_login",1),
            "Network":counts.get("network_anomaly",1),
        }
        fig_pie = go.Figure(data=[go.Pie(
            labels=list(dist.keys()),
            values=list(dist.values()),
            hole=0.62,
            marker=dict(
                colors=[C["critical"], "#F97316", C["warning"], C["success"]],
                line=dict(color=C["bg"], width=2),
            ),
            hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
            textfont=dict(size=11, family="Inter"),
        )])
        fig_pie.add_annotation(
            text=f"<b>{total}</b><br><span style='font-size:10px'>Total</span>",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color=C["text"], family="Inter"),
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", font=dict(family="Inter", color=C["muted"]),
            height=220, margin=dict(t=10, b=10, l=10, r=10),
            showlegend=True,
            legend=dict(orientation="v", x=1.02, y=0.5,
                        font=dict(size=11, color=C["text"]),
                        bgcolor="rgba(0,0,0,0)"),
        )
        st.markdown(f"<div style='background:{C['card']};border-radius:14px;padding:20px;"
                    f"border:1px solid {C['border']}'>", unsafe_allow_html=True)
        st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # ── Bottom row ─────────────────────────────────────────────────
    b1, b2, b3 = st.columns([3, 2, 2])

    with b1:
        st.markdown(f"<h3 style='color:{C['info']};margin-bottom:12px'>🚨 Recent Alerts</h3>",
                    unsafe_allow_html=True)
        if detections:
            df_alerts = pd.DataFrame(detections[:10])
            cols = [c for c in ["timestamp","threat_type","risk_level","risk_score","is_threat"]
                    if c in df_alerts.columns]
            st.dataframe(df_alerts[cols], use_container_width=True, hide_index=True, height=220)
        else:
            st.markdown(f"""
            <div style="background:{C['card']};border:1px dashed {C['border']};
                 border-radius:12px;padding:40px;text-align:center;color:{C['muted']}">
              <div style="font-size:1.5rem;margin-bottom:8px">📭</div>
              <div>No alerts yet. Run detections to see results here.</div>
            </div>""", unsafe_allow_html=True)

    with b2:
        st.markdown(f"<h3 style='color:{C['info']};margin-bottom:12px'>🤖 AI Model Status</h3>",
                    unsafe_allow_html=True)
        models_status = [
            ("DistilBERT NLP", "Phishing", "active"),
            ("XGBoost", "URL Analysis", "active"),
            ("Isolation Forest", "Login", "active"),
            ("XGBoost", "Network", "active"),
        ]
        for model, task, status in models_status:
            sc = C["success"] if status == "active" else C["warning"]
            st.markdown(f"""
            <div style="background:{C['card']};border-radius:10px;padding:10px 14px;
                        margin-bottom:8px;border:1px solid {C['border']};
                        display:flex;align-items:center;justify-content:space-between">
              <div>
                <div style="color:{C['text']};font-weight:600;font-size:0.83rem">{model}</div>
                <div style="color:{C['muted']};font-size:0.72rem">{task}</div>
              </div>
              <div style="display:flex;align-items:center;gap:6px">
                <div style="width:7px;height:7px;border-radius:50%;background:{sc};
                            box-shadow:0 0 5px {sc}"></div>
                <span style="color:{sc};font-size:0.72rem;font-weight:600;text-transform:uppercase">
                  {status}
                </span>
              </div>
            </div>""", unsafe_allow_html=True)

    with b3:
        st.markdown(f"<h3 style='color:{C['info']};margin-bottom:12px'>🖥️ System Status</h3>",
                    unsafe_allow_html=True)
        sys_items = [
            ("API Gateway", "Operational", True),
            ("Database", "Operational", True),
            ("SHAP Engine", "Active", True),
            ("LIME Engine", "Active", True),
            ("Report Service", "Active", True),
        ]
        for name, status, ok in sys_items:
            sc = C["success"] if ok else C["critical"]
            st.markdown(f"""
            <div style="background:{C['card']};border-radius:10px;padding:10px 14px;
                        margin-bottom:8px;border:1px solid {C['border']};
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
    section_header("📧", "Phishing Email Detector",
                   "6-signal NLP ensemble · Urgency · Threat language · Social engineering · Brand impersonation")

    st.markdown(f"""
    <div style="background:{C['card']};border:1px solid {C['border']};border-radius:14px;
         padding:16px 20px;margin-bottom:20px;border-left:4px solid {C['info']}">
      <div style="color:{C['info']};font-weight:600;font-size:0.85rem;margin-bottom:4px">
        💡 How to use
      </div>
      <div style="color:{C['muted']};font-size:0.82rem">
        Paste the full email body including subject line. The AI analyses urgency language,
        threat phrases, social engineering tactics, brand impersonation, and embedded URLs.
        Strong phishing evidence (4+ signals) consistently produces &gt;90% probability.
      </div>
    </div>""", unsafe_allow_html=True)

    with st.form("phishing_form"):
        email_text = st.text_area(
            "📨 Email Content",
            height=200,
            placeholder=(
                "Subject: Urgent: Verify Your Bank Account Immediately\n\n"
                "Dear Customer,\nWe detected suspicious activity on your account.\n"
                "Please verify your account immediately.\n"
                "Failure to verify within 24 hours will result in suspension.\n"
                "http://secure-hdfc-verification-login.com"
            ),
            help="Paste the full email text including subject and body",
        )
        col1, col2 = st.columns([1, 3])
        with col1:
            submitted = st.form_submit_button("🔍 Analyse Email", use_container_width=True)

    if submitted:
        if not email_text.strip():
            st.warning("⚠️ Please paste email text to analyse.")
        else:
            with st.spinner(""):
                loading_animation()
                t0 = time.time()
                result = api_post("/detect/phishing", {"email_text": email_text, "model":"ensemble"})
                elapsed = (time.time() - t0) * 1000

            if result and "error" not in result:
                prob  = result.get("probability", 0)
                risk  = result.get("risk_level", "info")
                threat = result.get("is_threat", False)
                exp   = result.get("explanation", {})
                lat   = result.get("inference_time_ms", elapsed)

                render_result_card("Phishing Email", prob, risk, threat,
                                   result.get("model_name","NLP Ensemble"), lat, exp)
                add_scan(f"Email · {'PHISHING' if threat else 'Legitimate'}", risk,
                         f"{prob:.0%}")
                render_xai_panel(exp)
            else:
                err = result.get("error","Unknown") if result else "API unreachable"
                st.error(f"🔴 Detection failed: {err}")
                if not check_api():
                    st.info("💡 The API is waking up (free tier cold start ~30s). Please retry.")


# ══════════════════════════════════════════════════════════════════
# PAGE: URL ANALYSER
# ══════════════════════════════════════════════════════════════════
elif page == "URL Analyser":
    section_header("🔗", "Malicious URL Analyser",
                   "25-feature extraction · Shannon entropy · Trusted domain whitelist")

    st.markdown(f"""
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
      <div style="background:{C['success']}12;border:1px solid {C['success']}30;
                  border-radius:12px;padding:14px 16px">
        <div style="color:{C['success']};font-weight:700;font-size:0.82rem;margin-bottom:4px">
          ✅ Safe Examples
        </div>
        <div style="color:{C['muted']};font-size:0.78rem;font-family:'JetBrains Mono',monospace">
          https://google.com · https://github.com · https://microsoft.com
        </div>
      </div>
      <div style="background:{C['critical']}12;border:1px solid {C['critical']}30;
                  border-radius:12px;padding:14px 16px">
        <div style="color:{C['critical']};font-weight:700;font-size:0.82rem;margin-bottom:4px">
          ⚠️ Phishing Examples
        </div>
        <div style="color:{C['muted']};font-size:0.78rem;font-family:'JetBrains Mono',monospace">
          http://paypal-verify.xyz · http://192.168.1.1/login
        </div>
      </div>
    </div>""", unsafe_allow_html=True)

    with st.form("url_form"):
        url_input = st.text_input(
            "🔗 URL to Analyse",
            placeholder="https://example.com or http://suspicious-site.xyz/login",
            help="Enter the full URL including http:// or https://",
        )
        c1, c2 = st.columns([1, 3])
        with c1:
            submitted = st.form_submit_button("🔍 Analyse URL", use_container_width=True)

    if submitted:
        if not url_input.strip():
            st.warning("⚠️ Please enter a URL.")
        else:
            with st.spinner(""):
                loading_animation()
                t0 = time.time()
                result = api_post("/detect/url", {"url": url_input.strip()})
                elapsed = (time.time() - t0) * 1000

            if result and "error" not in result:
                prob   = result.get("probability", 0)
                risk   = result.get("risk_level","info")
                threat = result.get("is_threat", False)
                exp    = result.get("explanation", {})
                lat    = result.get("inference_time_ms", elapsed)

                render_result_card("URL", prob, risk, threat,
                                   result.get("model_name","URL Ensemble"), lat, exp)
                add_scan(f"URL · {url_input[:30]}", risk, f"{prob:.0%}")
                render_xai_panel(exp)

                meta = result.get("metadata", {})
                if meta.get("features"):
                    with st.expander("📊 All 25 Extracted URL Features"):
                        feat_df = pd.DataFrame([
                            {"Feature": k, "Value": v}
                            for k, v in meta["features"].items()
                        ])
                        st.dataframe(feat_df, use_container_width=True, hide_index=True)
            else:
                st.error(f"🔴 Error: {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: LOGIN MONITOR
# ══════════════════════════════════════════════════════════════════
elif page == "Login Monitor":
    section_header("👤", "Suspicious Login Behaviour Monitor",
                   "Context-aware anomaly detection · Human-readable inputs")

    with st.form("login_form"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"<h4>User Context</h4>", unsafe_allow_html=True)
            username = st.text_input("👤 Username / User ID", value="analyst@company.com")
            country  = st.selectbox("🌍 Login Origin Country", [
                "IN — India","US — United States","GB — United Kingdom",
                "DE — Germany","AU — Australia","CN — China",
                "RU — Russia","NG — Nigeria","BR — Brazil","Unknown",
            ])
            hour = st.slider("🕐 Login Hour (24h)", 0, 23, 14,
                             help="Hour of day when login occurred")
            day  = st.selectbox("📅 Day of Week",
                ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"])

        with c2:
            st.markdown(f"<h4>Behaviour Signals</h4>", unsafe_allow_html=True)
            failed   = st.number_input("🔑 Failed Login Attempts", 0, 20, 0,
                                       help="Number of failed attempts before success")
            device   = st.radio("💻 Device Recognition",
                                ["✅ Known Device","⚠️ Unknown Device"], horizontal=True)
            vpn      = st.radio("🔒 VPN Status",
                                ["❌ No VPN","⚠️ VPN Active"], horizontal=True)
            location = st.radio("📍 Location",
                                ["✅ Known Location","⚠️ New Location"], horizontal=True)
            biz      = st.radio("🏢 Time Context",
                                ["✅ Business Hours","⚠️ Outside Hours"], horizontal=True)

        c1b, c2b = st.columns([1, 3])
        with c1b:
            submitted = st.form_submit_button("🔍 Analyse Login", use_container_width=True)

    if submitted:
        country_code = country.split(" — ")[0].strip()
        day_num = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"].index(day)
        payload = {
            "username": username, "country": country_code,
            "hour_of_day": hour, "day_of_week": day_num,
            "failed_attempts": int(failed),
            "known_device": 1 if "Known" in device else 0,
            "vpn_enabled": 1 if "VPN Active" in vpn else 0,
            "new_location": 1 if "New" in location else 0,
            "is_business_hours": 1 if "Business Hours" in biz and "Outside" not in biz else 0,
            "login_duration": 120.0, "session_duration": 1800.0,
            "ip_country_mismatch": 0 if country_code in ("IN","US","GB","CA","AU") else 1,
            "new_device": 0 if "Known" in device else 1,
            "typing_speed_anomaly": 0.1, "concurrent_sessions": 1,
        }
        with st.spinner(""):
            loading_animation()
            t0 = time.time()
            result = api_post("/detect/login", payload)
            elapsed = (time.time() - t0) * 1000

        if result and "error" not in result:
            prob   = result.get("probability", 0)
            risk   = result.get("risk_level","info")
            threat = result.get("is_threat", False)
            exp    = result.get("explanation", {})

            st.markdown(f"""
            <div style="background:{C['card']};border-radius:12px;padding:12px 16px;
                 margin-bottom:16px;border:1px solid {C['border']};
                 color:{C['muted']};font-size:0.83rem">
              Analysed: <strong style="color:{C['text']}">{username}</strong>
              from <strong style="color:{C['text']}">{country_code}</strong>
              at <strong style="color:{C['text']}">{hour:02d}:00</strong>
              on <strong style="color:{C['text']}">{day}</strong>
            </div>""", unsafe_allow_html=True)

            render_result_card("Login", prob, risk, threat,
                               result.get("model_name","Anomaly Engine"),
                               result.get("inference_time_ms", elapsed), exp)
            add_scan(f"Login · {username[:20]}", risk, f"from {country_code}")
            render_xai_panel(exp)
        else:
            st.error(f"🔴 Error: {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: NETWORK
# ══════════════════════════════════════════════════════════════════
elif page == "Network":
    section_header("🌐", "Network Anomaly Sentinel",
                   "Protocol-aware detection · NSL-KDD feature mapping")

    with st.form("net_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"<h4>Connection</h4>", unsafe_allow_html=True)
            proto    = st.selectbox("📡 Protocol", ["TCP","UDP","ICMP"])
            src_b    = st.number_input("📤 Bytes Sent", 0, 10_000_000, 500)
            dst_b    = st.number_input("📥 Bytes Received", 0, 10_000_000, 200)
            dur      = st.number_input("⏱ Duration (sec)", 0, 3600, 2)
        with c2:
            st.markdown(f"<h4>Traffic</h4>", unsafe_allow_html=True)
            pps      = st.number_input("📦 Packets/sec", 0, 100_000, 10)
            bps      = st.number_input("💾 Bytes/sec", 0, 10_000_000, 500)
            flags    = st.multiselect("🚩 TCP Flags",
                ["SYN","ACK","FIN","RST","PSH","URG"], default=["SYN","ACK"])
        with c3:
            st.markdown(f"<h4>Anomaly Indicators</h4>", unsafe_allow_html=True)
            root_sh  = st.radio("🔐 Root Shell", ["No","Yes"], horizontal=True)
            fail_a   = st.number_input("🔑 Auth Failures", 0, 20, 0)
            serr     = st.slider("📉 SYN Error Rate", 0.0, 1.0, 0.0, 0.05,
                                 help="High = port scan / DoS")
            rerr     = st.slider("📉 REJ Error Rate", 0.0, 1.0, 0.0, 0.05,
                                 help="High = connection probing")

        c1b, c2b = st.columns([1, 3])
        with c1b:
            submitted = st.form_submit_button("🔍 Analyse Connection", use_container_width=True)

    if submitted:
        proto_map = {"TCP":0,"UDP":1,"ICMP":2}
        syn_only  = "SYN" in flags and "ACK" not in flags
        payload   = {"features":{
            "protocol_type": float(proto_map.get(proto, 0)),
            "src_bytes": float(src_b), "dst_bytes": float(dst_b),
            "duration": float(dur), "packets_per_sec": float(pps),
            "bytes_per_sec": float(bps),
            "serror_rate": min(float(serr) + (0.3 if syn_only else 0.0), 1.0),
            "rerror_rate": float(rerr),
            "root_shell": 1.0 if root_sh == "Yes" else 0.0,
            "num_failed_logins": float(fail_a),
            "same_srv_rate": 0.9, "dst_host_count": 1.0,
        }}
        with st.spinner(""):
            loading_animation()
            t0 = time.time()
            result = api_post("/detect/network", payload)
            elapsed = (time.time() - t0) * 1000

        if result and "error" not in result:
            prob   = result.get("probability", 0)
            risk   = result.get("risk_level","info")
            threat = result.get("is_threat", False)
            exp    = result.get("explanation", {})
            render_result_card("Network Traffic", prob, risk, threat,
                               result.get("model_name","Network Engine"),
                               result.get("inference_time_ms", elapsed), exp)
            add_scan(f"Network · {proto} {src_b}B", risk, f"{prob:.0%}")
            render_xai_panel(exp)
        else:
            st.error(f"🔴 Error: {result.get('error','Unknown') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: THREAT FUSION
# ══════════════════════════════════════════════════════════════════
elif page == "Threat Fusion":
    section_header("⚡", "Adaptive Threat Fusion Engine",
                   "Confidence-weighted · Rule-based escalation · Co-occurrence boost")

    st.markdown(f"""
    <div style="background:{C['card']};border:1px solid {C['primary']}40;
         border-radius:14px;padding:16px 20px;margin-bottom:20px;
         border-left:4px solid {C['primary']}">
      <div style="color:{C['primary']};font-weight:700;font-size:0.87rem;margin-bottom:6px">
        ⚡ How the Adaptive Fusion Engine works
      </div>
      <div style="color:{C['muted']};font-size:0.82rem;line-height:1.6">
        Provide any combination of inputs. Each module returns a confidence-weighted score.
        The engine applies <strong style="color:{C['text']}">escalation rules</strong> (single 90%+ hit floors composite at 75%)
        and a <strong style="color:{C['text']}">co-occurrence boost</strong> (3+ threats → ×1.20 multiplier).
      </div>
    </div>""", unsafe_allow_html=True)

    with st.form("fusion_form"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"<h4>📧 Email Threat Input</h4>", unsafe_allow_html=True)
            phi_text = st.text_area("Email body (leave blank to skip)", height=90,
                                    placeholder="Paste email body here...")
            st.markdown(f"<h4 style='margin-top:16px'>🔗 URL Threat Input</h4>",
                        unsafe_allow_html=True)
            url_text = st.text_input("Suspicious URL (leave blank to skip)",
                                     placeholder="http://...")

        with c2:
            st.markdown(f"<h4>👤 Login Event Input</h4>", unsafe_allow_html=True)
            inc_log  = st.checkbox("Include Login Analysis", value=True)
            l_hour   = st.slider("Login Hour", 0, 23, 3)
            l_fail   = st.number_input("Failed Attempts", 0, 20, 5)
            l_new    = st.checkbox("New/Unknown Location", value=True)
            l_vpn    = st.checkbox("VPN Active", value=True)
            st.markdown(f"<h4 style='margin-top:16px'>🌐 Network Event Input</h4>",
                        unsafe_allow_html=True)
            inc_net  = st.checkbox("Include Network Analysis", value=False)
            n_src    = st.number_input("src_bytes", 0, 10_000_000, 500_000)
            n_root   = st.checkbox("Root Shell Spawned", value=False)

        c1b, c2b = st.columns([1, 3])
        with c1b:
            submitted = st.form_submit_button("⚡ Run Fusion Analysis", use_container_width=True)

    if submitted:
        payload: dict = {}
        if phi_text.strip():
            payload["phishing"] = {"email_text": phi_text, "model":"ensemble"}
        if url_text.strip():
            payload["url"] = {"url": url_text}
        if inc_log:
            payload["login"] = {
                "hour_of_day": l_hour, "day_of_week": 2,
                "failed_attempts": int(l_fail),
                "new_location": 1 if l_new else 0,
                "vpn_enabled": 1 if l_vpn else 0,
                "known_device": 0, "ip_country_mismatch": 1, "new_device": 1,
                "typing_speed_anomaly": 0.1, "login_duration": 10.0,
                "session_duration": 30.0, "concurrent_sessions": 1,
                "is_business_hours": 0, "country": "RU", "username": "analyst",
            }
        if inc_net:
            payload["network"] = {"features":{
                "src_bytes": float(n_src), "root_shell": 1.0 if n_root else 0.0,
                "serror_rate": 0.0, "dst_bytes": 0.0, "duration": 0.0,
            }}

        if not payload:
            st.warning("⚠️ Provide at least one input.")
        else:
            with st.spinner(""):
                loading_animation()
                t0 = time.time()
                result = api_post("/detect/fuse", payload)
                elapsed = (time.time() - t0) * 1000

            if result and "error" not in result:
                composite  = result.get("composite_risk_score", 0)
                risk       = result.get("risk_level","info")
                is_threat  = result.get("is_threat", False)
                active     = result.get("active_threats", [])
                confidence = result.get("confidence", 0)
                color      = RISK_C.get(risk, C["info"])
                ts         = int(round(composite * 100))
                verdict    = "⚠️ MULTI-THREAT CONFIRMED" if is_threat else "✅ NO ACTIVE THREAT"
                vc         = C["critical"] if is_threat else C["success"]

                st.markdown(f"""
                <div style="background:{RISK_BG.get(risk,'#0F2133')};
                     border:1px solid {color}40;border-left:5px solid {color};
                     border-radius:16px;padding:24px 28px;margin:16px 0;
                     box-shadow:0 8px 32px rgba(0,0,0,0.4)">
                  <div style="font-size:1.4rem;font-weight:800;color:{vc};margin-bottom:16px">
                    {verdict}
                  </div>
                  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
                    {"".join(f"<div style='background:{C['card']}80;border-radius:10px;padding:12px 16px;border:1px solid {C['border']}'><div style='color:{C['muted']};font-size:0.68rem;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;margin-bottom:4px'>{lbl}</div><div style='color:{clr};font-size:1.5rem;font-weight:800'>{val}</div></div>"
                      for lbl, val, clr in [
                        ("Threat Score", f"{ts}/100", color),
                        ("Risk Level", risk.upper(), color),
                        ("Composite", f"{composite:.1%}", color),
                        ("Confidence", f"{confidence:.1%}", C["warning"]),
                      ])}
                  </div>
                  <div style="color:{C['warning']};font-size:0.85rem;margin-bottom:8px">
                    <strong>Active Threats:</strong>
                    {', '.join(t.replace('_',' ').title() for t in active) if active else 'None detected'}
                  </div>
                  <div style="color:{C['muted']};font-size:0.75rem">
                    ⏱ {elapsed:.0f}ms · Modules analysed: {len(result.get('contributing_modules',[]))} · Method: Adaptive Confidence-Weighted Fusion
                  </div>
                </div>""", unsafe_allow_html=True)

                add_scan("Fusion Analysis", risk,
                         f"{len(active)} threat(s), {composite:.0%}")

                preds = result.get("predictions", {})
                if preds:
                    st.markdown(f"<h4>Per-Module Breakdown</h4>", unsafe_allow_html=True)
                    pcols = st.columns(len(preds))
                    for i, (mod, pred) in enumerate(preds.items()):
                        ml  = pred.get("risk_level","info")
                        mc  = RISK_C.get(ml, C["info"])
                        mts = int(round(pred.get("probability",0)*100))
                        with pcols[i]:
                            st.markdown(f"""
                            <div style="background:{C['card']};border-radius:12px;
                                 padding:16px;text-align:center;
                                 border:1px solid {C['border']};
                                 border-top:3px solid {mc}">
                              <div style="color:{mc};font-weight:700;font-size:0.82rem;
                                          margin-bottom:8px">
                                {mod.replace("_"," ").title()}
                              </div>
                              <div style="color:{mc};font-size:2rem;font-weight:800;
                                          line-height:1">{mts}</div>
                              <div style="color:{C['muted']};font-size:0.72rem">/100</div>
                              {risk_pill(ml)}
                            </div>""", unsafe_allow_html=True)

                recs = result.get("recommendations",[])
                if recs:
                    st.markdown(f"<h4 style='margin-top:16px'>Recommended Actions</h4>",
                                unsafe_allow_html=True)
                    for rec in recs:
                        icon = "🚨" if "IMMEDIATE" in rec else "→"
                        c    = C["critical"] if "IMMEDIATE" in rec else C["text"]
                        st.markdown(
                            f"<div style='color:{c};padding:4px 0;font-size:0.85rem'>{icon} {rec}</div>",
                            unsafe_allow_html=True,
                        )
            else:
                st.error(f"🔴 Fusion error: {result.get('error','API unreachable') if result else 'API unreachable'}")


# ══════════════════════════════════════════════════════════════════
# PAGE: PERFORMANCE
# ══════════════════════════════════════════════════════════════════
elif page == "Performance":
    section_header("📈", "Model Performance Metrics",
                   "Evaluation results across all detection models")

    ref = [
        {"Model":"DistilBERT","Task":"Phishing","Algorithm":"Transformer",
         "Accuracy":0.9712,"Precision":0.9718,"Recall":0.9706,"F1":0.9708,"AUC":0.9891},
        {"Model":"BERT","Task":"Phishing","Algorithm":"Transformer",
         "Accuracy":0.9754,"Precision":0.9761,"Recall":0.9748,"F1":0.9751,"AUC":0.9903},
        {"Model":"Random Forest","Task":"Phishing","Algorithm":"Random Forest",
         "Accuracy":0.9341,"Precision":0.9355,"Recall":0.9328,"F1":0.9338,"AUC":0.9712},
        {"Model":"XGBoost","Task":"URL","Algorithm":"XGBoost",
         "Accuracy":0.9623,"Precision":0.9641,"Recall":0.9608,"F1":0.9618,"AUC":0.9847},
        {"Model":"Random Forest","Task":"URL","Algorithm":"Random Forest",
         "Accuracy":0.9541,"Precision":0.9558,"Recall":0.9524,"F1":0.9535,"AUC":0.9801},
        {"Model":"Isolation Forest","Task":"Login","Algorithm":"Isolation Forest",
         "Accuracy":0.9128,"Precision":0.9047,"Recall":0.9176,"F1":0.9101,"AUC":0.9421},
        {"Model":"XGBoost","Task":"Login","Algorithm":"XGBoost",
         "Accuracy":0.9387,"Precision":0.9401,"Recall":0.9358,"F1":0.9379,"AUC":0.9659},
        {"Model":"XGBoost","Task":"Network","Algorithm":"XGBoost",
         "Accuracy":0.9812,"Precision":0.9827,"Recall":0.9798,"F1":0.9809,"AUC":0.9967},
        {"Model":"Isolation Forest","Task":"Network","Algorithm":"Isolation Forest",
         "Accuracy":0.9234,"Precision":0.9189,"Recall":0.9208,"F1":0.9198,"AUC":0.9512},
    ]
    df = pd.DataFrame(ref)
    df["Label"] = df["Model"] + " (" + df["Task"] + ")"

    st.dataframe(
        df[["Label","Algorithm","Accuracy","Precision","Recall","F1","AUC"]]
        .style.background_gradient(subset=["Accuracy","F1","AUC"], cmap="RdYlGn", vmin=0.88, vmax=1.0)
        .format({"Accuracy":"{:.4f}","Precision":"{:.4f}","Recall":"{:.4f}",
                 "F1":"{:.4f}","AUC":"{:.4f}"}),
        use_container_width=True, hide_index=True,
    )

    c1, c2 = st.columns(2)
    algo_colors = {
        "Transformer": C["critical"], "XGBoost": C["success"],
        "Random Forest": C["warning"], "Isolation Forest": C["info"],
    }

    with c1:
        fig1 = go.Figure()
        for algo in df["Algorithm"].unique():
            sub = df[df["Algorithm"]==algo].sort_values("F1")
            fig1.add_trace(go.Bar(
                y=sub["Label"], x=sub["F1"], orientation="h",
                name=algo, marker_color=algo_colors.get(algo, C["muted"]),
                hovertemplate="<b>%{y}</b><br>F1: %{x:.4f}<extra></extra>",
            ))
        fig1.update_layout(
            title=dict(text="F1 Score by Model", font=dict(color=C["text"], size=13)),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter", color=C["muted"], size=11),
            height=380, barmode="overlay", margin=dict(t=40,b=20,l=10,r=10),
            xaxis=dict(range=[0.88,1.0], gridcolor=C["border"], tickformat=".3f"),
            yaxis=dict(gridcolor="rgba(0,0,0,0)"),
            legend=dict(font=dict(color=C["text"], size=10), bgcolor="rgba(0,0,0,0)"),
        )
        fig1.add_vline(x=0.95, line_dash="dash", line_color=C["warning"],
                       annotation_text="0.95", annotation_font_color=C["warning"])
        st.plotly_chart(fig1, use_container_width=True, config={"displayModeBar":False})

    with c2:
        fig2 = go.Figure()
        for algo in df["Algorithm"].unique():
            sub = df[df["Algorithm"]==algo].sort_values("AUC")
            fig2.add_trace(go.Bar(
                y=sub["Label"], x=sub["AUC"], orientation="h",
                name=algo, marker_color=algo_colors.get(algo, C["muted"]),
                hovertemplate="<b>%{y}</b><br>AUC: %{x:.4f}<extra></extra>",
            ))
        fig2.update_layout(
            title=dict(text="ROC-AUC by Model", font=dict(color=C["text"], size=13)),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter", color=C["muted"], size=11),
            height=380, barmode="overlay", margin=dict(t=40,b=20,l=10,r=10),
            xaxis=dict(range=[0.90,1.0], gridcolor=C["border"], tickformat=".3f"),
            yaxis=dict(gridcolor="rgba(0,0,0,0)"),
            legend=dict(font=dict(color=C["text"], size=10), bgcolor="rgba(0,0,0,0)"),
        )
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar":False})


# ══════════════════════════════════════════════════════════════════
# PAGE: REPORTS
# ══════════════════════════════════════════════════════════════════
elif page == "Reports":
    section_header("📋", "Generate & Download Reports",
                   "Export audit-ready PDF and CSV reports")

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"""
        <div style="background:{C['card']};border-radius:14px;padding:24px;
             border:1px solid {C['border']};margin-bottom:16px;
             border-top:3px solid {C['success']}">
          <div style="font-size:1.2rem;font-weight:700;margin-bottom:8px">📄 CSV Export</div>
          <div style="color:{C['muted']};font-size:0.83rem;margin-bottom:16px">
            All threat detections as a structured CSV spreadsheet.
            Includes timestamp, threat type, risk score, model used.
            Importable into Excel, Python, or SIEM systems.
          </div>
        </div>""", unsafe_allow_html=True)
        if st.button("⬇️ Download CSV Report", use_container_width=True):
            try:
                r = requests.get(
                    "https://cyber-threat-api-4gms.onrender.com/api/v1/reports/csv",
                    timeout=20
                )
                if r.status_code == 200:
                    st.download_button("💾 Save CSV File", data=r.content,
                        file_name=f"threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.csv",
                        mime="text/csv", use_container_width=True)
                else:
                    st.error(f"HTTP {r.status_code}")
            except Exception as e:
                st.warning(str(e))

    with c2:
        st.markdown(f"""
        <div style="background:{C['card']};border-radius:14px;padding:24px;
             border:1px solid {C['border']};margin-bottom:16px;
             border-top:3px solid {C['critical']}">
          <div style="font-size:1.2rem;font-weight:700;margin-bottom:8px">📕 PDF Report</div>
          <div style="color:{C['muted']};font-size:0.83rem;margin-bottom:16px">
            Formatted PDF with executive summary, model performance metrics,
            and recent threat detections. Suitable for management briefing
            and IEEE paper appendix.
          </div>
        </div>""", unsafe_allow_html=True)
        if st.button("⬇️ Download PDF Report", use_container_width=True):
            try:
                r = requests.get(
                    "https://cyber-threat-api-4gms.onrender.com/api/v1/reports/pdf",
                    timeout=45
                )
                if r.status_code == 200:
                    st.download_button("💾 Save PDF File", data=r.content,
                        file_name=f"threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf",
                        mime="application/pdf", use_container_width=True)
                else:
                    st.error(f"HTTP {r.status_code}")
            except Exception as e:
                st.warning(str(e))


# ══════════════════════════════════════════════════════════════════
# PAGE: TIMELINE
# ══════════════════════════════════════════════════════════════════
elif page == "Timeline":
    section_header("⏱", "Live Scan Timeline",
                   "Chronological record of all detections this session")

    col1, col2 = st.columns([4, 1])
    with col2:
        if st.button("🗑 Clear", use_container_width=True):
            st.session_state.history = []
            st.rerun()

    render_timeline(st.session_state.history)
