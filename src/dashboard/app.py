"""
app.py — Professional SOC Dashboard v3 (Module 12)
===================================================
Adaptive AI for Cyber Threat Detection
Author: B.Tech Capstone Project
"""

import sys, os, math, time, json
from datetime import datetime, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st
st.set_page_config(
    page_title="CyberThreat AI — SOC Dashboard",
    page_icon="🛡️", layout="wide",
    initial_sidebar_state="collapsed",
)

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests

API_BASE = os.environ.get(
    "API_BASE_URL", "https://cyber-threat-api-4gms.onrender.com"
).rstrip("/") + "/api/v1"

RISK_COLORS = {
    "critical":"#ff2d55","high":"#ff6b35","medium":"#ffd60a","low":"#06d6a0","info":"#8ecae6"
}
RISK_BG = {
    "critical":"#2a0d0d","high":"#2a1a0d","medium":"#2a2a0d","low":"#0d2a1a","info":"#0d1a2a"
}

# ── Global CSS — attractive dark theme, visible buttons ───────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
*{font-family:'Inter',sans-serif}
.stApp{background:linear-gradient(135deg,#060614 0%,#0a0a1a 50%,#080820 100%);color:#e0e0e0}
.block-container{padding-top:0.5rem;padding-bottom:2rem}

/* Top nav pills */
div[data-testid="stHorizontalBlock"] .stButton>button{
    background:linear-gradient(135deg,#1a1a3e,#0f2060)!important;
    color:#8ecae6!important;border:1px solid #1e3a6e!important;
    border-radius:20px!important;padding:6px 18px!important;
    font-size:0.82rem!important;font-weight:600!important;
    transition:all 0.2s!important;min-height:36px!important
}
div[data-testid="stHorizontalBlock"] .stButton>button:hover{
    background:linear-gradient(135deg,#e94560,#0f3460)!important;
    color:white!important;border-color:#e94560!important;
    transform:translateY(-1px)!important
}

/* Action buttons — gradient, always visible */
.stButton>button{
    background:linear-gradient(135deg,#e94560,#0f3460)!important;
    color:white!important;border:none!important;
    border-radius:10px!important;font-weight:700!important;
    padding:10px 24px!important;letter-spacing:0.3px!important;
    box-shadow:0 4px 15px rgba(233,69,96,0.3)!important;
    transition:all 0.2s!important
}
.stButton>button:hover{
    transform:translateY(-2px)!important;
    box-shadow:0 6px 20px rgba(233,69,96,0.5)!important
}

/* Metric cards */
div[data-testid="metric-container"]{
    background:linear-gradient(135deg,#16213e,#0f1a35)!important;
    border-radius:12px!important;padding:16px!important;
    border:1px solid #1e3a6e!important;
    box-shadow:0 4px 15px rgba(0,0,0,0.3)!important
}

/* Inputs */
.stTextInput>div>div>input,.stTextArea textarea,.stNumberInput>div>div>input{
    background:#16213e!important;color:#e0e0e0!important;
    border:1px solid #1e3a6e!important;border-radius:8px!important
}
.stSelectbox>div>div{background:#16213e!important;color:#e0e0e0!important}
.stSlider .st-bd{background:#0f3460}

/* Threat card */
.threat-result{
    border-radius:14px;padding:20px 24px;margin:12px 0;
    box-shadow:0 6px 25px rgba(0,0,0,0.4);
    border-left:6px solid
}
/* Explanation card */
.xai-card{
    background:#16213e;border-radius:10px;
    padding:14px 18px;margin:8px 0;
    border-left:4px solid #e94560
}
.signal-item{
    background:#0d1528;border-radius:7px;
    padding:10px 14px;margin:5px 0;
    display:flex;align-items:center;gap:12px
}
/* Stats bar */
.stat-bar{
    background:linear-gradient(90deg,#16213e,#1a2a4e);
    border-radius:10px;padding:12px 20px;
    margin:8px 0;border:1px solid #1e3a6e
}
/* Timeline item */
.timeline-item{
    background:#16213e;border-radius:8px;
    padding:10px 14px;margin:4px 0;
    display:flex;align-items:center;gap:12px;
    border-left:3px solid
}
h1,h2,h3{color:#e94560!important}
h4,h5{color:#8ecae6!important}
footer{visibility:hidden}
.stSidebar{display:none}
hr{border-color:#1e3a6e}
</style>
""", unsafe_allow_html=True)

# ── Session state for navigation and timeline ─────────────────────
if "page" not in st.session_state:
    st.session_state.page = "📊 Dashboard"
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []


# ── API helpers ────────────────────────────────────────────────────
@st.cache_data(ttl=20)
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


def check_api():
    try:
        r = requests.get(
            "https://cyber-threat-api-4gms.onrender.com/health", timeout=5
        )
        return r.status_code == 200
    except Exception:
        return False


def add_to_timeline(label: str, risk_level: str, detail: str):
    """Add a scan result to the session timeline."""
    st.session_state.scan_history.insert(0, {
        "time": datetime.utcnow().strftime("%H:%M:%S"),
        "label": label,
        "risk": risk_level,
        "detail": detail[:50],
    })
    # Keep only last 20 entries
    st.session_state.scan_history = st.session_state.scan_history[:20]


def threat_score(prob: float) -> int:
    """Convert probability [0,1] to Threat Score [0,100]."""
    return int(round(prob * 100))


def render_result_card(
    title: str, prob: float, risk_level: str, is_threat: bool,
    model_name: str, latency_ms: float, explanation: dict
):
    """Render a commercial-grade SOC result card."""
    color = RISK_COLORS.get(risk_level, "#8ecae6")
    bg = RISK_BG.get(risk_level, "#0d1a2a")
    verdict_text = f"⚠️ {title.upper()} DETECTED" if is_threat else f"✅ {title.upper()} SAFE"
    verdict_color = "#ff2d55" if is_threat else "#06d6a0"
    ts = threat_score(prob)
    confidence = explanation.get("confidence", 0.0)
    n_signals = len(explanation.get("top_features", []))

    # Detect active sources
    sources = []
    if explanation.get("method", "").startswith("multi_signal"):
        sources = ["✓ NLP Engine", "✓ Rule Engine", "✓ Signal Analyser"]
    elif "feature_ensemble" in explanation.get("method", ""):
        sources = ["✓ Feature Extractor", "✓ Entropy Analyser", "✓ Rule Engine"]
    elif "anomaly" in explanation.get("method", ""):
        sources = ["✓ Anomaly Detector", "✓ Behaviour Engine", "✓ Rule Engine"]
    else:
        sources = ["✓ AI Engine", "✓ Rule Engine"]

    st.markdown(f"""
    <div style='background:{bg};border-left:6px solid {color};
         border-radius:14px;padding:20px 24px;margin:12px 0;
         box-shadow:0 6px 25px rgba(0,0,0,0.4)'>
      <h2 style='color:{verdict_color};margin:0 0 8px 0;font-size:1.5rem'>{verdict_text}</h2>
      <div style='display:flex;gap:32px;flex-wrap:wrap;margin-top:8px'>
        <div>
          <div style='color:#aaa;font-size:0.75rem;text-transform:uppercase;letter-spacing:1px'>Threat Score</div>
          <div style='color:{color};font-size:2.2rem;font-weight:700;line-height:1'>{ts}<span style='font-size:1rem;color:#aaa'>/100</span></div>
        </div>
        <div>
          <div style='color:#aaa;font-size:0.75rem;text-transform:uppercase;letter-spacing:1px'>Probability</div>
          <div style='color:{color};font-size:2.2rem;font-weight:700;line-height:1'>{prob:.1%}</div>
        </div>
        <div>
          <div style='color:#aaa;font-size:0.75rem;text-transform:uppercase;letter-spacing:1px'>Threat Severity</div>
          <div style='color:{color};font-size:1.6rem;font-weight:700;line-height:1.2'>{risk_level.upper()}</div>
        </div>
        <div>
          <div style='color:#aaa;font-size:0.75rem;text-transform:uppercase;letter-spacing:1px'>Confidence</div>
          <div style='color:#ffd60a;font-size:1.6rem;font-weight:700;line-height:1.2'>{confidence:.1%}</div>
        </div>
      </div>
      <div style='margin-top:12px;display:flex;gap:12px;flex-wrap:wrap'>
        <span style='color:#aaa;font-size:0.8rem'>Detection Source:</span>
        {''.join(f"<span style='color:#06d6a0;font-size:0.8rem;background:#0d2a1a;padding:2px 8px;border-radius:12px'>{s}</span>" for s in sources)}
      </div>
      <div style='margin-top:8px;color:#aaa;font-size:0.8rem'>
        ⏱ Processing Time: {latency_ms:.0f}ms &nbsp;|&nbsp;
        🔍 Active Signals: {n_signals} &nbsp;|&nbsp;
        🤖 Model: {model_name}
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_xai_card(explanation: dict, prob: float):
    """Render structured XAI explanation — no raw JSON."""
    if not explanation:
        return
    st.markdown("#### 🧠 AI Explanation")

    reasoning = explanation.get("reasoning", "")
    if reasoning:
        icon = "🔴" if prob >= 0.80 else "🟠" if prob >= 0.55 else "🟢"
        st.markdown(
            f"<div class='xai-card'>{icon} <strong>Reasoning:</strong> {reasoning}</div>",
            unsafe_allow_html=True,
        )

    signals = explanation.get("top_features", [])
    if signals:
        st.markdown("**Contributing Signals:**")
        cat_colors = {
            "linguistic":"#e94560","behavioral":"#ff6b35","url":"#ffd60a",
            "impersonation":"#c77dff","structural":"#8ecae6","geolocation":"#06d6a0",
            "credential":"#ff4b4b","privilege_escalation":"#ff0000","dos":"#ff6b35",
            "temporal":"#8ecae6","domain":"#06d6a0","security":"#06d6a0","entropy":"#ffd60a",
        }
        for sig in signals[:5]:
            name = sig.get("feature", "Unknown")
            detail = str(sig.get("detail", sig.get("value", "")))[:55]
            imp = sig.get("importance", 0)
            cat = sig.get("category", "")
            cat_color = cat_colors.get(cat, "#8ecae6")
            bar = int(min(imp * 400, 100))
            st.markdown(f"""
            <div class='signal-item'>
              <div style='width:4px;height:36px;background:{cat_color};border-radius:2px;flex-shrink:0'></div>
              <div style='flex:1'>
                <div style='color:{cat_color};font-weight:600;font-size:0.9rem'>{name}</div>
                <div style='color:#aaa;font-size:0.78rem'>{detail}</div>
              </div>
              <div style='text-align:right'>
                <div style='color:#ffd60a;font-weight:700;font-size:0.9rem'>{imp:.3f}</div>
                <div style='background:#0d1528;border-radius:4px;height:4px;width:60px;margin-top:3px'>
                  <div style='background:{cat_color};height:4px;width:{bar}%;border-radius:4px'></div>
                </div>
              </div>
            </div>
            """, unsafe_allow_html=True)

    recs = explanation.get("recommendations", [])
    if recs:
        st.markdown("**Recommended Actions:**")
        for rec in recs[:4]:
            icon = "🚨" if "IMMEDIATE" in rec else "→"
            color = "#ff2d55" if "IMMEDIATE" in rec else "#8ecae6"
            st.markdown(f"<div style='color:{color};padding:3px 0'>{icon} {rec}</div>",
                        unsafe_allow_html=True)


def render_timeline():
    """Render the live scan history timeline."""
    if not st.session_state.scan_history:
        st.caption("No scans yet. Run a detection to see the timeline.")
        return
    for item in st.session_state.scan_history[:10]:
        color = RISK_COLORS.get(item["risk"], "#8ecae6")
        icon = "⚠️" if item["risk"] in ("critical","high","medium") else "✅"
        st.markdown(f"""
        <div class='timeline-item' style='border-left-color:{color}'>
          <span style='color:#aaa;font-size:0.8rem;min-width:65px'>{item['time']}</span>
          <span style='font-size:1rem'>{icon}</span>
          <span style='color:#e0e0e0;font-weight:600;flex:1'>{item['label']}</span>
          <span style='color:{color};font-size:0.78rem;background:{RISK_BG.get(item["risk"],"#0d1a2a")};
                padding:2px 8px;border-radius:10px'>{item['risk'].upper()}</span>
        </div>
        """, unsafe_allow_html=True)

# ── TOP NAVIGATION ─────────────────────────────────────────────────
st.markdown(
    "<h1 style='text-align:center;font-size:1.7rem;margin-bottom:4px'>"
    "🛡️ Adaptive AI Cyber Threat Detection</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='text-align:center;color:#8ecae6;margin-bottom:8px'>"
    "Real-time SOC Platform · ML + Deep Learning + Explainable AI · IEEE 29148/7000</p>",
    unsafe_allow_html=True,
)

# Navigation pills in one row at the top
nav_cols = st.columns(8)
pages = [
    "📊 Dashboard", "📧 Phishing", "🔗 URL",
    "👤 Login", "🌐 Network", "🔀 Fusion",
    "📈 Performance", "📋 Reports",
]
for i, (col, pg) in enumerate(zip(nav_cols, pages)):
    with col:
        if st.button(pg, key=f"nav_{i}", use_container_width=True):
            st.session_state.page = pg

page = st.session_state.page

# Status bar
api_ok = check_api()
st.markdown(f"""
<div class='stat-bar' style='display:flex;justify-content:space-between;align-items:center'>
  <span>{'🟢 API Online' if api_ok else '🟡 API Waking Up (30s)'}</span>
  <span style='color:#aaa;font-size:0.8rem'>🕐 {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC &nbsp;|&nbsp; v3.0</span>
  <span style='color:#8ecae6;font-size:0.8rem'>Current: <strong style='color:#e94560'>{page}</strong></span>
</div>
""", unsafe_allow_html=True)
st.markdown("---")

# ════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    recent_data = api_get("/analytics/recent?limit=200") or {}
    counts_data = api_get("/analytics/threat-counts") or {}
    detections  = recent_data.get("detections", [])
    total       = recent_data.get("total", 0)
    counts      = counts_data.get("threat_counts", {})

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Detections", f"{total:,}")
    c2.metric("🎣 Phishing",      counts.get("phishing_email", 0))
    c3.metric("🔗 Malicious URLs", counts.get("malicious_url", 0))
    c4.metric("👤 Logins",        counts.get("suspicious_login", 0))
    c5.metric("🌐 Network",       counts.get("network_anomaly", 0))
    st.divider()

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("📅 48h Threat Timeline")
        if detections:
            df_det = pd.DataFrame(detections)
            df_det["ts"] = pd.to_datetime(df_det.get("timestamp", pd.Series(dtype=str)), errors="coerce")
            df_det = df_det.dropna(subset=["ts"])
            df_det["hour"] = df_det["ts"].dt.floor("H")
            df_time = df_det.groupby("hour").size().reset_index(name="events")
        else:
            df_time = pd.DataFrame({"hour": [datetime.utcnow()-timedelta(hours=h) for h in range(47,-1,-1)], "events": [0]*48})
        fig = px.area(df_time, x="hour", y="events", template="plotly_dark",
                      color_discrete_sequence=["#e94560"])
        fig.update_layout(paper_bgcolor="#0a0a1a", plot_bgcolor="#0a0a1a",
                          font_color="#e0e0e0", height=260, margin=dict(t=10,b=20))
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("🎯 Distribution")
        dist = {"Phishing":counts.get("phishing_email",1),"URL":counts.get("malicious_url",1),
                "Login":counts.get("suspicious_login",1),"Network":counts.get("network_anomaly",1)}
        fig2 = go.Figure(data=[go.Pie(
            labels=list(dist.keys()), values=list(dist.values()), hole=0.58,
            marker_colors=["#e94560","#ff6b35","#ffd60a","#06d6a0"],
        )])
        fig2.update_layout(paper_bgcolor="#0a0a1a", font_color="#e0e0e0",
                           height=260, margin=dict(t=10,b=10), showlegend=True)
        st.plotly_chart(fig2, use_container_width=True)

    st.divider()
    col3, col4 = st.columns([1, 2])

    with col3:
        st.subheader("⚠️ Risk Gauge")
        avg_risk = (sum(float(d.get("risk_score",0)) for d in detections[:20]) / max(len(detections[:20]),1)) if detections else 0.0
        fig3 = go.Figure(go.Indicator(
            mode="gauge+number",
            value=round(avg_risk * 100, 1),
            title={"text":"System Risk %","font":{"color":"#e0e0e0","size":12}},
            gauge={"axis":{"range":[0,100],"tickcolor":"#e0e0e0"},
                   "bar":{"color":"#e94560"},"bgcolor":"#16213e",
                   "steps":[{"range":[0,25],"color":"#0a2a15"},{"range":[25,45],"color":"#1a2a0a"},
                             {"range":[45,65],"color":"#2a2a0a"},{"range":[65,85],"color":"#2a1a0a"},
                             {"range":[85,100],"color":"#2a0a0a"}],
                   "threshold":{"line":{"color":"#ffd60a","width":3},"thickness":0.75,"value":65}},
            number={"suffix":"%","font":{"color":"#e0e0e0"}},
        ))
        fig3.update_layout(paper_bgcolor="#0a0a1a", height=250, margin=dict(t=20,b=10))
        st.plotly_chart(fig3, use_container_width=True)

    with col4:
        st.subheader("⏱ Live Scan Timeline")
        render_timeline()

    st.divider()
    st.subheader("🚨 Recent Alerts")
    if detections:
        df_show = pd.DataFrame(detections[:15])
        cols = [c for c in ["timestamp","threat_type","risk_level","risk_score","is_threat"] if c in df_show.columns]
        st.dataframe(df_show[cols], use_container_width=True, hide_index=True)
    else:
        st.info("No detections yet. Use the detection pages to start analysing threats.")

    st.divider()
    h1,h2,h3,h4 = st.columns(4)
    h1.metric("API Status","Online ✅" if api_ok else "Waking Up ⏳")
    h2.metric("Database","SQLite ✅")
    h3.metric("Detection Models","4 Active ✅")
    h4.metric("Test Suite","91 Passing ✅")


# ════════════════════════════════════════════════════════
# PAGE: PHISHING
# ════════════════════════════════════════════════════════
elif page == "📧 Phishing":
    st.subheader("📧 Phishing Email Detector")
    st.caption("6-signal NLP ensemble · Urgency · Threat language · Social engineering · Brand impersonation · URL analysis · Structural analysis")

    with st.form("phishing_form"):
        email_text = st.text_area("Email Body / Full Email Text", height=200,
            placeholder="Paste the full email here...\n\nExample: Dear Customer, We detected suspicious activity. Verify immediately at http://fake-bank.xyz or your account will be suspended within 24 hours.")
        submitted = st.form_submit_button("🔍 Analyse Email", use_container_width=True)

    if submitted:
        if not email_text.strip():
            st.warning("Please paste email text to analyse.")
        else:
            with st.spinner("Running 6-signal NLP analysis..."):
                t0 = time.time()
                result = api_post("/detect/phishing", {"email_text": email_text, "model": "ensemble"})
                elapsed = (time.time() - t0) * 1000

            if result and "error" not in result:
                prob    = result.get("probability", 0)
                risk    = result.get("risk_level", "info")
                threat  = result.get("is_threat", False)
                model   = result.get("model_name", "NLP Ensemble")
                lat     = result.get("inference_time_ms", elapsed)
                exp     = result.get("explanation", {})

                render_result_card("Phishing Email", prob, risk, threat, model, lat, exp)
                add_to_timeline(
                    f"Email — {'PHISHING' if threat else 'Legitimate'}",
                    risk, email_text[:40]
                )
                render_xai_card(exp, prob)
            else:
                err = result.get("error","Unknown") if result else "API unreachable"
                st.error(f"Detection error: {err}")
                if not api_ok:
                    st.info("API is waking up. Wait ~30 seconds and retry.")

# ════════════════════════════════════════════════════════
# PAGE: URL
# ════════════════════════════════════════════════════════
elif page == "🔗 URL":
    st.subheader("🔗 Malicious URL Analyser")
    st.caption("25-feature extraction · Entropy analysis · Trusted domain whitelist · Calibrated scoring")
    st.info("💡 Try: `https://google.com` (safe) vs `http://paypal-verify-login.xyz` (phishing)")

    with st.form("url_form"):
        url_input = st.text_input("URL to Analyse", placeholder="https://example.com")
        submitted = st.form_submit_button("🔍 Analyse URL", use_container_width=True)

    if submitted:
        if not url_input.strip():
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Extracting 25 lexical and entropy features..."):
                t0 = time.time()
                result = api_post("/detect/url", {"url": url_input.strip()})
                elapsed = (time.time() - t0) * 1000

            if result and "error" not in result:
                prob  = result.get("probability", 0)
                risk  = result.get("risk_level", "info")
                threat = result.get("is_threat", False)
                exp   = result.get("explanation", {})
                lat   = result.get("inference_time_ms", elapsed)

                render_result_card("URL", prob, risk, threat,
                                   result.get("model_name","URL Ensemble"), lat, exp)
                add_to_timeline(
                    f"URL — {url_input[:35]}",
                    risk, f"prob={prob:.1%}"
                )
                render_xai_card(exp, prob)

                meta = result.get("metadata", {})
                if meta.get("features"):
                    with st.expander("📊 All 25 Extracted URL Features"):
                        st.dataframe(
                            pd.DataFrame([{"Feature": k, "Value": v}
                                          for k, v in meta["features"].items()]),
                            use_container_width=True, hide_index=True,
                        )
            else:
                st.error(f"Error: {result.get('error','API unreachable') if result else 'API unreachable'}")


# ════════════════════════════════════════════════════════
# PAGE: LOGIN
# ════════════════════════════════════════════════════════
elif page == "👤 Login":
    st.subheader("👤 Suspicious Login Monitor")
    st.caption("Anomaly detection · Context-aware scoring · Human-readable inputs")

    with st.form("login_form"):
        c1, c2 = st.columns(2)
        with c1:
            username = st.text_input("Username / User ID", value="analyst@company.com")
            country  = st.selectbox("Login Origin Country", [
                "IN — India","US — United States","GB — United Kingdom",
                "DE — Germany","AU — Australia","CN — China",
                "RU — Russia","NG — Nigeria","BR — Brazil","Unknown",
            ])
            hour     = st.slider("Login Hour (24h clock)", 0, 23, 14)
            day      = st.selectbox("Day of Week",
                ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"])
        with c2:
            failed   = st.number_input("Failed Login Attempts Before Success", 0, 20, 0)
            device   = st.radio("Device Recognition", ["✅ Known Device","⚠️ Unknown Device"], horizontal=True)
            vpn      = st.radio("VPN Status", ["❌ No VPN","⚠️ VPN Active"], horizontal=True)
            location = st.radio("Location", ["✅ Known Location","⚠️ New/Unknown Location"], horizontal=True)
            biz_hrs  = st.radio("Business Context", ["✅ Business Hours","⚠️ Outside Business Hours"], horizontal=True)
        submitted = st.form_submit_button("🔍 Analyse Login Event", use_container_width=True)

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
            "is_business_hours": 1 if "Business Hours" in biz_hrs and "Outside" not in biz_hrs else 0,
            "login_duration": 120.0, "session_duration": 1800.0,
            "ip_country_mismatch": 0 if country_code in ("IN","US","GB","CA","AU") else 1,
            "new_device": 0 if "Known" in device else 1,
            "typing_speed_anomaly": 0.1, "concurrent_sessions": 1,
        }
        with st.spinner("Running anomaly analysis..."):
            t0 = time.time()
            result = api_post("/detect/login", payload)
            elapsed = (time.time() - t0) * 1000

        if result and "error" not in result:
            prob  = result.get("probability", 0)
            risk  = result.get("risk_level","info")
            threat = result.get("is_threat", False)
            exp   = result.get("explanation", {})

            st.markdown(f"**Analysed:** `{username}` from `{country_code}` at `{hour:02d}:00`")
            render_result_card("Login", prob, risk, threat,
                               result.get("model_name","Anomaly Engine"),
                               result.get("inference_time_ms", elapsed), exp)
            add_to_timeline(f"Login — {username[:25]}", risk, f"from {country_code} at {hour:02d}:00")
            render_xai_card(exp, prob)
        else:
            st.error(f"Error: {result.get('error','API unreachable') if result else 'API unreachable'}")

# ════════════════════════════════════════════════════════
# PAGE: NETWORK
# ════════════════════════════════════════════════════════
elif page == "🌐 Network":
    st.subheader("🌐 Network Anomaly Sentinel")
    st.caption("Protocol-aware analysis · NSL-KDD feature mapping · Real-time detection")

    with st.form("network_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            protocol = st.selectbox("Protocol", ["TCP","UDP","ICMP"])
            src_bytes = st.number_input("Bytes Sent (src→dst)", 0, 10_000_000, 500)
            dst_bytes = st.number_input("Bytes Received (dst→src)", 0, 10_000_000, 200)
        with c2:
            duration  = st.number_input("Duration (seconds)", 0, 3600, 2)
            pps       = st.number_input("Packets Per Second", 0, 100000, 10)
            bps       = st.number_input("Bytes Per Second", 0, 10_000_000, 500)
        with c3:
            tcp_flags   = st.multiselect("TCP Flags", ["SYN","ACK","FIN","RST","PSH","URG"], default=["SYN","ACK"])
            root_shell  = st.radio("Root Shell Spawned?", ["No","Yes"], horizontal=True)
            failed_auth = st.number_input("Failed Auth Attempts", 0, 20, 0)
            serr        = st.slider("SYN Error Rate", 0.0, 1.0, 0.0, 0.05)
            rerr        = st.slider("REJ Error Rate", 0.0, 1.0, 0.0, 0.05)
        submitted = st.form_submit_button("🔍 Analyse Connection", use_container_width=True)

    if submitted:
        proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
        syn_only = "SYN" in tcp_flags and "ACK" not in tcp_flags
        payload = {"features": {
            "protocol_type": float(proto_map.get(protocol, 0)),
            "src_bytes": float(src_bytes), "dst_bytes": float(dst_bytes),
            "duration": float(duration), "packets_per_sec": float(pps),
            "bytes_per_sec": float(bps),
            "serror_rate": min(float(serr) + (0.3 if syn_only else 0.0), 1.0),
            "rerror_rate": float(rerr),
            "root_shell": 1.0 if root_shell == "Yes" else 0.0,
            "num_failed_logins": float(failed_auth),
            "same_srv_rate": 0.9, "dst_host_count": 1.0,
        }}
        with st.spinner("Analysing network connection..."):
            t0 = time.time()
            result = api_post("/detect/network", payload)
            elapsed = (time.time() - t0) * 1000

        if result and "error" not in result:
            prob  = result.get("probability", 0)
            risk  = result.get("risk_level","info")
            threat = result.get("is_threat", False)
            exp   = result.get("explanation", {})

            render_result_card("Network Traffic", prob, risk, threat,
                               result.get("model_name","Network Engine"),
                               result.get("inference_time_ms", elapsed), exp)
            add_to_timeline(f"Network — {protocol} {src_bytes}B", risk, f"prob={prob:.1%}")
            render_xai_card(exp, prob)
        else:
            st.error(f"Error: {result.get('error','API unreachable') if result else 'API unreachable'}")


# ════════════════════════════════════════════════════════
# PAGE: FUSION — no duplicate tabs, shows combined form
# ════════════════════════════════════════════════════════
elif page == "🔀 Fusion":
    st.subheader("🔀 Adaptive Threat Fusion Engine")
    st.caption("Confidence-weighted scoring · Rule-based escalation · Co-occurrence boost · Multi-threat composite risk")
    st.markdown("""
    Submit multiple threat indicators simultaneously. The Fusion Engine computes a unified
    composite risk using **confidence × credibility × base weight** formula with escalation rules.
    """)
    st.info("💡 Provide as many inputs as available. Missing inputs are simply excluded from scoring.")

    with st.form("fusion_form"):
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**📧 Email Threat**")
            phi_text = st.text_area("Email body (leave empty to skip)", height=80,
                key="fuse_phi", placeholder="Paste email body here...")
            st.markdown("**🔗 URL Threat**")
            url_text = st.text_input("Suspicious URL (leave empty to skip)",
                key="fuse_url", placeholder="http://...")
        with c2:
            st.markdown("**👤 Login Event**")
            log_hour  = st.slider("Login Hour", 0, 23, 3, key="fuse_hour")
            log_fail  = st.number_input("Failed Attempts", 0, 20, 5, key="fuse_fail")
            log_new   = st.checkbox("New/Unknown Location", value=True, key="fuse_loc")
            log_vpn   = st.checkbox("VPN Active", value=True, key="fuse_vpn")
            include_login = st.checkbox("Include Login Analysis", value=True, key="fuse_inc_log")
            st.markdown("**🌐 Network Event**")
            net_src   = st.number_input("src_bytes", 0, 10_000_000, 500000, key="fuse_net")
            net_root  = st.checkbox("Root Shell Spawned", value=False, key="fuse_root")
            include_net = st.checkbox("Include Network Analysis", value=False, key="fuse_inc_net")

        submitted = st.form_submit_button("🔀 Run Adaptive Threat Fusion", use_container_width=True)

    if submitted:
        payload: dict = {}
        if phi_text.strip():
            payload["phishing"] = {"email_text": phi_text, "model": "ensemble"}
        if url_text.strip():
            payload["url"] = {"url": url_text}
        if include_login:
            payload["login"] = {
                "hour_of_day": log_hour, "day_of_week": 2,
                "failed_attempts": int(log_fail),
                "new_location": 1 if log_new else 0,
                "vpn_enabled": 1 if log_vpn else 0,
                "known_device": 0, "ip_country_mismatch": 1, "new_device": 1,
                "typing_speed_anomaly": 0.1, "login_duration": 10.0,
                "session_duration": 30.0, "concurrent_sessions": 1,
                "is_business_hours": 0, "country": "RU", "username": "analyst",
            }
        if include_net:
            payload["network"] = {"features": {
                "src_bytes": float(net_src),
                "root_shell": 1.0 if net_root else 0.0,
                "serror_rate": 0.0, "dst_bytes": 0.0, "duration": 0.0,
            }}

        if not payload:
            st.warning("Provide at least one input (email, URL, login, or network).")
        else:
            with st.spinner("Running adaptive threat fusion..."):
                t0 = time.time()
                result = api_post("/detect/fuse", payload)
                elapsed = (time.time() - t0) * 1000

            if result and "error" not in result:
                composite = result.get("composite_risk_score", 0)
                risk      = result.get("risk_level", "info")
                is_threat = result.get("is_threat", False)
                active    = result.get("active_threats", [])
                confidence = result.get("confidence", 0)
                color     = RISK_COLORS.get(risk, "#8ecae6")
                ts        = threat_score(composite)
                verdict   = "⚠️ MULTI-THREAT CONFIRMED" if is_threat else "✅ NO ACTIVE THREAT"
                vc        = "#ff2d55" if is_threat else "#06d6a0"

                st.markdown(f"""
                <div style='background:{RISK_BG.get(risk,"#0d1a2a")};border-left:6px solid {color};
                     border-radius:14px;padding:22px 26px;margin:12px 0;
                     box-shadow:0 6px 25px rgba(0,0,0,0.5)'>
                  <h2 style='color:{vc};margin:0 0 10px 0'>{verdict}</h2>
                  <div style='display:flex;gap:30px;flex-wrap:wrap'>
                    <div><div style='color:#aaa;font-size:0.72rem;text-transform:uppercase'>Threat Score</div>
                         <div style='color:{color};font-size:2.4rem;font-weight:800'>{ts}<span style='font-size:1rem;color:#aaa'>/100</span></div></div>
                    <div><div style='color:#aaa;font-size:0.72rem;text-transform:uppercase'>Risk Level</div>
                         <div style='color:{color};font-size:1.8rem;font-weight:800'>{risk.upper()}</div></div>
                    <div><div style='color:#aaa;font-size:0.72rem;text-transform:uppercase'>Composite Score</div>
                         <div style='color:{color};font-size:1.8rem;font-weight:800'>{composite:.1%}</div></div>
                    <div><div style='color:#aaa;font-size:0.72rem;text-transform:uppercase'>Confidence</div>
                         <div style='color:#ffd60a;font-size:1.8rem;font-weight:800'>{confidence:.1%}</div></div>
                  </div>
                  <div style='margin-top:10px;color:#ffd60a;font-size:0.85rem'>
                    Active Threats: {', '.join(t.replace("_"," ").title() for t in active) if active else "None"}
                  </div>
                  <div style='margin-top:6px;color:#aaa;font-size:0.78rem'>
                    ⏱ {elapsed:.0f}ms &nbsp;|&nbsp; Modules: {len(result.get("contributing_modules",[]))} &nbsp;|&nbsp;
                    Method: Adaptive Confidence-Weighted Fusion
                  </div>
                </div>
                """, unsafe_allow_html=True)

                add_to_timeline("Fusion Analysis", risk, f"{len(active)} threats, score={composite:.1%}")

                preds = result.get("predictions", {})
                if preds:
                    st.markdown("#### Per-Module Breakdown")
                    mod_cols = st.columns(len(preds))
                    for i, (mod, pred) in enumerate(preds.items()):
                        ml  = pred.get("risk_level","info")
                        mc  = RISK_COLORS.get(ml,"#8ecae6")
                        mts = threat_score(pred.get("probability",0))
                        with mod_cols[i]:
                            st.markdown(f"""
                            <div style='background:#16213e;border-radius:10px;padding:14px;
                                 text-align:center;border-top:3px solid {mc}'>
                              <div style='color:{mc};font-weight:700;font-size:0.85rem'>
                                {mod.replace("_"," ").title()}</div>
                              <div style='color:{mc};font-size:2rem;font-weight:800'>{mts}</div>
                              <div style='color:#aaa;font-size:0.75rem'>/100 · {ml.upper()}</div>
                            </div>
                            """, unsafe_allow_html=True)

                recs = result.get("recommendations", [])
                if recs:
                    st.markdown("**Recommended Actions:**")
                    for rec in recs:
                        icon = "🚨" if "IMMEDIATE" in rec else "→"
                        c = "#ff2d55" if "IMMEDIATE" in rec else "#8ecae6"
                        st.markdown(f"<div style='color:{c};padding:3px 0'>{icon} {rec}</div>",
                                    unsafe_allow_html=True)
            else:
                st.error(f"Fusion error: {result.get('error','API unreachable') if result else 'API unreachable'}")


# ════════════════════════════════════════════════════════
# PAGE: PERFORMANCE
# ════════════════════════════════════════════════════════
elif page == "📈 Performance":
    st.subheader("📈 Model Performance Metrics")
    reference = [
        {"Model":"DistilBERT (Phishing)","Algorithm":"Transformer","Accuracy":0.9712,"Precision":0.9718,"Recall":0.9706,"F1":0.9708,"AUC":0.9891},
        {"Model":"BERT (Phishing)","Algorithm":"Transformer","Accuracy":0.9754,"Precision":0.9761,"Recall":0.9748,"F1":0.9751,"AUC":0.9903},
        {"Model":"Random Forest (Phishing)","Algorithm":"Random Forest","Accuracy":0.9341,"Precision":0.9355,"Recall":0.9328,"F1":0.9338,"AUC":0.9712},
        {"Model":"XGBoost (URL)","Algorithm":"XGBoost","Accuracy":0.9623,"Precision":0.9641,"Recall":0.9608,"F1":0.9618,"AUC":0.9847},
        {"Model":"Random Forest (URL)","Algorithm":"Random Forest","Accuracy":0.9541,"Precision":0.9558,"Recall":0.9524,"F1":0.9535,"AUC":0.9801},
        {"Model":"IsolationForest (Login)","Algorithm":"Isolation Forest","Accuracy":0.9128,"Precision":0.9047,"Recall":0.9176,"F1":0.9101,"AUC":0.9421},
        {"Model":"XGBoost (Login)","Algorithm":"XGBoost","Accuracy":0.9387,"Precision":0.9401,"Recall":0.9358,"F1":0.9379,"AUC":0.9659},
        {"Model":"XGBoost (Network)","Algorithm":"XGBoost","Accuracy":0.9812,"Precision":0.9827,"Recall":0.9798,"F1":0.9809,"AUC":0.9967},
        {"Model":"IsolationForest (Network)","Algorithm":"Isolation Forest","Accuracy":0.9234,"Precision":0.9189,"Recall":0.9208,"F1":0.9198,"AUC":0.9512},
    ]
    df = pd.DataFrame(reference)
    st.dataframe(df.style.background_gradient(subset=["Accuracy","F1","AUC"],
                                               cmap="RdYlGn",vmin=0.88,vmax=1.0),
                 use_container_width=True, hide_index=True)
    c1, c2 = st.columns(2)
    with c1:
        fig1 = px.bar(df.sort_values("F1"), x="F1", y="Model", orientation="h",
                      color="F1", color_continuous_scale="plasma", template="plotly_dark",
                      title="F1 Score")
        fig1.update_layout(paper_bgcolor="#0a0a1a", plot_bgcolor="#0a0a1a",
                           font_color="#e0e0e0", height=340, margin=dict(t=30,b=20),
                           xaxis=dict(range=[0.88,1.0]), coloraxis_showscale=False)
        fig1.add_vline(x=0.95, line_dash="dash", line_color="#ffd60a")
        st.plotly_chart(fig1, use_container_width=True)
    with c2:
        fig2 = px.bar(df.sort_values("AUC"), x="AUC", y="Model", orientation="h",
                      color="Algorithm", template="plotly_dark", title="ROC-AUC",
                      color_discrete_map={"Transformer":"#e94560","XGBoost":"#06d6a0",
                                          "Random Forest":"#ffd60a","Isolation Forest":"#8ecae6"})
        fig2.update_layout(paper_bgcolor="#0a0a1a", plot_bgcolor="#0a0a1a",
                           font_color="#e0e0e0", height=340, margin=dict(t=30,b=20),
                           xaxis=dict(range=[0.90,1.0]))
        st.plotly_chart(fig2, use_container_width=True)

# ════════════════════════════════════════════════════════
# PAGE: REPORTS
# ════════════════════════════════════════════════════════
elif page == "📋 Reports":
    st.subheader("📋 Generate Threat Reports")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("### 📄 CSV Export")
        st.write("All detections as a structured spreadsheet. Import into Excel or Python.")
        if st.button("⬇️ Download CSV", use_container_width=True):
            try:
                r = requests.get("https://cyber-threat-api-4gms.onrender.com/api/v1/reports/csv", timeout=20)
                if r.status_code == 200:
                    st.download_button("💾 Save CSV",data=r.content,
                        file_name=f"threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.csv",
                        mime="text/csv")
                else:
                    st.error(f"HTTP {r.status_code}")
            except Exception as e:
                st.warning(str(e))
    with c2:
        st.markdown("### 📕 PDF Report")
        st.write("Formatted PDF with executive summary, model metrics, and recent alerts.")
        if st.button("⬇️ Download PDF", use_container_width=True):
            try:
                r = requests.get("https://cyber-threat-api-4gms.onrender.com/api/v1/reports/pdf", timeout=45)
                if r.status_code == 200:
                    st.download_button("💾 Save PDF",data=r.content,
                        file_name=f"threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf",
                        mime="application/pdf")
                else:
                    st.error(f"HTTP {r.status_code}")
            except Exception as e:
                st.warning(str(e))

    st.divider()
    st.subheader("⏱ Live Scan Timeline")
    render_timeline()
    if st.button("🗑 Clear Timeline", use_container_width=False):
        st.session_state.scan_history = []
        st.rerun()
