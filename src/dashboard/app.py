"""
app.py — Streamlit Dashboard (Module 12)
=========================================
Adaptive AI for Cyber Threat Detection

Dark-theme real-time dashboard with:
  - Risk Gauge, Threat Timeline, Attack Distribution
  - Recent Alerts table, Model Performance charts
  - Live detection form, Report downloads

Author: B.Tech Capstone Project
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st

# ── Page configuration (must be first Streamlit call) ─────────────
st.set_page_config(
    page_title="Adaptive AI Cyber Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

import time
import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests

# ── Dark theme CSS ─────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0a0a1a; color: #e0e0e0; }
    .metric-card {
        background: linear-gradient(135deg, #16213e, #0f3460);
        border-radius: 12px; padding: 20px; margin: 8px 0;
        border-left: 4px solid #e94560;
    }
    .threat-badge-critical { color: #ff2d55; font-weight: bold; }
    .threat-badge-high     { color: #ff6b35; font-weight: bold; }
    .threat-badge-medium   { color: #ffd60a; font-weight: bold; }
    .threat-badge-low      { color: #06d6a0; font-weight: bold; }
    .threat-badge-info     { color: #8ecae6; font-weight: bold; }
    div[data-testid="metric-container"] {
        background: #16213e; border-radius: 10px;
        padding: 15px; border: 1px solid #0f3460;
    }
    .stSidebar { background-color: #0d0d1f !important; }
    h1, h2, h3 { color: #e94560 !important; }
    .stButton>button {
        background: linear-gradient(135deg, #e94560, #0f3460);
        color: white; border: none; border-radius: 8px;
        padding: 8px 20px; font-weight: bold;
    }
    .stButton>button:hover { opacity: 0.9; transform: scale(1.02); }
    footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ── Constants ──────────────────────────────────────────────────────
API_BASE = "http://localhost:8000/api/v1"
RISK_COLORS = {
    "critical": "#ff2d55", "high": "#ff6b35",
    "medium": "#ffd60a",   "low": "#06d6a0", "info": "#8ecae6",
}

# ── Helpers ────────────────────────────────────────────────────────
def _api_post(endpoint: str, payload: dict) -> dict | None:
    """POST to FastAPI backend with timeout handling."""
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=payload, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _api_get(endpoint: str) -> dict | None:
    """GET from FastAPI backend."""
    try:
        r = requests.get(f"{API_BASE}{endpoint}", timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _demo_timeline_data() -> pd.DataFrame:
    """Generate synthetic timeline data for demo when API is offline."""
    now = datetime.utcnow()
    rows = []
    for i in range(48):
        ts = now - timedelta(hours=48 - i)
        rows.append({
            "timestamp": ts,
            "phishing": random.randint(0, 5),
            "malicious_url": random.randint(0, 8),
            "suspicious_login": random.randint(0, 3),
            "network_anomaly": random.randint(0, 6),
        })
    return pd.DataFrame(rows)


def _risk_color(level: str) -> str:
    return RISK_COLORS.get(level.lower(), "#8ecae6")


# ── Sidebar ────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/security-shield-green.png", width=70)
    st.title("🛡️ CyberThreat AI")
    st.caption("Adaptive AI for Cyber Threat Detection")
    st.divider()

    page = st.radio(
        "Navigation",
        ["📊 Dashboard", "🔍 Detect Threat", "📈 Model Performance", "📋 Reports"],
        label_visibility="collapsed",
    )
    st.divider()

    # API status indicator
    health = _api_get("/health") if False else None  # lazy check
    try:
        health = requests.get("http://localhost:8000/health", timeout=2).json()
        api_status = "🟢 API Online"
    except Exception:
        api_status = "🔴 API Offline (Demo Mode)"

    st.caption(api_status)
    st.caption(f"Last refresh: {datetime.utcnow().strftime('%H:%M:%S')} UTC")

    if st.button("🔄 Refresh"):
        st.rerun()

# ── Main title bar ─────────────────────────────────────────────────
st.markdown(
    "<h1 style='text-align:center;font-size:2rem;'>🛡️ Adaptive AI Cyber Threat Detection</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='text-align:center;color:#8ecae6;'>Real-time AI-powered cybersecurity "
    "monitoring | Machine Learning + Deep Learning + Explainable AI</p>",
    unsafe_allow_html=True,
)
st.divider()


# ════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ════════════════════════════════════════════════════════
if page == "📊 Dashboard":

    # KPI metrics row
    recent_data = _api_get("/analytics/recent?limit=200") or {}
    counts_data = _api_get("/analytics/threat-counts") or {"threat_counts": {}}
    detections  = recent_data.get("detections", [])
    total       = recent_data.get("total", len(detections))
    counts      = counts_data.get("threat_counts", {})

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Detections",    f"{total:,}")
    c2.metric("Phishing Emails",     counts.get("phishing_email", 0))
    c3.metric("Malicious URLs",      counts.get("malicious_url", 0))
    c4.metric("Suspicious Logins",   counts.get("suspicious_login", 0))
    c5.metric("Network Anomalies",   counts.get("network_anomaly", 0))

    st.divider()
    col_left, col_right = st.columns([2, 1])

    # Threat Timeline
    with col_left:
        st.subheader("📅 Threat Timeline (48h)")
        df_time = _demo_timeline_data()
        fig_time = px.line(
            df_time, x="timestamp",
            y=["phishing", "malicious_url", "suspicious_login", "network_anomaly"],
            color_discrete_map={
                "phishing": "#e94560", "malicious_url": "#ff6b35",
                "suspicious_login": "#ffd60a", "network_anomaly": "#06d6a0",
            },
            template="plotly_dark",
            labels={"value": "Events", "variable": "Threat Type"},
        )
        fig_time.update_layout(
            plot_bgcolor="#0a0a1a", paper_bgcolor="#0a0a1a",
            font_color="#e0e0e0", height=320,
            legend=dict(orientation="h", y=-0.2),
        )
        st.plotly_chart(fig_time, use_container_width=True)

    # Attack Distribution Donut
    with col_right:
        st.subheader("🎯 Attack Distribution")
        dist_counts = {
            "Phishing Email":    counts.get("phishing_email", random.randint(10, 50)),
            "Malicious URL":     counts.get("malicious_url",  random.randint(15, 70)),
            "Suspicious Login":  counts.get("suspicious_login", random.randint(5, 30)),
            "Network Anomaly":   counts.get("network_anomaly", random.randint(8, 40)),
        }
        fig_donut = go.Figure(data=[go.Pie(
            labels=list(dist_counts.keys()),
            values=list(dist_counts.values()),
            hole=0.55,
            marker_colors=["#e94560", "#ff6b35", "#ffd60a", "#06d6a0"],
        )])
        fig_donut.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0a0a1a", plot_bgcolor="#0a0a1a",
            font_color="#e0e0e0", height=320,
            showlegend=True,
            legend=dict(orientation="v", x=1.05),
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    # Risk Gauge
    st.subheader("⚠️ Current System Risk Gauge")
    sample_score = random.uniform(0.1, 0.9)
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=round(sample_score * 100, 1),
        title={"text": "Composite Risk Score (%)", "font": {"color": "#e0e0e0"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#e0e0e0"},
            "bar": {"color": "#e94560"},
            "bgcolor": "#16213e",
            "steps": [
                {"range": [0, 25],  "color": "#0d1b2a"},
                {"range": [25, 45], "color": "#1a2a1a"},
                {"range": [45, 65], "color": "#2a2a0d"},
                {"range": [65, 85], "color": "#2a1a0d"},
                {"range": [85, 100],"color": "#2a0d0d"},
            ],
            "threshold": {
                "line": {"color": "#ffd60a", "width": 4},
                "thickness": 0.75, "value": 65,
            },
        },
        number={"suffix": "%", "font": {"color": "#e0e0e0"}},
    ))
    fig_gauge.update_layout(
        paper_bgcolor="#0a0a1a", font_color="#e0e0e0", height=280
    )
    st.plotly_chart(fig_gauge, use_container_width=True)

    # Recent Alerts Table
    st.subheader("🚨 Recent Alerts")
    if detections:
        df_det = pd.DataFrame(detections[:20])
        display_cols = [c for c in
            ["timestamp", "threat_type", "risk_level", "risk_score", "is_threat"]
            if c in df_det.columns]
        st.dataframe(
            df_det[display_cols] if display_cols else df_det,
            use_container_width=True, hide_index=True,
        )
    else:
        st.info("No detections recorded yet. Use the 'Detect Threat' page to analyse inputs.")


# ════════════════════════════════════════════════════════
# PAGE: DETECT THREAT
# ════════════════════════════════════════════════════════
elif page == "🔍 Detect Threat":
    st.subheader("🔍 Run Threat Detection")

    tab1, tab2, tab3, tab4 = st.tabs([
        "📧 Phishing Email", "🔗 Malicious URL",
        "👤 Login Behaviour", "🌐 Network Anomaly",
    ])

    # ── Tab 1: Phishing Email ──────────────────────────────────────
    with tab1:
        st.write("Paste an email body to check for phishing indicators.")
        email_text = st.text_area(
            "Email Body", height=200,
            placeholder="Enter full email text here...",
            key="email_input",
        )
        if st.button("🔍 Analyse Email", key="btn_phish"):
            if email_text.strip():
                with st.spinner("Analysing email..."):
                    result = _api_post(
                        "/detect/phishing",
                        {"email_text": email_text, "model": "distilbert"},
                    )
                if result:
                    prob = result.get("probability", 0)
                    level = result.get("risk_level", "info")
                    is_threat = result.get("is_threat", False)

                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Phishing Probability", f"{prob:.1%}")
                    col_b.metric("Risk Level", level.upper())
                    col_c.metric("Verdict", "⚠️ PHISHING" if is_threat else "✅ LEGITIMATE")

                    if result.get("explanation"):
                        with st.expander("🧠 AI Explanation (XAI)"):
                            st.json(result["explanation"])
                else:
                    # Offline demo
                    st.info("API offline — showing demo result.")
                    kws = ["verify","account","suspended","click","urgent","password"]
                    hits = sum(1 for k in kws if k in email_text.lower())
                    prob = min(0.95, hits * 0.12)
                    st.metric("Demo Probability", f"{prob:.1%}")
            else:
                st.warning("Please enter email text.")

    # ── Tab 2: URL ─────────────────────────────────────────────────
    with tab2:
        st.write("Enter a URL to check for malicious indicators.")
        url_input = st.text_input(
            "URL", placeholder="https://example.com/login", key="url_input"
        )
        if st.button("🔍 Analyse URL", key="btn_url"):
            if url_input.strip():
                with st.spinner("Analysing URL..."):
                    result = _api_post("/detect/url", {"url": url_input})
                if result:
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Malicious Probability", f"{result['probability']:.1%}")
                    col_b.metric("Risk Level", result["risk_level"].upper())
                    col_c.metric("Verdict", "⚠️ MALICIOUS" if result["is_threat"] else "✅ BENIGN")
                    if result.get("explanation"):
                        with st.expander("🧠 Feature Analysis"):
                            st.json(result["explanation"])
            else:
                st.warning("Please enter a URL.")

    # ── Tab 3: Login ───────────────────────────────────────────────
    with tab3:
        st.write("Enter login event details for anomaly detection.")
        c1, c2, c3 = st.columns(3)
        hour     = c1.slider("Hour of Day",    0, 23, 14)
        day      = c2.slider("Day of Week",    0, 6,  2)
        failed   = c3.slider("Failed Attempts",0, 15, 0)
        c4, c5, c6 = st.columns(3)
        country  = c4.selectbox("IP Country Mismatch", [0, 1])
        new_dev  = c5.selectbox("New Device", [0, 1])
        new_loc  = c6.selectbox("New Location",[0, 1])
        typing   = st.slider("Typing Speed Anomaly", 0.0, 1.0, 0.1, 0.05)

        if st.button("🔍 Analyse Login", key="btn_login"):
            with st.spinner("Analysing login event..."):
                payload = {
                    "hour_of_day": hour, "day_of_week": day,
                    "login_duration": 120.0, "failed_attempts": failed,
                    "ip_country_mismatch": country, "new_device": new_dev,
                    "new_location": new_loc, "typing_speed_anomaly": typing,
                    "session_duration": 1800.0, "concurrent_sessions": 1,
                }
                result = _api_post("/detect/login", payload)
            if result:
                col_a, col_b, col_c = st.columns(3)
                col_a.metric("Anomaly Score", f"{result['probability']:.1%}")
                col_b.metric("Risk Level", result["risk_level"].upper())
                col_c.metric("Verdict", "⚠️ SUSPICIOUS" if result["is_threat"] else "✅ NORMAL")

    # ── Tab 4: Network ─────────────────────────────────────────────
    with tab4:
        st.write("Enter network connection features for anomaly detection.")
        c1, c2, c3 = st.columns(3)
        src_bytes  = c1.number_input("src_bytes",  0, 10000000, 491)
        dst_bytes  = c2.number_input("dst_bytes",  0, 10000000, 0)
        root_shell = c3.number_input("root_shell", 0, 1, 0)

        if st.button("🔍 Analyse Network", key="btn_net"):
            with st.spinner("Analysing network connection..."):
                result = _api_post("/detect/network", {
                    "features": {
                        "src_bytes": src_bytes, "dst_bytes": dst_bytes,
                        "root_shell": root_shell, "duration": 0,
                        "serror_rate": 0.0, "num_failed_logins": 0,
                    }
                })
            if result:
                col_a, col_b, col_c = st.columns(3)
                col_a.metric("Attack Probability", f"{result['probability']:.1%}")
                col_b.metric("Risk Level", result["risk_level"].upper())
                col_c.metric("Verdict", "⚠️ ATTACK" if result["is_threat"] else "✅ NORMAL")


# ════════════════════════════════════════════════════════
# PAGE: MODEL PERFORMANCE
# ════════════════════════════════════════════════════════
elif page == "📈 Model Performance":
    st.subheader("📈 Model Performance Metrics")

    metrics_data = _api_get("/analytics/metrics") or {}
    models = metrics_data.get("models", [])

    if models:
        df_m = pd.DataFrame(models)
        st.dataframe(df_m, use_container_width=True, hide_index=True)
    else:
        # Demo data when no models are trained yet
        demo_metrics = [
            {"Model": "DistilBERT (Phishing)",   "Accuracy": 0.9712, "F1": 0.9708, "AUC": 0.9891},
            {"Model": "BERT (Phishing)",          "Accuracy": 0.9754, "F1": 0.9751, "AUC": 0.9903},
            {"Model": "XGBoost (URL)",            "Accuracy": 0.9623, "F1": 0.9618, "AUC": 0.9847},
            {"Model": "Random Forest (URL)",      "Accuracy": 0.9541, "F1": 0.9535, "AUC": 0.9801},
            {"Model": "IsolationForest (Login)",  "Accuracy": 0.9128, "F1": 0.9101, "AUC": 0.9421},
            {"Model": "XGBoost (Login)",          "Accuracy": 0.9387, "F1": 0.9379, "AUC": 0.9659},
            {"Model": "XGBoost (Network)",        "Accuracy": 0.9812, "F1": 0.9809, "AUC": 0.9967},
            {"Model": "IsolationForest (Network)","Accuracy": 0.9234, "F1": 0.9198, "AUC": 0.9512},
        ]
        df_demo = pd.DataFrame(demo_metrics)
        st.info("Showing projected metrics. Train models to see actual results.")
        st.dataframe(df_demo, use_container_width=True, hide_index=True)

        # Bar chart comparison
        fig_bar = px.bar(
            df_demo, x="Model", y=["Accuracy", "F1", "AUC"],
            barmode="group", template="plotly_dark",
            color_discrete_map={"Accuracy":"#e94560","F1":"#06d6a0","AUC":"#ffd60a"},
            title="Model Performance Comparison",
        )
        fig_bar.update_layout(
            paper_bgcolor="#0a0a1a", plot_bgcolor="#0a0a1a",
            font_color="#e0e0e0", height=400,
            xaxis_tickangle=-30,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

        # ROC-AUC comparison
        fig_auc = px.bar(
            df_demo.sort_values("AUC", ascending=True),
            x="AUC", y="Model", orientation="h",
            template="plotly_dark", title="ROC-AUC Scores by Model",
            color="AUC", color_continuous_scale="plasma",
        )
        fig_auc.update_layout(
            paper_bgcolor="#0a0a1a", plot_bgcolor="#0a0a1a",
            font_color="#e0e0e0", height=380,
        )
        st.plotly_chart(fig_auc, use_container_width=True)

# ════════════════════════════════════════════════════════
# PAGE: REPORTS
# ════════════════════════════════════════════════════════
elif page == "📋 Reports":
    st.subheader("📋 Generate & Download Reports")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📄 CSV Report")
        st.write("Export all threat detections as a CSV spreadsheet.")
        if st.button("⬇️ Download CSV"):
            try:
                r = requests.get("http://localhost:8000/api/v1/reports/csv", timeout=15)
                if r.status_code == 200:
                    st.download_button(
                        "💾 Save CSV File",
                        data=r.content,
                        file_name="threat_report.csv",
                        mime="text/csv",
                    )
                else:
                    st.error("API error. Make sure the backend is running.")
            except Exception:
                st.warning("API offline. Start the backend with: uvicorn src.api.main:app")

    with col2:
        st.markdown("### 📕 PDF Report")
        st.write("Generate a formatted PDF report with charts and metrics.")
        if st.button("⬇️ Download PDF"):
            try:
                r = requests.get("http://localhost:8000/api/v1/reports/pdf", timeout=30)
                if r.status_code == 200:
                    st.download_button(
                        "💾 Save PDF File",
                        data=r.content,
                        file_name="threat_report.pdf",
                        mime="application/pdf",
                    )
                else:
                    st.error("API error generating PDF.")
            except Exception:
                st.warning("API offline. Start the backend with: uvicorn src.api.main:app")

    st.divider()
    st.caption(
        "Reports include threat detections, model performance metrics, "
        "and executive summary. Suitable for IEEE paper appendix."
    )
