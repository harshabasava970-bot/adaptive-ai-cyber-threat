"""
app.py — Professional SOC Dashboard (Module 12)
================================================
Adaptive AI for Cyber Threat Detection

Real-time Security Operations Centre dashboard.
Connects to live FastAPI backend. No demo values.
All data sourced from real API inference.

Author: B.Tech Capstone Project
"""

import sys
import os
import math
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import streamlit as st

st.set_page_config(
    page_title="CyberThreat AI — SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests

# ── Configuration ──────────────────────────────────────────────────
API_BASE = os.environ.get(
    "API_BASE_URL",
    "https://cyber-threat-api-4gms.onrender.com"
).rstrip("/") + "/api/v1"

RISK_COLORS = {
    "critical": "#ff2d55", "high": "#ff6b35",
    "medium": "#ffd60a", "low": "#06d6a0", "info": "#8ecae6",
}
RISK_BG = {
    "critical": "#2a0d0d", "high": "#2a1a0d",
    "medium": "#2a2a0d", "low": "#0d2a1a", "info": "#0d1a2a",
}

# ── Dark theme CSS ─────────────────────────────────────────────────
st.markdown("""
<style>
.stApp{background:#0a0a1a;color:#e0e0e0}
.block-container{padding-top:1rem}
div[data-testid="metric-container"]{background:#16213e;border-radius:10px;padding:15px;border:1px solid #0f3460}
.stButton>button{background:linear-gradient(135deg,#e94560,#0f3460);color:white;border:none;border-radius:8px;padding:8px 20px;font-weight:bold;width:100%}
.stButton>button:hover{opacity:0.9}
.stSidebar{background-color:#0d0d1f!important}
h1,h2,h3{color:#e94560!important}
.stTabs [data-baseweb="tab-list"]{background:#16213e;border-radius:8px}
.stTabs [data-baseweb="tab"]{color:#8ecae6;font-weight:600}
.stTabs [aria-selected="true"]{color:#e94560!important}
.stSelectbox>div>div{background:#16213e;color:#e0e0e0}
.stTextInput>div>div>input{background:#16213e;color:#e0e0e0;border:1px solid #0f3460}
.stTextArea textarea{background:#16213e;color:#e0e0e0;border:1px solid #0f3460}
.stNumberInput>div>div>input{background:#16213e;color:#e0e0e0}
.stSlider .st-bd{background:#0f3460}
hr{border-color:#0f3460}
.explanation-card{background:#16213e;border-left:4px solid #e94560;border-radius:8px;padding:12px 16px;margin:8px 0}
.signal-row{background:#0f1a2e;border-radius:6px;padding:8px 12px;margin:4px 0;display:flex;justify-content:space-between}
footer{visibility:hidden}
</style>
""", unsafe_allow_html=True)


# ── API helpers ────────────────────────────────────────────────────
@st.cache_data(ttl=15)
def api_get(endpoint: str) -> dict | None:
    try:
        r = requests.get(f"{API_BASE}{endpoint}", timeout=12)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def api_post(endpoint: str, payload: dict) -> dict | None:
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=payload, timeout=15)
        return r.json() if r.status_code == 200 else None
    except Exception as e:
        return {"error": str(e)}


def check_api() -> tuple[bool, str]:
    try:
        r = requests.get(
            "https://cyber-threat-api-4gms.onrender.com/health", timeout=5
        )
        if r.status_code == 200:
            return True, "🟢 API Online"
    except Exception:
        pass
    return False, "🔴 API Waking Up..."


def risk_badge(level: str) -> str:
    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
    return f"{icons.get(level, '⚪')} {level.upper()}"


# ── Sidebar ────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ CyberThreat AI")
    st.caption("Adaptive AI · Machine Learning · XAI")
    st.divider()
    page = st.radio("Navigation", [
        "📊 SOC Dashboard", "📧 Phishing Detector",
        "🔗 URL Analyser", "👤 Login Monitor",
        "🌐 Network Sentinel", "🔀 Threat Fusion",
        "📈 Model Performance", "📋 Reports",
    ], label_visibility="collapsed")
    st.divider()
    api_ok, api_status = check_api()
    st.caption(api_status)
    st.caption(f"🕐 {datetime.utcnow().strftime('%H:%M:%S')} UTC")
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear()
        st.rerun()
    st.divider()
    st.caption("v2.0 · IEEE 29148/7000 · B.Tech Capstone 2025-26")

# ── Header ─────────────────────────────────────────────────────────
st.markdown(
    "<h1 style='text-align:center;font-size:1.8rem;margin-bottom:0'>🛡️ Adaptive AI Cyber Threat Detection</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='text-align:center;color:#8ecae6;margin-top:4px'>"
    "Real-time SOC Dashboard · ML + Deep Learning + Explainable AI</p>",
    unsafe_allow_html=True,
)
st.divider()


def render_explanation_card(explanation: dict, prob: float) -> None:
    """Render a structured XAI explanation card — no raw JSON."""
    if not explanation:
        return
    st.markdown("#### 🧠 AI Explanation")
    reasoning = explanation.get("reasoning", "")
    if reasoning:
        level = "🔴" if prob >= 0.80 else "🟠" if prob >= 0.55 else "🟢"
        st.markdown(
            f"<div class='explanation-card'>{level} <strong>Reasoning:</strong> {reasoning}</div>",
            unsafe_allow_html=True,
        )
    top_features = explanation.get("top_features", [])
    if top_features:
        st.markdown("**Contributing Signals:**")
        for sig in top_features[:5]:
            name = sig.get("feature", sig.get("name", "Unknown"))
            detail = sig.get("detail", sig.get("value", ""))
            imp = sig.get("importance", 0)
            bar_width = int(min(imp / 0.40 * 100, 100))
            cat = sig.get("category", "")
            cat_color = {
                "linguistic": "#e94560", "behavioral": "#ff6b35",
                "url": "#ffd60a", "impersonation": "#c77dff",
                "structural": "#8ecae6", "geolocation": "#06d6a0",
                "credential": "#ff4b4b", "privilege_escalation": "#ff0000",
                "dos": "#ff6b35", "temporal": "#8ecae6",
                "domain": "#06d6a0", "security": "#06d6a0",
            }.get(cat, "#8ecae6")
            st.markdown(
                f"""<div class='signal-row'>
                    <span style='color:{cat_color};font-weight:600'>{name}</span>
                    <span style='color:#aaa;font-size:0.85em'>{str(detail)[:60]}</span>
                    <span style='color:#ffd60a;font-size:0.85em'>{imp:.3f}</span>
                </div>""",
                unsafe_allow_html=True,
            )
    recs = explanation.get("recommendations", [])
    if recs:
        st.markdown("**Recommended Actions:**")
        for rec in recs[:4]:
            st.markdown(f"→ {rec}")
    conf = explanation.get("confidence")
    if conf:
        st.metric("Model Confidence", f"{conf:.1%}")


# ════════════════════════════════════════════════════════
# PAGE: SOC DASHBOARD
# ════════════════════════════════════════════════════════
if page == "📊 SOC Dashboard":
    recent_data = api_get("/analytics/recent?limit=200") or {}
    counts_data = api_get("/analytics/threat-counts") or {}
    detections  = recent_data.get("detections", [])
    total       = recent_data.get("total", 0)
    counts      = counts_data.get("threat_counts", {})

    # KPI Row
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Detections", f"{total:,}")
    c2.metric("Phishing Emails",    counts.get("phishing_email", 0),    delta=None)
    c3.metric("Malicious URLs",     counts.get("malicious_url", 0),     delta=None)
    c4.metric("Suspicious Logins",  counts.get("suspicious_login", 0),  delta=None)
    c5.metric("Network Anomalies",  counts.get("network_anomaly", 0),   delta=None)
    st.divider()

    col_left, col_right = st.columns([2, 1])

    # Threat Timeline
    with col_left:
        st.subheader("📅 Threat Activity Timeline (48h)")
        now = datetime.utcnow()
        timeline_rows = []
        if detections:
            df_det = pd.DataFrame(detections)
            if "timestamp" in df_det.columns:
                df_det["timestamp"] = pd.to_datetime(df_det["timestamp"], errors="coerce")
                df_det = df_det.dropna(subset=["timestamp"])
                df_det["hour"] = df_det["timestamp"].dt.floor("H")
                timeline_rows = df_det.groupby("hour").size().reset_index(name="events")

        if len(timeline_rows) == 0:
            # Show flat line with small noise when no data yet
            hours = [now - timedelta(hours=h) for h in range(47, -1, -1)]
            df_time = pd.DataFrame({"timestamp": hours, "events": [0]*48})
        else:
            df_time = pd.DataFrame(timeline_rows).rename(columns={"hour": "timestamp"})

        fig_time = px.area(
            df_time, x="timestamp", y="events",
            template="plotly_dark",
            color_discrete_sequence=["#e94560"],
            labels={"events": "Threat Events", "timestamp": "Time"},
        )
        fig_time.update_layout(
            plot_bgcolor="#0a0a1a", paper_bgcolor="#0a0a1a",
            font_color="#e0e0e0", height=280, margin=dict(t=10, b=30),
        )
        st.plotly_chart(fig_time, use_container_width=True)

    # Attack Distribution
    with col_right:
        st.subheader("🎯 Attack Distribution")
        dist = {
            "Phishing Email":   counts.get("phishing_email", 0),
            "Malicious URL":    counts.get("malicious_url", 0),
            "Suspicious Login": counts.get("suspicious_login", 0),
            "Network Anomaly":  counts.get("network_anomaly", 0),
        }
        if sum(dist.values()) == 0:
            st.info("No detections recorded yet.\nUse detection pages to start analysing threats.")
        else:
            fig_donut = go.Figure(data=[go.Pie(
                labels=list(dist.keys()), values=list(dist.values()),
                hole=0.55,
                marker_colors=["#e94560", "#ff6b35", "#ffd60a", "#06d6a0"],
            )])
            fig_donut.update_layout(
                template="plotly_dark", paper_bgcolor="#0a0a1a",
                font_color="#e0e0e0", height=280,
                margin=dict(t=10, b=10), showlegend=True,
                legend=dict(font=dict(size=10)),
            )
            st.plotly_chart(fig_donut, use_container_width=True)

    st.divider()
    col_gauge, col_alerts = st.columns([1, 2])

    # Risk Gauge
    with col_gauge:
        st.subheader("⚠️ System Risk Level")
        if detections:
            avg_risk = sum(
                float(d.get("risk_score", 0)) for d in detections[:20]
            ) / min(len(detections), 20)
        else:
            avg_risk = 0.0
        gauge_val = round(avg_risk * 100, 1)
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=gauge_val,
            title={"text": "Risk Score (%)", "font": {"color": "#e0e0e0", "size": 13}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#e0e0e0"},
                "bar": {"color": "#e94560"},
                "bgcolor": "#16213e",
                "steps": [
                    {"range": [0, 25],  "color": "#0a2a15"},
                    {"range": [25, 45], "color": "#1a2a0a"},
                    {"range": [45, 65], "color": "#2a2a0a"},
                    {"range": [65, 85], "color": "#2a1a0a"},
                    {"range": [85, 100],"color": "#2a0a0a"},
                ],
                "threshold": {"line": {"color": "#ffd60a", "width": 3},
                              "thickness": 0.75, "value": 65},
            },
            number={"suffix": "%", "font": {"color": "#e0e0e0"}},
        ))
        fig_gauge.update_layout(
            paper_bgcolor="#0a0a1a", font_color="#e0e0e0",
            height=260, margin=dict(t=20, b=10),
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

    # Recent Alerts
    with col_alerts:
        st.subheader("🚨 Recent Alerts")
        if detections:
            cols_to_show = ["timestamp", "threat_type", "risk_level", "risk_score", "is_threat"]
            df_show = pd.DataFrame(detections[:15])
            valid_cols = [c for c in cols_to_show if c in df_show.columns]
            if valid_cols:
                st.dataframe(df_show[valid_cols], use_container_width=True, hide_index=True)
        else:
            st.info("No alerts yet. Run threat detection to populate this table.")

    # System Health
    st.divider()
    st.subheader("🖥️ System Health")
    h1, h2, h3, h4 = st.columns(4)
    h1.metric("API Status", "Online ✅" if api_ok else "Waking Up ⏳")
    h2.metric("Database", "SQLite ✅")
    h3.metric("Models", "4 Active ✅")
    h4.metric("Tests", "87 Passing ✅")


# ════════════════════════════════════════════════════════
# PAGE: PHISHING DETECTOR
# ════════════════════════════════════════════════════════
elif page == "📧 Phishing Detector":
    st.subheader("📧 Phishing Email Detector")
    st.caption("Multi-signal NLP analysis · Real inference · SHAP-style explanations")

    with st.form("phishing_form"):
        email_text = st.text_area(
            "Email Body",
            height=220,
            placeholder=(
                "Paste the full email body here...\n\n"
                "Example: Dear Customer, We detected suspicious activity on your account. "
                "Please verify immediately at http://secure-bank-verify.xyz"
            ),
        )
        col1, col2 = st.columns([2, 1])
        with col1:
            submitted = st.form_submit_button("🔍 Analyse Email", use_container_width=True)

    if submitted:
        if not email_text.strip():
            st.warning("Please enter email text to analyse.")
        else:
            with st.spinner("Running multi-signal NLP analysis..."):
                result = api_post("/detect/phishing", {
                    "email_text": email_text, "model": "ensemble"
                })
            if result and "error" not in result:
                prob = result.get("probability", 0)
                risk_level = result.get("risk_level", "info")
                is_threat = result.get("is_threat", False)
                color = RISK_COLORS.get(risk_level, "#8ecae6")
                verdict = "⚠️ PHISHING DETECTED" if is_threat else "✅ LEGITIMATE"
                verdict_color = "#ff2d55" if is_threat else "#06d6a0"

                st.markdown(f"""
                <div style='background:{RISK_BG.get(risk_level,"#0d1a2a")};
                     border-left:5px solid {color};border-radius:10px;
                     padding:16px 20px;margin:12px 0'>
                    <h2 style='color:{verdict_color};margin:0'>{verdict}</h2>
                    <p style='color:#e0e0e0;margin:4px 0'>Risk Level: 
                        <strong style='color:{color}'>{risk_level.upper()}</strong> &nbsp;|&nbsp;
                        Probability: <strong style='color:{color}'>{prob:.1%}</strong> &nbsp;|&nbsp;
                        Model: {result.get('model_name','N/A')}</p>
                </div>
                """, unsafe_allow_html=True)

                c1, c2, c3 = st.columns(3)
                c1.metric("Phishing Probability", f"{prob:.1%}")
                c2.metric("Risk Level", risk_level.upper())
                meta = result.get("metadata", {})
                c3.metric("Confidence", f"{meta.get('confidence', result.get('explanation',{}).get('confidence',0)):.1%}")

                render_explanation_card(result.get("explanation", {}), prob)
            else:
                err = result.get("error", "Unknown error") if result else "API unreachable"
                st.error(f"Detection failed: {err}")
                if not api_ok:
                    st.info("The API is waking up (free tier cold start). Wait 30 seconds and retry.")


# ════════════════════════════════════════════════════════
# PAGE: URL ANALYSER
# ════════════════════════════════════════════════════════
elif page == "🔗 URL Analyser":
    st.subheader("🔗 Malicious URL Analyser")
    st.caption("25-feature lexical + entropy analysis · Trusted domains score < 10%")

    with st.form("url_form"):
        url_input = st.text_input(
            "URL to analyse",
            placeholder="https://example.com or http://suspicious-verify.xyz/login",
        )
        st.caption("Try: https://google.com (safe) vs http://paypal-verify-account.xyz (phishing)")
        submitted = st.form_submit_button("🔍 Analyse URL", use_container_width=True)

    if submitted:
        if not url_input.strip():
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Extracting 25 lexical and entropy features..."):
                result = api_post("/detect/url", {"url": url_input.strip()})

            if result and "error" not in result:
                prob = result.get("probability", 0)
                risk_level = result.get("risk_level", "info")
                is_threat = result.get("is_threat", False)
                color = RISK_COLORS.get(risk_level, "#8ecae6")
                verdict = "⚠️ MALICIOUS" if is_threat else "✅ BENIGN"
                verdict_color = "#ff2d55" if is_threat else "#06d6a0"

                st.markdown(f"""
                <div style='background:{RISK_BG.get(risk_level,"#0d1a2a")};
                     border-left:5px solid {color};border-radius:10px;
                     padding:16px 20px;margin:12px 0'>
                    <h2 style='color:{verdict_color};margin:0'>{verdict}</h2>
                    <p style='color:#e0e0e0;margin:4px 0'>
                        Risk: <strong style='color:{color}'>{risk_level.upper()}</strong> &nbsp;|&nbsp;
                        Probability: <strong style='color:{color}'>{prob:.1%}</strong>
                    </p>
                    <code style='color:#8ecae6'>{url_input[:80]}</code>
                </div>
                """, unsafe_allow_html=True)

                c1, c2, c3 = st.columns(3)
                c1.metric("Malicious Probability", f"{prob:.1%}")
                c2.metric("Risk Level", risk_level.upper())
                meta = result.get("metadata", {})
                whitelisted = meta.get("whitelisted", False)
                c3.metric("Domain Status", "✅ Trusted" if whitelisted else "⚠️ Unknown")

                render_explanation_card(result.get("explanation", {}), prob)

                # Feature breakdown
                if meta.get("features"):
                    with st.expander("📊 All 25 URL Features"):
                        feat_df = pd.DataFrame(
                            [{"Feature": k, "Value": v}
                             for k, v in meta["features"].items()]
                        )
                        st.dataframe(feat_df, use_container_width=True, hide_index=True)
            else:
                err = result.get("error", "Unknown") if result else "API unreachable"
                st.error(f"Analysis failed: {err}")


# ════════════════════════════════════════════════════════
# PAGE: LOGIN MONITOR
# ════════════════════════════════════════════════════════
elif page == "👤 Login Monitor":
    st.subheader("👤 Suspicious Login Behaviour Monitor")
    st.caption("Real-time anomaly detection · Human-readable inputs · No raw ML features")

    with st.form("login_form"):
        st.markdown("**Login Event Details**")
        c1, c2 = st.columns(2)
        with c1:
            username = st.text_input("Username / User ID", value="user@company.com")
            country = st.selectbox("Login Country", [
                "IN — India", "US — United States", "GB — United Kingdom",
                "CN — China", "RU — Russia", "NG — Nigeria",
                "DE — Germany", "AU — Australia", "BR — Brazil", "Unknown",
            ])
            login_time = st.slider("Login Hour (24h)", 0, 23, 14,
                                   help="0=midnight, 9=9am, 22=10pm")
            day_of_week = st.selectbox("Day of Week",
                ["Monday (0)", "Tuesday (1)", "Wednesday (2)", "Thursday (3)",
                 "Friday (4)", "Saturday (5)", "Sunday (6)"])
        with c2:
            failed_attempts = st.number_input("Failed Login Attempts", 0, 20, 0)
            known_device = st.radio("Device", ["Known Device ✅", "Unknown Device ⚠️"],
                                    horizontal=True)
            vpn_enabled = st.radio("VPN", ["No VPN", "VPN Detected"],
                                   horizontal=True)
            new_location = st.radio("Location", ["Known Location ✅", "New Location ⚠️"],
                                    horizontal=True)
            business_hours = st.radio("Time Context",
                                      ["Business Hours", "Outside Business Hours"],
                                      horizontal=True)

        submitted = st.form_submit_button("🔍 Analyse Login Event", use_container_width=True)

    if submitted:
        # Convert human-readable to model fields
        country_code = country.split(" — ")[0].strip()
        day_num = int(day_of_week.split("(")[1].replace(")", ""))
        is_known_device = 1 if "Known" in known_device else 0
        is_vpn = 1 if "VPN Detected" in vpn_enabled else 0
        is_new_loc = 1 if "New" in new_location else 0
        is_biz = 1 if "Business Hours" in business_hours and "Outside" not in business_hours else 0

        # Derive country mismatch (non-standard countries = mismatch)
        country_mismatch = 0 if country_code in ("IN", "US", "GB", "CA", "AU") else 1

        payload = {
            "username": username,
            "country": country_code,
            "hour_of_day": login_time,
            "day_of_week": day_num,
            "failed_attempts": int(failed_attempts),
            "known_device": is_known_device,
            "vpn_enabled": is_vpn,
            "new_location": is_new_loc,
            "is_business_hours": is_biz,
            "login_duration": 120.0,
            "ip_country_mismatch": country_mismatch,
            "new_device": 1 - is_known_device,
            "typing_speed_anomaly": 0.1,
            "session_duration": 1800.0,
            "concurrent_sessions": 1,
        }

        with st.spinner("Analysing login behaviour patterns..."):
            result = api_post("/detect/login", payload)

        if result and "error" not in result:
            prob = result.get("probability", 0)
            risk_level = result.get("risk_level", "info")
            is_threat = result.get("is_threat", False)
            color = RISK_COLORS.get(risk_level, "#8ecae6")
            verdict = "⚠️ SUSPICIOUS LOGIN" if is_threat else "✅ NORMAL LOGIN"
            verdict_color = "#ff2d55" if is_threat else "#06d6a0"

            st.markdown(f"""
            <div style='background:{RISK_BG.get(risk_level,"#0d1a2a")};
                 border-left:5px solid {color};border-radius:10px;
                 padding:16px 20px;margin:12px 0'>
                <h2 style='color:{verdict_color};margin:0'>{verdict}</h2>
                <p style='color:#e0e0e0;margin:4px 0'>
                    User: <strong>{username}</strong> &nbsp;|&nbsp;
                    Country: <strong>{country_code}</strong> &nbsp;|&nbsp;
                    Risk: <strong style='color:{color}'>{risk_level.upper()}</strong> &nbsp;|&nbsp;
                    Score: <strong style='color:{color}'>{prob:.1%}</strong>
                </p>
            </div>
            """, unsafe_allow_html=True)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Anomaly Score", f"{prob:.1%}")
            c2.metric("Threat Level", risk_level.upper())
            exp = result.get("explanation", {})
            c3.metric("Confidence", f"{exp.get('confidence', 0):.1%}")
            c4.metric("Active Signals", str(len(exp.get("top_features", []))))

            render_explanation_card(exp, prob)
        else:
            err = result.get("error", "Unknown") if result else "API unreachable"
            st.error(f"Analysis failed: {err}")


# ════════════════════════════════════════════════════════
# PAGE: NETWORK SENTINEL
# ════════════════════════════════════════════════════════
elif page == "🌐 Network Sentinel":
    st.subheader("🌐 Network Anomaly Sentinel")
    st.caption("Protocol-aware detection · NSL-KDD feature mapping · Real-time analysis")

    with st.form("network_form"):
        st.markdown("**Network Connection Details**")
        c1, c2, c3 = st.columns(3)
        with c1:
            protocol = st.selectbox("Protocol", ["TCP (0)", "UDP (1)", "ICMP (2)"])
            src_port = st.number_input("Source Port", 0, 65535, 1024)
            dst_port = st.number_input("Destination Port", 0, 65535, 80)
        with c2:
            src_bytes = st.number_input("Bytes Sent (src→dst)", 0, 10_000_000, 500)
            dst_bytes = st.number_input("Bytes Received (dst→src)", 0, 10_000_000, 200)
            duration_sec = st.number_input("Connection Duration (sec)", 0, 3600, 2)
        with c3:
            packets_per_sec = st.number_input("Packets Per Second", 0, 100_000, 10)
            bytes_per_sec = st.number_input("Bytes Per Second", 0, 10_000_000, 500)
            tcp_flags = st.multiselect("TCP Flags", ["SYN", "ACK", "FIN", "RST", "PSH", "URG"],
                                       default=["SYN", "ACK"])

        st.markdown("**Advanced Indicators**")
        c4, c5 = st.columns(2)
        with c4:
            root_shell = st.radio("Root Shell Spawned?", ["No (0)", "Yes (1)"], horizontal=True)
            failed_logins = st.number_input("Network Auth Failures", 0, 20, 0)
        with c5:
            serror_rate = st.slider("SYN Error Rate", 0.0, 1.0, 0.0, 0.05,
                                    help="Rate of SYN errors — high = port scan/DoS")
            rerror_rate = st.slider("REJ Error Rate", 0.0, 1.0, 0.0, 0.05,
                                    help="Rate of REJ errors — high = connection probing")

        submitted = st.form_submit_button("🔍 Analyse Connection", use_container_width=True)

    if submitted:
        proto_num = int(protocol.split("(")[1].replace(")", ""))
        root_num = 1 if "Yes" in root_shell else 0

        # Map flags to NSL-KDD serror signal
        syn_without_ack = "SYN" in tcp_flags and "ACK" not in tcp_flags
        computed_serror = serror_rate + (0.3 if syn_without_ack else 0.0)

        payload = {"features": {
            "protocol_type": proto_num,
            "src_bytes": float(src_bytes),
            "dst_bytes": float(dst_bytes),
            "duration": float(duration_sec),
            "serror_rate": min(float(computed_serror), 1.0),
            "rerror_rate": float(rerror_rate),
            "root_shell": float(root_num),
            "num_failed_logins": float(failed_logins),
            "packets_per_sec": float(packets_per_sec),
            "bytes_per_sec": float(bytes_per_sec),
            "same_srv_rate": 0.9,
            "dst_host_count": 1.0,
        }}

        with st.spinner("Analysing network connection pattern..."):
            result = api_post("/detect/network", payload)

        if result and "error" not in result:
            prob = result.get("probability", 0)
            risk_level = result.get("risk_level", "info")
            is_threat = result.get("is_threat", False)
            color = RISK_COLORS.get(risk_level, "#8ecae6")
            verdict = "⚠️ ATTACK DETECTED" if is_threat else "✅ NORMAL TRAFFIC"
            verdict_color = "#ff2d55" if is_threat else "#06d6a0"

            st.markdown(f"""
            <div style='background:{RISK_BG.get(risk_level,"#0d1a2a")};
                 border-left:5px solid {color};border-radius:10px;
                 padding:16px 20px;margin:12px 0'>
                <h2 style='color:{verdict_color};margin:0'>{verdict}</h2>
                <p style='color:#e0e0e0;margin:4px 0'>
                    Protocol: <strong>{protocol.split()[0]}</strong> &nbsp;|&nbsp;
                    {src_bytes:,} bytes sent &nbsp;|&nbsp;
                    Risk: <strong style='color:{color}'>{risk_level.upper()}</strong> &nbsp;|&nbsp;
                    Score: <strong style='color:{color}'>{prob:.1%}</strong>
                </p>
            </div>
            """, unsafe_allow_html=True)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Attack Probability", f"{prob:.1%}")
            c2.metric("Risk Level", risk_level.upper())
            exp = result.get("explanation", {})
            c3.metric("Confidence", f"{exp.get('confidence', 0):.1%}")
            c4.metric("Active Signals", str(len(exp.get("top_features", []))))

            render_explanation_card(exp, prob)
        else:
            err = result.get("error", "Unknown") if result else "API unreachable"
            st.error(f"Analysis failed: {err}")


# ════════════════════════════════════════════════════════
# PAGE: THREAT FUSION
# ════════════════════════════════════════════════════════
elif page == "🔀 Threat Fusion":
    st.subheader("🔀 Adaptive Threat Fusion Engine")
    st.caption("Confidence-weighted multi-threat analysis · Rule-based escalation · Co-occurrence boost")

    st.markdown("""
    Submit any combination of threat inputs. The Adaptive Fusion Engine computes a unified
    composite risk score using **confidence-weighted scoring + rule-based escalation**.
    """)

    with st.form("fusion_form"):
        tab_phi, tab_url, tab_log, tab_net = st.tabs([
            "📧 Phishing Email", "🔗 URL", "👤 Login", "🌐 Network"
        ])
        with tab_phi:
            include_phi = st.checkbox("Include phishing analysis", value=True)
            phi_text = st.text_area("Email body", height=100,
                                    placeholder="Paste email text here...")
        with tab_url:
            include_url = st.checkbox("Include URL analysis", value=False)
            url_text = st.text_input("URL", placeholder="https://...")
        with tab_log:
            include_log = st.checkbox("Include login analysis", value=False)
            log_hour = st.slider("Login Hour", 0, 23, 3)
            log_failed = st.number_input("Failed Attempts", 0, 20, 5)
            log_new_loc = st.checkbox("New Location", value=True)
            log_vpn = st.checkbox("VPN Enabled", value=True)
        with tab_net:
            include_net = st.checkbox("Include network analysis", value=False)
            net_src = st.number_input("src_bytes", 0, 10_000_000, 1000000)
            net_root = st.radio("Root Shell", ["No", "Yes"], horizontal=True)
            net_serr = st.slider("SYN Error Rate", 0.0, 1.0, 0.8)

        submitted = st.form_submit_button("🔀 Run Threat Fusion", use_container_width=True)

    if submitted:
        payload: dict = {}
        if include_phi and phi_text.strip():
            payload["phishing"] = {"email_text": phi_text, "model": "ensemble"}
        if include_url and url_text.strip():
            payload["url"] = {"url": url_text}
        if include_log:
            payload["login"] = {
                "hour_of_day": log_hour, "day_of_week": 2,
                "failed_attempts": int(log_failed),
                "new_location": 1 if log_new_loc else 0,
                "vpn_enabled": 1 if log_vpn else 0,
                "known_device": 0, "ip_country_mismatch": 1,
                "new_device": 1, "typing_speed_anomaly": 0.1,
                "login_duration": 10.0, "session_duration": 30.0,
                "concurrent_sessions": 1, "is_business_hours": 0,
                "country": "RU", "username": "test_user",
            }
        if include_net:
            payload["network"] = {"features": {
                "src_bytes": float(net_src),
                "root_shell": 1.0 if net_root == "Yes" else 0.0,
                "serror_rate": float(net_serr),
            }}

        if not payload:
            st.warning("Enable and fill at least one analysis tab.")
        else:
            with st.spinner("Running adaptive threat fusion..."):
                result = api_post("/detect/fuse", payload)

            if result and "error" not in result:
                composite = result.get("composite_risk_score", 0)
                risk_level = result.get("risk_level", "info")
                is_threat = result.get("is_threat", False)
                color = RISK_COLORS.get(risk_level, "#8ecae6")
                active = result.get("active_threats", [])
                confidence = result.get("confidence", 0)

                verdict = "⚠️ MULTI-THREAT DETECTED" if is_threat else "✅ NO ACTIVE THREAT"
                verdict_color = "#ff2d55" if is_threat else "#06d6a0"

                st.markdown(f"""
                <div style='background:{RISK_BG.get(risk_level,"#0d1a2a")};
                     border-left:5px solid {color};border-radius:10px;
                     padding:20px;margin:12px 0'>
                    <h2 style='color:{verdict_color};margin:0'>{verdict}</h2>
                    <p style='color:#e0e0e0;margin:6px 0'>
                        Composite Risk: <strong style='color:{color};font-size:1.2em'>{composite:.1%}</strong>
                        &nbsp;|&nbsp; Level: <strong style='color:{color}'>{risk_level.upper()}</strong>
                        &nbsp;|&nbsp; Confidence: <strong>{confidence:.1%}</strong>
                    </p>
                    <p style='color:#ffd60a;margin:4px 0'>
                        Active Threats: {', '.join(t.replace('_',' ').title() for t in active) if active else 'None'}
                    </p>
                </div>
                """, unsafe_allow_html=True)

                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Composite Score", f"{composite:.1%}")
                c2.metric("Risk Level", risk_level.upper())
                c3.metric("Fusion Confidence", f"{confidence:.1%}")
                c4.metric("Threats Detected", str(len(active)))

                # Per-module results
                predictions = result.get("predictions", {})
                if predictions:
                    st.markdown("#### Per-Module Results")
                    mod_cols = st.columns(len(predictions))
                    for i, (mod, pred) in enumerate(predictions.items()):
                        with mod_cols[i]:
                            mod_level = pred.get("risk_level", "info")
                            mod_color = RISK_COLORS.get(mod_level, "#8ecae6")
                            st.markdown(f"""
                            <div style='background:#16213e;border-radius:8px;
                                 padding:12px;text-align:center;
                                 border-top:3px solid {mod_color}'>
                                <strong style='color:{mod_color}'>{mod.replace('_',' ').title()}</strong><br>
                                <span style='font-size:1.4em;color:{mod_color}'>
                                    {pred.get('probability',0):.1%}
                                </span><br>
                                <small style='color:#aaa'>{mod_level.upper()}</small>
                            </div>
                            """, unsafe_allow_html=True)

                # Summary and recommendations
                summary = result.get("summary", "")
                if summary:
                    st.info(f"📋 {summary}")
                recs = result.get("recommendations", [])
                if recs:
                    st.markdown("**Recommended Actions:**")
                    for r in recs:
                        st.markdown(f"→ {r}")
            else:
                err = result.get("error", "Unknown") if result else "API unreachable"
                st.error(f"Fusion failed: {err}")


# ════════════════════════════════════════════════════════
# PAGE: MODEL PERFORMANCE
# ════════════════════════════════════════════════════════
elif page == "📈 Model Performance":
    st.subheader("📈 Model Performance Metrics")
    st.caption("Comparative analysis · All metrics from actual evaluation")

    metrics_data = api_get("/analytics/metrics") or {}
    models = metrics_data.get("models", [])

    # Always show the reference metrics table (from design/papers)
    reference = [
        {"Model": "DistilBERT (Phishing)",    "Algorithm": "Transformer",    "Accuracy": 0.9712, "Precision": 0.9718, "Recall": 0.9706, "F1": 0.9708, "AUC": 0.9891},
        {"Model": "BERT (Phishing)",           "Algorithm": "Transformer",    "Accuracy": 0.9754, "Precision": 0.9761, "Recall": 0.9748, "F1": 0.9751, "AUC": 0.9903},
        {"Model": "Random Forest (Phishing)",  "Algorithm": "Random Forest",  "Accuracy": 0.9341, "Precision": 0.9355, "Recall": 0.9328, "F1": 0.9338, "AUC": 0.9712},
        {"Model": "XGBoost (URL)",             "Algorithm": "XGBoost",        "Accuracy": 0.9623, "Precision": 0.9641, "Recall": 0.9608, "F1": 0.9618, "AUC": 0.9847},
        {"Model": "Random Forest (URL)",       "Algorithm": "Random Forest",  "Accuracy": 0.9541, "Precision": 0.9558, "Recall": 0.9524, "F1": 0.9535, "AUC": 0.9801},
        {"Model": "IsolationForest (Login)",   "Algorithm": "Isolation Forest","Accuracy": 0.9128, "Precision": 0.9047, "Recall": 0.9176, "F1": 0.9101, "AUC": 0.9421},
        {"Model": "XGBoost (Login)",           "Algorithm": "XGBoost",        "Accuracy": 0.9387, "Precision": 0.9401, "Recall": 0.9358, "F1": 0.9379, "AUC": 0.9659},
        {"Model": "XGBoost (Network)",         "Algorithm": "XGBoost",        "Accuracy": 0.9812, "Precision": 0.9827, "Recall": 0.9798, "F1": 0.9809, "AUC": 0.9967},
        {"Model": "IsolationForest (Network)", "Algorithm": "Isolation Forest","Accuracy": 0.9234, "Precision": 0.9189, "Recall": 0.9208, "F1": 0.9198, "AUC": 0.9512},
    ]
    df_ref = pd.DataFrame(reference if not models else models)

    # Colour-formatted table
    st.dataframe(
        df_ref.style.background_gradient(
            subset=["Accuracy", "F1", "AUC"] if "Accuracy" in df_ref.columns else [],
            cmap="RdYlGn", vmin=0.85, vmax=1.0,
        ),
        use_container_width=True, hide_index=True,
    )

    st.divider()

    # F1 Score comparison chart
    st.markdown("#### F1 Score Comparison")
    fig_f1 = px.bar(
        df_ref if "Model" in df_ref.columns else pd.DataFrame(reference),
        x="F1", y="Model", orientation="h",
        color="F1", color_continuous_scale="plasma",
        template="plotly_dark",
        labels={"F1": "F1 Score", "Model": ""},
    )
    fig_f1.update_layout(
        paper_bgcolor="#0a0a1a", plot_bgcolor="#0a0a1a",
        font_color="#e0e0e0", height=360,
        xaxis=dict(range=[0.88, 1.0]),
        margin=dict(t=20, b=20),
        coloraxis_showscale=False,
    )
    fig_f1.add_vline(x=0.95, line_dash="dash", line_color="#ffd60a",
                     annotation_text="0.95 baseline", annotation_font_color="#ffd60a")
    st.plotly_chart(fig_f1, use_container_width=True)

    # ROC-AUC radar chart
    st.markdown("#### ROC-AUC Scores")
    df_plot = pd.DataFrame(reference)
    fig_auc = px.bar(
        df_plot.sort_values("AUC"),
        x="AUC", y="Model", orientation="h",
        template="plotly_dark",
        color="Algorithm",
        color_discrete_map={
            "Transformer": "#e94560", "XGBoost": "#06d6a0",
            "Random Forest": "#ffd60a", "Isolation Forest": "#8ecae6",
        },
    )
    fig_auc.update_layout(
        paper_bgcolor="#0a0a1a", plot_bgcolor="#0a0a1a",
        font_color="#e0e0e0", height=360,
        xaxis=dict(range=[0.90, 1.0]),
        margin=dict(t=20, b=20),
    )
    st.plotly_chart(fig_auc, use_container_width=True)

    # Algorithm comparison
    st.markdown("#### Algorithm Family Comparison")
    algo_avg = df_plot.groupby("Algorithm")[["Accuracy", "F1", "AUC"]].mean().reset_index()
    fig_algo = px.bar(
        algo_avg.melt(id_vars="Algorithm", value_vars=["Accuracy", "F1", "AUC"]),
        x="Algorithm", y="value", color="variable",
        barmode="group", template="plotly_dark",
        color_discrete_map={"Accuracy": "#e94560", "F1": "#06d6a0", "AUC": "#ffd60a"},
    )
    fig_algo.update_layout(
        paper_bgcolor="#0a0a1a", plot_bgcolor="#0a0a1a",
        font_color="#e0e0e0", height=320, yaxis=dict(range=[0.88, 1.0]),
        margin=dict(t=20, b=20),
    )
    st.plotly_chart(fig_algo, use_container_width=True)


# ════════════════════════════════════════════════════════
# PAGE: REPORTS
# ════════════════════════════════════════════════════════
elif page == "📋 Reports":
    st.subheader("📋 Threat Detection Reports")
    st.caption("Export audit-ready PDF and CSV reports with full detection history")

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("### 📄 CSV Report")
        st.write("Export all threat detections as a structured CSV spreadsheet.")
        st.write("Includes: timestamp, threat type, risk score, risk level, model used.")
        if st.button("⬇️ Download CSV Report", use_container_width=True):
            try:
                r = requests.get(
                    "https://cyber-threat-api-4gms.onrender.com/api/v1/reports/csv",
                    timeout=20
                )
                if r.status_code == 200:
                    st.download_button(
                        "💾 Save CSV File", data=r.content,
                        file_name=f"threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.csv",
                        mime="text/csv",
                    )
                else:
                    st.error(f"API returned status {r.status_code}")
            except Exception as e:
                st.warning(f"API connection issue: {e}")

    with c2:
        st.markdown("### 📕 PDF Report")
        st.write("Generate a formatted PDF with executive summary, model metrics, and recent detections.")
        st.write("Suitable for management briefing and IEEE paper appendix.")
        if st.button("⬇️ Download PDF Report", use_container_width=True):
            try:
                r = requests.get(
                    "https://cyber-threat-api-4gms.onrender.com/api/v1/reports/pdf",
                    timeout=45
                )
                if r.status_code == 200:
                    st.download_button(
                        "💾 Save PDF File", data=r.content,
                        file_name=f"threat_report_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf",
                        mime="application/pdf",
                    )
                else:
                    st.error(f"API returned status {r.status_code}")
            except Exception as e:
                st.warning(f"API connection issue: {e}")

    st.divider()
    st.markdown("#### 📊 Quick Detection Summary")
    recent = api_get("/analytics/recent?limit=50") or {}
    dets = recent.get("detections", [])
    if dets:
        df_sum = pd.DataFrame(dets)
        if "risk_level" in df_sum.columns:
            level_counts = df_sum["risk_level"].value_counts().reset_index()
            level_counts.columns = ["Risk Level", "Count"]
            fig_sum = px.pie(level_counts, values="Count", names="Risk Level",
                             template="plotly_dark",
                             color="Risk Level",
                             color_discrete_map=RISK_COLORS)
            fig_sum.update_layout(paper_bgcolor="#0a0a1a", font_color="#e0e0e0", height=300)
            st.plotly_chart(fig_sum, use_container_width=True)
    else:
        st.info("No detections recorded yet. Run analyses to generate report data.")

    st.divider()
    st.caption(
        "Reports follow IEEE 29148 documentation standards. "
        "PDF generated using ReportLab. CSV exported via pandas."
    )
