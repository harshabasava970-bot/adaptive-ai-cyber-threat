"""
_full_redesign.py
=================
Complete, single-pass, syntax-verified UI redesign of src/dashboard/app.py.
All changes are purely visual. Zero functional modifications.
Aborts with restore if syntax fails at any step.
"""
import ast, re, pathlib, shutil, sys

SRC = pathlib.Path("src/dashboard/app.py")
BAK = pathlib.Path("src/dashboard/app.py.bak2")

src = SRC.read_text(encoding="utf-8")
shutil.copy(SRC, BAK)
print(f"Backup: {BAK}  ({src.count(chr(10))} lines)")

def check(label):
    try:
        ast.parse(src)
        print(f"  OK  {label}")
    except SyntaxError as e:
        print(f"  FAIL {label} — line {e.lineno}: {e.msg}")
        SRC.write_text(original, encoding="utf-8")
        print("  Restored original.")
        sys.exit(1)

original = src  # keep for emergency restore

# ══════════════════════════════════════════════════════════════════
# STEP 1 — Replace design tokens + full CSS block
# ══════════════════════════════════════════════════════════════════
# Find exact boundaries
tok_start = src.find("# ── Design tokens")
css_close = '""", unsafe_allow_html=True)'
css_end   = src.find(css_close, tok_start) + len(css_close)
assert tok_start != -1 and css_end > tok_start, "Could not find token+CSS block"

NEW = r'''# ── Design tokens ─────────────────────────────────────────────────
BG       = "#F4F6F9"
CARD     = "#FFFFFF"
SIDEBAR  = "#0D1B2A"
BORDER   = "#E0E7EF"
PRIMARY  = "#0E7490"
SUCCESS  = "#10B981"
WARN     = "#F59E0B"
CRIT     = "#EF4444"
INFO     = "#0E7490"
HIGH     = "#F97316"
TEXT     = "#1A202C"
MUTED    = "#6B7280"
SUBTLE   = "#9CA3AF"
PURPLE   = "#818CF8"
ACCENT   = "#10B981"
M_PHISH  = "#E11D48"
M_URL    = "#0D9488"
M_LOGIN  = "#7C3AED"
M_NET    = "#059669"
M_FUSION = "#D97706"
M_XAI    = "#4F46E5"

RISK_CLR = {"critical":"#EF4444","high":"#F97316","medium":"#F59E0B",
            "low":"#10B981","info":"#0E7490"}
RISK_BG  = {"critical":"#FFF1F2","high":"#FFF7ED","medium":"#FFFBEB",
            "low":"#F0FDF4","info":"#ECFEFF"}
RISK_ICO = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","info":"🔵"}

# ══════════════════════════════════════════════════════════════════
# GLOBAL CSS — Premium Cybersecurity Theme
# ══════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html,body,.stApp{
  background:#F4F6F9 !important;color:#1A202C !important;
  font-family:'Plus Jakarta Sans',-apple-system,sans-serif !important;
  font-size:14px !important;line-height:1.65 !important;-webkit-font-smoothing:antialiased;
}
section[data-testid="stSidebar"]{
  background:#0D1B2A !important;border-right:none !important;
  box-shadow:4px 0 24px rgba(0,0,0,0.2) !important;
}
section[data-testid="stSidebar"]>div{padding:0 !important;}
.block-container{padding:0 2.5rem 4rem 2.5rem !important;max-width:100% !important;}
h1{font-size:1.6rem !important;font-weight:800 !important;color:#1A202C !important;letter-spacing:-0.5px !important;}
h2{font-size:1.2rem !important;font-weight:700 !important;color:#1A202C !important;}
h3{font-size:1rem !important;font-weight:600 !important;color:#1A202C !important;}
h4{font-size:0.75rem !important;font-weight:700 !important;color:#6B7280 !important;text-transform:uppercase !important;letter-spacing:1px !important;}
p{color:#1A202C !important;}
label{color:#374151 !important;font-weight:500 !important;}
div[data-testid="metric-container"]{
  background:#FFFFFF !important;border:1px solid #E0E7EF !important;
  border-radius:14px !important;padding:20px !important;
  box-shadow:0 1px 6px rgba(0,0,0,0.05) !important;
  transition:transform 0.2s,box-shadow 0.2s !important;
}
div[data-testid="metric-container"]:hover{
  transform:translateY(-2px) !important;
  box-shadow:0 8px 24px rgba(14,116,144,0.14) !important;
  border-color:#0E7490 !important;
}
div[data-testid="metric-container"] [data-testid="stMetricLabel"]>div{
  font-size:0.68rem !important;font-weight:700 !important;
  color:#6B7280 !important;text-transform:uppercase !important;letter-spacing:1px !important;
}
div[data-testid="metric-container"] [data-testid="stMetricValue"]>div{
  font-size:1.75rem !important;font-weight:800 !important;color:#1A202C !important;
}
.stButton>button{
  background:#0E7490 !important;color:#fff !important;border:none !important;
  border-radius:10px !important;padding:10px 22px !important;font-weight:600 !important;
  font-size:0.84rem !important;box-shadow:0 2px 8px rgba(14,116,144,0.25) !important;
  transition:background 0.15s,transform 0.15s !important;width:100% !important;
}
.stButton>button:hover{background:#0C6480 !important;transform:translateY(-1px) !important;}
.stButton>button:disabled{background:#D1D5DB !important;color:#9CA3AF !important;}
.stTextInput>div>div>input,
.stTextArea>div>div>textarea,
.stNumberInput>div>div>input{
  background:#FFFFFF !important;color:#1A202C !important;
  border:1.5px solid #D1D5DB !important;border-radius:10px !important;
  padding:10px 14px !important;font-size:0.87rem !important;
  transition:border-color 0.2s,box-shadow 0.2s !important;
}
.stTextInput>div>div>input:focus,
.stTextArea>div>div>textarea:focus{
  border-color:#0E7490 !important;
  box-shadow:0 0 0 3px rgba(14,116,144,0.12) !important;
}
.stTextInput label,.stTextArea label,.stNumberInput label,
.stSelectbox label,.stMultiSelect label,.stSlider label,.stRadio label,.stCheckbox label{
  color:#374151 !important;font-weight:500 !important;font-size:0.84rem !important;
}
.stSelectbox>div>div,.stMultiSelect>div>div{
  background:#FFFFFF !important;border:1.5px solid #D1D5DB !important;
  border-radius:10px !important;color:#1A202C !important;
}
.stMultiSelect [data-baseweb="tag"]{background:#DCFCE7 !important;color:#065F46 !important;}
.stTabs [data-baseweb="tab-list"]{
  background:#EEF2F7 !important;border-radius:12px !important;
  padding:4px !important;border:1px solid #E0E7EF !important;
}
.stTabs [data-baseweb="tab"]{
  background:transparent !important;border-radius:9px !important;
  color:#6B7280 !important;font-weight:500 !important;padding:8px 18px !important;
}
.stTabs [aria-selected="true"]{
  background:#FFFFFF !important;color:#1A202C !important;
  font-weight:700 !important;box-shadow:0 1px 4px rgba(0,0,0,0.08) !important;
}
.stDataFrame{border-radius:14px !important;overflow:hidden !important;
  box-shadow:0 1px 6px rgba(0,0,0,0.05) !important;}
.stDataFrame thead tr th{
  background:#F8FAFC !important;color:#1A202C !important;
  font-weight:700 !important;font-size:0.74rem !important;
  text-transform:uppercase !important;letter-spacing:0.8px !important;
  padding:10px 14px !important;border-bottom:1px solid #E0E7EF !important;
}
.stDataFrame tbody tr td{
  background:#FFFFFF !important;color:#374151 !important;
  font-size:0.84rem !important;padding:9px 14px !important;
  border-bottom:1px solid #F3F4F6 !important;
}
.stDataFrame tbody tr:hover td{background:#F8FAFC !important;}
.streamlit-expanderHeader{
  background:#FFFFFF !important;border:1px solid #E0E7EF !important;
  border-radius:12px !important;padding:12px 18px !important;
  color:#1A202C !important;font-weight:600 !important;
}
.streamlit-expanderContent{
  background:#F8FAFC !important;border:1px solid #E0E7EF !important;
  border-top:none !important;border-radius:0 0 12px 12px !important;padding:16px !important;
}
.stSuccess>div{background:#F0FDF4 !important;border:1px solid #A7F3D0 !important;border-radius:10px !important;color:#065F46 !important;}
.stWarning>div{background:#FFFBEB !important;border:1px solid #FDE68A !important;border-radius:10px !important;color:#92400E !important;}
.stError>div{background:#FFF1F2 !important;border:1px solid #FECDD3 !important;border-radius:10px !important;color:#9F1239 !important;}
.stInfo>div{background:#ECFEFF !important;border:1px solid #A5F3FC !important;border-radius:10px !important;color:#164E63 !important;}
.stProgress>div>div{background:#0E7490 !important;border-radius:4px !important;}
.stProgress>div{background:#E5E7EB !important;border-radius:4px !important;}
hr{border-color:#E0E7EF !important;margin:20px 0 !important;}
::-webkit-scrollbar{width:5px;height:5px;}
::-webkit-scrollbar-track{background:#F4F6F9;}
::-webkit-scrollbar-thumb{background:#CBD5E1;border-radius:3px;}
::-webkit-scrollbar-thumb:hover{background:#94A3B8;}
#MainMenu,footer,header{visibility:hidden !important;height:0 !important;}
.viewerBadge_container__1QSob{display:none !important;}
[data-testid="stToolbar"]{display:none !important;}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:translateY(0);}}
.fade-in{animation:fadeIn 0.4s ease-out both;}
</style>
""", unsafe_allow_html=True)'''

src = src[:tok_start] + NEW + src[css_end:]
check("Step 1 — tokens + CSS")

# ══════════════════════════════════════════════════════════════════
# STEP 2 — Replace kpi_card
# ══════════════════════════════════════════════════════════════════
kpi_s = src.find("def kpi_card(")
kpi_e = src.find("\ndef ", kpi_s + 10)
assert kpi_s != -1 and kpi_e != -1

NEW_KPI = '''def kpi_card(icon: str, label: str, value: str, color: str = "",
             sub: str = "") -> str:
    color = color or "#0E7490"
    sub_html = f"<div style='color:#6B7280;font-size:0.71rem;margin-top:5px'>{sub}</div>" if sub else ""
    return f"""
    <div style='background:#FFFFFF;border-radius:16px;border:1px solid #E0E7EF;
         padding:22px 20px;box-shadow:0 1px 6px rgba(0,0,0,0.05);height:100%;
         transition:transform 0.2s,box-shadow 0.2s,border-color 0.2s;cursor:default;'>
      <div style='display:flex;align-items:center;gap:10px;margin-bottom:12px'>
        <div style='font-size:1.05rem;background:{color}18;border-radius:10px;
                    width:38px;height:38px;display:flex;align-items:center;
                    justify-content:center;flex-shrink:0;border:1px solid {color}22'>
          {icon}</div>
        <span style='color:#6B7280;font-size:0.68rem;font-weight:700;
                     text-transform:uppercase;letter-spacing:1px'>{label}</span>
      </div>
      <div style='color:{color};font-size:1.75rem;font-weight:800;line-height:1'>{value}</div>
      {sub_html}
    </div>"""
'''
src = src[:kpi_s] + NEW_KPI + src[kpi_e:]
check("Step 2 — kpi_card")

# ══════════════════════════════════════════════════════════════════
# STEP 3 — Replace section_hdr
# ══════════════════════════════════════════════════════════════════
shdr_s = src.find("def section_hdr(")
shdr_e = src.find("\ndef ", shdr_s + 10)
assert shdr_s != -1 and shdr_e != -1

NEW_SHDR = '''def section_hdr(icon: str, title: str, sub: str = "") -> None:
    sub_html = f"<div style='color:rgba(248,250,252,0.65);font-size:0.84rem;margin-top:5px'>{sub}</div>" if sub else ""
    st.markdown(f"""
    <div style='background:linear-gradient(135deg,#0D1B2A 0%,#0E3A4A 100%);
         border-radius:18px;padding:28px 32px;margin-bottom:24px;
         box-shadow:0 6px 28px rgba(13,27,42,0.18);' class='fade-in'>
      <div style='display:flex;align-items:center;gap:14px'>
        <div style='background:rgba(14,116,144,0.3);border:1px solid rgba(14,116,144,0.5);
                    border-radius:14px;width:50px;height:50px;display:flex;
                    align-items:center;justify-content:center;font-size:1.4rem;flex-shrink:0'>
          {icon}</div>
        <div>
          <div style='font-size:1.3rem;font-weight:800;color:#F8FAFC;letter-spacing:-0.3px'>{title}</div>
          {sub_html}
        </div>
      </div>
    </div>""", unsafe_allow_html=True)
'''
src = src[:shdr_s] + NEW_SHDR + src[shdr_e:]
check("Step 3 — section_hdr")

# ══════════════════════════════════════════════════════════════════
# STEP 4 — Replace sticky header (api_ok block at module level)
# ══════════════════════════════════════════════════════════════════
# Find the exact existing header — look for the PROFESSIONAL HEADER comment
hdr_comment = "# ══════════════════════════════════════════════════════════════════\n# PROFESSIONAL HEADER"
hdr_s = src.find(hdr_comment)
if hdr_s == -1:
    # fallback: find api_ok = api_health() at module level
    hdr_s = src.find("\napi_ok = api_health()")
    hdr_s += 1  # skip leading newline
hdr_e_marker = '""", unsafe_allow_html=True)\n\n# ══'
hdr_e = src.find(hdr_e_marker, hdr_s)
assert hdr_s != -1 and hdr_e != -1, f"Could not find header block (hdr_s={hdr_s})"
hdr_e += len(hdr_e_marker) - len("\n\n# ══")  # keep the \n\n# ══ for next section

# Build header with NO inline ternaries inside HTML strings
NEW_HDR = '''# ══════════════════════════════════════════════════════════════════
# PROFESSIONAL HEADER
# ══════════════════════════════════════════════════════════════════
api_ok = api_health()
S      = stats()

_dot   = "#10B981" if api_ok else "#F59E0B"
_glow  = "#10B98180" if api_ok else "#F59E0B80"
_pbg   = "rgba(16,185,129,0.15)" if api_ok else "rgba(245,158,11,0.15)"
_pbdr  = "rgba(16,185,129,0.3)" if api_ok else "rgba(245,158,11,0.3)"
_ptxt  = "API Online" if api_ok else "API Waking"
_pclr  = "#10B981" if api_ok else "#F59E0B"
_htime = (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%d %b %Y · %H:%M")

st.markdown(f"""
<div style='background:#0D1B2A;border-bottom:1px solid rgba(255,255,255,0.08);
     padding:14px 32px;margin:0 -2.5rem 0;position:sticky;top:0;z-index:100;
     box-shadow:0 2px 16px rgba(0,0,0,0.25);'>
  <div style='display:flex;justify-content:space-between;align-items:center'>
    <div style='display:flex;align-items:center;gap:14px'>
      <div style='background:linear-gradient(135deg,#0E7490,#10B981);border-radius:11px;
                  width:38px;height:38px;display:flex;align-items:center;justify-content:center;
                  font-size:1.1rem;box-shadow:0 3px 10px rgba(14,116,144,0.4)'>🛡️</div>
      <div>
        <div style='font-size:0.96rem;font-weight:800;color:#F8FAFC'>CyberShield AI</div>
        <div style='font-size:0.63rem;color:rgba(248,250,252,0.5);margin-top:1px'>
          Multi-Source Threat Detection · B.Tech Capstone 2026–2027</div>
      </div>
    </div>
    <div style='display:flex;align-items:center;gap:14px'>
      <div>
        <div style='display:flex;align-items:center;gap:6px;justify-content:flex-end;margin-bottom:3px'>
          <div style='width:7px;height:7px;border-radius:50%;background:{_dot};
                      box-shadow:0 0 7px {_glow}'></div>
          <span style='background:{_pbg};color:{_pclr};border:1px solid {_pbdr};
                       border-radius:20px;padding:2px 10px;font-size:0.71rem;font-weight:600'>
            {_ptxt}</span>
        </div>
        <div style='color:rgba(248,250,252,0.4);font-size:0.62rem;text-align:right;
                    font-family:"JetBrains Mono",monospace'>{_htime} IST</div>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)
'''
src = src[:hdr_s] + NEW_HDR + src[hdr_e:]
check("Step 4 — header")

# ══════════════════════════════════════════════════════════════════
# STEP 5 — Replace sidebar brand block
# ══════════════════════════════════════════════════════════════════
# Find "with st.sidebar:" and the brand markdown
SB_OPEN = "with st.sidebar:"
sb_pos  = src.find(SB_OPEN)
# Find the brand div block
brand_s = src.find('    st.markdown("""', sb_pos)
brand_e = src.find('""", unsafe_allow_html=True)', brand_s) + len('""", unsafe_allow_html=True)')
assert brand_s != -1 and brand_e > brand_s

NEW_BRAND = '''    st.markdown("""
    <div style='padding:24px 20px 18px;border-bottom:1px solid rgba(255,255,255,0.08)'>
      <div style='display:flex;align-items:center;gap:11px'>
        <div style='background:linear-gradient(135deg,#0E7490,#10B981);border-radius:10px;
                    width:36px;height:36px;display:flex;align-items:center;justify-content:center;
                    font-size:1.1rem;box-shadow:0 3px 8px rgba(14,116,144,0.4)'>🛡️</div>
        <div>
          <div style='color:#F8FAFC;font-size:0.9rem;font-weight:800'>CyberShield AI</div>
          <div style='color:rgba(248,250,252,0.4);font-size:0.59rem;margin-top:1px'>Threat Detection Platform</div>
        </div>
      </div>
    </div>""", unsafe_allow_html=True)'''

src = src[:brand_s] + NEW_BRAND + src[brand_e:]
check("Step 5 — sidebar brand")

# ══════════════════════════════════════════════════════════════════
# STEP 6 — Update sidebar nav group headers (colour only)
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "        st.markdown(f\"\"\"\n        <div style='padding:10px 18px 4px;color:rgba(248,250,252,0.35);font-size:0.59rem;\n                    text-transform:uppercase;letter-spacing:1.6px;font-weight:700'>\n          {grp}</div>\"\"\", unsafe_allow_html=True)",
    "        st.markdown(f\"\"\"\n        <div style='padding:10px 18px 4px;color:rgba(248,250,252,0.35);font-size:0.59rem;\n                    text-transform:uppercase;letter-spacing:1.5px;font-weight:700'>\n          {grp}</div>\"\"\", unsafe_allow_html=True)"
)
# Update nav item active state colours
src = src.replace(
    "            clr_act, bg_act = (\"#10B981\",\"rgba(16,185,129,0.15)\") if active else (\"#F8FAFC\",\"transparent\")",
    "            clr_act = \"#10B981\" if active else \"#E2E8F0\"\n            bg_act  = \"rgba(16,185,129,0.12)\" if active else \"transparent\""
)
src = src.replace(
    "            bl_act  = \"#10B981\" if active else \"transparent\"",
    "            bl_act = \"#10B981\" if active else \"transparent\""
)
# Fix the nav item HTML to use the correct variable
src = src.replace(
    "<span style='color:{clr_act};font-weight:{fw_act};font-size:0.82rem'>",
    "<span style='color:{clr_act};font-weight:{fw_act};font-size:0.83rem'>"
)
check("Step 6 — nav colours")

# ══════════════════════════════════════════════════════════════════
# STEP 7 — Update sidebar session metrics + API status to navy theme
# ══════════════════════════════════════════════════════════════════
# Session metrics card
src = src.replace(
    "    <div style='margin:10px 12px 6px;padding:14px;background:#F8FAFC;\n         border-radius:12px;border:1px solid #E2E8F0'>",
    "    <div style='margin:10px 12px 6px;padding:14px;background:rgba(255,255,255,0.06);\n         border-radius:12px;border:1px solid rgba(255,255,255,0.1)'>"
)
src = src.replace(
    "font-size:0.62rem;text-transform:uppercase;letter-spacing:1px;font-weight:700;margin-bottom:10px'>Session Metrics</div>",
    "font-size:0.62rem;text-transform:uppercase;letter-spacing:1px;font-weight:700;margin-bottom:10px;color:rgba(248,250,252,0.5)'>Session Metrics</div>"
)
# Mini stat cells inside session widget
for old_mini, new_mini in [
    ("background:#FFFFFF;border-radius:8px;border:1px solid #E2E8F0'>",
     "background:rgba(255,255,255,0.08);border-radius:8px;border:1px solid rgba(255,255,255,0.1)'>"),
]:
    src = src.replace(old_mini, new_mini)
# SCANS / THREATS labels
for lbl in ["SCANS", "THREATS", "SPEED"]:
    src = src.replace(
        f"font-size:0.59rem;font-weight:600;text-transform:uppercase'>{lbl}</div>",
        f"font-size:0.59rem;font-weight:600;text-transform:uppercase;color:rgba(248,250,252,0.4)'>{lbl}</div>"
    )
# API status card
src = src.replace(
    "    <div style='margin:0 12px 6px;padding:10px 14px;background:rgba(255,255,255,0.06);\n         border-radius:10px;border:1px solid rgba(255,255,255,0.1)'>",
    "    <div style='margin:0 12px 6px;padding:10px 14px;background:rgba(255,255,255,0.05);\n         border-radius:10px;border:1px solid rgba(255,255,255,0.09)'>"
)
# API status text colour
src = src.replace(
    "<span style='color:#F8FAFC;font-size:0.76rem;font-weight:600'>API {status_text}</span>",
    "<span style='color:rgba(248,250,252,0.85);font-size:0.76rem;font-weight:600'>API {status_text}</span>"
)
check("Step 7 — sidebar widget colours")

# ══════════════════════════════════════════════════════════════════
# STEP 8 — Footer
# ══════════════════════════════════════════════════════════════════
# Find the last st.markdown call (footer)
foot_s = src.rfind("st.markdown(\"\"\"")
foot_e = src.rfind('""", unsafe_allow_html=True)')
if foot_s != -1 and foot_e > foot_s:
    NEW_FOOTER = '''st.markdown("""
<div style='background:#0D1B2A;border-top:1px solid rgba(255,255,255,0.07);
     padding:18px 32px;margin:0 -2.5rem -4rem;'>
  <div style='display:flex;justify-content:space-between;align-items:center;
              flex-wrap:wrap;gap:12px'>
    <div style='display:flex;align-items:center;gap:11px'>
      <div style='background:linear-gradient(135deg,#0E7490,#10B981);border-radius:9px;
                  width:30px;height:30px;display:flex;align-items:center;
                  justify-content:center;font-size:0.95rem'>🛡️</div>
      <div>
        <div style='color:#F8FAFC;font-weight:700;font-size:0.82rem'>CyberShield AI</div>
        <div style='color:rgba(248,250,252,0.4);font-size:0.62rem;margin-top:1px'>
          Adaptive Explainable Multi-Source Cyber Threat Detection</div>
      </div>
    </div>
    <div style='color:rgba(248,250,252,0.3);font-size:0.66rem;text-align:center'>
      Python · FastAPI · Streamlit · DistilBERT · XGBoost · Isolation Forest · SHAP · LIME
    </div>
    <div style='text-align:right'>
      <div style='color:rgba(248,250,252,0.35);font-size:0.62rem'>B.Tech Capstone 2026–2027</div>
      <div style='color:rgba(248,250,252,0.2);font-size:0.6rem;margin-top:2px'>
        Designed with requirements engineering &amp; explainability principles</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)'''
    src = src[:foot_s] + NEW_FOOTER
    check("Step 8 — footer")

# ══════════════════════════════════════════════════════════════════
# STEP 9 — loading_card
# ══════════════════════════════════════════════════════════════════
OLD_LOAD = '''    ph.markdown(f"""
    <div style='background:{CARD};border:1px solid {PRIMARY}35;border-radius:14px;
         padding:36px;text-align:center;margin:12px 0'>
      <div style='font-size:2rem;margin-bottom:10px'>⚡</div>
      <div style='color:{PRIMARY};font-size:1rem;font-weight:700;margin-bottom:5px'>
        AI Engine Processing...</div>
      <div style='color:{MUTED};font-size:0.82rem'>
        Running multi-signal analysis · Please wait</div>
    </div>""", unsafe_allow_html=True)'''

NEW_LOAD = '''    ph.markdown("""
    <div style='background:#FFFFFF;border:1px solid #E0E7EF;border-radius:16px;
         padding:40px;text-align:center;margin:12px 0;
         box-shadow:0 4px 20px rgba(14,116,144,0.08)'>
      <div style='width:48px;height:48px;border-radius:50%;
                  background:linear-gradient(135deg,#0E7490,#10B981);
                  display:flex;align-items:center;justify-content:center;
                  font-size:1.4rem;margin:0 auto 14px;
                  box-shadow:0 4px 14px rgba(14,116,144,0.3)'>⚡</div>
      <div style='color:#0E7490;font-size:1rem;font-weight:700;margin-bottom:6px'>
        AI Engine Processing...</div>
      <div style='color:#6B7280;font-size:0.82rem'>
        Running multi-signal analysis · Please wait</div>
    </div>""", unsafe_allow_html=True)'''

if OLD_LOAD in src:
    src = src.replace(OLD_LOAD, NEW_LOAD)
    check("Step 9 — loading_card")
else:
    print("  SKIP Step 9 — loading_card pattern not found (already updated)")

# ══════════════════════════════════════════════════════════════════
# STEP 10 — Chart font/grid colours for light background
# ══════════════════════════════════════════════════════════════════
for old_c, new_c in [
    ('color="#CBD5E1", size=11)', 'color="#6B7280", size=11)'),
    ('color="#CBD5E1", size=10)', 'color="#6B7280", size=10)'),
    ('color=MUTED, size=11)',     'color="#6B7280", size=11)'),
    ('color=MUTED)',              'color="#6B7280")'),
    ('color=TEXT, size=11)',      'color="#1A202C", size=11)'),
    ('color=TEXT)',               'color="#1A202C")'),
    ('gridcolor=BORDER',          'gridcolor="#E5E7EB"'),
    ('tickfont=dict(color="#CBD5E1")',  'tickfont=dict(color="#6B7280")'),
    ('tickfont=dict(color=MUTED)',      'tickfont=dict(color="#6B7280")'),
    ('tickfont=dict(color=TEXT)',       'tickfont=dict(color="#1A202C")'),
    ('annotation_font=dict(color=CRIT,', 'annotation_font=dict(color="#EF4444",'),
    ('annotation_font=dict(color=HIGH,', 'annotation_font=dict(color="#F97316",'),
    ('annotation_font=dict(color=WARN,', 'annotation_font=dict(color="#F59E0B",'),
]:
    src = src.replace(old_c, new_c)
check("Step 10 — chart colours")

# ══════════════════════════════════════════════════════════════════
# STEP 11 — Timeline: light table header + white rows
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "         gap:8px;padding:8px 14px;background:{SIDEBAR};border-radius:8px;margin-bottom:4px'>",
    "         gap:8px;padding:9px 14px;background:#EEF2F7;border-radius:10px;margin-bottom:6px;\n         border:1px solid #E0E7EF;'>"
)
src = src.replace(
    "             margin-bottom:4px;border:1px solid {BORDER};border-left:3px solid {color};",
    "             margin-bottom:5px;border:1px solid #E0E7EF;border-left:3px solid {color};"
)
src = src.replace(
    "             gap:8px;padding:10px 14px;background:{CARD};border-radius:9px;",
    "             gap:8px;padding:10px 14px;background:#FFFFFF;border-radius:11px;"
)
check("Step 11 — timeline rows")

# ══════════════════════════════════════════════════════════════════
# STEP 12 — Empty state cards
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "border:2px dashed {BORDER};border-radius:14px;",
    "border:2px dashed #D1D5DB;border-radius:14px;"
)
check("Step 12 — empty states")

# ══════════════════════════════════════════════════════════════════
# STEP 13 — About page hero (dark banner)
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "    <div style='background:linear-gradient(135deg,{PRIMARY}18,{INFO}12);\n         border:1px solid {PRIMARY}35;border-radius:16px;\n         padding:28px 32px;margin-bottom:24px;\n         box-shadow:0 6px 24px rgba(37,99,235,0.15)'>",
    "    <div style='background:linear-gradient(135deg,#0D1B2A 0%,#0E3A4A 100%);\n         border:none;border-radius:18px;\n         padding:30px 36px;margin-bottom:24px;\n         box-shadow:0 8px 32px rgba(13,27,42,0.18)'>"
)
# about title text colour
src = src.replace(
    "        <div style='font-size:1.4rem;font-weight:900;color:{TEXT};margin-bottom:6px'>",
    "        <div style='font-size:1.3rem;font-weight:800;color:#F8FAFC;margin-bottom:8px;line-height:1.3'>"
)
src = src.replace(
    "      <div style='color:{INFO};font-size:0.88rem;font-weight:600;margin-bottom:12px'>",
    "      <div style='color:#10B981;font-size:0.86rem;font-weight:600;margin-bottom:12px'>"
)
src = src.replace(
    "        Designed with requirements engineering, software testing, and AI explainability principles.\n      </div>",
    "        Designed with requirements engineering, software testing, and AI explainability principles.\n      </div>".replace("</div>", "</div>")
)
check("Step 13 — about hero")

# ══════════════════════════════════════════════════════════════════
# STEP 14 — Detection intro cards (coloured left borders)
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "    <div style='background:{CARD};border:1px solid {BORDER};border-radius:16px;\n         padding:26px 30px 22px;margin-bottom:22px;\n         box-shadow:0 4px 20px rgba(0,0,0,0.4)'>",
    "    <div style='background:#FFFFFF;border:1px solid #E0E7EF;border-left:4px solid #E11D48;\n         border-radius:16px;padding:26px 30px 22px;margin-bottom:22px;\n         box-shadow:0 2px 12px rgba(0,0,0,0.05)'>"
)
src = src.replace(
    "    <div style='background:{CARD};border:1px solid {BORDER};border-radius:16px;\n         padding:20px 24px;margin-bottom:18px;box-shadow:0 4px 16px rgba(0,0,0,0.3)'>",
    "    <div style='background:#FFFFFF;border:1px solid #E0E7EF;border-left:4px solid #0D9488;\n         border-radius:16px;padding:20px 24px;margin-bottom:18px;\n         box-shadow:0 2px 12px rgba(0,0,0,0.05)'>"
)
src = src.replace(
    "border-radius:14px;\n         padding:16px 20px;margin-bottom:18px;border-left:3px solid {WARN};",
    "border-radius:14px;\n         padding:16px 20px;margin-bottom:18px;border-left:4px solid #7C3AED;"
)
src = src.replace(
    "border-radius:14px;\n         padding:16px 20px;margin-bottom:18px;border-left:3px solid {INFO};",
    "border-radius:14px;\n         padding:16px 20px;margin-bottom:18px;border-left:4px solid #059669;"
)
check("Step 14 — detection intro cards")

# ══════════════════════════════════════════════════════════════════
# STEP 15 — Remaining {CARD}/{BORDER}/{SIDEBAR} in HTML strings
# ══════════════════════════════════════════════════════════════════
for old, new in [
    ("background:{CARD};border-radius:12px;border:1px solid {BORDER};",
     "background:#FFFFFF;border-radius:12px;border:1px solid #E0E7EF;"),
    ("background:{CARD};border-radius:14px;border:1px solid {BORDER};",
     "background:#FFFFFF;border-radius:14px;border:1px solid #E0E7EF;"),
    ("background:{CARD};border-radius:16px;border:1px solid {BORDER};",
     "background:#FFFFFF;border-radius:16px;border:1px solid #E0E7EF;"),
    ("background:{CARD};border-radius:9px;",
     "background:#FFFFFF;border-radius:9px;"),
    ("background:{BG};border-radius:",
     "background:#F4F6F9;border-radius:"),
    ("border:1px solid {BORDER}'",
     "border:1px solid #E0E7EF'"),
    ("border:1px solid {BORDER};",
     "border:1px solid #E0E7EF;"),
]:
    src = src.replace(old, new)
check("Step 15 — remaining card/border literals")

# ══════════════════════════════════════════════════════════════════
# FINAL SYNTAX CHECK + WRITE
# ══════════════════════════════════════════════════════════════════
try:
    ast.parse(src)
    print("\n✅ FINAL SYNTAX CHECK PASSED")
except SyntaxError as e:
    print(f"\n❌ FINAL SYNTAX ERROR line {e.lineno}: {e.msg}")
    SRC.write_text(original, encoding="utf-8")
    print("Restored original.")
    sys.exit(1)

SRC.write_text(src, encoding="utf-8")
print(f"✅ Written: {src.count(chr(10))} lines")
print(f"   File: {SRC}")
