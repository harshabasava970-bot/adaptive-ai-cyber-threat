"""
Apply complete UI/UX redesign to src/dashboard/app.py.
Replaces design tokens + CSS block + all page section headers.
Zero functional changes — only visual/layout.
"""
import re
import pathlib
import shutil

SRC = pathlib.Path("src/dashboard/app.py")
BAK = pathlib.Path("src/dashboard/app.py.bak")

# ── Backup ─────────────────────────────────────────────────────────
shutil.copy(SRC, BAK)
print(f"Backup: {BAK}")

src = SRC.read_text(encoding="utf-8")
original_lines = src.count("\n")
print(f"Original: {original_lines} lines")

# ══════════════════════════════════════════════════════════════════
# 1. REPLACE DESIGN TOKENS
# ══════════════════════════════════════════════════════════════════
NEW_TOKENS = '''# ── Design tokens — Premium Cybersecurity Theme ──────────────────
# Backgrounds
BG       = "#F4F6F9"      # soft off-white page bg
CARD     = "#FFFFFF"      # pure white cards
SIDEBAR  = "#0D1B2A"      # deep midnight navy sidebar
SIDEBAR2 = "#1A2B3C"      # slightly lighter sidebar hover
BORDER   = "#E0E7EF"      # subtle border
SECTION  = "#EEF2F7"      # section background tint

# Brand / Accents
PRIMARY  = "#0E7490"      # muted teal
PRIMARY2 = "#0C6480"      # darker teal hover
ACCENT   = "#10B981"      # emerald accent
ACCENT2  = "#059669"      # deeper emerald
LAVENDER = "#818CF8"      # soft lavender highlight
NAVY     = "#0D1B2A"      # deep navy text / sidebar

# Status
SUCCESS  = "#10B981"      # emerald green
WARN     = "#F59E0B"      # amber
CRIT     = "#EF4444"      # red
INFO     = "#0E7490"      # teal
HIGH     = "#F97316"      # orange
PURPLE   = "#818CF8"      # lavender

# Text
TEXT     = "#1A202C"      # near-black primary text
MUTED    = "#6B7280"      # medium grey muted
SUBTLE   = "#9CA3AF"      # lighter grey subtle
TEXT_INV = "#F8FAFC"      # inverted text on dark bg

# Per-module accents
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
'''

NEW_CSS = '''# ══════════════════════════════════════════════════════════════════
# GLOBAL CSS — Premium Cybersecurity SaaS Design
# ══════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=Manrope:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ── Reset ── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}

/* ── Root ── */
html,body,.stApp{
  background:#F4F6F9 !important;
  color:#1A202C !important;
  font-family:\'Plus Jakarta Sans\',\'Manrope\',-apple-system,BlinkMacSystemFont,sans-serif !important;
  font-size:14px !important;
  line-height:1.65 !important;
  -webkit-font-smoothing:antialiased;
}

/* ── Sidebar — deep navy ── */
section[data-testid="stSidebar"]{
  background:#0D1B2A !important;
  border-right:none !important;
  box-shadow:4px 0 24px rgba(0,0,0,0.18) !important;
}
section[data-testid="stSidebar"]>div{padding:0 !important;}

/* ── Main container ── */
.block-container{padding:0 2.5rem 4rem 2.5rem !important;max-width:100% !important;}

/* ── Typography ── */
h1{font-size:1.65rem !important;font-weight:800 !important;color:#1A202C !important;letter-spacing:-0.5px !important;line-height:1.2 !important;}
h2{font-size:1.25rem !important;font-weight:700 !important;color:#1A202C !important;}
h3{font-size:1rem !important;font-weight:600 !important;color:#1A202C !important;}
h4{font-size:0.75rem !important;font-weight:700 !important;color:#6B7280 !important;text-transform:uppercase !important;letter-spacing:1px !important;}
p{color:#1A202C !important;}
label{color:#374151 !important;font-weight:500 !important;}
code,pre,[class*="mono"]{font-family:\'JetBrains Mono\',monospace !important;}

/* ── Metric cards ── */
div[data-testid="metric-container"]{
  background:#FFFFFF !important;
  border:1px solid #E0E7EF !important;
  border-radius:14px !important;
  padding:20px !important;
  box-shadow:0 1px 6px rgba(0,0,0,0.05),0 4px 16px rgba(0,0,0,0.04) !important;
  transition:transform 0.2s ease,box-shadow 0.2s ease !important;
}
div[data-testid="metric-container"]:hover{
  transform:translateY(-2px) !important;
  box-shadow:0 8px 28px rgba(14,116,144,0.14) !important;
  border-color:#0E7490 !important;
}
div[data-testid="metric-container"] [data-testid="stMetricLabel"]>div{
  font-size:0.68rem !important;font-weight:700 !important;
  color:#6B7280 !important;text-transform:uppercase !important;letter-spacing:1.1px !important;
}
div[data-testid="metric-container"] [data-testid="stMetricValue"]>div{
  font-size:1.75rem !important;font-weight:800 !important;color:#1A202C !important;
}

/* ── Buttons ── */
.stButton>button{
  background:#0E7490 !important;color:#fff !important;border:none !important;
  border-radius:10px !important;padding:10px 22px !important;font-weight:600 !important;
  font-size:0.84rem !important;font-family:\'Plus Jakarta Sans\',sans-serif !important;
  box-shadow:0 2px 8px rgba(14,116,144,0.25) !important;
  transition:background 0.15s,transform 0.15s,box-shadow 0.15s !important;
  width:100% !important;cursor:pointer !important;letter-spacing:0.1px !important;
}
.stButton>button:hover{
  background:#0C6480 !important;transform:translateY(-1px) !important;
  box-shadow:0 6px 18px rgba(14,116,144,0.35) !important;
}
.stButton>button:disabled{background:#D1D5DB !important;color:#9CA3AF !important;box-shadow:none !important;}

/* ── Inputs ── */
.stTextInput>div>div>input,
.stTextArea>div>div>textarea,
.stNumberInput>div>div>input{
  background:#FFFFFF !important;color:#1A202C !important;
  border:1.5px solid #D1D5DB !important;border-radius:10px !important;
  padding:10px 14px !important;font-family:\'Plus Jakarta Sans\',sans-serif !important;
  font-size:0.87rem !important;transition:border-color 0.2s,box-shadow 0.2s !important;
}
.stTextInput>div>div>input:focus,
.stTextArea>div>div>textarea:focus{
  border-color:#0E7490 !important;box-shadow:0 0 0 3px rgba(14,116,144,0.12) !important;
  outline:none !important;
}
.stTextInput label,.stTextArea label,.stNumberInput label,
.stSelectbox label,.stMultiSelect label,.stSlider label,
.stRadio label,.stCheckbox label{
  color:#374151 !important;font-weight:500 !important;font-size:0.84rem !important;
}
.stSelectbox>div>div,.stMultiSelect>div>div{
  background:#FFFFFF !important;border:1.5px solid #D1D5DB !important;
  border-radius:10px !important;color:#1A202C !important;
}
.stMultiSelect [data-baseweb="tag"]{background:#DCFCE7 !important;color:#065F46 !important;}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"]{
  background:#EEF2F7 !important;border-radius:12px !important;
  padding:4px !important;border:1px solid #E0E7EF !important;gap:3px !important;
}
.stTabs [data-baseweb="tab"]{
  background:transparent !important;border-radius:9px !important;
  color:#6B7280 !important;font-weight:500 !important;
  padding:8px 18px !important;font-size:0.84rem !important;border:none !important;
}
.stTabs [aria-selected="true"]{
  background:#FFFFFF !important;color:#1A202C !important;
  font-weight:700 !important;box-shadow:0 1px 4px rgba(0,0,0,0.08) !important;
}

/* ── Dataframes ── */
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

/* ── Expander ── */
.streamlit-expanderHeader{
  background:#FFFFFF !important;border:1px solid #E0E7EF !important;
  border-radius:12px !important;padding:12px 18px !important;
  color:#1A202C !important;font-weight:600 !important;font-size:0.87rem !important;
}
.streamlit-expanderContent{
  background:#F8FAFC !important;border:1px solid #E0E7EF !important;
  border-top:none !important;border-radius:0 0 12px 12px !important;padding:16px !important;
}

/* ── Alerts ── */
.stSuccess>div{background:#F0FDF4 !important;border:1px solid #A7F3D0 !important;border-radius:10px !important;color:#065F46 !important;}
.stWarning>div{background:#FFFBEB !important;border:1px solid #FDE68A !important;border-radius:10px !important;color:#92400E !important;}
.stError>div{background:#FFF1F2 !important;border:1px solid #FECDD3 !important;border-radius:10px !important;color:#9F1239 !important;}
.stInfo>div{background:#ECFEFF !important;border:1px solid #A5F3FC !important;border-radius:10px !important;color:#164E63 !important;}

/* ── Progress ── */
.stProgress>div>div{background:#0E7490 !important;border-radius:4px !important;}
.stProgress>div{background:#E5E7EB !important;border-radius:4px !important;}

/* ── Divider ── */
hr{border-color:#E0E7EF !important;margin:20px 0 !important;}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:5px;height:5px;}
::-webkit-scrollbar-track{background:#F4F6F9;}
::-webkit-scrollbar-thumb{background:#CBD5E1;border-radius:3px;}
::-webkit-scrollbar-thumb:hover{background:#94A3B8;}

/* ── Hide Streamlit chrome ── */
#MainMenu,footer,header{visibility:hidden !important;height:0 !important;}
.viewerBadge_container__1QSob{display:none !important;}
[data-testid="stToolbar"]{display:none !important;}

/* ── Page hero sections ── */
.page-hero{
  background:linear-gradient(135deg,#0D1B2A 0%,#0E3A4A 100%);
  border-radius:18px;padding:32px 36px;margin-bottom:28px;
  box-shadow:0 8px 32px rgba(13,27,42,0.15);position:relative;overflow:hidden;
}
.page-hero::before{
  content:'';position:absolute;top:-40px;right:-40px;
  width:200px;height:200px;
  background:radial-gradient(circle,rgba(16,185,129,0.12) 0%,transparent 70%);
  pointer-events:none;
}
.page-hero::after{
  content:'';position:absolute;bottom:-30px;left:20%;
  width:150px;height:150px;
  background:radial-gradient(circle,rgba(14,116,144,0.10) 0%,transparent 70%);
  pointer-events:none;
}

/* ── Section cards ── */
.section-card{
  background:#FFFFFF;border:1px solid #E0E7EF;
  border-radius:16px;padding:24px;
  box-shadow:0 1px 6px rgba(0,0,0,0.04),0 4px 16px rgba(0,0,0,0.03);
  margin-bottom:20px;
}

/* ── Status badges ── */
.badge{
  display:inline-flex;align-items:center;gap:5px;
  padding:3px 11px;border-radius:20px;
  font-size:0.71rem;font-weight:700;letter-spacing:0.3px;white-space:nowrap;
}

/* ── Detection result card ── */
.result-card{
  border-radius:16px;padding:24px 28px;
  box-shadow:0 6px 24px rgba(0,0,0,0.08);
  transition:transform 0.2s;
}
.result-card:hover{transform:translateY(-2px);}

/* ── Animated loading ── */
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.5;}}
.loading-pulse{animation:pulse 1.5s ease-in-out infinite;}

@keyframes fadeIn{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:translateY(0);}}
.fade-in{animation:fadeIn 0.4s ease-out both;}

/* ── Feature cards on landing ── */
.feature-card{
  background:#FFFFFF;border:1px solid #E0E7EF;border-radius:16px;
  padding:24px;transition:transform 0.22s,box-shadow 0.22s,border-color 0.22s;
  cursor:default;
}
.feature-card:hover{
  transform:translateY(-4px);border-color:#0E7490;
  box-shadow:0 12px 36px rgba(14,116,144,0.14);
}

/* ── Nav items ── */
.nav-item-active{
  background:rgba(14,116,144,0.15) !important;
  border-left:3px solid #0E7490 !important;
}
</style>
""", unsafe_allow_html=True)
'''

# ── Find and replace the design tokens block ─────────────────────
token_start = src.find("# ── Design tokens")
css_end_marker = '""", unsafe_allow_html=True)'
# find first occurrence of the CSS closing marker after token_start
css_end_pos = src.find(css_end_marker, token_start)
if css_end_pos == -1:
    raise ValueError("Could not find CSS end marker")

old_block = src[token_start : css_end_pos + len(css_end_marker)]
new_block  = NEW_TOKENS + "\n" + NEW_CSS

src = src[:token_start] + new_block + src[css_end_pos + len(css_end_marker):]
print(f"Replaced token+CSS block ({len(old_block)} → {len(new_block)} chars)")

# ══════════════════════════════════════════════════════════════════
# 2. REPLACE kpi_card helper
# ══════════════════════════════════════════════════════════════════
NEW_KPI_CARD = '''def kpi_card(icon: str, label: str, value: str, color: str = "",
             sub: str = "") -> str:
    color = color or "#0E7490"
    sub_html = f"<div style=\'color:#6B7280;font-size:0.71rem;margin-top:5px;line-height:1.4\'>{sub}</div>" if sub else ""
    return f"""
    <div style=\'background:#FFFFFF;border-radius:16px;border:1px solid #E0E7EF;
         padding:22px 20px;box-shadow:0 1px 6px rgba(0,0,0,0.05);
         transition:transform 0.2s,box-shadow 0.2s,border-color 0.2s;
         height:100%;cursor:default\'
         onmouseover="this.style.transform=\'translateY(-2px)\';this.style.boxShadow=\'0 8px 28px rgba(14,116,144,0.14)\';this.style.borderColor=\'{color}\'"
         onmouseout="this.style.transform=\'\';this.style.boxShadow=\'0 1px 6px rgba(0,0,0,0.05)\';this.style.borderColor=\'#E0E7EF\'">
      <div style=\'display:flex;align-items:center;gap:10px;margin-bottom:12px\'>
        <div style=\'font-size:1.05rem;background:{color}18;border-radius:10px;
                    width:38px;height:38px;display:flex;align-items:center;
                    justify-content:center;flex-shrink:0;border:1px solid {color}22\'>
          {icon}</div>
        <span style=\'color:#6B7280;font-size:0.68rem;font-weight:700;
                     text-transform:uppercase;letter-spacing:1.1px;line-height:1.3\'>{label}</span>
      </div>
      <div style=\'color:{color};font-size:1.75rem;font-weight:800;line-height:1;
                  letter-spacing:-0.5px\'>{value}</div>
      {sub_html}
    </div>"""
'''

# replace from "def kpi_card" to the next "def " that's not indented
kpi_start = src.find("def kpi_card(")
kpi_end   = src.find("\ndef ", kpi_start + 10)
if kpi_start != -1 and kpi_end != -1:
    src = src[:kpi_start] + NEW_KPI_CARD + src[kpi_end:]
    print("Replaced kpi_card")

# ══════════════════════════════════════════════════════════════════
# 3. REPLACE section_hdr helper
# ══════════════════════════════════════════════════════════════════
NEW_SECTION_HDR = '''def section_hdr(icon: str, title: str, sub: str = "") -> None:
    sub_html = f"<div style=\'color:rgba(248,250,252,0.7);font-size:0.84rem;margin-top:5px;font-weight:400;line-height:1.5\'>{sub}</div>" if sub else ""
    st.markdown(f"""
    <div class=\'page-hero fade-in\'>
      <div style=\'display:flex;align-items:center;gap:16px\'>
        <div style=\'background:rgba(14,116,144,0.3);border:1px solid rgba(14,116,144,0.5);
                    border-radius:14px;width:50px;height:50px;display:flex;
                    align-items:center;justify-content:center;font-size:1.4rem;flex-shrink:0\'>
          {icon}</div>
        <div>
          <div style=\'font-size:1.3rem;font-weight:800;color:#F8FAFC;letter-spacing:-0.3px\'>{title}</div>
          {sub_html}
        </div>
      </div>
    </div>""", unsafe_allow_html=True)
'''

shdr_start = src.find("def section_hdr(")
shdr_end   = src.find("\ndef ", shdr_start + 10)
if shdr_start != -1 and shdr_end != -1:
    src = src[:shdr_start] + NEW_SECTION_HDR + src[shdr_end:]
    print("Replaced section_hdr")

# ══════════════════════════════════════════════════════════════════
# 4. REPLACE STICKY HEADER (top navigation bar)
# ══════════════════════════════════════════════════════════════════
# Find the header block
hdr_marker = "api_ok = api_health()"
hdr_pos = src.find(hdr_marker)
hdr_end_marker = '""", unsafe_allow_html=True)\n'
# find the st.markdown( that starts the header
pre_hdr = src.rfind("st.markdown(f", 0, hdr_pos)
hdr_block_end = src.find(hdr_end_marker, hdr_pos) + len(hdr_end_marker)

if pre_hdr != -1 and hdr_block_end > pre_hdr:
    new_header = '''api_ok = api_health()
S      = stats()

st.markdown(f"""
<div style=\'background:#0D1B2A;border-bottom:1px solid rgba(255,255,255,0.08);
     padding:14px 32px;margin:0 -2.5rem 0;position:sticky;top:0;z-index:100;
     box-shadow:0 2px 16px rgba(0,0,0,0.25);\'>
  <div style=\'display:flex;justify-content:space-between;align-items:center\'>
    <div style=\'display:flex;align-items:center;gap:14px\'>
      <div style=\'background:linear-gradient(135deg,#0E7490,#10B981);border-radius:11px;
                  width:38px;height:38px;display:flex;align-items:center;justify-content:center;
                  font-size:1.1rem;flex-shrink:0;box-shadow:0 3px 10px rgba(14,116,144,0.4)\'>🛡️</div>
      <div>
        <div style=\'font-size:0.96rem;font-weight:800;color:#F8FAFC;letter-spacing:-0.2px\'>CyberShield AI</div>
        <div style=\'font-size:0.63rem;color:rgba(248,250,252,0.55);font-weight:400;margin-top:1px\'>
          Multi-Source Threat Detection · B.Tech Capstone 2026–2027</div>
      </div>
    </div>
    <div style=\'display:flex;align-items:center;gap:14px\'>
      <div>
        <div style=\'display:flex;align-items:center;gap:6px;justify-content:flex-end;margin-bottom:2px\'>
          <div style=\'width:7px;height:7px;border-radius:50%;
                      background:{"#10B981" if api_ok else "#F59E0B"};
                      box-shadow:0 0 7px {"#10B98180" if api_ok else "#F59E0B80"}\'\''
                      ''></div>
          <span style=\'background:{"rgba(16,185,129,0.15)" if api_ok else "rgba(245,158,11,0.15)"};
                       color:{"#10B981" if api_ok else "#F59E0B"};
                       border:1px solid {"rgba(16,185,129,0.3)" if api_ok else "rgba(245,158,11,0.3)"};
                       border-radius:20px;padding:2px 10px;font-size:0.71rem;font-weight:600\'>
            {"API Online" if api_ok else "API Waking"}</span>
        </div>
        <div style=\'color:rgba(248,250,252,0.45);font-size:0.62rem;text-align:right;
                    font-family:"JetBrains Mono",monospace\'>
          {(datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%d %b %Y · %H:%M")} IST</div>
      </div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)
'''
    src = src[:pre_hdr] + new_header + src[hdr_block_end:]
    print("Replaced sticky header")

# ══════════════════════════════════════════════════════════════════
# 5. REPLACE SIDEBAR BRANDING + NAVIGATION
# ══════════════════════════════════════════════════════════════════
# Find the sidebar "with st.sidebar:" block branding section
old_brand_start = src.find("    # Brand\n    st.markdown(\"\"\"")
if old_brand_start == -1:
    old_brand_start = src.find("    st.markdown(\"\"\"\n    <div style=\'padding:20px 18px 16px;border-bottom:1px solid #E2E8F0")
old_brand_end   = src.find("    NAV = {", old_brand_start)

if old_brand_start != -1 and old_brand_end != -1:
    new_brand = """    # ── Brand ──────────────────────────────────────────────────────
    st.markdown(\"\"\"
    <div style='padding:24px 20px 20px;border-bottom:1px solid rgba(255,255,255,0.08)'>
      <div style='display:flex;align-items:center;gap:11px'>
        <div style='background:linear-gradient(135deg,#0E7490,#10B981);border-radius:10px;
                    width:36px;height:36px;display:flex;align-items:center;justify-content:center;
                    font-size:1.1rem;flex-shrink:0;box-shadow:0 3px 8px rgba(14,116,144,0.4)'>🛡️</div>
        <div>
          <div style='color:#F8FAFC;font-size:0.9rem;font-weight:800;line-height:1.2'>CyberShield AI</div>
          <div style='color:rgba(248,250,252,0.45);font-size:0.59rem;font-weight:400;margin-top:1px'>
            Threat Detection Platform</div>
        </div>
      </div>
    </div>\"\"\", unsafe_allow_html=True)

"""
    src = src[:old_brand_start] + new_brand + src[old_brand_end:]
    print("Replaced sidebar brand")

# ── Update NAV to remove emoji group prefixes (cleaner sidebar) ──
src = src.replace(
    '''    NAV = {
        "Overview":    [("📊","Dashboard")],
        "Detection":   [("📧","Phishing"),("🔗","URL Analyser"),
                        ("👤","Login Monitor"),("🌐","Network")],
        "Analysis":    [("⚡","Threat Fusion"),("⏱","Timeline")],
        "Operations":  [("📋","Reports"),("📊","Analytics"),("🎮","Simulation")],
        "Research":    [("🏆","Model Performance"),("📚","Dataset Info"),
                        ("⚙","System Workflow"),("ℹ","About")],
    }''',
    '''    NAV = {
        "Overview":    [("📊","Dashboard")],
        "Detection":   [("📧","Phishing"),("🔗","URL Analyser"),
                        ("👤","Login Monitor"),("🌐","Network")],
        "Analysis":    [("⚡","Threat Fusion"),("⏱","Timeline")],
        "Operations":  [("📋","Reports"),("📊","Analytics"),("🎮","Simulation")],
        "Research":    [("🏆","Model Performance"),("📚","Dataset Info"),
                        ("⚙","System Workflow"),("ℹ","About")],
    }'''
)

# ── Update sidebar nav item style ───────────────────────────────
# Replace the nav group header style
src = src.replace(
    "        st.markdown(f\"\"\"\n        <div style='padding:10px 18px 3px;color:{MUTED};font-size:0.6rem;\n                    text-transform:uppercase;letter-spacing:1.5px;font-weight:700'>\n          {grp}</div>\"\"\", unsafe_allow_html=True)",
    "        st.markdown(f\"\"\"\n        <div style='padding:10px 18px 4px;color:rgba(248,250,252,0.35);font-size:0.59rem;\n                    text-transform:uppercase;letter-spacing:1.6px;font-weight:700'>\n          {grp}</div>\"\"\", unsafe_allow_html=True)"
)

# Replace nav item active/inactive styling
src = src.replace(
    "            bg_c  = f\"{PRIMARY}15\" if active else \"transparent\"\n            bl_c  = PRIMARY if active else \"transparent\"\n            tc    = PRIMARY if active else TEXT\n            fw    = \"600\" if active else \"400\"\n            st.markdown(f\"\"\"\n            <div style='padding:2px 10px 2px 16px'>\n              <div style='background:{bg_c};border-left:2px solid {bl_c};\n                          border-radius:0 8px 8px 0;padding:8px 10px;margin-bottom:1px;\n                          transition:background 0.15s'>\n                <span style='color:{tc};font-weight:{fw};font-size:0.83rem'>\n                  {ico}&nbsp;&nbsp;{name}</span>\n              </div>\n            </div>\"\"\", unsafe_allow_html=True)",
    """            clr_act, bg_act = ("#10B981","rgba(16,185,129,0.15)") if active else ("#F8FAFC","transparent")
            bl_act  = "#10B981" if active else "transparent"
            fw_act  = "600" if active else "400"
            st.markdown(f\"\"\"
            <div style='padding:2px 8px 2px 14px'>
              <div style='background:{bg_act};border-left:2px solid {bl_act};
                          border-radius:0 9px 9px 0;padding:8px 10px;margin-bottom:2px;
                          transition:background 0.15s,border-color 0.15s'>
                <span style='color:{clr_act};font-weight:{fw_act};font-size:0.82rem'>
                  {ico}&nbsp;&nbsp;{name}</span>
              </div>
            </div>\"\"\", unsafe_allow_html=True)"""
)
print("Updated sidebar nav styles")

# ══════════════════════════════════════════════════════════════════
# 6. UPDATE SIDEBAR SESSION METRICS + API STATUS
# ══════════════════════════════════════════════════════════════════
# Replace the session metrics card colors to match navy sidebar
OLD_SESS = "    <div style='margin:10px 12px 6px;padding:14px;background:#F8FAFC;\n         border-radius:12px;border:1px solid #E2E8F0'>  <div style='color:#64748B;font-size:0.62rem;"
NEW_SESS = "    <div style='margin:10px 12px 6px;padding:14px;background:rgba(255,255,255,0.06);\n         border-radius:12px;border:1px solid rgba(255,255,255,0.1)'>  <div style='color:rgba(248,250,252,0.5);font-size:0.62rem;"
src = src.replace(OLD_SESS, NEW_SESS)

# also fix the inner mini-cards
src = src.replace(
    "background:#FFFFFF;border-radius:8px;border:1px solid #E2E8F0'>\n          <div style='color:#0F172A",
    "background:rgba(255,255,255,0.08);border-radius:8px;border:1px solid rgba(255,255,255,0.1)'>\n          <div style='color:#F8FAFC"
)
src = src.replace(
    "background:#FFFFFF;border-radius:8px;border:1px solid #E2E8F0'>",
    "background:rgba(255,255,255,0.08);border-radius:8px;border:1px solid rgba(255,255,255,0.1)'>"
)
src = src.replace(
    "font-size:0.59rem;font-weight:600;text-transform:uppercase'>SCANS</div>",
    "font-size:0.59rem;font-weight:600;text-transform:uppercase;color:rgba(248,250,252,0.45)'>SCANS</div>"
)

# API status card in sidebar
src = src.replace(
    "    st.markdown(f\"\"\"\n    <div style='margin:0 12px 6px;padding:10px 14px;background:#F8FAFC;\n         border-radius:10px;border:1px solid #E2E8F0'>",
    "    st.markdown(f\"\"\"\n    <div style='margin:0 12px 6px;padding:10px 14px;background:rgba(255,255,255,0.06);\n         border-radius:10px;border:1px solid rgba(255,255,255,0.1)'>"
)
src = src.replace(
    "<span style='color:#0F172A;font-size:0.76rem;font-weight:600'>API {status_text}</span>",
    "<span style='color:#F8FAFC;font-size:0.76rem;font-weight:600'>API {status_text}</span>"
)
src = src.replace(
    "        <div style='color:#94A3B8;font-size:0.65rem'>",
    "        <div style='color:rgba(248,250,252,0.4);font-size:0.65rem'>"
)
print("Updated sidebar session/API styles")

# ══════════════════════════════════════════════════════════════════
# 7. REPLACE FOOTER
# ══════════════════════════════════════════════════════════════════
old_footer_start = src.rfind('st.markdown("""')
old_footer_end   = src.rfind('""", unsafe_allow_html=True)')
if old_footer_start != -1 and old_footer_end != -1 and old_footer_end > old_footer_start:
    new_footer = '''st.markdown("""
<div style='background:#0D1B2A;border-top:1px solid rgba(255,255,255,0.07);
     padding:20px 32px;margin:0 -2.5rem -4rem;'>
  <div style='display:flex;justify-content:space-between;align-items:center;
              flex-wrap:wrap;gap:12px;max-width:1200px;margin:0 auto'>
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
    <div style='color:rgba(248,250,252,0.35);font-size:0.66rem;text-align:center'>
      Python · FastAPI · Streamlit · DistilBERT · XGBoost · Isolation Forest · SHAP · LIME
    </div>
    <div style='text-align:right'>
      <div style='color:rgba(248,250,252,0.4);font-size:0.62rem'>
        B.Tech Capstone Project · 2026–2027</div>
      <div style='color:rgba(248,250,252,0.25);font-size:0.6rem;margin-top:2px'>
        Designed with requirements engineering &amp; explainability principles</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)'''
    src = src[:old_footer_start] + new_footer
    print("Replaced footer")

# ══════════════════════════════════════════════════════════════════
# 8. UPDATE loading_card helper colours
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "    ph.markdown(f\"\"\"\n    <div style='background:{CARD};border:1px solid {PRIMARY}35;border-radius:14px;\n         padding:36px;text-align:center;margin:12px 0'>\n      <div style='font-size:2rem;margin-bottom:10px'>⚡</div>\n      <div style='color:{PRIMARY};font-size:1rem;font-weight:700;margin-bottom:5px'>\n        AI Engine Processing...</div>\n      <div style='color:{MUTED};font-size:0.82rem'>\n        Running multi-signal analysis · Please wait</div>\n    </div>\"\"\", unsafe_allow_html=True)",
    """    ph.markdown(f\"\"\"
    <div style='background:#FFFFFF;border:1px solid #E0E7EF;border-radius:16px;
         padding:40px;text-align:center;margin:12px 0;
         box-shadow:0 4px 20px rgba(14,116,144,0.08)'>
      <div style='width:48px;height:48px;border-radius:50%;background:linear-gradient(135deg,#0E7490,#10B981);
                  display:flex;align-items:center;justify-content:center;
                  font-size:1.4rem;margin:0 auto 14px;
                  box-shadow:0 4px 14px rgba(14,116,144,0.3)' class='loading-pulse'>⚡</div>
      <div style='color:#0E7490;font-size:1rem;font-weight:700;margin-bottom:6px;
                  font-family:\"Plus Jakarta Sans\",sans-serif'>
        AI Engine Processing...</div>
      <div style='color:#6B7280;font-size:0.82rem'>
        Running multi-signal analysis · Please wait</div>
    </div>\"\"\", unsafe_allow_html=True)"""
)
print("Updated loading_card")

# ══════════════════════════════════════════════════════════════════
# 9. UPDATE Dashboard section headers (replace old h3 markdown)
# ══════════════════════════════════════════════════════════════════
# Replace old inline h3 section labels on dashboard with styled divs
def replace_section_label(text, old_h3_text, label, icon=""):
    old = f"        st.markdown(f\"<h3 style='margin-bottom:12px'>{old_h3_text}</h3>\",\n                    unsafe_allow_html=True)"
    new = f"""        st.markdown(f\"\"\"
        <div style='display:flex;align-items:center;gap:8px;margin-bottom:12px'>
          <div style='width:4px;height:20px;background:#0E7490;border-radius:2px'></div>
          <span style='font-size:0.82rem;font-weight:700;color:#374151;
                       text-transform:uppercase;letter-spacing:1px'>{label}</span>
        </div>\"\"\", unsafe_allow_html=True)"""
    return text.replace(old, new) if old in text else text

src = replace_section_label(src, "📅 Threat Activity Timeline", "Threat Activity Timeline")
src = replace_section_label(src, "🎯 Attack Distribution", "Attack Distribution")

# simpler label replacements for dashboard cards that use old h3 inline style
for old_lbl, new_lbl in [
    ("📅 Threat Activity Timeline", "Threat Activity Timeline"),
    ("🎯 Attack Distribution", "Attack Distribution"),
    ("🚨 Recent Alerts", "Recent Alerts"),
    ("📊 Risk Score Trend", "Risk Score Trend"),
    ("🖥️ System Status", "System Status"),
]:
    src = src.replace(
        f"        st.markdown(f\"<h3 style='margin-bottom:12px'>{old_lbl}</h3>\",\n                    unsafe_allow_html=True)",
        f"        st.markdown(\"\"\"<div style='display:flex;align-items:center;gap:8px;margin-bottom:12px'>"
        f"<div style='width:4px;height:20px;background:#0E7490;border-radius:2px'></div>"
        f"<span style='font-size:0.82rem;font-weight:700;color:#374151;text-transform:uppercase;letter-spacing:1px'>"
        f"{new_lbl}</span></div>\"\"\", unsafe_allow_html=True)"
    )
print("Updated dashboard section labels")

# ══════════════════════════════════════════════════════════════════
# 10. SYNTAX CHECK
# ══════════════════════════════════════════════════════════════════
import ast
try:
    ast.parse(src)
    print("SYNTAX OK")
except SyntaxError as e:
    print(f"SYNTAX ERROR line {e.lineno}: {e.msg}")
    # restore backup
    shutil.copy(BAK, SRC)
    print("Restored backup due to syntax error")
    raise

# ══════════════════════════════════════════════════════════════════
# WRITE
# ══════════════════════════════════════════════════════════════════
SRC.write_text(src, encoding="utf-8")
new_lines = src.count("\n")
print(f"Written: {new_lines} lines (was {original_lines})")
print(f"File: {SRC}")
