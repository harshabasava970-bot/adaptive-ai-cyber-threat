"""patch_theme.py — Replace dark design tokens + CSS with complete light theme."""
import re

NEW_BLOCK = '''# ── Design tokens — LIGHT THEME ───────────────────────────────────
BG       = "#F7F9FC"
CARD     = "#FFFFFF"
SIDEBAR  = "#FFFFFF"
BORDER   = "#E2E8F0"
PRIMARY  = "#2563EB"
SUCCESS  = "#16A34A"
WARN     = "#D97706"
CRIT     = "#DC2626"
INFO     = "#0891B2"
HIGH     = "#EA580C"
TEXT     = "#0F172A"
MUTED    = "#64748B"
SUBTLE   = "#94A3B8"
PURPLE   = "#7C3AED"
ACCENT   = "#0891B2"
# Per-module accent colors
M_PHISH  = "#E11D48"
M_URL    = "#0D9488"
M_LOGIN  = "#7C3AED"
M_NET    = "#059669"
M_FUSION = "#D97706"
M_XAI    = "#4F46E5"

RISK_CLR = {"critical":"#DC2626","high":"#EA580C","medium":"#D97706",
            "low":"#16A34A","info":"#0891B2"}
RISK_BG  = {"critical":"#FFF1F2","high":"#FFF7ED","medium":"#FFFBEB",
            "low":"#F0FDF4","info":"#ECFEFF"}
RISK_ICO = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","info":"🔵"}

# ══════════════════════════════════════════════════════════════════
# GLOBAL CSS — Complete Light Theme
# ══════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url(\'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap\');

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}

/* Global light background */
html,body,.stApp{
  background:#F7F9FC !important;
  color:#0F172A !important;
  font-family:\'Inter\',-apple-system,BlinkMacSystemFont,sans-serif !important;
  font-size:14px !important;
  line-height:1.6 !important;
  -webkit-font-smoothing:antialiased;
}

/* White sidebar */
section[data-testid="stSidebar"]{
  background:#FFFFFF !important;
  border-right:1px solid #E2E8F0 !important;
}
section[data-testid="stSidebar"]>div{padding:0 !important;}

/* Main container */
.block-container{padding:0 2rem 3rem 2rem !important;max-width:100% !important;}

/* Typography */
h1{font-size:1.6rem !important;font-weight:800 !important;color:#0F172A !important;letter-spacing:-0.5px !important;}
h2{font-size:1.2rem !important;font-weight:700 !important;color:#0F172A !important;}
h3{font-size:1rem !important;font-weight:600 !important;color:#1E293B !important;}
h4{font-size:0.75rem !important;font-weight:700 !important;color:#64748B !important;text-transform:uppercase !important;letter-spacing:1px !important;}
p{color:#0F172A !important;}
label{color:#1E293B !important;font-weight:500 !important;}

/* Metric cards */
div[data-testid="metric-container"]{
  background:#FFFFFF !important;
  border:1px solid #E2E8F0 !important;
  border-radius:16px !important;
  padding:20px !important;
  box-shadow:0 1px 8px rgba(15,23,42,0.06) !important;
  transition:transform 0.2s,box-shadow 0.2s !important;
}
div[data-testid="metric-container"]:hover{
  transform:translateY(-2px) !important;
  box-shadow:0 8px 24px rgba(37,99,235,0.12) !important;
  border-color:#BFDBFE !important;
}
div[data-testid="metric-container"] [data-testid="stMetricLabel"]>div{
  font-size:0.68rem !important;font-weight:700 !important;
  color:#64748B !important;text-transform:uppercase !important;letter-spacing:1px !important;
}
div[data-testid="metric-container"] [data-testid="stMetricValue"]>div{
  font-size:1.75rem !important;font-weight:800 !important;color:#0F172A !important;
}

/* Buttons */
.stButton>button{
  background:#2563EB !important;color:#fff !important;border:none !important;
  border-radius:10px !important;padding:10px 22px !important;font-weight:600 !important;
  font-size:0.84rem !important;font-family:\'Inter\',sans-serif !important;
  box-shadow:0 2px 8px rgba(37,99,235,0.20) !important;
  transition:background 0.15s,transform 0.15s,box-shadow 0.15s !important;
  width:100% !important;cursor:pointer !important;
}
.stButton>button:hover{
  background:#1D4ED8 !important;transform:translateY(-1px) !important;
  box-shadow:0 6px 16px rgba(37,99,235,0.30) !important;
}
.stButton>button:disabled{background:#E2E8F0 !important;color:#94A3B8 !important;box-shadow:none !important;}

/* Inputs — white with light borders */
.stTextInput>div>div>input,
.stTextArea>div>div>textarea,
.stNumberInput>div>div>input{
  background:#FFFFFF !important;color:#0F172A !important;
  border:1.5px solid #CBD5E1 !important;border-radius:10px !important;
  padding:10px 14px !important;font-family:\'Inter\',sans-serif !important;
  font-size:0.87rem !important;transition:border-color 0.2s,box-shadow 0.2s !important;
}
.stTextInput>div>div>input:focus,
.stTextArea>div>div>textarea:focus{
  border-color:#2563EB !important;
  box-shadow:0 0 0 3px rgba(37,99,235,0.10) !important;outline:none !important;
}
.stTextInput label,.stTextArea label,.stNumberInput label,
.stSelectbox label,.stMultiSelect label,.stSlider label,
.stRadio label,.stCheckbox label{color:#1E293B !important;font-weight:500 !important;font-size:0.84rem !important;}
.stSelectbox>div>div,.stMultiSelect>div>div{
  background:#FFFFFF !important;border:1.5px solid #CBD5E1 !important;
  border-radius:10px !important;color:#0F172A !important;
}
.stRadio>div>div>label,.stCheckbox>label{color:#1E293B !important;font-size:0.86rem !important;}
.stMultiSelect [data-baseweb="tag"]{background:#DBEAFE !important;color:#1E40AF !important;}

/* Tabs */
.stTabs [data-baseweb="tab-list"]{
  background:#F1F5F9 !important;border-radius:12px !important;
  padding:4px !important;border:1px solid #E2E8F0 !important;gap:3px !important;
}
.stTabs [data-baseweb="tab"]{
  background:transparent !important;border-radius:9px !important;
  color:#64748B !important;font-weight:500 !important;
  padding:8px 18px !important;font-size:0.84rem !important;border:none !important;
}
.stTabs [aria-selected="true"]{
  background:#FFFFFF !important;color:#0F172A !important;
  font-weight:700 !important;box-shadow:0 1px 4px rgba(0,0,0,0.08) !important;
}

/* Dataframes */
.stDataFrame{border-radius:14px !important;overflow:hidden !important;box-shadow:0 1px 8px rgba(15,23,42,0.06) !important;}
.stDataFrame thead tr th{
  background:#F8FAFC !important;color:#0F172A !important;
  font-weight:700 !important;font-size:0.75rem !important;
  text-transform:uppercase !important;letter-spacing:0.8px !important;
  padding:10px 14px !important;border-bottom:1px solid #E2E8F0 !important;
}
.stDataFrame tbody tr td{
  background:#FFFFFF !important;color:#1E293B !important;
  font-size:0.84rem !important;padding:9px 14px !important;
  border-bottom:1px solid #F1F5F9 !important;
}
.stDataFrame tbody tr:hover td{background:#F8FAFC !important;}

/* Expander */
.streamlit-expanderHeader{
  background:#FFFFFF !important;border:1px solid #E2E8F0 !important;
  border-radius:12px !important;padding:12px 18px !important;
  color:#0F172A !important;font-weight:600 !important;font-size:0.87rem !important;
}
.streamlit-expanderContent{
  background:#F8FAFC !important;border:1px solid #E2E8F0 !important;
  border-top:none !important;border-radius:0 0 12px 12px !important;padding:16px !important;
}

/* Alerts */
.stSuccess>div{background:#F0FDF4 !important;border:1px solid #BBF7D0 !important;border-radius:10px !important;color:#166534 !important;}
.stWarning>div{background:#FFFBEB !important;border:1px solid #FDE68A !important;border-radius:10px !important;color:#92400E !important;}
.stError>div  {background:#FFF1F2 !important;border:1px solid #FECDD3 !important;border-radius:10px !important;color:#9F1239 !important;}
.stInfo>div   {background:#ECFEFF !important;border:1px solid #A5F3FC !important;border-radius:10px !important;color:#164E63 !important;}

/* Progress */
.stProgress>div>div{background:#2563EB !important;border-radius:4px !important;}
.stProgress>div{background:#E2E8F0 !important;border-radius:4px !important;}

/* Divider */
hr{border-color:#E2E8F0 !important;margin:20px 0 !important;}

/* Scrollbar */
::-webkit-scrollbar{width:5px;height:5px;}
::-webkit-scrollbar-track{background:#F1F5F9;}
::-webkit-scrollbar-thumb{background:#CBD5E1;border-radius:3px;}
::-webkit-scrollbar-thumb:hover{background:#94A3B8;}

/* Hide Streamlit chrome */
#MainMenu,footer,header{visibility:hidden !important;height:0 !important;}
.viewerBadge_container__1QSob{display:none !important;}
[data-testid="stToolbar"]{display:none !important;}
</style>
""", unsafe_allow_html=True)
'''

src = open('src/dashboard/app.py', encoding='utf-8').read()
lines = src.split('\n')

# Find start (design tokens line) and end (closing =""", after </style>)
start = None
end = None
for i, l in enumerate(lines):
    if '# \u2500\u2500 Design tokens' in l and start is None:
        start = i
    if '</style>' in l and start is not None and end is None:
        # find the closing """, unsafe line
        for j in range(i, min(i+5, len(lines))):
            if '""", unsafe_allow_html=True)' in lines[j]:
                end = j + 1
                break
        if end is None:
            end = i + 3

print(f"Replacing lines {start+1}–{end} ({end-start} lines)")

new_lines = lines[:start] + NEW_BLOCK.split('\n') + lines[end:]
open('src/dashboard/app.py', 'w', encoding='utf-8').write('\n'.join(new_lines))
print("Done.")
