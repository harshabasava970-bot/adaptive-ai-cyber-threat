"""One-shot beige redesign. All direct str_replace. Syntax-checked after every step."""
import ast, pathlib, shutil, sys

SRC = pathlib.Path("src/dashboard/app.py")
src = SRC.read_text(encoding="utf-8")
shutil.copy(SRC, pathlib.Path("src/dashboard/app.py.bak_bf"))
orig = src
print(f"Start: {src.count(chr(10))} lines")

def ck(label):
    try: ast.parse(src)
    except SyntaxError as e:
        print(f"FAIL {label} L{e.lineno}: {e.msg}")
        SRC.write_text(orig, encoding="utf-8"); sys.exit(1)
    print(f"  OK  {label}")

def rp(old, new, required=True):
    global src
    if old in src: src = src.replace(old, new)
    elif required: print(f"  WARN: pattern not found — {old[:60]}")

# ── 1. TOKENS + CSS ───────────────────────────────────────────────
tok_s = src.find("# \u2500\u2500 Design tokens")
css_e = src.find('""", unsafe_allow_html=True)', tok_s) + len('""", unsafe_allow_html=True)')
src = src[:tok_s] + r'''# ── Design tokens — Premium Beige ─────────────────────────────────
BG       = "#F3E9DC"
BG2      = "#E8D9C8"
CARD     = "#FFFDF8"
ESPRESSO = "#2A1F17"
BORDER   = "#DED0C0"
PRIMARY  = "#B86F52"
PRIMARY2 = "#9A5A40"
BRONZE   = "#B18A60"
TEXT     = "#342820"
MUTED    = "#81756B"
SUCCESS  = "#788B70"
CRIT     = "#C0392B"
WARN     = "#C47C2B"
INFO     = "#5B7FA6"
HIGH     = "#A0522D"
PURPLE   = "#7B6D8D"
SUBTLE   = "#A89A8F"

RISK_CLR = {"critical":"#C0392B","high":"#A0522D","medium":"#C47C2B","low":"#788B70","info":"#5B7FA6"}
RISK_BG  = {"critical":"#FCF0EE","high":"#FBF0EB","medium":"#FCF5EC","low":"#EFF3EE","info":"#EEF3F8"}
RISK_ICO = {"critical":"●","high":"●","medium":"●","low":"●","info":"●"}

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800&family=Manrope:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html,body,.stApp{background:#F3E9DC !important;color:#342820 !important;font-family:'Manrope',system-ui,sans-serif !important;font-size:14px !important;line-height:1.7 !important;-webkit-font-smoothing:antialiased;}
section[data-testid="stSidebar"]{background:#2A1F17 !important;border-right:1px solid rgba(255,255,255,0.06) !important;box-shadow:3px 0 20px rgba(0,0,0,0.25) !important;}
section[data-testid="stSidebar"]>div{padding:0 !important;}
.block-container{padding:0 2.5rem 4rem 2.5rem !important;max-width:100% !important;}
h1{font-family:'Sora',sans-serif !important;font-size:2rem !important;font-weight:700 !important;color:#342820 !important;letter-spacing:-0.5px !important;line-height:1.2 !important;}
h2{font-family:'Sora',sans-serif !important;font-size:1.35rem !important;font-weight:600 !important;color:#342820 !important;}
h3{font-family:'Sora',sans-serif !important;font-size:1.05rem !important;font-weight:600 !important;color:#342820 !important;}
h4{font-family:'Manrope',sans-serif !important;font-size:0.72rem !important;font-weight:700 !important;color:#81756B !important;text-transform:uppercase !important;letter-spacing:1.2px !important;}
p{color:#342820 !important;}label{color:#4A3728 !important;font-weight:500 !important;}
div[data-testid="metric-container"]{background:#FFFDF8 !important;border:1px solid #DED0C0 !important;border-radius:16px !important;padding:22px !important;box-shadow:0 2px 8px rgba(52,40,32,0.06) !important;transition:transform 0.2s,box-shadow 0.2s !important;}
div[data-testid="metric-container"]:hover{transform:translateY(-2px) !important;box-shadow:0 8px 24px rgba(184,111,82,0.15) !important;border-color:#B86F52 !important;}
div[data-testid="metric-container"] [data-testid="stMetricLabel"]>div{font-size:0.67rem !important;font-weight:700 !important;color:#81756B !important;text-transform:uppercase !important;letter-spacing:1.1px !important;}
div[data-testid="metric-container"] [data-testid="stMetricValue"]>div{font-size:1.8rem !important;font-weight:700 !important;color:#342820 !important;font-family:'Sora',sans-serif !important;}
.stButton>button{background:#B86F52 !important;color:#FFFDF8 !important;border:none !important;border-radius:10px !important;padding:11px 24px !important;font-weight:600 !important;font-size:0.84rem !important;font-family:'Manrope',sans-serif !important;box-shadow:0 2px 8px rgba(184,111,82,0.30) !important;transition:background 0.15s,transform 0.15s !important;width:100% !important;}
.stButton>button:hover{background:#9A5A40 !important;transform:translateY(-1px) !important;box-shadow:0 6px 18px rgba(184,111,82,0.4) !important;}
.stButton>button:disabled{background:#C4B5A8 !important;color:#9A8A80 !important;box-shadow:none !important;}
.stTextInput>div>div>input,.stTextArea>div>div>textarea,.stNumberInput>div>div>input{background:#FFFDF8 !important;color:#342820 !important;border:1.5px solid #DED0C0 !important;border-radius:10px !important;padding:10px 14px !important;font-family:'Manrope',sans-serif !important;font-size:0.87rem !important;transition:border-color 0.2s,box-shadow 0.2s !important;}
.stTextInput>div>div>input:focus,.stTextArea>div>div>textarea:focus{border-color:#B86F52 !important;box-shadow:0 0 0 3px rgba(184,111,82,0.12) !important;}
.stTextInput label,.stTextArea label,.stNumberInput label,.stSelectbox label,.stMultiSelect label,.stSlider label,.stRadio label,.stCheckbox label{color:#4A3728 !important;font-weight:500 !important;font-size:0.84rem !important;font-family:'Manrope',sans-serif !important;}
.stSelectbox>div>div,.stMultiSelect>div>div{background:#FFFDF8 !important;border:1.5px solid #DED0C0 !important;border-radius:10px !important;color:#342820 !important;}
.stMultiSelect [data-baseweb="tag"]{background:#EDE0D2 !important;color:#5A3A25 !important;}
.stTabs [data-baseweb="tab-list"]{background:#E8D9C8 !important;border-radius:12px !important;padding:4px !important;border:1px solid #DED0C0 !important;}
.stTabs [data-baseweb="tab"]{background:transparent !important;border-radius:9px !important;color:#81756B !important;font-weight:500 !important;padding:8px 18px !important;}
.stTabs [aria-selected="true"]{background:#FFFDF8 !important;color:#342820 !important;font-weight:700 !important;box-shadow:0 1px 4px rgba(52,40,32,0.08) !important;}
.stDataFrame{border-radius:14px !important;overflow:hidden !important;box-shadow:0 2px 8px rgba(52,40,32,0.06) !important;}
.stDataFrame thead tr th{background:#EDE0D2 !important;color:#342820 !important;font-weight:700 !important;font-size:0.72rem !important;text-transform:uppercase !important;letter-spacing:0.8px !important;padding:10px 14px !important;border-bottom:1px solid #DED0C0 !important;}
.stDataFrame tbody tr td{background:#FFFDF8 !important;color:#4A3728 !important;font-size:0.84rem !important;padding:9px 14px !important;border-bottom:1px solid #F0E6DA !important;}
.stDataFrame tbody tr:hover td{background:#FBF4ED !important;}
.streamlit-expanderHeader{background:#FFFDF8 !important;border:1px solid #DED0C0 !important;border-radius:12px !important;padding:12px 18px !important;color:#342820 !important;font-weight:600 !important;}
.streamlit-expanderContent{background:#FBF4ED !important;border:1px solid #DED0C0 !important;border-top:none !important;border-radius:0 0 12px 12px !important;padding:16px !important;}
.stSuccess>div{background:#EEF3EE !important;border:1px solid #A8C4A0 !important;border-radius:10px !important;color:#3A5A32 !important;}
.stWarning>div{background:#FBF3E8 !important;border:1px solid #DEB882 !important;border-radius:10px !important;color:#7A5020 !important;}
.stError>div{background:#FCF0EE !important;border:1px solid #DDA090 !important;border-radius:10px !important;color:#7A2018 !important;}
.stInfo>div{background:#EEF2F8 !important;border:1px solid #90AED0 !important;border-radius:10px !important;color:#2A4A70 !important;}
.stProgress>div>div{background:#B86F52 !important;border-radius:4px !important;}
.stProgress>div{background:#DED0C0 !important;border-radius:4px !important;}
hr{border-color:#DED0C0 !important;margin:20px 0 !important;}
::-webkit-scrollbar{width:5px;height:5px;}::-webkit-scrollbar-track{background:#F3E9DC;}::-webkit-scrollbar-thumb{background:#C4B5A8;border-radius:3px;}::-webkit-scrollbar-thumb:hover{background:#B18A60;}
#MainMenu,footer,header{visibility:hidden !important;height:0 !important;}
.viewerBadge_container__1QSob{display:none !important;}[data-testid="stToolbar"]{display:none !important;}
.page-hero{background:linear-gradient(135deg,#2A1F17 0%,#4A2E1A 100%);border-radius:20px;padding:36px 40px;margin-bottom:28px;box-shadow:0 8px 32px rgba(42,31,23,0.2);position:relative;overflow:hidden;}
.page-hero::before{content:'';position:absolute;top:-40px;right:-40px;width:200px;height:200px;background:radial-gradient(circle,rgba(184,111,82,0.15) 0%,transparent 70%);}
@keyframes warmFadeIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
.fade-in{animation:warmFadeIn 0.45s ease-out both;}
</style>
""", unsafe_allow_html=True)
''' + src[css_e:]
ck("tokens+CSS")

# ── 2. kpi_card ───────────────────────────────────────────────────
kpi_s = src.find("def kpi_card("); kpi_e = src.find("\ndef ", kpi_s+10)
src = src[:kpi_s] + '''def kpi_card(icon, label, value, color="", sub=""):
    color = color or "#B86F52"
    sub_html = f"<div style='color:#81756B;font-size:0.71rem;margin-top:5px'>{sub}</div>" if sub else ""
    return f"""<div style='background:#FFFDF8;border-radius:16px;border:1px solid #DED0C0;
         padding:22px 20px;box-shadow:0 2px 8px rgba(52,40,32,0.06);
         transition:transform 0.2s,box-shadow 0.2s,border-color 0.2s;height:100%;'>
      <div style='display:flex;align-items:center;gap:10px;margin-bottom:12px'>
        <div style='font-size:1rem;background:{color}18;border-radius:10px;width:38px;height:38px;
                    display:flex;align-items:center;justify-content:center;border:1px solid {color}25'>{icon}</div>
        <span style='color:#81756B;font-size:0.67rem;font-weight:700;text-transform:uppercase;letter-spacing:1.1px;font-family:Manrope,sans-serif'>{label}</span>
      </div>
      <div style='color:{color};font-size:1.75rem;font-weight:700;line-height:1;font-family:Sora,sans-serif'>{value}</div>
      {sub_html}</div>"""
''' + src[kpi_e:]
ck("kpi_card")

# ── 3. section_hdr ────────────────────────────────────────────────
sh_s = src.find("def section_hdr("); sh_e = src.find("\ndef ", sh_s+10)
src = src[:sh_s] + '''def section_hdr(icon, title, sub=""):
    sub_html = f"<div style='color:rgba(255,253,248,0.65);font-size:0.87rem;margin-top:6px;font-family:Manrope,sans-serif'>{sub}</div>" if sub else ""
    st.markdown(f"""<div class='page-hero fade-in'>
      <div style='display:flex;align-items:center;gap:16px'>
        <div style='background:rgba(184,111,82,0.25);border:1px solid rgba(184,111,82,0.45);
                    border-radius:14px;width:52px;height:52px;display:flex;align-items:center;
                    justify-content:center;font-size:1.3rem;flex-shrink:0'>{icon}</div>
        <div>
          <div style='font-size:1.4rem;font-weight:700;color:#FFFDF8;font-family:Sora,sans-serif'>{title}</div>
          {sub_html}
        </div>
      </div></div>""", unsafe_allow_html=True)
''' + src[sh_e:]
ck("section_hdr")

# ── 4. loading_card ───────────────────────────────────────────────
rp('      <div style=\'font-size:2rem;margin-bottom:10px\'>⚡</div>\n      <div style=\'color:#0E7490;font-size:1rem;font-weight:700;margin-bottom:6px;\n                  font-family:\'Plus Jakarta Sans\',sans-serif\'>\n        AI Engine Processing...</div>\n      <div style=\'color:#6B7280;font-size:0.82rem\'>\n        Running multi-signal analysis · Please wait</div>',
   '      <div style=\'font-size:1.5rem;margin-bottom:14px\'>⚡</div>\n      <div style=\'color:#B86F52;font-size:1rem;font-weight:600;margin-bottom:7px;font-family:Sora,sans-serif\'>\n        AI Engine Processing...</div>\n      <div style=\'color:#81756B;font-size:0.82rem;font-family:Manrope,sans-serif\'>\n        Running multi-signal threat analysis · Please wait</div>', required=False)

# loading_card outer div bg
rp("background:#FFFFFF;border:1px solid #E0E7EF;border-radius:16px;\n         padding:40px;text-align:center;margin:12px 0;\n         box-shadow:0 4px 20px rgba(14,116,144,0.08)",
   "background:#FFFDF8;border:1px solid #DED0C0;border-radius:18px;\n         padding:44px;text-align:center;margin:12px 0;\n         box-shadow:0 4px 20px rgba(184,111,82,0.08)", required=False)
ck("loading_card")

# ── 5. Header ─────────────────────────────────────────────────────
rp("background:#0D1B2A;border-bottom:1px solid rgba(255,255,255,0.08);\n     padding:14px 32px;margin:0 -2.5rem 0;position:sticky;top:0;z-index:100;\n     box-shadow:0 2px 16px rgba(0,0,0,0.25);",
   "background:#2A1F17;border-bottom:1px solid rgba(255,255,255,0.07);\n     padding:14px 32px;margin:0 -2.5rem 0;position:sticky;top:0;z-index:100;\n     box-shadow:0 2px 16px rgba(0,0,0,0.3);")
rp("background:linear-gradient(135deg,#0E7490,#10B981);border-radius:11px;\n                  width:38px;height:38px;display:flex;align-items:center;justify-content:center;\n                  font-size:1.1rem;box-shadow:0 3px 10px rgba(14,116,144,0.4)",
   "background:linear-gradient(135deg,#B86F52,#B18A60);border-radius:11px;\n                  width:38px;height:38px;display:flex;align-items:center;justify-content:center;\n                  font-size:1.1rem;box-shadow:0 3px 10px rgba(184,111,82,0.4)")
rp("font-size:0.97rem;font-weight:700;color:#FFFDF8;\n                    font-family:Sora,sans-serif;letter-spacing:-0.2px",
   "font-size:0.97rem;font-weight:700;color:#FFFDF8;\n                    font-family:'Sora',sans-serif;letter-spacing:-0.2px", required=False)
# API dot / pill colours in header
rp('_dot   = "#788B70" if api_ok else "#C47C2B"',
   '_dot   = "#788B70" if api_ok else "#C47C2B"', required=False)  # already set
ck("header")

# ── 6. Sidebar brand ──────────────────────────────────────────────
rp("background:linear-gradient(135deg,#0E7490,#10B981);border-radius:10px;\n                    width:36px;height:36px;display:flex;align-items:center;justify-content:center;\n                    font-size:1.1rem;box-shadow:0 3px 8px rgba(14,116,144,0.4)",
   "background:linear-gradient(135deg,#B86F52,#B18A60);border-radius:10px;\n                    width:36px;height:36px;display:flex;align-items:center;justify-content:center;\n                    font-size:1.1rem;box-shadow:0 3px 8px rgba(184,111,82,0.4)")
rp("color:#F8FAFC;font-size:0.9rem;font-weight:800;font-family:Sora,sans-serif",
   "color:#FFFDF8;font-size:0.9rem;font-weight:700;font-family:'Sora',sans-serif", required=False)
# nav group header colour
rp("color:rgba(248,250,252,0.35);font-size:0.59rem;\n                    text-transform:uppercase;letter-spacing:1.6px;font-weight:700",
   "color:rgba(255,253,248,0.32);font-size:0.59rem;\n                    text-transform:uppercase;letter-spacing:1.6px;font-weight:700;font-family:'Manrope',sans-serif")
# nav active colour
rp('clr_act = "#10B981" if active else "rgba(248,250,252,0.65)"',
   'clr_act = "#D4956B" if active else "rgba(255,253,248,0.65)"', required=False)
rp('clr_act = "#10B981" if active else "#E2E8F0"',
   'clr_act = "#D4956B" if active else "rgba(255,253,248,0.62)"', required=False)
rp('bg_act  = "rgba(16,185,129,0.12)" if active else "transparent"',
   'bg_act  = "rgba(184,111,82,0.18)" if active else "transparent"', required=False)
rp('bl_act = "#10B981" if active else "transparent"',
   'bl_act = "#B86F52" if active else "transparent"', required=False)
# session metrics card
rp("background:rgba(255,253,248,0.06);\n         border-radius:12px;border:1px solid rgba(255,253,248,0.09)",
   "background:rgba(255,253,248,0.05);\n         border-radius:12px;border:1px solid rgba(255,253,248,0.08)", required=False)
rp("background:rgba(255,255,255,0.08);border-radius:8px;border:1px solid rgba(255,255,255,0.1)",
   "background:rgba(255,253,248,0.07);border-radius:8px;border:1px solid rgba(255,253,248,0.09)", required=False)
for lbl in ["SCANS","THREATS","SPEED"]:
    rp(f"color:rgba(248,250,252,0.4)'>{lbl}</div>",
       f"color:rgba(255,253,248,0.38);font-family:Manrope,sans-serif'>{lbl}</div>", required=False)
ck("sidebar")

# ── 7. Footer ─────────────────────────────────────────────────────
foot_s = src.rfind('st.markdown("""')
src = src[:foot_s] + '''st.markdown("""
<div style='background:#2A1F17;border-top:1px solid rgba(255,255,255,0.07);
     padding:20px 32px;margin:0 -2.5rem -4rem;'>
  <div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px'>
    <div style='display:flex;align-items:center;gap:11px'>
      <div style='background:linear-gradient(135deg,#B86F52,#B18A60);border-radius:9px;
                  width:30px;height:30px;display:flex;align-items:center;justify-content:center;font-size:0.95rem'>🛡️</div>
      <div>
        <div style='color:#FFFDF8;font-weight:700;font-size:0.82rem;font-family:Sora,sans-serif'>CyberShield AI</div>
        <div style='color:rgba(255,253,248,0.38);font-size:0.62rem;margin-top:1px;font-family:Manrope,sans-serif'>
          Adaptive Explainable Multi-Source Cyber Threat Detection</div>
      </div>
    </div>
    <div style='color:rgba(255,253,248,0.28);font-size:0.65rem;font-family:Manrope,sans-serif'>
      Python · FastAPI · Streamlit · DistilBERT · XGBoost · Isolation Forest · SHAP · LIME</div>
    <div style='text-align:right'>
      <div style='color:rgba(255,253,248,0.32);font-size:0.62rem;font-family:Manrope,sans-serif'>B.Tech Capstone 2026–2027</div>
      <div style='color:rgba(255,253,248,0.2);font-size:0.6rem;margin-top:2px;font-family:Manrope,sans-serif'>
        Designed with requirements engineering &amp; explainability principles</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)'''
ck("footer")

# ── 8. Charts ─────────────────────────────────────────────────────
for o,n in [
    ('color="#6B7280", size=11)','color="#81756B", size=11)'),
    ('color="#6B7280", size=10)','color="#81756B", size=10)'),
    ('color="#1A202C", size=11)','color="#342820", size=11)'),
    ('color="#1A202C")',         'color="#342820")'),
    ('gridcolor="#E5E7EB"',      'gridcolor="#DED0C0"'),
    ('tickfont=dict(color="#6B7280")', 'tickfont=dict(color="#81756B")'),
    ('tickfont=dict(color="#1A202C")', 'tickfont=dict(color="#342820")'),
    ('annotation_font=dict(color="#EF4444",','annotation_font=dict(color="#C0392B",'),
    ('annotation_font=dict(color="#F97316",','annotation_font=dict(color="#A0522D",'),
    ('annotation_font=dict(color="#F59E0B",','annotation_font=dict(color="#C47C2B",'),
]: rp(o, n, required=False)
ck("charts")

# ── 9. All remaining blue/teal → beige tones in HTML strings ──────
for o,n in [
    # card/border literals
    ("background:#FFFDF8;border-radius:12px;border:1px solid #E0E7EF;",
     "background:#FFFDF8;border-radius:12px;border:1px solid #DED0C0;"),
    ("background:#FFFDF8;border-radius:14px;border:1px solid #E0E7EF;",
     "background:#FFFDF8;border-radius:14px;border:1px solid #DED0C0;"),
    ("background:#FFFDF8;border-radius:16px;border:1px solid #E0E7EF;",
     "background:#FFFDF8;border-radius:16px;border:1px solid #DED0C0;"),
    ("border:1px solid #E0E7EF;",    "border:1px solid #DED0C0;"),
    ("background:#EEF2F7;",          "background:#E8D9C8;"),
    ("background:#F8FAFC;",          "background:#F3E9DC;"),
    ("background:#EDE0D2;",          "background:#E8D9C8;"),
    # timeline header
    ("background:#E8D9C8;border-radius:10px;margin-bottom:6px;\n         border:1px solid #DED0C0;",
     "background:#E8D9C8;border-radius:10px;margin-bottom:6px;\n         border:1px solid #DED0C0;"),
    # timeline row
    ("background:#FFFFFF;border-radius:11px;\n             margin-bottom:5px;border:1px solid #E0E7EF;",
     "background:#FFFDF8;border-radius:11px;\n             margin-bottom:5px;border:1px solid #DED0C0;"),
    # empty states
    ("border:2px dashed #C4B5A8;", "border:2px dashed #C4B5A8;"),
    ("border:2px dashed #D1D5DB;", "border:2px dashed #C4B5A8;"),
    # detection intro cards left-border colours
    ("border-left:4px solid #E11D48;", "border-left:4px solid #C0392B;"),
    ("border-left:4px solid #0D9488;", "border-left:4px solid #B18A60;"),
    ("border-left:4px solid #7C3AED;", "border-left:4px solid #7B6D8D;"),
    ("border-left:4px solid #788B70;", "border-left:4px solid #788B70;"),
    # about/page-hero backgrounds already set by page-hero class
    ("background:linear-gradient(135deg,#2A1F17 0%,#4A2E1A 100%);\n         border:none;border-radius:18px;\n         padding:30px 36px;margin-bottom:24px;",
     "background:linear-gradient(135deg,#2A1F17 0%,#4A2E1A 100%);\n         border:none;border-radius:20px;\n         padding:32px 40px;margin-bottom:28px;"),
    # model perf top-border colours
    ("border-top:4px solid #788B70;", "border-top:4px solid #788B70;"),
    ("border-top:4px solid #B18A60;", "border-top:4px solid #B18A60;"),
    ("border-top:4px solid #C47C2B;", "border-top:4px solid #C47C2B;"),
    # reports/simulation
    ("border-top:3px solid #788B70;", "border-top:3px solid #788B70;"),
    ("border-top:3px solid #C0392B;", "border-top:3px solid #C0392B;"),
    ("background:#FBF3E8;border:1px solid #DEB882;", "background:#FBF3E8;border:1px solid #DEB882;"),
    # fusion source boxes
    ("background:#F3E9DC;border:1px solid #DED0C0;border-radius:9px;",
     "background:#F3E9DC;border:1px solid #DED0C0;border-radius:9px;"),
]: rp(o, n, required=False)
ck("all remaining tones")

# ── FINAL ─────────────────────────────────────────────────────────
try: ast.parse(src)
except SyntaxError as e:
    print(f"FINAL FAIL L{e.lineno}: {e.msg}")
    SRC.write_text(orig, encoding="utf-8"); sys.exit(1)

SRC.write_text(src, encoding="utf-8")
print(f"DONE — {src.count(chr(10))} lines written")
