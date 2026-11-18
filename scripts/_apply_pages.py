"""
Apply per-page visual redesigns to every page section.
Only styling changes — zero functional changes.
"""
import ast, pathlib, shutil

SRC = pathlib.Path("src/dashboard/app.py")
src = SRC.read_text(encoding="utf-8")
original = src.count("\n")

# ══════════════════════════════════════════════════════════════════
# HELPER: replace ANY fstring with a colour token reference
# ══════════════════════════════════════════════════════════════════
def r(old, new):
    global src
    if old in src:
        src = src.replace(old, new)
        return True
    return False

# ══════════════════════════════════════════════════════════════════
# 1.  DETECTION PAGE INTRO CARDS — upgrade border-left accent + bg
# ══════════════════════════════════════════════════════════════════
# Phishing intro card — replace old CRIT}18 / CRIT}30
old_phi = """    st.markdown(f\"\"\"
    <div style='background:{CARD};border:1px solid {BORDER};border-radius:16px;
         padding:26px 30px 22px;margin-bottom:22px;
         box-shadow:0 4px 20px rgba(0,0,0,0.4)'>"""
new_phi = """    st.markdown(f\"\"\"
    <div style='background:#FFFFFF;border:1px solid #E0E7EF;border-left:4px solid #E11D48;
         border-radius:16px;padding:26px 30px 22px;margin-bottom:22px;
         box-shadow:0 2px 12px rgba(0,0,0,0.05)'>"""
r(old_phi, new_phi)

# URL intro card
old_url = """    st.markdown(f\"\"\"
    <div style='background:{CARD};border:1px solid {BORDER};border-radius:16px;
         padding:20px 24px;margin-bottom:18px;box-shadow:0 4px 16px rgba(0,0,0,0.3)'>"""
new_url = """    st.markdown(f\"\"\"
    <div style='background:#FFFFFF;border:1px solid #E0E7EF;border-left:4px solid #0D9488;
         border-radius:16px;padding:20px 24px;margin-bottom:18px;
         box-shadow:0 2px 12px rgba(0,0,0,0.05)'>"""
r(old_url, new_url)

# Login + Network intro cards (same pattern used twice more)
src = src.replace(
    "border-radius:14px;\n         padding:16px 20px;margin-bottom:18px;border-left:3px solid {WARN};",
    "border-radius:14px;\n         padding:16px 20px;margin-bottom:18px;border-left:4px solid #7C3AED;"
)
src = src.replace(
    "border-radius:14px;\n         padding:16px 20px;margin-bottom:18px;border-left:3px solid {INFO};",
    "border-radius:14px;\n         padding:16px 20px;margin-bottom:18px;border-left:4px solid #059669;"
)
print("Updated detection intro cards")

# ══════════════════════════════════════════════════════════════════
# 2.  SYSTEM STATUS ROW (dashboard) — improve card styles
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "            <div style='background:{CARD};border-radius:10px;padding:8px 12px;\n                        margin-bottom:5px;border:1px solid {BORDER};",
    "            <div style='background:#FFFFFF;border-radius:10px;padding:9px 13px;\n                        margin-bottom:6px;border:1px solid #E0E7EF;"
)
print("Updated system status cards")

# ══════════════════════════════════════════════════════════════════
# 3.  TIMELINE HEADER ROW — make it look like a real data table
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "    <div style='display:grid;grid-template-columns:90px 80px 1fr 90px 90px 80px 80px 70px;\n         gap:8px;padding:8px 14px;background:{SIDEBAR};border-radius:8px;margin-bottom:4px'>",
    "    <div style='display:grid;grid-template-columns:90px 80px 1fr 90px 90px 80px 80px 70px;\n         gap:8px;padding:9px 14px;background:#EEF2F7;border-radius:10px;margin-bottom:6px;\n         border:1px solid #E0E7EF;'>"
)
# Timeline row bg
src = src.replace(
    "        <div style='display:grid;grid-template-columns:90px 80px 1fr 90px 90px 80px 80px 70px;\n             gap:8px;padding:10px 14px;background:{CARD};border-radius:9px;\n             margin-bottom:4px;border:1px solid {BORDER};border-left:3px solid {color};",
    "        <div style='display:grid;grid-template-columns:90px 80px 1fr 90px 90px 80px 80px 70px;\n             gap:8px;padding:10px 14px;background:#FFFFFF;border-radius:11px;\n             margin-bottom:5px;border:1px solid #E0E7EF;border-left:3px solid {color};"
)
print("Updated timeline rows")

# ══════════════════════════════════════════════════════════════════
# 4.  PLOTLY CHART DEFAULTS — update backgrounds for light theme
# ══════════════════════════════════════════════════════════════════
# All charts: change dark plot bg to transparent (inherits light bg)
src = src.replace(
    'paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",',
    'paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",'
)  # already transparent — good

# Update font colors in charts from #CBD5E1 (grey-on-dark) to #6B7280 (grey-on-light)
src = src.replace('color="#CBD5E1", size=11)', 'color="#6B7280", size=11)')
src = src.replace('color="#CBD5E1", size=10)', 'color="#6B7280", size=10)')
src = src.replace('font=dict(family="Inter", color="#CBD5E1", size=11)', 'font=dict(family="Plus Jakarta Sans", color="#6B7280", size=11)')
src = src.replace('font=dict(family="Inter", color="#CBD5E1", size=10)', 'font=dict(family="Plus Jakarta Sans", color="#6B7280", size=10)')
src = src.replace('font=dict(family="Inter", color=MUTED, size=11)', 'font=dict(family="Plus Jakarta Sans", color="#6B7280", size=11)')
src = src.replace('tickfont=dict(color="#CBD5E1", size=10)', 'tickfont=dict(color="#6B7280", size=10)')
src = src.replace('tickfont=dict(color="#CBD5E1")', 'tickfont=dict(color="#6B7280")')
src = src.replace('tickfont=dict(color=MUTED)', 'tickfont=dict(color="#6B7280")')
src = src.replace('tickfont=dict(color=TEXT, size=11)', 'tickfont=dict(color="#1A202C", size=11)')
src = src.replace('tickfont=dict(color=TEXT)', 'tickfont=dict(color="#1A202C")')
src = src.replace('font=dict(color=TEXT, size=11)', 'font=dict(color="#1A202C", size=11)')
src = src.replace('font=dict(color=TEXT, size=12)', 'font=dict(color="#1A202C", size=12)')
# grid color
src = src.replace('gridcolor=BORDER', 'gridcolor="#E5E7EB"')
src = src.replace('gridcolor="#E0E7EF"', 'gridcolor="#E5E7EB"')
# annotation font colors for threshold lines
src = src.replace(
    'annotation_font=dict(color=CRIT, size=9)',
    'annotation_font=dict(color="#EF4444", size=9)'
)
src = src.replace(
    'annotation_font=dict(color=HIGH, size=9)',
    'annotation_font=dict(color="#F97316", size=9)'
)
src = src.replace(
    'annotation_font=dict(color=WARN, size=9)',
    'annotation_font=dict(color="#F59E0B", size=9)'
)
print("Updated chart styles for light theme")

# ══════════════════════════════════════════════════════════════════
# 5.  EMPTY STATE CARDS — replace dark dashed borders
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "border:2px dashed {BORDER};border-radius:14px;",
    "border:2px dashed #D1D5DB;border-radius:14px;"
)
# text colours in empty states
src = src.replace(
    "color:#CBD5E1;font-size:0.87rem'>",
    "color:#6B7280;font-size:0.87rem'>"
)
print("Updated empty state cards")

# ══════════════════════════════════════════════════════════════════
# 6.  ABOUT PAGE — upgrade hero banner
# ══════════════════════════════════════════════════════════════════
old_about_hero = """      <div style='font-size:1.4rem;font-weight:900;color:{TEXT};margin-bottom:6px'>
        Adaptive Explainable Multi-Source Cyber Threat Detection Framework using DistilBERT, XGBoost, Isolation Forest and SHAP-LIME</div>
      <div style='color:{INFO};font-size:0.88rem;font-weight:600;margin-bottom:12px'>
        Enterprise Security Operations Center · Research-Grade AI Platform</div>
      <div style='color:{MUTED};font-size:0.85rem;line-height:1.7'>"""
new_about_hero = """      <div style='font-size:1.3rem;font-weight:800;color:#F8FAFC;margin-bottom:8px;line-height:1.3'>
        Adaptive Explainable Multi-Source Cyber Threat Detection Framework using DistilBERT, XGBoost, Isolation Forest and SHAP-LIME</div>
      <div style='color:#10B981;font-size:0.86rem;font-weight:600;margin-bottom:12px'>
        Research-Grade AI Platform · B.Tech Capstone 2026–2027</div>
      <div style='color:rgba(248,250,252,0.72);font-size:0.84rem;line-height:1.7'>"""
r(old_about_hero, new_about_hero)

old_about_wrap = """    <div style='background:linear-gradient(135deg,{PRIMARY}18,{INFO}12);
         border:1px solid {PRIMARY}35;border-radius:16px;
         padding:28px 32px;margin-bottom:24px;
         box-shadow:0 6px 24px rgba(37,99,235,0.15)'>"""
new_about_wrap = """    <div style='background:linear-gradient(135deg,#0D1B2A 0%,#0E3A4A 100%);
         border:none;border-radius:18px;
         padding:30px 36px;margin-bottom:24px;
         box-shadow:0 8px 32px rgba(13,27,42,0.18)'>"""
r(old_about_wrap, new_about_wrap)
print("Updated About page hero")

# ══════════════════════════════════════════════════════════════════
# 7.  MODEL PERFORMANCE CARDS — fix dark card backgrounds
# ══════════════════════════════════════════════════════════════════
# performance summary cards
src = src.replace(
    "        <div style='background:{CARD};border-radius:14px;padding:22px;\n             border:1px solid {BORDER};border-top:4px solid {SUCCESS};text-align:center'>",
    "        <div style='background:#FFFFFF;border-radius:14px;padding:22px;\n             border:1px solid #E0E7EF;border-top:4px solid #10B981;text-align:center;\n             box-shadow:0 2px 10px rgba(0,0,0,0.04)'>"
)
src = src.replace(
    "        <div style='background:{CARD};border-radius:14px;padding:22px;\n             border:1px solid {BORDER};border-top:4px solid {INFO};text-align:center'>",
    "        <div style='background:#FFFFFF;border-radius:14px;padding:22px;\n             border:1px solid #E0E7EF;border-top:4px solid #0E7490;text-align:center;\n             box-shadow:0 2px 10px rgba(0,0,0,0.04)'>"
)
src = src.replace(
    "        <div style='background:{CARD};border-radius:14px;padding:22px;\n             border:1px solid {BORDER};border-top:4px solid {WARN};text-align:center'>",
    "        <div style='background:#FFFFFF;border-radius:14px;padding:22px;\n             border:1px solid #E0E7EF;border-top:4px solid #F59E0B;text-align:center;\n             box-shadow:0 2px 10px rgba(0,0,0,0.04)'>"
)
print("Updated model performance cards")

# ══════════════════════════════════════════════════════════════════
# 8.  DATASET INFO CARDS — improve visual styling
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "            <div style='background:{CARD};border-radius:14px;padding:22px 24px;\n                 border:1px solid {BORDER};border-left:5px solid {ds[\"color\"]};",
    "            <div style='background:#FFFFFF;border-radius:14px;padding:22px 24px;\n                 border:1px solid #E0E7EF;border-left:5px solid {ds[\"color\"]};"
)
src = src.replace(
    "                <div style='background:{SIDEBAR};border-radius:8px;padding:10px 12px'>",
    "                <div style='background:#F4F6F9;border-radius:8px;padding:10px 12px;border:1px solid #E0E7EF'>"
)
print("Updated dataset info cards")

# ══════════════════════════════════════════════════════════════════
# 9.  SYSTEM WORKFLOW STEPS — upgrade step cards
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "        <div style='background:{CARD};border-radius:14px;padding:18px 22px;\n             border:1px solid {BORDER};border-left:5px solid {color};",
    "        <div style='background:#FFFFFF;border-radius:14px;padding:18px 22px;\n             border:1px solid #E0E7EF;border-left:5px solid {color};"
)
print("Updated workflow step cards")

# ══════════════════════════════════════════════════════════════════
# 10. REPORTS / ANALYTICS PAGE — fix card backgrounds
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "        <div style='background:{CARD};border-radius:14px;padding:22px;\n             border:1px solid {BORDER};border-top:3px solid {SUCCESS};margin-bottom:12px'>",
    "        <div style='background:#FFFFFF;border-radius:14px;padding:22px;\n             border:1px solid #E0E7EF;border-top:3px solid #10B981;margin-bottom:12px;\n             box-shadow:0 2px 8px rgba(0,0,0,0.04)'>"
)
src = src.replace(
    "        <div style='background:{CARD};border-radius:14px;padding:22px;\n             border:1px solid {BORDER};border-top:3px solid {CRIT};margin-bottom:12px'>",
    "        <div style='background:#FFFFFF;border-radius:14px;padding:22px;\n             border:1px solid #E0E7EF;border-top:3px solid #EF4444;margin-bottom:12px;\n             box-shadow:0 2px 8px rgba(0,0,0,0.04)'>"
)
print("Updated reports page cards")

# ══════════════════════════════════════════════════════════════════
# 11. TIMELINE PAGE SECTION HEADER LABEL
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "    section_hdr(\"⏱\",\"Live Scan Timeline\",\n                \"Auto-updated after every scan · Full metadata · IST timestamps (Asia/Kolkata)\")",
    "    section_hdr(\"⏱\",\"Live Scan Timeline\",\n                \"Real-time event log · Full metadata · Asia/Kolkata (IST) timestamps\")"
)
print("Updated timeline page header")

# ══════════════════════════════════════════════════════════════════
# 12. FUSION PAGE INTRO — upgrade to premium card design
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "    <div style='background:{CARD};border:1px solid {BORDER};border-radius:16px;\n         padding:20px 24px;margin-bottom:20px;box-shadow:0 4px 16px rgba(0,0,0,0.3)'>",
    "    <div style='background:#FFFFFF;border:1px solid #E0E7EF;border-radius:16px;\n         padding:22px 26px;margin-bottom:22px;box-shadow:0 2px 12px rgba(0,0,0,0.05)'>"
)
# fusion source boxes inside the grid
src = src.replace(
    "                <div style='background:#0A1220;border:1px solid {BORDER};border-radius:9px;\n                        padding:9px 10px;text-align:center'>",
    "                <div style='background:#F4F6F9;border:1px solid #E0E7EF;border-radius:9px;\n                        padding:9px 10px;text-align:center'>"
)
print("Updated fusion page intro")

# ══════════════════════════════════════════════════════════════════
# 13. SIMULATION PAGE BADGE styling
# ══════════════════════════════════════════════════════════════════
src = src.replace(
    "    <div style='background:{PURPLE}15;border:1px solid {PURPLE}35;border-radius:12px;\n         padding:14px 18px;margin-bottom:20px;border-left:3px solid {PURPLE}'>",
    "    <div style='background:#F5F3FF;border:1px solid #DDD6FE;border-radius:12px;\n         padding:14px 18px;margin-bottom:20px;border-left:4px solid #7C3AED'>"
)
print("Updated simulation page")

# ══════════════════════════════════════════════════════════════════
# 14. ALL REMAINING GENERIC {CARD} background references in page content
# ══════════════════════════════════════════════════════════════════
# Replace any leftover {CARD} and {BORDER} in HTML string literals
src = src.replace("background:{CARD};border-radius:12px;border:1px solid {BORDER};",
                  "background:#FFFFFF;border-radius:12px;border:1px solid #E0E7EF;")
src = src.replace("background:{CARD};border-radius:14px;border:1px solid {BORDER};",
                  "background:#FFFFFF;border-radius:14px;border:1px solid #E0E7EF;")
src = src.replace("background:{CARD};border-radius:9px;padding:9px 13px;",
                  "background:#FFFFFF;border-radius:9px;padding:9px 13px;")
src = src.replace("background:{CARD};border-radius:11px;padding:14px 15px;",
                  "background:#FFFFFF;border-radius:11px;padding:14px 15px;")
# text colours
src = src.replace("color:{MUTED};font-size:0.83rem'>", "color:#6B7280;font-size:0.83rem'>")
src = src.replace("color:{TEXT};font-size:1rem;font-weight:700;", "color:#1A202C;font-size:1rem;font-weight:700;")
print("Replaced remaining CARD/BORDER/MUTED/TEXT literals")

# ══════════════════════════════════════════════════════════════════
# 15. SYNTAX CHECK & WRITE
# ══════════════════════════════════════════════════════════════════
import ast
try:
    ast.parse(src)
    print("SYNTAX OK")
except SyntaxError as e:
    print(f"SYNTAX ERROR line {e.lineno}: {e.msg}")
    raise

SRC.write_text(src, encoding="utf-8")
print(f"Written: {src.count(chr(10))} lines (was {original})")
print("DONE — all page redesigns applied.")
