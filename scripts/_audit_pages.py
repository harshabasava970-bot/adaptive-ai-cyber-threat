import re
src = open('src/dashboard/app.py', encoding='utf-8').read()
pages_elif = re.findall(r'elif page == "([^"]+)"', src)
pages_if   = re.findall(r'if page == "([^"]+)"', src)
all_pages  = pages_if + pages_elif
print(f"Total lines: {src.count(chr(10))}")
print(f"Pages ({len(all_pages)}):")
for p in all_pages:
    print(f"  {p}")
# also find streamlit_app.py
import pathlib
sp = pathlib.Path('streamlit_app.py')
if sp.exists():
    print(f"\nstreamlit_app.py exists ({sp.stat().st_size} bytes)")
