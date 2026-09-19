# streamlit_app.py — Root entry point for Streamlit Cloud deployment
# Streamlit Cloud looks for this file at the repo root.
# This file re-executes the actual dashboard so all code runs in Streamlit context.

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Execute the dashboard module directly in this process
with open(os.path.join(os.path.dirname(__file__), "src", "dashboard", "app.py"),
          encoding="utf-8") as _f:
    exec(compile(_f.read(), "src/dashboard/app.py", "exec"))
