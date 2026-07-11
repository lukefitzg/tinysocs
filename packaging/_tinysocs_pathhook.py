# packaging/_tinysocs_pathhook.py
# Ensure the bundled 'tinysocs' source tree (added as data) is importable at runtime.
import os
import sys

try:
    meipass = getattr(sys, "_MEIPASS", None)  # PyInstaller temp dir
    if meipass:
        p = os.path.join(meipass, "tinysocs")
        if os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)
except Exception:
    # Non-fatal: launcher will print import warnings if this fails.
    pass
