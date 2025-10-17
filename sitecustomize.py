# C:\tinysocs\tinysocs\sitecustomize.py
# Ensure the package root (parent of this folder) is on sys.path when running from tinysocs/tinysocs
from pathlib import Path
import sys

_here = Path(__file__).resolve().parent          # ...\tinysocs\tinysocs
_root = _here.parent                              # ...\tinysocs
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))