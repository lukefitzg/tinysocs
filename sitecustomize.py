"""
TinySocs – sitecustomize.py
Auto-loads the local .env file for per-repo persistence.
Executed automatically by Python for every interpreter started in this repo.
"""

import os
import sys
from pathlib import Path

# --- Ensure repo root is importable ---
_here = Path(__file__).resolve().parent          # ...\tinysocs\tinysocs
_root = _here.parent                              # ...\tinysocs
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

# --- Auto-load .env from repo root ---
def _load_env():
    try:
        from dotenv import load_dotenv, find_dotenv
        # usecwd=True so it finds .env even when running submodules
        env_file = find_dotenv(usecwd=True)
        if env_file:
            load_dotenv(env_file, override=False)
            print(f"[sitecustomize] Loaded environment from {env_file}")
        else:
            print("[sitecustomize] No .env file found.")
    except Exception:
        # Fallback manual parser
        env_path = Path.cwd() / ".env"
        if env_path.is_file():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
            print(f"[sitecustomize] Fallback parser loaded environment from {env_path}")

_load_env()