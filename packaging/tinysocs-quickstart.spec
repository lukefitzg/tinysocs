# -*- mode: python ; coding: utf-8 -*-
import os, sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

SPEC_DIR   = os.path.abspath(os.path.dirname(sys.argv[0])) if (sys.argv and sys.argv[0]) else os.getcwd()
REPO       = os.path.abspath(os.path.join(SPEC_DIR, '..'))
SRC_DIR    = os.path.join(REPO, 'src')
PKG_SRC    = os.path.join(SRC_DIR, 'tinysocs')
ROOT_LAUNCH = os.path.join(REPO, 'launcher', 'quickstart.py')
PKG_LAUNCH  = os.path.join(PKG_SRC, 'launcher', 'quickstart.py')

SCRIPT = PKG_LAUNCH if os.path.isfile(PKG_LAUNCH) else ROOT_LAUNCH
if not os.path.isfile(SCRIPT):
    raise SystemExit(f"quickstart.py not found at {PKG_LAUNCH} or {ROOT_LAUNCH}")

datas = collect_data_files("tinysocs", includes=["**/*.yaml","**/*.yml"])

# Explicit fallback: collect_data_files may miss files when tinysocs isn't pip-installed.
# Walk PKG_SRC for YAML/YML files and add any that aren't already in datas.
import glob as _glob
_existing_srcs = {os.path.normpath(s) for s, _ in datas}
for _pattern in ("**/*.yaml", "**/*.yml"):
    for _f in _glob.glob(os.path.join(PKG_SRC, _pattern), recursive=True):
        if os.path.normpath(_f) not in _existing_srcs:
            _rel = os.path.relpath(os.path.dirname(_f), SRC_DIR)
            datas.append((_f, _rel))

hiddenimports = []
try: hiddenimports += collect_submodules("tinysocs")
except Exception: pass

# must-haves for runtime
hiddenimports += ["fastapi","uvicorn","pydantic","yaml","httpx","starlette","anyio","sniffio","h11","idna","certifi"]

# LLM backends (optional — tolerate missing)
for _pkg in ("anthropic", "openai"):
    try: hiddenimports += collect_submodules(_pkg)
    except Exception: pass

a = Analysis(
    [SCRIPT],
    pathex=[REPO, SRC_DIR],
    binaries=[], datas=datas, hiddenimports=hiddenimports,
    hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="TinySocs-Quickstart",
    debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False, console=True,
)
coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=False, upx_exclude=[],
    name="TinySocs-Quickstart",
)
