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

hiddenimports = []
try: hiddenimports += collect_submodules("tinysocs")
except Exception: pass

# must-haves for runtime
hiddenimports += ["fastapi","uvicorn","pydantic","yaml","httpx","starlette","anyio","sniffio","h11","idna","certifi"]

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
