# -*- mode: python ; coding: utf-8 -*-
import os, sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, COLLECT
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

SPEC_DIR    = os.path.abspath(os.path.dirname(sys.argv[0])) if (sys.argv and sys.argv[0]) else os.getcwd()
REPO        = os.path.abspath(os.path.join(SPEC_DIR, '..'))
PKG_SRC     = os.path.join(REPO, 'tinysocs')
ROOT_LAUNCH = os.path.join(REPO, 'launcher', 'quickstart.py')
PKG_LAUNCH  = os.path.join(PKG_SRC, 'launcher', 'quickstart.py')

SCRIPT = PKG_LAUNCH if os.path.isfile(PKG_LAUNCH) else ROOT_LAUNCH
if not os.path.isfile(SCRIPT):
    raise SystemExit(f"quickstart.py not found at {PKG_LAUNCH} or {ROOT_LAUNCH}")

# data files (yaml)
datas = collect_data_files("tinysocs", includes=["**/*.yaml", "**/*.yml"])
flat_rules = os.path.join(REPO, "agent", "detections", "rules.yaml")
if os.path.isfile(flat_rules):
    datas.append((flat_rules, os.path.join("tinysocs", "agent", "detections")))
pkg_rules = os.path.join(PKG_SRC, "agent", "detections", "rules.yaml")
if os.path.isfile(pkg_rules):
    datas.append((pkg_rules, os.path.join("tinysocs", "agent", "detections")))

# hidden imports (packaged + flat)
hidden = []
# packaged tree
try:
    hidden += collect_submodules("tinysocs")
except Exception:
    pass

# flat top-level pkgs
for ns in ("api", "orchestrator", "agent"):
    try:
        hidden += collect_submodules(ns)
    except Exception:
        pass

# explicitly drag the subpackages we care about (defensive)
for ns in (
    "agent.adapters",
    "agent.detections",
    "agent.models",
):
    try:
        hidden += collect_submodules(ns)
    except Exception:
        pass

# explicit must-haves
hidden += [
    # flat
    "api", "api.node", "api.bot",
    "orchestrator", "orchestrator.master", "orchestrator.anchors",
    "agent", "agent.adapters", "agent.adapters.select", "agent.adapters.opensearch_client",
    "agent.detections", "agent.detections.engine",
    "agent.models", "agent.models.evidence",
    "agent.llm_select", "agent.llm_openai_tools", "agent.llm_ollama",
    "agent.actions_queue", "agent.config", "agent.netutil",
    "agent.summarizer_adapter", "agent.report", "agent.tools", "agent.privacy", "agent.redact", "agent.enrich", "agent.main",
    # web/runtime stack
    "fastapi", "uvicorn", "pydantic", "yaml", "httpx", "starlette", "anyio", "sniffio", "h11", "idna", "certifi",
]

try:
    import tzdata  # noqa
    hidden.append("tzdata")
except Exception:
    pass

# de-dupe preserving order
_seen = set()
hiddenimports = [m for m in hidden if not (m in _seen or _seen.add(m))]

# runtime hook that aliases tinysocs.* -> flat pkgs when needed
runtime_hook = os.path.join(SPEC_DIR, "_rt_tinysocs_alias.py")

a = Analysis(
    [SCRIPT],
    pathex=[REPO, PKG_SRC],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[runtime_hook],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="TinySocs-Quickstart",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)

coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=True, upx_exclude=[],
    name="TinySocs-Quickstart",
)