# PyInstaller runtime hook:
# Alias imports from "tinysocs.*" to the bundled flat packages ("api.*", "agent.*", "orchestrator.*"),
# including deep submodules like "tinysocs.agent.models.evidence".
# Also backfill the *reverse* direction when only namespaced modules exist, and
# synthesize a safe fallback for `agent.adapters.select.make_client()` that
# uses the bundled OpenSearch client if the selector module isn't present.

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
import types


# ---------- helpers ----------
def _ensure_pkg(name: str) -> types.ModuleType:
    m = sys.modules.get(name)
    if isinstance(m, types.ModuleType):
        # ensure it looks like a package for submodule imports
        if not hasattr(m, "__path__"):
            try:
                m.__path__ = []  # type: ignore[attr-defined]
            except Exception:
                pass
        return m
    m = types.ModuleType(name)
    try:
        m.__path__ = []  # type: ignore[attr-defined]
    except Exception:
        pass
    sys.modules[name] = m
    return m

def _opt_import(name: str):
    try:
        return importlib.import_module(name)
    except Exception:
        return None

# Ensure a root "tinysocs" pkg exists so "import tinysocs" never fails.
_ensure_pkg("tinysocs")

# Map first segment under "tinysocs" -> flat package name
_HEAD_MAP = {
    "api": "api",
    "agent": "agent",
    "orchestrator": "orchestrator",
}

def _fallback_name(fullname: str) -> str | None:
    # "tinysocs.X[.rest]" -> "X[.rest]" if X in _HEAD_MAP
    if not fullname.startswith("tinysocs."):
        return None
    rest = fullname[len("tinysocs."):]  # "api.bot" / "agent.models.evidence" / "api"
    head, sep, tail = rest.partition(".")
    flat_head = _HEAD_MAP.get(head)
    if not flat_head:
        return None
    return flat_head if not sep else f"{flat_head}.{tail}"

class _TinySocsAliasFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Meta path finder/loader that transparently aliases tinysocs.* -> flat pkgs."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "tinysocs":
            # Already injected as a package module above
            return importlib.machinery.ModuleSpec("tinysocs", loader=self, is_package=True)

        fb = _fallback_name(fullname)
        if not fb:
            return None  # not our namespace

        # If the fallback exists, we promise to load fullname.
        try:
            fb_spec = importlib.util.find_spec(fb)
        except Exception:
            fb_spec = None
        if not fb_spec:
            return None

        is_pkg = fb_spec.submodule_search_locations is not None
        return importlib.machinery.ModuleSpec(fullname, loader=self, is_package=is_pkg)

    def create_module(self, spec):
        # Use default module creation semantics
        return None

    def exec_module(self, module):
        fullname = module.__name__
        fb = _fallback_name(fullname)
        # Import the real flat module and alias it under the tinysocs.* name
        real = importlib.import_module(fb)
        sys.modules[fullname] = real

        # Ensure parents (tinysocs, tinysocs.head, tinysocs.head.sub, …) exist and reference the child.
        parts = fullname.split(".")
        for i in range(1, len(parts)):
            parent_name = ".".join(parts[:i])
            child_name  = ".".join(parts[: i+1])
            parent = sys.modules.get(parent_name)
            child  = sys.modules.get(child_name)
            if parent and child:
                setattr(parent, parts[i], child)

# Install our finder at the *front* so it wins.
if not any(isinstance(f, _TinySocsAliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _TinySocsAliasFinder())

# ---------- Reverse aliasing (flat -> namespaced) when only namespaced exists ----------
for head in ("api", "agent", "orchestrator"):
    flat_name = head
    ns_name = f"tinysocs.{head}"
    if flat_name not in sys.modules and _opt_import(ns_name):
        sys.modules[flat_name] = sys.modules[ns_name]

# ---------- Synthesize selector fallback if missing ----------
# Make sure 'agent' and 'agent.adapters' pkgs exist (flat side, since api.node imports flat).
_ensure_pkg("agent")
_ensure_pkg("agent.adapters")
_ensure_pkg("tinysocs.agent")
_ensure_pkg("tinysocs.agent.adapters")

# Module-level cache for the OpenSearch client class
OSC = None  # will be resolved lazily

if _opt_import("agent.adapters.select") is None:
    # Try to locate an OpenSearch client implementation from either path.
    for cand in (
        "tinysocs.agent.adapters.opensearch_client",
        "agent.adapters.opensearch_client",
    ):
        mod = _opt_import(cand)
        if mod and hasattr(mod, "OpenSearchClient"):
            OSC = getattr(mod, "OpenSearchClient")
            break

    sel = types.ModuleType("agent.adapters.select")

    def make_client():
        global OSC
        # Late bind if not resolved yet (aliasing above might make it available later).
        if OSC is None:
            mod2 = _opt_import("tinysocs.agent.adapters.opensearch_client") or _opt_import("agent.adapters.opensearch_client")
            if mod2 and hasattr(mod2, "OpenSearchClient"):
                OSC = getattr(mod2, "OpenSearchClient")
        if OSC is None:
            raise ImportError("OpenSearchClient not available for fallback client")
        return OSC()

    sel.make_client = make_client  # type: ignore[attr-defined]
    # Register under both flat and namespaced paths
    sys.modules["agent.adapters.select"] = sel
    sys.modules["tinysocs.agent.adapters.select"] = sel
    # Stitch into package attributes for attribute-based imports
    setattr(sys.modules["agent.adapters"], "select", sel)
    setattr(sys.modules["tinysocs.agent.adapters"], "select", sel)

# ---------- Keep opensearch_client visible both ways ----------
osc_flat  = _opt_import("agent.adapters.opensearch_client")
osc_ns    = _opt_import("tinysocs.agent.adapters.opensearch_client")
if osc_flat and not osc_ns:
    sys.modules["tinysocs.agent.adapters.opensearch_client"] = osc_flat
    setattr(sys.modules["tinysocs.agent.adapters"], "opensearch_client", osc_flat)
elif osc_ns and not osc_flat:
    sys.modules["agent.adapters.opensearch_client"] = osc_ns
    setattr(sys.modules["agent.adapters"], "opensearch_client", osc_ns)
