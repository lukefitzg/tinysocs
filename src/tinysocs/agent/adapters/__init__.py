# tinysocs/agent/adapters/__init__.py
# Allow both `tinysocs.agent.adapters.*` and flat `agent.adapters.*`
import sys, importlib as _il
_pkg = __name__

# Alias the flat package
try:
    pkg = _il.import_module("agent.adapters")
    sys.modules[_pkg] = pkg
except Exception:
    pkg = None  # optional

# Also alias common submodules explicitly
for _mod in ("select", "opensearch_client"):
    try:
        m = _il.import_module(f"agent.adapters.{_mod}")
        sys.modules[f"{_pkg}.{_mod}"] = m
    except Exception:
        pass

del _il, _mod, _pkg, pkg
