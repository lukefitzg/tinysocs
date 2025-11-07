# Allow both `tinysocs.agent.detections.*` and flat `agent.detections.*`
import sys, importlib as _il
_pkg = __name__

# Alias the flat package into this namespace (if present)
try:
    pkg = _il.import_module("agent.detections")
    sys.modules[_pkg] = pkg
except Exception:
    pkg = None  # optional

# Ensure key submodules are reachable at tinysocs.agent.detections.*
for _mod in ("engine",):
    try:
        m = _il.import_module(f"agent.detections.{_mod}")
        sys.modules[f"{_pkg}.{_mod}"] = m
    except Exception:
        pass

del _il, _mod, _pkg, pkg
