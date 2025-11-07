import sys, importlib as _il
_pkg = __name__
# Try to alias flat package into namespaced path
try:
    pkg = _il.import_module("agent.detections")
    sys.modules[_pkg] = pkg
except Exception:
    pkg = None
# Ensure submodules resolve at tinysocs.agent.detections.*
for _mod in ("engine",):
    try:
        m = _il.import_module(f"agent.detections.{_mod}")
        sys.modules[f"{_pkg}.{_mod}"] = m
    except Exception:
        pass
del _il, _mod, _pkg, pkg
