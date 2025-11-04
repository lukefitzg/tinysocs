import sys, importlib as _il
_pkg = __name__
try:
    pkg = _il.import_module("agent.adapters")
    sys.modules[_pkg] = pkg
except Exception:
    pkg = None
for _mod in ("select","opensearch_client"):
    try:
        m = _il.import_module(f"agent.adapters.{_mod}")
        sys.modules[f"{_pkg}.{_mod}"] = m
    except Exception:
        pass
del _il, _mod, _pkg, pkg
