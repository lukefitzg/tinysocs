import sys, importlib as _il
_pkg = __name__
for _mod in ("master","anchors"):
    try:
        m = _il.import_module(f"orchestrator.{_mod}")
        sys.modules[f"{_pkg}.{_mod}"] = m
    except Exception:
        pass
del _il, _mod, _pkg
