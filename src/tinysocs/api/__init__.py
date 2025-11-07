import sys, importlib as _il
_pkg = __name__
for _mod in ("bot","node"):
    try:
        m = _il.import_module(f"api.{_mod}")
        sys.modules[f"{_pkg}.{_mod}"] = m
    except Exception:
        pass
del _il, _pkg, _mod
