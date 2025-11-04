# tinysocs/api/__init__.py
# Surface flat `api.node`/`api.bot` as `tinysocs.api.node`/`tinysocs.api.bot`
import sys, importlib as _il
_pkg = __name__

for _mod in ("node", "bot"):
    try:
        m = _il.import_module(f"api.{_mod}")
        sys.modules[f"{_pkg}.{_mod}"] = m
    except Exception:
        pass

del _il, _mod, _pkg