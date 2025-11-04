# tinysocs/orchestrator/__init__.py
import sys
import importlib as _il

_pkg = __name__

def _bind(mod: str) -> None:
    try:
        m = _il.import_module(f"orchestrator.{mod}")
        sys.modules[f"{_pkg}.{mod}"] = m
    except Exception:
        pass

for _m in ("master", "anchors"):
    _bind(_m)

del _il, _bind, _pkg, _m