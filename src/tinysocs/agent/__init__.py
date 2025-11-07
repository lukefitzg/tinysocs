import sys, importlib as _il
_pkg = __name__
try:
    pkg = _il.import_module("agent")
    sys.modules[_pkg] = pkg
except Exception:
    pass
del _il, _pkg
