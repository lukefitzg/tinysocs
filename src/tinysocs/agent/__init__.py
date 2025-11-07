# tinysocs/agent/__init__.py
# Allow both `tinysocs.agent.*` and flat `agent.*`
import sys, importlib as _il
try:
    m = _il.import_module("agent")
    sys.modules[__name__] = m
except Exception:
    pass
del _il
