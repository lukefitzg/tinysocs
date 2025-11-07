# tinysocs/agent/__init__.py
# Allow both `tinysocs.agent.*` and flat `agent.*`
import importlib as _il
import sys

try:
    m = _il.import_module("agent")
    sys.modules[__name__] = m
except Exception:
    pass
del _il
