# tinysocs/api/__init__.py
"""Thin shims so 'tinysocs.api.*' resolves to flat 'api.*' at runtime."""
import importlib as _il, sys as _sys

# Preload the flat package if possible (not fatal if absent during analysis)
try:
    _il.import_module("api")
except Exception:
    pass

# Alias known submodules when present
for _name in ("node", "bot", "bot_actions"):
    try:
        _flat = _il.import_module(f"api.{_name}")
        _pkg  = _il.import_module(f"tinysocs.api")  # this module
        # Create a proper module object under 'tinysocs.api.<name>'
        _sys.modules[f"tinysocs.api.{_name}"] = _flat
    except Exception:
        pass

del _il, _sys, _name, _flat, _pkg