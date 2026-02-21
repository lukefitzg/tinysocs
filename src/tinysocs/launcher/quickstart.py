# tinysocs/launcher/quickstart.py
from __future__ import annotations

import importlib
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    def load_dotenv(*_a, **_k): return False

import uvicorn


# --------------------------------------------------------------------------- #
# Env + .env loading
# --------------------------------------------------------------------------- #
def _load_env() -> None:
    here = Path(__file__).resolve()
    candidates: list[Path] = []
    for n in (3, 2):
        try:
            candidates.append(here.parents[n] / ".env")
        except Exception:
            pass
    candidates.append(Path.cwd() / ".env")
    for p in candidates:
        try:
            if p.is_file():
                load_dotenv(p, override=False)
                break
        except Exception:
            pass

# --------------------------------------------------------------------------- #
# Frozen-bundle import help (EXE)
# --------------------------------------------------------------------------- #
def _extend_sys_path_for_frozen() -> None:
    """
    When frozen (PyInstaller), ensure the extracted bundle dir and the EXE dir
    are on sys.path, and explicitly add subfolders that hold code we ship as
    plain files (tinysocs/, api/, orchestrator/, agent/).
    """
    base_candidates: list[Path] = []
    if getattr(sys, "frozen", False):
        # PyInstaller extraction dir
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            base_candidates.append(Path(meipass))
        # The onedir dist folder where the EXE lives
        try:
            base_candidates.append(Path(sys.executable).resolve().parent)
        except Exception:
            pass

    for base in base_candidates:
        # Add the base folder itself
        b = str(base)
        if b and b not in sys.path:
            sys.path.insert(0, b)
        # Add known source subfolders if present
        for name in ("tinysocs", "api", "orchestrator", "agent"):
            p = base / name
            if p.exists():
                sp = str(p)
                if sp not in sys.path:
                    sys.path.insert(0, sp)

# --------------------------------------------------------------------------- #
# Import helpers
# --------------------------------------------------------------------------- #
def _import_app_obj(module_attr: str) -> Optional[Any]:
    """Try to import 'package.module:attr' and return the attribute (ASGI app)."""
    try:
        mod, _, attr = module_attr.partition(":")
        if not mod or not attr:
            return None
        m = importlib.import_module(mod)
        return getattr(m, attr, None)
    except Exception:
        return None

def _import_func(module_name: str, attr: str) -> Optional[Any]:
    """Import a function attr from module_name; return None if not found."""
    try:
        m = importlib.import_module(module_name)
        return getattr(m, attr, None)
    except Exception:
        return None

def _start_uvicorn(
    app_or_str: Any, port: int, host: str = "127.0.0.1",
    ssl_certfile: str = "", ssl_keyfile: str = "",
) -> uvicorn.Server:
    ssl_kwargs: dict = {}
    if ssl_certfile and ssl_keyfile:
        ssl_kwargs = {"ssl_certfile": ssl_certfile, "ssl_keyfile": ssl_keyfile}
    cfg = uvicorn.Config(
        app_or_str, host=host, port=port,
        log_level=os.getenv("UVICORN_LOG_LEVEL", "warning"),
        **ssl_kwargs,
    )
    srv = uvicorn.Server(cfg)
    threading.Thread(target=srv.run, daemon=True).start()
    time.sleep(1.0)
    return srv

def _maybe_add_local_tinysocs_to_sys_path() -> None:
    """
    If running from source, prepend the repo root so 'tinysocs' (and flat tree)
    imports succeed.
    """
    here = Path(__file__).resolve()
    for candidate in (here.parents[1], here.parents[2], Path.cwd()):
        t = candidate / "tinysocs"
        if (t / "__init__.py").exists() or t.is_dir():
            p = str(candidate)
            if p not in sys.path:
                sys.path.insert(0, p)
            break

def _choose_app_spec() -> tuple[Any, Any, str]:
    """
    Return (node_spec, bot_spec, strategy) where *spec can be an app object
    or an import string suitable for uvicorn.
    """
    frozen = bool(getattr(sys, "frozen", False))
    strategy_env = (os.getenv("QUICKSTART_IMPORT_STRATEGY") or "").strip().lower()
    strategy = strategy_env or ("package" if frozen else "package")

    def have(mod: str) -> bool:
        try:
            import importlib.util as _iu
            return _iu.find_spec(mod) is not None
        except Exception:
            return False

    def pick(pkg: str, flat: str) -> tuple[Any, Any, str]:
        nonlocal strategy
        if strategy == "flat":
            if not have("api"):
                print("[quickstart] flat strategy requested but 'api' not bundled → switching to 'package'")
                strategy = "package"
        if strategy == "package":
            if have("tinysocs.api"):
                n = _import_app_obj("tinysocs.api.node:app")
                b = _import_app_obj("tinysocs.api.bot:app")
                if n and b:
                    return n, b, "package"
            # fall through to flat if package missing
            strategy = "flat"

        if strategy == "flat" and have("api"):
            n = _import_app_obj("api.node:app")
            b = _import_app_obj("api.bot:app")
            if n and b:
                return n, b, "flat"

        # Last resort: import strings; uvicorn will import lazily
        return f"{pkg}.node:app", f"{pkg}.bot:app", "import-string"

    node_spec, bot_spec, used = pick("tinysocs.api", "api")
    if used == "import-string":
        # If we fell all the way through, prefer package strings if present; else flat strings.
        if have("tinysocs.api"):
            print("[quickstart] using import string (last resort) <- tinysocs.api.node:app")
            print("[quickstart] using import string (last resort) <- tinysocs.api.bot:app")
            return "tinysocs.api.node:app", "tinysocs.api.bot:app", used
        elif have("api"):
            print("[quickstart] using import string (last resort) <- api.node:app")
            print("[quickstart] using import string (last resort) <- api.bot:app")
            return "api.node:app", "api.bot:app", used
        else:
            # no visible modules — still return package strings; path shim may make them importable
            print("[quickstart] neither 'tinysocs.api' nor 'api' visible; relying on path shim + import strings")
            return "tinysocs.api.node:app", "tinysocs.api.bot:app", used
    return node_spec, bot_spec, used

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    _load_env()

    # Make imports work in both dev (source) and frozen (EXE) modes
    if getattr(sys, "frozen", False):
        _extend_sys_path_for_frozen()
    else:
        _maybe_add_local_tinysocs_to_sys_path()

    # Sane local defaults
    os.environ.setdefault("SIEM_URL", "https://127.0.0.1:9201")
    os.environ.setdefault("SIEM_SSL_VERIFY", "false")
    os.environ.setdefault("MASTER_SHARED_SECRET", "dev-secret-change-me")
    os.environ.setdefault("TINYSOCS_QUEUE_PATH", ".\\data\\actions_queue.jsonl")

    host = os.getenv("DASHBOARD_BIND", os.getenv("HOST", "127.0.0.1"))
    node_port = int(os.getenv("NODE_PORT", os.getenv("PORT", "8081")))
    bot_port  = int(os.getenv("BOT_PORT", "8090"))

    # Dashboard TLS config (Phase 14 M0)
    tls_cert = os.getenv("DASHBOARD_TLS_CERT", "").strip()
    tls_key = os.getenv("DASHBOARD_TLS_KEY", "").strip()
    if host != "127.0.0.1" and not (tls_cert and tls_key):
        print("[quickstart] WARNING: Network bind requested but no TLS certs configured. "
              "Falling back to localhost.")
        host = "127.0.0.1"
    if tls_cert and tls_key:
        print(f"[quickstart] TLS enabled: cert={tls_cert}")

    frozen = bool(getattr(sys, "frozen", False))
    node_spec, bot_spec, used = _choose_app_spec()
    print(f"[quickstart] frozen={frozen} import_strategy={used}")

    print(f"[quickstart] starting Node@{host}:{node_port} + Bot@{host}:{bot_port} ...")
    _start_uvicorn(node_spec, node_port, host=host)
    _start_uvicorn(bot_spec, bot_port, host=host,
                   ssl_certfile=tls_cert, ssl_keyfile=tls_key)

    # One master run (preview) — try package path, then flat path
    run_master = _import_func("tinysocs.orchestrator.master", "run_master") \
                 or _import_func("orchestrator.master", "run_master")
    if run_master is None:
        print("[quickstart] master WARN: run_master not found (tinysocs.orchestrator.master / orchestrator.master)")
    else:
        try:
            os.environ.setdefault("TINYSOCS_NODES", f"http://localhost:{node_port}")
            run_master(
                rules="auth_failed_burst,script_block_volume",
                window="15m",
                host=None,
                deadline_sec=float(os.getenv("MASTER_DEADLINE_SEC", "20")),
                always_anchor=False,
            )
        except Exception as e:
            print(f"[quickstart] master WARN: {e}")

    # Doctor (anchors ensure) — try both module paths
    ensure_anchors = _import_func("tinysocs.orchestrator.anchors", "ensure_anchors_if_missing") \
                     or _import_func("orchestrator.anchors", "ensure_anchors_if_missing")
    if ensure_anchors is None:
        print("[quickstart] doctor: anchors ensure WARN -> helper not found")
    else:
        try:
            ensure_anchors()
            print("[quickstart] doctor: anchors ensure OK")
        except Exception as e:
            print(f"[quickstart] doctor: anchors ensure WARN -> {e}")

    print("[quickstart] ready.")
    # Keep servers alive in frozen builds; also stay up if explicitly requested
    if getattr(sys, "frozen", False) or os.getenv("QUICKSTART_STAY_UP") in ("1","true","yes","on"):
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            pass
    else:
        time.sleep(5.0)

# Console-script entrypoint expects `cli`
def cli() -> None:
    main()

if __name__ == "__main__":
    main()
