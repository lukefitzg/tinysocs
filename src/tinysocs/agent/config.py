# tinysocs/agent/config.py
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from tinysocs.env import load_dotenv_if_present
load_dotenv_if_present(Path(__file__).resolve())

# Package root (â€¦/tinysocs)
PKG_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Config:
    siem_url: str
    siem_user: str
    siem_pass: str
    ssl_verify: bool
    actions_queue_path: Path
    rules_path: Path


def _to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _prod_guard(cfg: Config, env_mode: str) -> None:
    """
    Refuse to run with dangerous defaults when ENV=prod.
    """
    if env_mode.lower() != "prod":
        return

    if cfg.siem_url.startswith("http://localhost") or cfg.siem_url.startswith("https://localhost"):
        raise RuntimeError("Refusing to run in prod with SIEM_URL pointing at localhost.")

    if cfg.siem_user.lower() in {"admin", "changeme"}:
        raise RuntimeError("Refusing to run in prod with default SIEM_USER.")

    if cfg.siem_pass in {"ChangeMe", "ChangeMe123!", "changeme"}:
        raise RuntimeError("Refusing to run in prod with default SIEM_PASS.")


def load() -> Config:
    load_dotenv_if_present(Path(__file__).resolve())

    siem_url = os.getenv("SIEM_URL", "https://localhost:9201")
    siem_user = os.getenv("SIEM_USER", "admin")
    siem_pass = os.getenv("SIEM_PASS", "ChangeMe123!")
    ssl_verify = _to_bool(os.getenv("SIEM_SSL_VERIFY"), False)

    # Cross-platform default; ensure parent directory exists
    actions_queue_path = Path(os.getenv("ACTIONS_QUEUE_PATH", "./data/actions_queue.jsonl")).resolve()
    actions_queue_path.parent.mkdir(parents=True, exist_ok=True)

    # Rules file (still overridable) â€” now anchored to package root
    rules_path = Path(os.getenv(
        "TINYSOCS_RULES",
        str(PKG_ROOT / "agent" / "detections" / "rules.yaml")
    )).resolve()

    cfg = Config(siem_url, siem_user, siem_pass, ssl_verify, actions_queue_path, rules_path)

    # Production safety checks
    env_mode = os.getenv("ENV", "dev")
    _prod_guard(cfg, env_mode)

    return cfg
