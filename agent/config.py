# tinysocs/agent/config.py
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path

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

def load() -> Config:
    siem_url = os.getenv("SIEM_URL", "https://localhost:9201")
    siem_user = os.getenv("SIEM_USER", "admin")
    siem_pass = os.getenv("SIEM_PASS", "ChangeMe123!")
    ssl_verify = _to_bool(os.getenv("SIEM_SSL_VERIFY"), False)
    actions_queue_path = Path(os.getenv("ACTIONS_QUEUE_PATH", "./data/actions_queue.jsonl")).resolve()
    rules_path = Path(os.getenv("TINYSOCS_RULES", "tinysocs/agent/detections/rules.yaml")).resolve()
    actions_queue_path.parent.mkdir(parents=True, exist_ok=True)
    return Config(siem_url, siem_user, siem_pass, ssl_verify, actions_queue_path, rules_path)
