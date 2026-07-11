# actions_queue.py
"""
TinySocs local action staging queue.
Stores candidate response actions (dry-run only).
Later phases will expose these via API/UI for human approval.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

# Use unified config so defaults are cross-platform and directory is auto-created.
from tinysocs.agent.config import load as load_config

_CFG = load_config()
QUEUE_PATH = Path(os.getenv("ACTIONS_QUEUE_PATH", str(_CFG.actions_queue_path))).resolve()


def _ensure_file() -> None:
    QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not QUEUE_PATH.exists():
        QUEUE_PATH.write_text("", encoding="utf-8")


def stage_actions(actions: list[dict[str, Any]]) -> None:
    """
    Append staged actions to local queue (JSON Lines format).
    Each entry gets a timestamp and context.
    """
    if not actions:
        return

    _ensure_file()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with QUEUE_PATH.open("a", encoding="utf-8") as f:
        for a in actions:
            entry = {
                "timestamp": ts,
                "action": a.get("action"),
                "params": a.get("params", {}),
                "status": "staged",
            }
            f.write(json.dumps(entry) + "\n")


def load_queue(limit: int = 50) -> list[dict[str, Any]]:
    """
    Read back most recent staged actions for debugging or inspection.
    """
    _ensure_file()
    with QUEUE_PATH.open("r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]
    return [json.loads(line) for line in lines if line.strip()]


def clear_queue() -> None:
    """Erase all staged entries (for testing only)."""
    _ensure_file()
    QUEUE_PATH.write_text("", encoding="utf-8")
