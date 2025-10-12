# actions_queue.py
"""
TinySocs local action staging queue.
Stores candidate response actions (dry-run only).
Later phases will expose these via API/UI for human approval.
"""

import json
import os
import time
from typing import Dict, Any, List

QUEUE_PATH = os.getenv("ACTIONS_QUEUE_PATH", "C:\\tinysocs\\agent\\actions_queue.jsonl")

def _ensure_file():
    os.makedirs(os.path.dirname(QUEUE_PATH), exist_ok=True)
    if not os.path.exists(QUEUE_PATH):
        with open(QUEUE_PATH, "w", encoding="utf-8") as f:
            f.write("")

def stage_actions(actions: List[Dict[str, Any]]):
    """
    Append staged actions to local queue (JSON Lines format).
    Each entry gets a timestamp and context.
    """
    if not actions:
        return

    _ensure_file()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with open(QUEUE_PATH, "a", encoding="utf-8") as f:
        for a in actions:
            entry = {
                "timestamp": ts,
                "action": a.get("action"),
                "params": a.get("params", {}),
                "status": "staged",
            }
            f.write(json.dumps(entry) + "\n")

def load_queue(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Read back most recent staged actions for debugging or inspection.
    """
    _ensure_file()
    with open(QUEUE_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]
    return [json.loads(l) for l in lines if l.strip()]

def clear_queue():
    """Erase all staged entries (for testing only)."""
    _ensure_file()
    open(QUEUE_PATH, "w").close()
