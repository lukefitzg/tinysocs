# agent/actions_queue.py
import json, os, time
from typing import List, Dict, Any

QUEUE_PATH = os.getenv("TS_ACTIONS_QUEUE", "pending_actions.jsonl")

def stage_actions(actions: List[Dict[str,Any]]):
    if not actions:
        return
    os.makedirs(os.path.dirname(QUEUE_PATH) or ".", exist_ok=True)
    ts = int(time.time())
    with open(QUEUE_PATH, "a", encoding="utf-8") as f:
        for a in actions:
            rec = {
                "ts": ts,
                "action": a.get("action"),
                "params": a.get("params"),
                "status": "pending"
            }
            f.write(json.dumps(rec) + "\n")
