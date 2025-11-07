# tinysocs/agent/main.py
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from tinysocs.agent.actions_queue import stage_actions
from tinysocs.agent.detections.engine import run_detections
from tinysocs.agent.llm_select import summarize as summarize_findings
from tinysocs.agent.report import to_markdown


@dataclass(frozen=True)
class Config:
    siem_url: str
    ssl_verify: bool
    actions_queue_path: Path


def _to_bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def load_config() -> Config:
    """Read runtime config from env with sane defaults."""
    siem_url = os.getenv("SIEM_URL", "https://localhost:9201")
    ssl_verify = _to_bool(os.getenv("SIEM_SSL_VERIFY"), default=False)
    aq_path = Path(os.getenv("ACTIONS_QUEUE_PATH", "./data/actions_queue.jsonl")).resolve()
    return Config(siem_url=siem_url, ssl_verify=ssl_verify, actions_queue_path=aq_path)


def _load_env():
    """
    Load .env from the project root. Given this file lives at:
      .../<repo_root>/tinysocs/agent/main.py
    the repo root is parents[2]. We also try parents[1] (the 'tinysocs' dir)
    as a fallback in case the .env is kept there during dev.
    """
    here = Path(__file__).resolve()
    repo_root = here.parents[2]  # <repo_root>
    package_root = here.parents[1]  # <repo_root>/tinysocs
    # Try project root first, then package root
    for candidate in (repo_root / ".env", package_root / ".env"):
        try:
            if candidate.exists():
                load_dotenv(candidate)
                print(f"[main] loaded env from {candidate}", flush=True)
                return
        except Exception:
            # Don't fail startup if .env loading isn't available
            pass


def main():
    _load_env()

    cfg = load_config()
    print(
        "[main] TinySocs starting...\n"
        f"[main] SIEM_URL={cfg.siem_url!r} SSL_VERIFY={cfg.ssl_verify} "
        f"ACTIONS_QUEUE={str(cfg.actions_queue_path)!r}\n"
        f"[main] LLM_MODE={os.getenv('LLM_MODE')!r}",
        flush=True,
    )

    t0 = time.time()
    print("[main] starting detectionsâ€¦", flush=True)
    findings = run_detections()
    print(
        f"[main] detections â†’ {len(findings)} finding(s) in {time.time() - t0:.2f}s",
        flush=True,
    )

    mode = (os.getenv("LLM_MODE") or "").lower()
    print(f"[main] summarizer mode = {mode or '(default)'}", flush=True)
    try:
        t1 = time.time()
        incident = summarize_findings(findings)
        print(f"[main] summarize ok in {time.time() - t1:.2f}s", flush=True)
    except Exception as e:
        print(f"[main] summarize failed: {e}", flush=True)
        incident = {
            "title": "Summary failed",
            "findings": findings,
            "candidate_actions": [],
            "meta": {"error": str(e)},
        }

    print("[main] rendering reportâ€¦", flush=True)
    print(to_markdown(incident))

    actions = incident.get("candidate_actions") or []
    if actions:
        stage_actions(actions)
        print(f"[main] staged {len(actions)} candidate action(s) to queue", flush=True)

    print("[main] done.", flush=True)


if __name__ == "__main__":
    main()
