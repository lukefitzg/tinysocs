# agent/main.py
from pathlib import Path
import sys, os, time

# --- Put both repo root AND agent/ on sys.path so imports work either way ---
REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = REPO_ROOT / "agent"
for p in (REPO_ROOT, AGENT_DIR):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

# --- Load .env from repo root (if present) ---
try:
    from dotenv import load_dotenv
    load_dotenv(REPO_ROOT / ".env")
except Exception:
    pass

# --- Import detections (try both locations) ---
try:
    from detections.engine import run_detections
except ModuleNotFoundError:
    try:
        from agent.detections.engine import run_detections  # nested layout
    except ModuleNotFoundError as e:
        print("[main] Could not import detections.engine", file=sys.stderr, flush=True)
        print(f"[main] REPO_ROOT={REPO_ROOT}", file=sys.stderr, flush=True)
        print(f"[main] sys.path[0:5]={sys.path[0:5]}", file=sys.stderr, flush=True)
        raise e

from llm_select import summarize as summarize_findings
from report import to_markdown
from actions_queue import stage_actions


def main():
    print(
        "[main] TinySOCS starting...\n"
        f"[main] SIEM_BACKEND={os.getenv('SIEM_BACKEND')!r} "
        f"SIEM_URL={os.getenv('SIEM_URL')!r}\n"
        f"[main] LLM_MODE={os.getenv('LLM_MODE')!r}",
        flush=True,
    )

    t0 = time.time()
    print("[main] starting detections…", flush=True)
    findings = run_detections()
    print(f"[main] detections → {len(findings)} finding(s) in {time.time()-t0:.2f}s", flush=True)

    mode = (os.getenv("LLM_MODE") or "").lower()
    print(f"[main] summarizer mode = {mode or '(default)'}", flush=True)
    try:
        t1 = time.time()
        incident = summarize_findings(findings)
        print(f"[main] summarize ok in {time.time()-t1:.2f}s", flush=True)
    except Exception as e:
        print(f"[main] summarize failed: {e}", file=sys.stderr, flush=True)
        incident = {"title": "Summary failed", "findings": findings, "candidate_actions": [], "meta": {"error": str(e)}}

    print("[main] rendering report…", flush=True)
    print(to_markdown(incident))

    actions = incident.get("candidate_actions") or []
    if actions:
        stage_actions(actions)
        print(f"[DEBUG] staged {len(actions)} candidate action(s) to queue", flush=True)

    print("[main] done.", flush=True)


if __name__ == "__main__":
    main()