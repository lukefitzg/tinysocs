# agent/main.py
from detections.engine import run_detections
from llm_select import summarize as summarize_findings   # selector
from report import to_markdown
from actions_queue import stage_actions


def main():
    # Run detections across configured SIEM backend
    findings = run_detections()

    # Summarize via selected LLM path (offline or online)
    incident = summarize_findings(findings)

    # Print human-readable Markdown summary to stdout
    print(to_markdown(incident))

    # Enqueue proposed actions (if any) for later approval
    actions = incident.get("candidate_actions") or []
    if actions:
        stage_actions(actions)
        print(f"[DEBUG] staged {len(actions)} candidate action(s) to queue")


if __name__ == "__main__":
    main()
