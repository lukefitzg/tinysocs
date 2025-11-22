# agent/report.py
from typing import Any, Dict, List


def _lines_if(title: str, items: List[str]) -> List[str]:
    if not items:
        return []
    out = [f"\n## {title}"]
    out.extend(f"- {x}" for x in items)
    return out

def to_markdown(incident: Dict[str,Any]) -> str:
    lines = [
      "# TinySocs Incident Report",
      f"**Severity:** {incident.get('severity','Unknown')}",
      f"**TL;DR:** {incident.get('tldr','')}",
      "\n## Evidence"
    ]

    ev = incident.get("evidence", []) or []
    for e in ev:
        pretty = ", ".join(f"{k}={v}" for k,v in e.items() if v is not None)
        lines.append(f"- {pretty}")

    lines += _lines_if("Hypotheses", incident.get("hypotheses") or [])
    lines += _lines_if("Next Steps", incident.get("next_steps") or [])

    ca = incident.get("candidate_actions") or []
    if ca:
        lines.append("\n## Candidate Actions (dry-run)")
        for a in ca:
            action = a.get("action")
            params = a.get("params", {})
            lines.append(f"- {action}: {params} *(dry-run)*")

    # footer: reflect true generator
    src = (incident.get("generator") or "unknown").lower()
    if src.startswith("openai"):
        note = "via OpenAI (tools)"
    elif src == "ollama":
        note = "via Ollama (local)"
    elif src.startswith("fallback"):
        note = "via local fallback (no model)"
    else:
        note = "generated locally"

    lines.append(f"\n*Generated {note}; your data stayed on this machine unless using OpenAI.*")
    return "\n".join(lines)
