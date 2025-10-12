# agent/llm_openai.py
import os, json, httpx
from typing import Any, Dict, List
from llm_schema import SCHEMA
from redact import scrub
from netutil import is_loopback

API_KEY = os.getenv("OPENAI_API_KEY")
MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
DEBUG   = os.getenv("DEBUG_LLM") == "1"

MAX_FINDINGS_FOR_CLOUD = int(os.getenv("MAX_FINDINGS_FOR_CLOUD", "12"))
MAX_PROMPT_CHARS       = int(os.getenv("MAX_PROMPT_CHARS", "18000"))

def _compact_findings(findings: List[Dict[str,Any]]) -> List[Dict[str,Any]]:
    compact: List[Dict[str,Any]] = []
    for f in (findings or [])[:MAX_FINDINGS_FOR_CLOUD]:
        row: Dict[str,Any] = {}
        if f.get("rule"):       row["rule"]    = f["rule"]
        if f.get("summary"):
            s = str(f["summary"])
            row["summary"] = (s[:180] + "…") if len(s) > 180 else s
        if isinstance(f.get("count"), int):
            row["count"] = f["count"]
        ev = f.get("evidence") or {}
        if isinstance(ev, dict):
            ev_small = {}
            for k in ("ip","ip_rdns","user","count","host","process"):
                v = ev.get(k)
                if v is None: continue
                if isinstance(v, str) and len(v) > 160:
                    v = v[:160] + "…"
                ev_small[k] = v
            if ev_small:
                row["evidence"] = ev_small
        compact.append(row)
    return compact

def _coerce_incident(obj, findings):
    out = {
        "tldr": (obj or {}).get("tldr") or "LLM summary unavailable; using raw findings.",
        "severity": ((obj or {}).get("severity") or "Low").title(),
        "evidence": (obj or {}).get("evidence") or [],
        "hypotheses": (obj or {}).get("hypotheses") or [],
        "next_steps": (obj or {}).get("next_steps") or [],
        "candidate_actions": (obj or {}).get("candidate_actions") or [],
    }
    # clip lists
    out["evidence"] = out["evidence"][:20] if isinstance(out["evidence"], list) else []
    out["next_steps"] = out["next_steps"][:10] if isinstance(out["next_steps"], list) else []
    out["candidate_actions"] = out["candidate_actions"][:10] if isinstance(out["candidate_actions"], list) else []

    # severity tweak for loopback-only evidence
    ev = out["evidence"]
    if ev and all(is_loopback(e.get("ip","")) for e in ev if isinstance(e, dict) and "ip" in e):
        if out["severity"] in {"High","Critical"}:
            out["severity"] = "Medium"
    return out

def summarize_findings(findings: List[Dict[str,Any]]) -> Dict[str,Any]:
    if not API_KEY:
        return {
            "tldr":"OpenAI unavailable: missing API key. Rendering raw findings.",
            "severity":"Low",
            "evidence":findings[:10],
            "next_steps":["Add OPENAI_API_KEY or use offline mode"],
            "candidate_actions":[],
            "generator":"fallback-online",
            "reason":"OPENAI_API_KEY missing",
        }

    compact = _compact_findings(scrub(findings))
    seed_json = json.dumps(compact)
    if len(seed_json) > MAX_PROMPT_CHARS:
        seed_json = seed_json[:MAX_PROMPT_CHARS] + "…"

    system = (
      "You are TinySocs' analyst. Return ONE JSON object that matches this schema: "
      + json.dumps({"type":"object","properties":SCHEMA["properties"],"required":["tldr","severity","evidence","next_steps","candidate_actions"]})
      + ". Evidence must be a flat list of small objects. No raw event dumps. JSON only."
    )
    user = f"Initial Findings (compact):\n{seed_json}"

    headers = {"Authorization": f"Bearer {API_KEY}"}
    body = {
      "model": MODEL,
      "messages": [
        {"role":"system","content":system},
        {"role":"user","content":user},
      ],
      "temperature": 0.0,
      "response_format": {"type":"json_object"},
    }

    with httpx.Client(timeout=90) as http:
        r = http.post("https://api.openai.com/v1/chat/completions", json=body, headers=headers)
        if r.status_code >= 400:
            reason = f"HTTP {r.status_code}: {r.text[:400]}"
            if DEBUG: print("[DEBUG][openai] call failed ->", reason)
            return {
                "tldr": f"OpenAI error: {reason}. Rendering raw findings.",
                "severity": "Low",
                "evidence": findings[:10],
                "next_steps": ["Retry later", "Use offline mode"],
                "candidate_actions": [],
                "generator": "fallback-online",
                "reason": reason
            }
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        txt = (msg.get("content") or "{}").strip() or "{}"
        try:
            obj = json.loads(txt)
        except Exception:
            return {
                "tldr":"OpenAI returned non-JSON; rendering raw findings.",
                "severity":"Low",
                "evidence":findings[:10],
                "next_steps":["Retry later","Use offline mode"],
                "candidate_actions":[],
                "generator":"fallback-online",
                "reason":"non-JSON response"
            }
        obj = _coerce_incident(obj, findings)
        obj["generator"] = "openai"
        return obj
