import os, json, httpx
from typing import List, Dict, Any
from llm_schema import SCHEMA
from redact import scrub

API_KEY = os.getenv("OPENAI_API_KEY")
MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

def _fallback(findings: List[Dict[str,Any]], reason: str) -> Dict[str,Any]:
    return {
        "tldr": f"OpenAI unavailable: {reason}. Rendering raw findings.",
        "severity": "Low",
        "evidence": findings[:10],
        "hypotheses": ["Online summarizer error/unavailable"],
        "next_steps": ["Retry locally (Ollama) or later online"],
        "candidate_actions": [],
        "generator": "fallback-online",
        "reason": reason,
    }

def summarize_findings(findings: List[Dict[str,Any]]) -> Dict[str,Any]:
    """Summarize findings using OpenAI model."""
    if not API_KEY:
        return _fallback(findings, "OPENAI_API_KEY missing")

    # scrub PII before cloud
    seed = scrub(findings[:25])

    schema = {
      "type": "object",
      "properties": SCHEMA["properties"],
      "required": ["tldr","severity","evidence","next_steps","candidate_actions"]
    }

    sys = "You are TinySocs' analyst. Return only JSON conforming to the provided JSON schema."
    body = {
      "model": MODEL,
      "messages": [
        {"role":"system","content":sys},
        {"role":"user","content":f"JSON Schema:\n{json.dumps(schema)}\n\nFindings:\n{json.dumps(seed)}"}
      ],
      "response_format": { "type": "json_object" },
      "temperature": 0.0,
    }
    headers = {"Authorization": f"Bearer {API_KEY}"}

    try:
        with httpx.Client(timeout=60) as http:
            r = http.post("https://api.openai.com/v1/chat/completions", json=body, headers=headers)
            if r.status_code >= 400:
                try: err = r.json()
                except Exception: err = {"error": r.text}
                return _fallback(findings, f"HTTP {r.status_code}: {err.get('error') or err}")
            text = r.json()["choices"][0]["message"]["content"].strip()
            obj = json.loads(text)
    except Exception as e:
        return _fallback(findings, str(e))

    # sanitize size and tag
    obj["evidence"] = obj.get("evidence", [])[:20]
    obj["next_steps"] = obj.get("next_steps", [])[:10]
    obj["candidate_actions"] = obj.get("candidate_actions", [])[:10]
    obj["generator"] = "openai"
    return obj
