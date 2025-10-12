# agent/llm_ollama.py
import os, json, re, httpx
from typing import List, Dict, Any
from llm_schema import SCHEMA

OLLAMA_URL = os.getenv("OFFLINE_LLM_URL", "http://localhost:11434")
MODEL      = os.getenv("OFFLINE_LLM_MODEL", "qwen2.5:0.5b-instruct")

SYS = (
  "You are TinySocs' analyst. Return ONE JSON object ONLY that strictly matches this JSON Schema: "
  + json.dumps(SCHEMA)
  + ". No markdown, no explanations, no surrounding text. If a field is unknown, omit it."
)

def _fallback(findings: List[Dict[str,Any]], reason: str) -> Dict[str,Any]:
    return {
        "tldr": f"Local LLM unavailable: {reason}. Rendering raw findings.",
        "severity": "Low",
        "evidence": findings[:10],
        "hypotheses": ["Model offline/unloaded or server error"],
        "next_steps": ["Start/verify Ollama model", "Review evidence manually"],
        "candidate_actions": [],
        "generator": "fallback",
        "reason": reason,
    }

def _extract_json(text: str) -> str | None:
    s = (text or "").strip()
    if s.startswith("{") and s.endswith("}"):
        return s
    m1, m2 = s.find("{"), s.rfind("}")
    if m1 != -1 and m2 != -1 and m2 > m1:
        return s[m1:m2+1]
    return None

def _normalize(incident: Dict[str,Any], findings: List[Dict[str,Any]]) -> Dict[str,Any]:
    """Backfill missing fields so the report is always useful."""
    if not incident.get("tldr"):
        total = sum(f.get("evidence", {}).get("count", 1) for f in findings)
        kinds = ", ".join({f.get("rule","?") for f in findings})
        incident["tldr"] = f"{len(findings)} finding(s), ~{total} related event(s): {kinds}."
    if not incident.get("severity"):
        incident["severity"] = "Low" if len(findings) < 5 else "Medium"
    if not incident.get("evidence"):
        # flatten to simple evidence rows
        ev = []
        for f in findings[:10]:
            row = f.get("evidence") or {}
            row = {**row, "rule": f.get("rule")}
            ev.append(row)
        incident["evidence"] = ev
    if "next_steps" not in incident or not incident["next_steps"]:
        incident["next_steps"] = [
            "Verify source host/user context",
            "Correlate with lockouts or new failures",
            "Consider temporary IP block if pattern persists",
        ]
    if "candidate_actions" not in incident:
        incident["candidate_actions"] = []
    incident.setdefault("generator", "ollama")
    return incident

def summarize_findings(findings: List[Dict[str,Any]]) -> Dict[str,Any]:
    findings_trimmed = findings[:20]
    prompt = (
      f"{SYS}\n\nFill the schema using ONLY the provided findings. Keep it concise.\nFindings:\n"
      f"{json.dumps(findings_trimmed)[:30000]}"
    )

    payload = {
      "model": MODEL,
      "prompt": prompt,
      "stream": False,
      "format": "json",
      "options": {"temperature": 0.0, "num_predict": 300, "num_ctx": 1024},
    }

    try:
        with httpx.Client(timeout=120) as http:
            r = http.post(f"{OLLAMA_URL}/api/generate", json=payload)
            if r.status_code >= 400:
                try:
                    err = r.json()
                except Exception:
                    err = {"error": r.text}
                return _fallback(findings, f"HTTP {r.status_code}: {err.get('error') or err}")
            text = r.json().get("response","")
    except httpx.RequestError as e:
        return _fallback(findings, str(e))

    blob = _extract_json(text)
    if not blob:
        return _fallback(findings, "non-JSON response")

    try:
        obj = json.loads(blob)
    except Exception:
        return _fallback(findings, "malformed JSON")

    # Normalize to guarantee useful content
    obj = _normalize(obj, findings)
    return obj
