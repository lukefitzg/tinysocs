# agent/llm_select.py
from __future__ import annotations
import os
from typing import Any, Dict, List, Optional, Union

# Your existing engines (expect: summarize_findings(findings: List[dict]) -> dict/str)
from tinysocs.agent.llm_openai_tools import summarize_findings as summarize_openai_tools
from tinysocs.agent.llm_ollama import summarize_findings as summarize_ollama

MODE = os.getenv("LLM_MODE", "openai").strip().lower()

def _minimal_local_summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    mode = payload.get("mode", "raw")
    window = payload.get("window") or "(window n/a)"

    if mode == "abstract":
        agg = payload.get("aggregate", {})
        counts = agg.get("counts", {}) or {}
        total = sum(int(v or 0) for v in counts.values())
        lines = [
            "# TinySOCS Incident (compat)",
            f"**TL;DR:** {total} event(s) across {len(counts)} rule(s) in {window}.",
            ""
        ]
        for rule, cnt in sorted(counts.items()):
            lines.append(f"- **{rule}**: {cnt}")
        return {"severity": "low", "tldr": f"{total} events across {len(counts)} rules", "markdown": "\n".join(lines)}

    findings = payload.get("evidences") or payload.get("findings") or []
    total = 0
    rules = set()
    for f in findings:
        rules.add(str(f.get("rule") or "unknown"))
        ev = f.get("evidence") or {}
        try:
            total += int(ev.get("count") or 0)
        except Exception:
            pass
    md = "\n".join([
        "# TinySOCS Incident (compat)",
        f"**TL;DR:** {total} events across {len(rules)} rules in {window}.",
        "",
        "This is a minimal local summary (engine fallback)."
    ])
    return {"severity": "low", "tldr": f"{total} events, {len(rules)} rules", "markdown": md}

def _normalize_input(arg=None, *, findings=None, data=None, **kwargs) -> Dict[str, Any]:
    """
    Accept legacy list (raw) or new dict (abstract). Return a dict with 'mode'.
    """
    if data is not None:
        if isinstance(data, dict):
            if "mode" not in data:
                data = {"mode": "abstract", **data} if ("aggregate" in data or "minimal" in data) else {"mode": "raw", **data}
            return data
        if isinstance(data, list):
            return {"mode": "raw", "evidences": data, "window": kwargs.get("window")}
    if findings is not None:
        if isinstance(findings, dict):
            return findings if "mode" in findings else {"mode": "abstract", **findings}
        if isinstance(findings, list):
            return {"mode": "raw", "evidences": findings, "window": kwargs.get("window")}
    if isinstance(arg, dict):
        return arg if "mode" in arg else ({"mode": "abstract", **arg} if ("aggregate" in arg or "minimal" in arg) else {"mode": "raw", **arg})
    if isinstance(arg, list):
        return {"mode": "raw", "evidences": arg, "window": kwargs.get("window")}
    return {"mode": "abstract", "window": kwargs.get("window"), "aggregate": {"rules": [], "counts": {}}, "minimal": []}

def _abstract_to_findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert the privacy 'abstract' dict to a low-PII findings list that your
    existing summarize_findings() functions already accept.
    """
    minimal = payload.get("minimal") or []
    window  = payload.get("window") or ""
    findings: List[Dict[str, Any]] = []

    # Optional per-rule host rollup for context
    hosts_per_rule = ((payload.get("aggregate") or {}).get("hosts_per_rule") or {})

    for m in minimal:
        rule  = m.get("rule")
        count = int(m.get("count") or 0)
        host  = m.get("host")
        summary_masked = m.get("summary") or {}
        # small, PII-light summary string
        s = f"Masked aggregate for {rule} (window={window})"
        evidence = {
            "host": host,
            "count": count,
            "masked_summary": summary_masked,
        }
        if rule in hosts_per_rule:
            evidence["hosts"] = hosts_per_rule.get(rule) or []

        # keep exemplar hashes if present (still privacy-safe)
        f: Dict[str, Any] = {
            "rule": rule,
            "summary": s,
            "evidence": evidence,
        }
        fps = m.get("exemplar_fingerprints") or []
        if fps:
            f["sample"] = [{"fingerprint": x} for x in fps]
        findings.append(f)

    return findings

def summarize(arg: Union[None, Dict[str, Any], List[Dict[str, Any]]] = None, *,
              findings: Optional[List[Dict[str, Any]]] = None,
              data: Optional[Dict[str, Any]] = None,
              **kwargs) -> Dict[str, Any]:
    """
    Universal entry:
      - summarize(findings=[...])            # legacy RAW
      - summarize(data={...}) or summarize({...})  # ABSTRACT dict
    """
    payload = _normalize_input(arg, findings=findings, data=data, **kwargs)
    mode = payload.get("mode", "raw")

    try:
        if mode == "abstract":
            # Convert to low-PII findings and feed your existing engines.
            converted = _abstract_to_findings(payload)
            if MODE == "openai":
                print("[DEBUG] Using OpenAI+tools summarizer (compat, abstractâ†’raw)")
                return summarize_openai_tools(converted)
            else:
                print("[DEBUG] Using Ollama summarizer (compat, abstractâ†’raw)")
                return summarize_ollama(converted)
        else:
            # RAW path unchanged
            raw_findings = payload.get("evidences") or payload.get("findings") or []
            if MODE == "openai":
                print("[DEBUG] Using OpenAI+tools summarizer")
                return summarize_openai_tools(raw_findings)
            else:
                print("[DEBUG] Using Ollama summarizer")
                return summarize_ollama(raw_findings)
    except Exception as e:
        # Engine rejected input or failed â€” return a safe minimal summary
        return _minimal_local_summary(payload)
