# agent/llm_select.py
from __future__ import annotations

import os
from typing import Any

# ---------------------------------------------------------------------------
# Robust imports so this works in both layouts:
#  - packaged: tinysocs/agent/...
#  - flat:     agent/...
# Also tolerate missing deps by falling back to a minimal summarizer.
# ---------------------------------------------------------------------------

# Optional import of netutil (some engines reference it or expect its side-effects).
try:
    from tinysocs.agent import netutil as _netutil  # packaged
except Exception:
    try:
        import tinysocs.netutil as _netutil  # type: ignore[no-redef] # shimmed alias to agent.netutil
    except Exception:
        try:
            from agent import netutil as _netutil  # type: ignore[no-redef] # flat
        except Exception:
            _netutil = None  # type: ignore[assignment] # not strictly required here

def _import_summarizers():
    openai_fn = None
    ollama_fn = None
    claude_fn = None

    # OpenAI+tools
    try:
        from tinysocs.agent.llm_openai_tools import summarize_findings as _s_openai
        openai_fn = _s_openai
    except Exception:
        try:
            from tinysocs.agent.llm_openai_tools import summarize_findings as _s_openai
            openai_fn = _s_openai
        except Exception:
            openai_fn = None

    # Ollama
    try:
        from tinysocs.agent.llm_ollama import summarize_findings as _s_ollama
        ollama_fn = _s_ollama
    except Exception:
        try:
            from tinysocs.agent.llm_ollama import summarize_findings as _s_ollama
            ollama_fn = _s_ollama
        except Exception:
            ollama_fn = None

    # Claude (Anthropic)
    try:
        from tinysocs.agent.llm_claude import summarize_findings as _s_claude
        claude_fn = _s_claude
    except Exception:
        claude_fn = None

    return openai_fn, ollama_fn, claude_fn

summarize_openai_tools, summarize_ollama, summarize_claude = _import_summarizers()

MODE = os.getenv("LLM_MODE", "openai").strip().lower()


# ---------------------------------------------------------------------------
# Minimal local summary (engine fallback)
# ---------------------------------------------------------------------------
def _minimal_local_summary(payload: dict[str, Any]) -> dict[str, Any]:
    mode = payload.get("mode", "raw")
    window = payload.get("window") or "(window n/a)"

    if mode == "abstract":
        agg = payload.get("aggregate", {}) or {}
        counts = agg.get("counts", {}) or {}
        total = sum(int(v or 0) for v in counts.values()) if isinstance(counts, dict) else 0
        lines = [
            "# TinySOCS Incident (compat)",
            f"**TL;DR:** {total} event(s) across {len(counts) if isinstance(counts, dict) else 0} rule(s) in {window}.",
            ""
        ]
        if isinstance(counts, dict):
            for rule, cnt in sorted(counts.items()):
                lines.append(f"- **{rule}**: {cnt}")
        return {
            "severity": "low",
            "tldr": f"{total} events across {len(counts) if isinstance(counts, dict) else 0} rules",
            "markdown": "\n".join(lines)
        }

    # RAW path
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


# ---------------------------------------------------------------------------
# Input normalization helpers
# ---------------------------------------------------------------------------
def _normalize_input(arg=None, *, findings=None, data=None, **kwargs) -> dict[str, Any]:
    """
    Accept legacy list (raw) or new dict (abstract). Return a dict with 'mode'.
    """
    if data is not None:
        if isinstance(data, dict):
            if "mode" not in data:
                data = {"mode": "abstract", **data} if ("aggregate" in data or "minimal" in data) \
                       else {"mode": "raw", **data}
            return data
        if isinstance(data, list):
            return {"mode": "raw", "evidences": data, "window": kwargs.get("window")}
    if findings is not None:
        if isinstance(findings, dict):
            return findings if "mode" in findings else {"mode": "abstract", **findings}
        if isinstance(findings, list):
            return {"mode": "raw", "evidences": findings, "window": kwargs.get("window")}
    if isinstance(arg, dict):
        return arg if "mode" in arg else (
            {"mode": "abstract", **arg} if ("aggregate" in arg or "minimal" in arg) else {"mode": "raw", **arg}
        )
    if isinstance(arg, list):
        return {"mode": "raw", "evidences": arg, "window": kwargs.get("window")}
    return {
        "mode": "abstract",
        "window": kwargs.get("window"),
        "aggregate": {"rules": [], "counts": {}},
        "minimal": [],
    }


def _abstract_to_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Convert the privacy 'abstract' dict to a low-PII findings list that your
    existing summarize_findings() functions already accept.
    """
    minimal = payload.get("minimal") or []
    window  = payload.get("window") or ""
    findings: list[dict[str, Any]] = []

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
        f: dict[str, Any] = {
            "rule": rule,
            "summary": s,
            "evidence": evidence,
        }
        fps = m.get("exemplar_fingerprints") or []
        if fps:
            f["sample"] = [{"fingerprint": x} for x in fps]
        findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def summarize(arg: None | dict[str, Any] | list[dict[str, Any]] = None, *,
              findings: list[dict[str, Any]] | None = None,
              data: dict[str, Any] | None = None,
              **kwargs) -> dict[str, Any]:
    """
    Universal entry:
      - summarize(findings=[...])                 # legacy RAW
      - summarize(data={...}) or summarize({...}) # ABSTRACT dict
    """
    payload = _normalize_input(arg, findings=findings, data=data, **kwargs)
    mode = payload.get("mode", "raw")

    # Pick engine function by MODE, tolerate missing engines.
    engine_fn = None
    engine_label = MODE
    if MODE == "openai":
        engine_fn = summarize_openai_tools
    elif MODE == "ollama":
        engine_fn = summarize_ollama
    elif MODE == "claude":
        engine_fn = summarize_claude

    try:
        if mode == "abstract":
            converted = _abstract_to_findings(payload)
            if engine_fn is None:
                return _minimal_local_summary(payload)
            print(f"[DEBUG] Using {engine_label} summarizer (compat, abstract->raw)")
            return engine_fn(converted)  # type: ignore[misc]
        else:
            raw_findings = payload.get("evidences") or payload.get("findings") or []
            if engine_fn is None:
                return _minimal_local_summary(payload)
            print(f"[DEBUG] Using {engine_label} summarizer")
            return engine_fn(raw_findings)  # type: ignore[misc]
    except Exception:
        # Engine rejected input or failed — return a safe minimal summary
        return _minimal_local_summary(payload)
