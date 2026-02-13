# tinysocs/agent/llm_claude.py
"""
Anthropic Claude LLM backend with tool-calling for TinySocs analyst.
Uses the same tool definitions as the OpenAI path (search_kql, aggregate,
propose_rule, stage_action) via Anthropic's tool_use API.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Any, Dict, List

from tinysocs.agent.llm_schema import SCHEMA
from tinysocs.agent.tools import aggregate, propose_rule, search_kql, stage_action

try:
    from tinysocs.agent.redact import scrub
except Exception:
    def scrub(x):
        return x

try:
    from tinysocs.netutil import is_loopback
except Exception:
    def is_loopback(_ip):
        return False

API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
DEBUG = os.getenv("DEBUG_LLM") == "1"

MAX_FINDINGS_FOR_CLOUD = int(os.getenv("MAX_FINDINGS_FOR_CLOUD", "12"))
MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "18000"))

ALLOW_INDICES = [
    s.strip()
    for s in os.getenv("LLM_TOOL_INDEX_ALLOW", "tinysocs-winlog-*").split(",")
    if s.strip()
]
DEFAULT_INDEX = ALLOW_INDICES[0] if ALLOW_INDICES else "tinysocs-winlog-*"

# Persistence
CASE_INDEX = os.getenv("SIEM_CASE_INDEX") or os.getenv("SIEM_INDEX_WRITE") or "siem_index"
PERSIST = str(os.getenv("SIEM_PERSIST_CASES", "1")).lower() in ("1", "true", "yes", "on")

HIGH_SIGNAL_RULES = {
    "proc_creation_powershell_suspicious",
    "proc_creation_lolbins",
    "lolbin_execs",
    "ps_script_block",
    "auth_failed_burst",
}

# --------------------------------------------------------------------------
# Tool definitions in Anthropic format
# --------------------------------------------------------------------------
TOOLS = [
    {
        "name": "search_kql",
        "description": "Search SIEM with KQL over a given index",
        "input_schema": {
            "type": "object",
            "properties": {
                "index": {"type": "string", "description": "Index pattern to search"},
                "kql": {"type": "string", "description": "KQL query string"},
                "size": {"type": "integer", "description": "Max results", "default": 100},
            },
            "required": ["index", "kql"],
        },
    },
    {
        "name": "aggregate",
        "description": "Run an Elasticsearch/OpenSearch DSL aggregation",
        "input_schema": {
            "type": "object",
            "properties": {
                "index": {"type": "string", "description": "Index pattern"},
                "dsl": {"type": "object", "description": "DSL aggregation body"},
            },
            "required": ["index", "dsl"],
        },
    },
    {
        "name": "propose_rule",
        "description": "Suggest a detection rule (design only; does not install)",
        "input_schema": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string"},
                "query": {"type": "string"},
                "schedule": {"type": "string", "default": "15m"},
            },
            "required": ["rule_id", "query"],
        },
    },
    {
        "name": "stage_action",
        "description": "Stage a response action (dry-run only; requires human approval)",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["block_ip", "disable_user", "isolate_host", "open_ticket"],
                },
                "params": {"type": "object"},
            },
            "required": ["action", "params"],
        },
    },
]


# --------------------------------------------------------------------------
# Helpers (shared logic with OpenAI path)
# --------------------------------------------------------------------------

def _index_allowed(idx: str) -> bool:
    return any(fnmatch(idx or "", pat) for pat in ALLOW_INDICES)


def _sanitize_tool_args(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name in ("search_kql", "aggregate"):
        idx = args.get("index") or DEFAULT_INDEX
        if not _index_allowed(idx):
            args["index"] = DEFAULT_INDEX
    return args


def _call_local_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    args = _sanitize_tool_args(name, dict(args or {}))
    try:
        if name == "search_kql":
            return search_kql(**args)
        if name == "aggregate":
            return aggregate(**args)
        if name == "propose_rule":
            return propose_rule(**args)
        if name == "stage_action":
            return stage_action(**args)
        return {"error": f"unknown tool {name}"}
    except Exception as e:
        return {"error": str(e), "tool": name, "args": args}


def _compact_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compact: List[Dict[str, Any]] = []
    for f in (findings or [])[:MAX_FINDINGS_FOR_CLOUD]:
        row: Dict[str, Any] = {}
        if f.get("rule"):
            row["rule"] = f["rule"]
        if f.get("summary"):
            s = str(f["summary"])
            row["summary"] = (s[:180] + "\u2026") if len(s) > 180 else s
        if isinstance(f.get("count"), int):
            row["count"] = f["count"]
        ev = f.get("evidence") or {}
        if isinstance(ev, dict):
            ev_small = {}
            for k in ("ip", "ip_rdns", "user", "count", "host", "process"):
                v = ev.get(k)
                if v is None:
                    continue
                if isinstance(v, str) and len(v) > 160:
                    v = v[:160] + "\u2026"
                ev_small[k] = v
            if ev_small:
                row["evidence"] = ev_small
        compact.append(row)
    return compact


def _persist_incident(incident: dict):
    if not PERSIST:
        return
    try:
        from tinysocs.agent.adapters.opensearch_client import OpenSearchClient as OSClient
        os_client = OSClient().os
        try:
            if not os_client.indices.exists(index=CASE_INDEX):
                os_client.indices.create(
                    index=CASE_INDEX,
                    body={
                        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                        "mappings": {"dynamic": True},
                    },
                )
        except Exception as e:
            if "resource_already_exists_exception" not in str(e):
                raise
        doc = dict(incident)
        doc.setdefault("@timestamp", datetime.now(timezone.utc).isoformat())
        os_client.index(index=CASE_INDEX, body=doc, refresh=True)
        print(f"[summarizer] incident persisted to {CASE_INDEX}", flush=True)
    except Exception as e:
        print(f"[summarizer] persist skipped: {e}", file=sys.stderr, flush=True)


def _coerce_incident(obj, findings):
    """Normalize LLM output into the expected incident schema."""
    out = {
        "tldr": (obj or {}).get("tldr") or "LLM summary unavailable; using raw findings.",
        "severity": ((obj or {}).get("severity") or "Low").title(),
        "evidence": [],
        "hypotheses": (obj or {}).get("hypotheses") or [],
        "next_steps": (obj or {}).get("next_steps") or [],
        "candidate_actions": (obj or {}).get("candidate_actions") or [],
    }

    ev = (obj or {}).get("evidence")
    if not isinstance(ev, list) or not ev:
        ev = []
        for f in findings[:10]:
            row = {}
            if isinstance(f.get("evidence"), dict):
                row.update({
                    k: v for k, v in f["evidence"].items()
                    if k in {"ip", "ip_rdns", "user", "count", "rule", "host", "process"} and v is not None
                })
            if f.get("rule"):
                row["rule"] = f["rule"]
            ev.append(row)
    else:
        flat = []
        for e in ev[:20]:
            if not isinstance(e, dict):
                continue
            pruned = {
                k: v for k, v in e.items()
                if k in {"ip", "ip_rdns", "user", "count", "rule", "host", "process", "details"}
            }
            if isinstance(pruned.get("details"), list) and len(pruned["details"]) > 3:
                pruned["details"] = pruned["details"][:3]
            flat.append(pruned)
        ev = flat
    out["evidence"] = ev[:20]

    # Normalize candidate actions
    norm_actions = []
    for a in out["candidate_actions"][:10]:
        if not isinstance(a, dict):
            continue
        action = a.get("action")
        params = a.get("params") or {}
        if action in {"block_ip", "disable_user", "isolate_host", "open_ticket"}:
            if not params:
                if action == "block_ip":
                    ip = next((e.get("ip") for e in out["evidence"] if e.get("ip")), None)
                    if ip:
                        params = {"ip": ip, "reason": "TinySocs suggested"}
                elif action == "open_ticket":
                    params = {"title": out["tldr"][:120]}
                elif action == "disable_user":
                    u = next((e.get("user") for e in out["evidence"] if e.get("user")), None)
                    if u:
                        params = {"user": u, "reason": "TinySocs suggested"}
                elif action == "isolate_host":
                    host = next((e.get("host") for e in out["evidence"] if e.get("host")), None)
                    if host:
                        params = {"host": host, "reason": "TinySocs suggested"}
            if params:
                norm_actions.append({"action": action, "params": params})
    out["candidate_actions"] = norm_actions

    # Severity tweak for loopback-only evidence
    if out["evidence"] and all(is_loopback(e.get("ip", "")) for e in out["evidence"] if "ip" in e):
        if out["severity"] in {"High", "Critical"}:
            out["severity"] = "Medium"

    return out


def _enforce_consistency(incident: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    ev = incident.get("evidence") or []
    total_from_ev = 0
    rules_from_ev: List[str] = []
    for e in ev:
        if isinstance(e, dict):
            try:
                total_from_ev += int(e.get("count") or 0)
            except Exception:
                pass
            r = e.get("rule")
            if isinstance(r, str):
                rules_from_ev.append(r)

    total_from_findings = 0
    rules_from_findings: List[str] = []
    for f in findings or []:
        try:
            total_from_findings += int((f or {}).get("count") or 0)
        except Exception:
            pass
        r = (f or {}).get("rule")
        if r:
            rules_from_findings.append(str(r))

    total = max(total_from_ev, total_from_findings)
    rules = rules_from_ev or rules_from_findings

    tldr = (incident.get("tldr") or "").strip()
    tldr_l = tldr.lower()
    looks_negative = (
        ("no " in tldr_l or "none " in tldr_l or "not detected" in tldr_l)
        and any(w in tldr_l for w in ("event", "powershell", "authentication", "suspicious", "script block"))
    )

    if total > 0 and (not tldr or looks_negative):
        uniq_rules = sorted(set(rules))
        short_rules = ", ".join(uniq_rules) if uniq_rules else "detections"
        incident["tldr"] = f"Detected {total} event(s) across {len(uniq_rules) or 1} rule(s): {short_rules}."

    sev = (incident.get("severity") or "").strip().title() or "Low"
    if set(rules).intersection(HIGH_SIGNAL_RULES) and sev in {"", "Low"}:
        sev = "Medium"
    incident["severity"] = sev

    return incident


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def summarize_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Let Claude process findings with tool-calling, then return one JSON incident."""
    if not findings:
        return {
            "tldr": "No findings in the selected window.",
            "severity": "Low",
            "evidence": [],
            "hypotheses": [],
            "next_steps": [],
            "candidate_actions": [],
            "generator": "claude+tools",
        }

    if not API_KEY:
        reason = "ANTHROPIC_API_KEY missing"
        if DEBUG:
            print("[DEBUG][claude] precheck failed ->", reason)
        return {
            "tldr": f"Claude tools error: {reason}. Rendering raw findings.",
            "severity": "Low",
            "evidence": findings[:10],
            "next_steps": ["Set ANTHROPIC_API_KEY", "Use offline mode"],
            "candidate_actions": [],
            "generator": "fallback-claude",
            "reason": reason,
        }

    try:
        import anthropic
    except ImportError:
        reason = "anthropic SDK not installed"
        return {
            "tldr": f"Claude tools error: {reason}. Rendering raw findings.",
            "severity": "Low",
            "evidence": findings[:10],
            "next_steps": ["Install anthropic: pip install anthropic", "Use offline mode"],
            "candidate_actions": [],
            "generator": "fallback-claude",
            "reason": reason,
        }

    compact = _compact_findings(scrub(findings))
    seed_json = json.dumps(compact)
    if len(seed_json) > MAX_PROMPT_CHARS:
        seed_json = seed_json[:MAX_PROMPT_CHARS] + "\u2026"

    schema = {
        "type": "object",
        "properties": SCHEMA["properties"],
        "required": ["tldr", "severity", "evidence", "next_steps", "candidate_actions"],
    }

    allowed_str = ", ".join(ALLOW_INDICES) if ALLOW_INDICES else "tinysocs-winlog-*"
    system = (
        "You are TinySocs' analyst. You may call tools to run LOCAL queries. "
        f"When calling tools, the ONLY allowed indices are: {allowed_str}. "
        "Do not invent index names; if unsure, skip tools and proceed. "
        "After at most 2 tool calls, return ONE JSON object matching the JSON schema. "
        "Evidence must be a flat list of small objects (ip, ip_rdns, user, count, rule). "
        "Do not include large nested arrays or raw event dumps. "
        "Final answer MUST be JSON only — no markdown fences, no explanation."
    )
    user_msg = f"JSON Schema:\n{json.dumps(schema)}\n\nInitial Findings (compact):\n{seed_json}"

    client = anthropic.Anthropic(api_key=API_KEY)
    messages = [{"role": "user", "content": user_msg}]

    def _fallback(reason: str):
        if DEBUG:
            print(f"[DEBUG][claude] fallback -> {reason}")
        return {
            "tldr": f"Claude tools error: {reason}. Rendering raw findings.",
            "severity": "Low",
            "evidence": findings[:10],
            "next_steps": ["Retry later", "Use offline mode"],
            "candidate_actions": [],
            "generator": "fallback-claude",
            "reason": reason,
        }

    try:
        # Allow up to 2 tool rounds
        for round_num in range(3):
            response = client.messages.create(
                model=MODEL,
                max_tokens=4096,
                system=system,
                messages=messages,
                tools=TOOLS,
                temperature=0.0,
            )

            # Check for tool_use blocks
            tool_uses = [b for b in response.content if b.type == "tool_use"]
            text_blocks = [b for b in response.content if b.type == "text"]

            if not tool_uses:
                # No tools requested — extract JSON from text
                final_text = ""
                for b in text_blocks:
                    final_text += b.text
                final_text = final_text.strip()

                if not final_text:
                    return _fallback("empty response from Claude")

                try:
                    obj = json.loads(final_text)
                except json.JSONDecodeError:
                    # Try to extract JSON from markdown fences
                    import re
                    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", final_text, re.DOTALL)
                    if match:
                        try:
                            obj = json.loads(match.group(1).strip())
                        except json.JSONDecodeError:
                            return _fallback("non-JSON response from Claude")
                    else:
                        return _fallback("non-JSON response from Claude")

                obj = _coerce_incident(obj, findings)
                obj = _enforce_consistency(obj, findings)
                obj["generator"] = "claude+tools"
                _persist_incident(obj)
                return obj

            # Process tool calls
            # Build assistant message with all content blocks
            messages.append({"role": "assistant", "content": response.content})

            # Execute each tool and build tool_result messages
            tool_results = []
            for tu in tool_uses:
                result = _call_local_tool(tu.name, tu.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": json.dumps(result),
                })

            messages.append({"role": "user", "content": tool_results})

        # Exhausted tool rounds
        return _fallback("tool-call loop limit")

    except Exception as e:
        return _fallback(f"API error: {e}")
