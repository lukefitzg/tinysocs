# agent/llm_openai_tools.py
import os, json, httpx, sys
from typing import Any, Dict, List
from fnmatch import fnmatch
from datetime import datetime, timezone

from llm_schema import SCHEMA
from redact import scrub
from agent.tools import search_kql, aggregate, propose_rule, stage_action
from netutil import is_loopback
from adapters.opensearch_client import OSClient  # for optional persistence

API_KEY = os.getenv("OPENAI_API_KEY")
MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
DEBUG   = os.getenv("DEBUG_LLM") == "1"

# Compacting knobs
MAX_FINDINGS_FOR_CLOUD = int(os.getenv("MAX_FINDINGS_FOR_CLOUD", "12"))
MAX_PROMPT_CHARS       = int(os.getenv("MAX_PROMPT_CHARS", "18000"))  # hard stop << 128k tokens

# ▶ tool index allow-list (model can ONLY query these)
ALLOW_INDICES   = [s.strip() for s in os.getenv("LLM_TOOL_INDEX_ALLOW", "winlogbeat-*").split(",") if s.strip()]
DEFAULT_INDEX   = ALLOW_INDICES[0] if ALLOW_INDICES else "winlogbeat-*"

# ▶ persistence toggles
CASE_INDEX = os.getenv("SIEM_CASE_INDEX", "siem_index")
PERSIST    = str(os.getenv("SIEM_PERSIST_CASES", "1")).lower() in ("1","true","yes","on")

def _ensure_index(os_client):
    """Create CASE_INDEX if it doesn't exist (idempotent)."""
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

def _persist_incident(incident: dict):
    """Write incident to OpenSearch (dev-safe defaults)."""
    if not PERSIST:
        return
    try:
        os_client = OSClient().os
        _ensure_index(os_client)
        doc = dict(incident)
        doc.setdefault("@timestamp", datetime.now(timezone.utc).isoformat())
        os_client.index(index=CASE_INDEX, body=doc, refresh=True)
        print(f"[summarizer] incident persisted to {CASE_INDEX}", flush=True)
    except Exception as e:
        print(f"[summarizer] persist skipped: {e}", file=sys.stderr, flush=True)

TOOLS = [
  {
    "type": "function",
    "function": {
      "name": "search_kql",
      "description": "Search SIEM with KQL over a given index",
      "parameters": {
        "type": "object",
        "properties": {
          "index": {"type": "string"},
          "kql":   {"type": "string"},
          "size":  {"type": "integer", "default": 100}
        },
        "required": ["index","kql"]
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "aggregate",
      "description": "Run an Elasticsearch/OpenSearch DSL aggregation",
      "parameters": {
        "type": "object",
        "properties": {
          "index": {"type": "string"},
          "dsl":   {"type": "object"}
        },
        "required": ["index","dsl"]
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "propose_rule",
      "description": "Suggest a detection rule (design only; does not install)",
      "parameters": {
        "type": "object",
        "properties": {
          "rule_id": {"type": "string"},
          "query":   {"type": "string"},
          "schedule":{"type": "string", "default":"15m"}
        },
        "required": ["rule_id","query"]
      }
    }
  },
  {
    "type": "function",
    "function": {
      "name": "stage_action",
      "description": "Stage a response action (dry-run only; requires human approval)",
      "parameters": {
        "type": "object",
        "properties": {
          "action": {"type": "string", "enum": ["block_ip","disable_user","isolate_host","open_ticket"]},
          "params": {"type": "object"}
        },
        "required": ["action","params"]
      }
    }
  }
]

def _index_allowed(idx: str) -> bool:
    return any(fnmatch(idx or "", pat) for pat in ALLOW_INDICES)

def _sanitize_tool_args(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    # enforce allowed indices for search/aggregate
    if name in ("search_kql", "aggregate"):
        idx = args.get("index") or DEFAULT_INDEX
        if not _index_allowed(idx):
            if DEBUG:
                print(f"[DEBUG][tools] index '{idx}' not in allow-list {ALLOW_INDICES}; using '{DEFAULT_INDEX}'", flush=True)
            args["index"] = DEFAULT_INDEX
    return args

def _call_local_tool(name: str, args: Dict[str,Any]) -> Dict[str,Any]:
    args = _sanitize_tool_args(name, dict(args or {}))
    try:
        if name == "search_kql":   return search_kql(**args)
        if name == "aggregate":    return aggregate(**args)
        if name == "propose_rule": return propose_rule(**args)
        if name == "stage_action": return stage_action(**args)
        return {"error": f"unknown tool {name}"}
    except Exception as e:
        # Fail-soft so the summarizer never dies on tool errors (e.g., 404 index)
        return {"error": str(e), "tool": name, "args": args}

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
        "evidence": [],
        "hypotheses": (obj or {}).get("hypotheses") or [],
        "next_steps": (obj or {}).get("next_steps") or [],
        "candidate_actions": (obj or {}).get("candidate_actions") or [],
    }

    # ---- Evidence ----
    ev = (obj or {}).get("evidence")
    if not isinstance(ev, list) or not ev:
        ev = []
        for f in findings[:10]:
            row = {}
            if isinstance(f.get("evidence"), dict):
                row.update({k:v for k,v in f["evidence"].items()
                            if k in {"ip","ip_rdns","user","count","host","process"} and v is not None})
            if f.get("rule"):
                row["rule"] = f["rule"]
            ev.append(row)
    else:
        flat = []
        for e in ev[:20]:
            if not isinstance(e, dict): continue
            pruned = {k: v for k, v in e.items()
                      if k in {"ip","ip_rdns","user","count","rule","host","process","details"}}
            if isinstance(pruned.get("details"), list) and len(pruned["details"]) > 3:
                pruned["details"] = pruned["details"][:3]
            flat.append(pruned)
        ev = flat

    for i, row in enumerate(ev):
        if isinstance(row, dict) and "ip" in row and "ip_rdns" not in row:
            match = next((f for f in findings if (f.get("evidence") or {}).get("ip") == row["ip"]), None)
            if match:
                rdns_val = (match.get("evidence") or {}).get("ip_rdns")
                if rdns_val:
                    row["ip_rdns"] = rdns_val
        ev[i] = row
    out["evidence"] = ev[:20]

    # ---- Candidate actions ----
    norm_actions = []
    for a in out["candidate_actions"][:10]:
        if not isinstance(a, dict): continue
        action = a.get("action")
        params = a.get("params") or {}
        if action in {"block_ip","disable_user","isolate_host","open_ticket"}:
            if not params:
                if action == "block_ip":
                    ip = next((e.get("ip") for e in out["evidence"] if e.get("ip")), None)
                    if ip: params = {"ip": ip, "reason": "TinySocs suggested"}
                elif action == "open_ticket":
                    params = {"title": out["tldr"][:120]}
                elif action == "disable_user":
                    u = next((e.get("user") for e in out["evidence"] if e.get("user")), None)
                    if u: params = {"user": u, "reason": "TinySocs suggested"}
                elif action == "isolate_host":
                    host = next((e.get("host") for e in out["evidence"] if e.get("host")), None)
                    if host: params = {"host": host, "reason": "TinySocs suggested"}
            if params:
                norm_actions.append({"action": action, "params": params})
    out["candidate_actions"] = norm_actions

    # ---- Severity tweak for loopback-only evidence
    any_evidence = out["evidence"]
    if any_evidence and all(is_loopback(e.get("ip","")) for e in any_evidence if "ip" in e):
        if out["severity"] in {"High","Critical"}:
            out["severity"] = "Medium"

    return out

def _enforce_consistency(incident: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Ensure TL;DR isn't claiming 'no events' when evidence shows counts.
    Also guarantees a severity is present.
    """
    ev = incident.get("evidence") or []
    total = 0
    rules = []
    for e in ev:
        if isinstance(e, dict):
            try:
                total += int(e.get("count") or 0)
            except Exception:
                pass
            r = e.get("rule")
            if isinstance(r, str):
                rules.append(r)

    tldr = (incident.get("tldr") or "").strip()
    says_none = ("no " in tldr.lower() and "event" in tldr.lower())
    if total > 0 and says_none:
        uniq_rules = ", ".join(sorted(set(rules))) if rules else "detections"
        incident["tldr"] = f"{total} event(s) detected across {uniq_rules}."

    if not incident.get("severity"):
        incident["severity"] = "Low"

    return incident

def summarize_findings(findings: List[Dict[str,Any]]) -> Dict[str,Any]:
    """Let the model request local queries, then return one JSON incident."""
    if not findings:
        return {
            "tldr": "No findings in the selected window.",
            "severity": "Low",
            "evidence": [],
            "hypotheses": [],
            "next_steps": [],
            "candidate_actions": [],
            "generator": "openai+tools",
        }

    if not API_KEY:
        reason = "OPENAI_API_KEY missing"
        if DEBUG: print("[DEBUG][openai tools] precheck failed ->", reason)
        return {
            "tldr": f"OpenAI tools error: {reason}. Rendering raw findings.",
            "severity": "Low",
            "evidence": findings[:10],
            "next_steps": ["Retry later", "Use offline mode"],
            "candidate_actions": [],
            "generator": "fallback-online",
            "reason": reason
        }

    compact = _compact_findings(scrub(findings))  # scrub PII, then compact
    seed_json = json.dumps(compact)
    if len(seed_json) > MAX_PROMPT_CHARS:
        seed_json = seed_json[:MAX_PROMPT_CHARS] + "…"

    schema = {
      "type":"object",
      "properties": SCHEMA["properties"],
      "required": ["tldr","severity","evidence","next_steps","candidate_actions"]
    }

    allowed_str = ", ".join(ALLOW_INDICES) if ALLOW_INDICES else "winlogbeat-*"
    system = (
      "You are TinySocs' analyst. You may call tools to run LOCAL queries. "
      f"When calling tools, the ONLY allowed indices are: {allowed_str}. "
      "Do not invent index names; if unsure, skip tools and proceed. "
      "After at most 2 tool calls, return ONE JSON object matching the JSON schema. "
      "Evidence must be a flat list of small objects (ip, ip_rdns, user, count, rule). "
      "Do not include large nested arrays or raw event dumps. "
      "Final answer MUST be JSON only."
    )
    user = f"JSON Schema:\n{json.dumps(schema)}\n\nInitial Findings (compact):\n{seed_json}"

    headers = {"Authorization": f"Bearer {API_KEY}"}
    messages = [
        {"role":"system","content":system},
        {"role":"user","content":user},
    ]

    with httpx.Client(timeout=90) as http:
        # -------- round 1: allow tool calls --------
        body1 = {
          "model": MODEL,
          "messages": messages,
          "tools": TOOLS,
          "tool_choice": "auto",
          "temperature": 0.0,
        }
        r1 = http.post("https://api.openai.com/v1/chat/completions", json=body1, headers=headers)
        if r1.status_code >= 400:
            reason = f"HTTP {r1.status_code}: {r1.text[:400]}"
            if DEBUG: print("[DEBUG][openai tools] first call failed ->", reason)
            return {
                "tldr": f"OpenAI tools error: {reason}. Rendering raw findings.",
                "severity": "Low",
                "evidence": findings[:10],
                "next_steps": ["Retry later", "Use offline mode"],
                "candidate_actions": [],
                "generator": "fallback-online",
                "reason": reason
            }
        r1.raise_for_status()

        msg1 = r1.json()["choices"][0]["message"]
        messages.append(msg1)

        tool_calls = msg1.get("tool_calls") or []

        if not tool_calls:
            # No tools requested: force a JSON-only final answer.
            body_final = {
              "model": MODEL,
              "messages": messages,
              "temperature": 0.0,
              "response_format": {"type":"json_object"}
            }
            r_final = http.post("https://api.openai.com/v1/chat/completions", json=body_final, headers=headers)
            if r_final.status_code >= 400:
                reason = f"HTTP {r_final.status_code}: {r_final.text[:400]}"
                if DEBUG: print("[DEBUG][openai tools] final call failed ->", reason)
                return {
                    "tldr": f"OpenAI tools error: {reason}. Rendering raw findings.",
                    "severity": "Low",
                    "evidence": findings[:10],
                    "next_steps": ["Retry later", "Use offline mode"],
                    "candidate_actions": [],
                    "generator": "fallback-online",
                    "reason": reason
                }
            r_final.raise_for_status()

            final_msg = r_final.json()["choices"][0]["message"]
            final_text = (final_msg.get("content") or "{}").strip() or "{}"
            try:
                obj = json.loads(final_text)
            except Exception:
                reason = "non-JSON response (no-tool path)"
                if DEBUG: print("[DEBUG][openai tools] json parse failed ->", reason, " RAW:", final_text[:400])
                return {
                    "tldr":"OpenAI tools error: non-JSON response. Rendering raw findings.",
                    "severity":"Low",
                    "evidence":findings[:10],
                    "next_steps":["Retry later","Use offline mode"],
                    "candidate_actions":[],
                    "generator":"fallback-online",
                    "reason": reason
                }
            obj = _coerce_incident(obj, findings)
            obj = _enforce_consistency(obj, findings)
            obj["generator"] = "openai+tools"
            _persist_incident(obj)
            return obj

        # -------- tool path: allow up to 2 tool rounds, then force JSON --------
        for _ in range(2):
            tool_msgs = []
            for tc in tool_calls:
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"] or "{}")
                except Exception as e:
                    reason = f"tool arg parse error: {e}"
                    if DEBUG: print("[DEBUG][openai tools] tool arg parse error ->", reason)
                    return {
                        "tldr": f"OpenAI tools error: {reason}. Rendering raw findings.",
                        "severity": "Low",
                        "evidence": findings[:10],
                        "next_steps": ["Retry later", "Use offline mode"],
                        "candidate_actions": [],
                        "generator": "fallback-online",
                        "reason": reason
                    }
                out  = _call_local_tool(name, args)
                tool_msgs.append({
                    "role":"tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps(out)
                })
            messages.extend(tool_msgs)

            body2 = {
              "model": MODEL,
              "messages": messages,
              "temperature": 0.0,
              "response_format": {"type":"json_object"}
            }
            r2 = http.post("https://api.openai.com/v1/chat/completions", json=body2, headers=headers)
            if r2.status_code >= 400:
                reason = f"HTTP {r2.status_code}: {r2.text[:400]}"
                if DEBUG: print("[DEBUG][openai tools] final call failed ->", reason)
                return {
                    "tldr": f"OpenAI tools error: {reason}. Rendering raw findings.",
                    "severity": "Low",
                    "evidence": findings[:10],
                    "next_steps": ["Retry later", "Use offline mode"],
                    "candidate_actions": [],
                    "generator": "fallback-online",
                    "reason": reason
                }
            r2.raise_for_status()

            msg2 = r2.json()["choices"][0]["message"]
            messages.append(msg2)

            tool_calls = msg2.get("tool_calls") or []
            if not tool_calls:
                final_text = (msg2.get("content") or "{}").strip() or "{}"
                try:
                    obj = json.loads(final_text)
                except Exception:
                    reason = "non-JSON response (tool path)"
                    if DEBUG: print("[DEBUG][openai tools] json parse failed ->", reason, " RAW:", final_text[:400])
                    return {
                        "tldr":"OpenAI tools error: non-JSON response. Rendering raw findings.",
                        "severity":"Low",
                        "evidence":findings[:10],
                        "next_steps":["Retry later","Use offline mode"],
                        "candidate_actions":[],
                        "generator":"fallback-online",
                        "reason": reason
                    }
                obj = _coerce_incident(obj, findings)
                obj = _enforce_consistency(obj, findings)
                obj["generator"] = "openai+tools"
                _persist_incident(obj)
                return obj

        # Loop exit still wanting tools -> fail-soft
        reason = "tool-call loop limit"
        if DEBUG: print("[DEBUG][openai tools] loop limit ->", reason)
        return {
            "tldr":"Model requested excessive tool calls; rendering raw findings.",
            "severity":"Low",
            "evidence":findings[:10],
            "next_steps":["Retry later","Increase tool round limit","Use offline mode"],
            "candidate_actions":[],
            "generator":"fallback-online",
            "reason": reason
        }