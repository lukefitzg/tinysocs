# agent/llm_openai_tools.py
import os, json, httpx
from typing import Any, Dict, List
from llm_schema import SCHEMA
from redact import scrub
from tools import search_kql, aggregate, propose_rule, stage_action
from netutil import is_loopback

API_KEY = os.getenv("OPENAI_API_KEY")
MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

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

def _call_local_tool(name: str, args: Dict[str,Any]) -> Dict[str,Any]:
    if name == "search_kql":   return search_kql(**args)
    if name == "aggregate":    return aggregate(**args)
    if name == "propose_rule": return propose_rule(**args)
    if name == "stage_action": return stage_action(**args)
    return {"error": f"unknown tool {name}"}

def _coerce_incident(obj, findings):
    """Normalize a model’s freeform output into our schema + sane defaults."""
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
                row.update(f["evidence"])
            if f.get("rule"):
                row["rule"] = f["rule"]
            safe = {k: v for k, v in row.items()
                    if v is not None and k in {"ip","ip_rdns","user","count","rule","host","process"}}
            ev.append(safe)
    else:
        flat = []
        for e in ev[:20]:
            if not isinstance(e, dict):
                continue
            pruned = {k: v for k, v in e.items()
                      if k not in {"details","detail","sample","samples","raw","events"}}
            if isinstance(e.get("details"), list) and len(e["details"]) <= 3:
                pruned["details"] = e["details"]
            flat.append(pruned)
        ev = flat

    # inject rdns if missing and available in original findings
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
        if not isinstance(a, dict):
            continue
        action = a.get("action")
        params = a.get("params") or {}
        if action in {"block_ip","disable_user","isolate_host","open_ticket"}:
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

    # ---- Severity policy tweak: if all IP evidence is loopback, cap High->Medium
    any_evidence = out["evidence"]
    if any_evidence and all(is_loopback(e.get("ip","")) for e in any_evidence if "ip" in e):
        if out["severity"] in {"High","Critical"}:
            out["severity"] = "Medium"

    return out

def summarize_findings(findings: List[Dict[str,Any]]) -> Dict[str,Any]:
    """Let the model request local queries, then return one JSON incident."""
    if not API_KEY:
        return {
            "tldr":"OpenAI unavailable: missing API key. Rendering raw findings.",
            "severity":"Low",
            "evidence":findings[:10],
            "hypotheses":["Online summarizer error/unavailable"],
            "next_steps":["Add OPENAI_API_KEY or use offline mode"],
            "candidate_actions":[],
            "generator":"fallback-online",
            "reason":"OPENAI_API_KEY missing",
        }

    seed = scrub(findings[:25])

    schema = {
      "type":"object",
      "properties": SCHEMA["properties"],
      "required": ["tldr","severity","evidence","next_steps","candidate_actions"]
    }

    system = (
      "You are TinySocs' analyst. You may call tools to run LOCAL queries. "
      "After at most 2 tool calls, return ONE JSON object matching the JSON schema. "
      "Evidence must be a flat list of small objects (ip, ip_rdns, user, count, rule). "
      "Do not include large nested arrays or raw event dumps. "
      "Final answer MUST be JSON only."
    )
    user = f"JSON Schema:\n{json.dumps(schema)}\n\nInitial Findings:\n{json.dumps(seed)}"

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
              "tool_choice": "none",
              "response_format": {"type":"json_object"}
            }
            r_final = http.post("https://api.openai.com/v1/chat/completions", json=body_final, headers=headers)
            r_final.raise_for_status()
            final_msg = r_final.json()["choices"][0]["message"]
            final_text = (final_msg.get("content") or "{}").strip() or "{}"
            try:
                obj = json.loads(final_text)
            except Exception:
                return {
                    "tldr":"OpenAI tools returned non-JSON; rendering raw findings.",
                    "severity":"Low",
                    "evidence":findings[:10],
                    "next_steps":["Retry later","Use offline mode"],
                    "candidate_actions":[],
                    "generator":"fallback-online",
                    "reason":"non-JSON response (no-tool path)"
                }
            obj = _coerce_incident(obj, findings)
            obj["generator"] = "openai+tools"
            return obj

        # -------- tool path: allow up to 2 tool rounds, then force JSON --------
        for _ in range(2):
            # run all requested tools
            tool_msgs = []
            for tc in tool_calls:
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"] or "{}")
                except Exception:
                    args = {}
                out  = _call_local_tool(name, args)
                tool_msgs.append({
                    "role":"tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps(out)
                })
            messages.extend(tool_msgs)

            # ask for final JSON (no more tools)
            body2 = {
              "model": MODEL,
              "messages": messages,
              "temperature": 0.0,
              "tool_choice": "none",
              "response_format": {"type":"json_object"}
            }
            r2 = http.post("https://api.openai.com/v1/chat/completions", json=body2, headers=headers)
            r2.raise_for_status()
            msg2 = r2.json()["choices"][0]["message"]
            messages.append(msg2)

            tool_calls = msg2.get("tool_calls") or []
            if not tool_calls:
                final_text = (msg2.get("content") or "{}").strip() or "{}"
                try:
                    obj = json.loads(final_text)
                except Exception:
                    return {
                        "tldr":"OpenAI tools returned non-JSON; rendering raw findings.",
                        "severity":"Low",
                        "evidence":findings[:10],
                        "next_steps":["Retry later","Use offline mode"],
                        "candidate_actions":[],
                        "generator":"fallback-online",
                        "reason":"non-JSON response (tool path)"
                    }
                obj = _coerce_incident(obj, findings)
                obj["generator"] = "openai+tools"
                return obj

        # If we exit the loop still asking for tools, fail-soft:
        return {
            "tldr":"Model requested excessive tool calls; rendering raw findings.",
            "severity":"Low",
            "evidence":findings[:10],
            "next_steps":["Retry later","Increase tool round limit","Use offline mode"],
            "candidate_actions":[],
            "generator":"fallback-online",
            "reason":"tool-call loop limit"
        }
