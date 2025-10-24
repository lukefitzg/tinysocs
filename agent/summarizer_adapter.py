# agent/summarizer_adapter.py
from __future__ import annotations
import hashlib, hmac, os, re, json
from typing import Dict, List, Any

# --------- env + defaults ----------
PRIVACY_MODE = os.getenv("PRIVACY_MODE", "abstract").strip().lower()  # abstract|raw
PRIVACY_SALT = os.getenv("PRIVACY_SALT", "")  # optional; set for stable cross-run correlation
PRIVACY_MAX_CMDLEN = int(os.getenv("PRIVACY_MAX_CMDLEN", "120"))
PRIVACY_TOP_TOKENS = int(os.getenv("PRIVACY_TOP_TOKENS", "25"))
DEBUG_SUMMARIZER = bool(int(os.getenv("DEBUG_SUMMARIZER", "1")))  # enable summary footer

_email_re = re.compile(r"(?i)\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b")
_ip_re    = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

def _mask_email(s: str) -> str:
    def _m(m):
        user, dom = m.group(1), m.group(2)
        u = (user[:1] + "***") if user else "***"
        d = dom.split(".")[0]
        dmask = (d[:1] + "***") if d else "***"
        return f"{u}@{dmask}"
    return _email_re.sub(_m, s)

def _coarsen_ip(s: str) -> str:
    def _m(m):
        parts = m.group(0).split(".")
        try:
            return ".".join(parts[:3] + ["0"]) + "/24"
        except Exception:
            return m.group(0)
    return _ip_re.sub(_m, s)

def _truncate_cmd(s: str) -> str:
    if s is None: 
        return s
    s = s.strip()
    return (s[:PRIVACY_MAX_CMDLEN] + " …") if len(s) > PRIVACY_MAX_CMDLEN else s

def _salted_hash(blob: Any, salt: str) -> str:
    try:
        b = json.dumps(blob, sort_keys=True, ensure_ascii=False).encode("utf-8")
    except Exception:
        b = repr(blob).encode("utf-8")
    if salt:
        return hmac.new(salt.encode("utf-8"), b, hashlib.sha256).hexdigest()
    return hashlib.sha256(b).hexdigest()

def _mask_str(s: str) -> str:
    if not s:
        return s
    return _coarsen_ip(_mask_email(s))

def _mask_any(v: Any) -> Any:
    if isinstance(v, str):
        return _mask_str(v)
    if isinstance(v, dict):
        return {k: _mask_any(val) for k, val in v.items()}
    if isinstance(v, list):
        return [_mask_any(x) for x in v]
    return v

def _extract_top_tokens(evidences: List[Dict[str, Any]]) -> List[str]:
    from collections import Counter
    c = Counter()
    for e in evidences:
        for k in ("summary", "exemplars"):
            if k not in e:
                continue
            chunk = e[k]
            if isinstance(chunk, dict):
                vals = list(chunk.values())
            elif isinstance(chunk, list):
                vals = chunk
            else:
                vals = [chunk]
            for v in vals:
                if isinstance(v, dict):
                    text = " ".join(str(x) for x in v.values())
                else:
                    text = str(v)
                for t in re.findall(r"[A-Za-z0-9._:-]{3,32}", text):
                    if re.fullmatch(r"\d{1,6}", t):
                        continue
                    c[t.lower()] += 1
    return [w for w, _ in c.most_common(PRIVACY_TOP_TOKENS)]

def _fingerprint_exemplar(ex: Any) -> str:
    return _salted_hash(ex, PRIVACY_SALT)

def prepare_payload(evidences: List[Dict[str, Any]], window: str) -> Dict[str, Any]:
    """
    Returns a dict to send to the summariser LLM.
    In 'abstract' mode: masked fact table (no raw PII or full cmdlines).
    In 'raw' mode: passthrough.
    """
    if PRIVACY_MODE == "raw":
        return {
            "mode": "raw",
            "window": window,
            "evidences": evidences,
            "note": "RAW mode: full evidences, no masking."
        }

    minimal = []
    for e in evidences:
        rule = e.get("rule")
        host = e.get("host") or e.get("node") or None
        count = int(e.get("count") or 0)

        summary = _mask_any(e.get("summary") or {})
        if isinstance(summary, dict):
            for k in list(summary.keys()):
                if "command" in k.lower() or "cmdline" in k.lower():
                    summary[k] = _truncate_cmd(_mask_str(str(summary[k])))

        exemplars = e.get("exemplars") or []
        fp = [_fingerprint_exemplar(_mask_any(x)) for x in exemplars][:10]

        minimal.append({
            "rule": rule,
            "host": _mask_str(host) if isinstance(host, str) else host,
            "count": count,
            "summary": summary,
            "exemplar_fingerprints": fp,
        })

    tokens = _extract_top_tokens(evidences)
    by_rule: Dict[str, Dict[str, Any]] = {}
    for m in minimal:
        key = (m["rule"] or "unknown")
        r = by_rule.setdefault(key, {"total": 0, "hosts": set()})
        r["total"] += m["count"]
        if m["host"]:
            r["hosts"].add(m["host"])

    aggregate = {
        "rules": sorted(by_rule.keys()),
        "counts": {k: v["total"] for k, v in by_rule.items()},
        "hosts_per_rule": {k: sorted(list(v["hosts"])) for k, v in by_rule.items()},
    }

    payload = {
        "mode": "abstract",
        "window": window,
        "aggregate": aggregate,
        "top_tokens": tokens,
        "notes": (
            "Payload redacted: emails masked, IPs /24-coarsened, "
            "command lines truncated, exemplars hashed."
        ),
        "minimal": minimal,
    }

    # Optional debug footer to help spot "phantom no-findings"
    if DEBUG_SUMMARIZER:
        total_evs = sum(x.get("count", 0) for x in minimal)
        rule_list = ", ".join(sorted(aggregate["rules"])) or "none"
        payload["debug_summary"] = {
            "total_rules": len(aggregate["rules"]),
            "total_evidences": len(evidences),
            "total_events_counted": total_evs,
            "rules_seen": rule_list,
            "window": window,
        }

        # Failsafe: if no evidences → insert stub; else ensure summarizer never sees empty
        if not evidences:
            payload["debug_summary"]["status_hint"] = "No evidences found by adapter."
        else:
            payload["debug_summary"]["status_hint"] = "Evidences exist; summarizer should not emit 'no findings'."

    return payload

def annotate_report_header(report_md: str, llm_mode: str = "openai") -> str:
    """
    Prefix the report with a one-liner stating privacy + backend.
    """
    privacy = "ON (abstract)" if PRIVACY_MODE != "raw" else "OFF (raw)"
    banner = f"**Summariser:** {llm_mode}  |  **Privacy:** {privacy}\n\n"
    if report_md.startswith("#"):
        parts = report_md.split("\n", 1)
        if len(parts) == 2:
            return parts[0] + "\n" + banner + parts[1]
    return banner + report_md