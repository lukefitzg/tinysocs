# tinysocs/api/dashboard.py
"""
Built-in operator dashboard — served by the bot FastAPI process.

No external JS/CSS dependencies. Everything is inline.
Queries OpenSearch via the bot's Python backend, so the browser
never needs direct SIEM access or credentials.

Mount:  app.mount("/dashboard", dashboard_app)
Browse: http://localhost:8090/dashboard
"""

from __future__ import annotations

import os
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

dashboard_app = FastAPI(title="TinySocs Dashboard", docs_url=None, redoc_url=None)

# ---------------------------------------------------------------------------
# OpenSearch helper (reuse same pattern as daily_summary)
# ---------------------------------------------------------------------------
def _os_query(index: str, body: Dict[str, Any], size: int = 0) -> Dict[str, Any]:
    import requests as _req
    try:
        import urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    url = os.getenv("SIEM_URL", "https://localhost:9201")
    user = os.getenv("SIEM_USER", "admin")
    passwd = os.getenv("SIEM_PASS", "admin")
    verify_str = os.getenv("SIEM_SSL_VERIFY", "false").lower()
    # Default to no-verify for local TinyBox (self-signed certs)
    verify = verify_str not in ("false", "0", "no", "")

    body["size"] = size
    resp = _req.post(
        f"{url.rstrip('/')}/{index}/_search",
        json=body,
        auth=(user, passwd),
        verify=verify,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def _safe_query(index: str, body: Dict[str, Any], size: int = 0) -> Dict[str, Any]:
    """Query with graceful error handling."""
    try:
        return _os_query(index, body, size)
    except Exception as exc:
        # Friendly error for operators — hide Python tracebacks
        err_type = type(exc).__name__
        err_str = str(exc)
        # Log the real error for diagnostics
        print(f"[dashboard] query error on {index}: {err_type}: {err_str[:200]}")
        if "SSL" in err_type or "SSL" in err_str:
            friendly = "SIEM SSL error"
        elif "Connection" in err_type or "ConnectionError" in err_str:
            friendly = "SIEM not connected"
        elif "401" in err_str or "403" in err_str:
            friendly = "SIEM authentication failed"
        elif "Timeout" in err_type:
            friendly = "SIEM request timed out"
        else:
            friendly = f"SIEM query failed ({err_type})"
        return {"error": friendly, "hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}


# ---------------------------------------------------------------------------
# Data API endpoints (no auth — local operator tool)
# ---------------------------------------------------------------------------
@dashboard_app.get("/api/alerts/timeline")
def api_alert_timeline(hours: int = Query(24, ge=1, le=720)):
    """Alert counts bucketed by hour and severity."""
    body = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {
            "timeline": {
                "date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 0},
                "aggs": {
                    "by_severity": {"terms": {"field": "alert.severity", "size": 10}}
                },
            }
        },
    }
    resp = _safe_query("tinysocs-alerts-*", body)
    buckets = resp.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    return {
        "hours": hours,
        "buckets": [
            {
                "time": b.get("key_as_string", ""),
                "count": b.get("doc_count", 0),
                "severity": {
                    s["key"]: s["doc_count"]
                    for s in b.get("by_severity", {}).get("buckets", [])
                },
            }
            for b in buckets
        ],
        "error": resp.get("error"),
    }


@dashboard_app.get("/api/alerts/summary")
def api_alert_summary(hours: int = Query(24, ge=1, le=720)):
    """Summary stats: total, by severity, top rules, top hosts."""
    # Total + severity
    body_sev = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {"by_severity": {"terms": {"field": "alert.severity", "size": 10}}},
    }
    resp_sev = _safe_query("tinysocs-alerts-*", body_sev)

    total_hit = resp_sev.get("hits", {}).get("total", {})
    total = total_hit.get("value", 0) if isinstance(total_hit, dict) else int(total_hit)
    severity = {
        b["key"]: b["doc_count"]
        for b in resp_sev.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
    }

    # Top rules
    body_rules = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {"by_rule": {"terms": {"field": "alert.rule_id", "size": 10, "order": {"_count": "desc"}}}},
    }
    resp_rules = _safe_query("tinysocs-alerts-*", body_rules)
    top_rules = [
        {"rule": b["key"], "count": b["doc_count"]}
        for b in resp_rules.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    ]

    # Top hosts — alerts store host in source.computer_name
    body_hosts = {
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "aggs": {"by_host": {"terms": {"field": "source.computer_name.keyword", "size": 10, "order": {"_count": "desc"}}}},
    }
    resp_hosts = _safe_query("tinysocs-alerts-*", body_hosts)
    top_hosts = [
        {"host": b["key"], "count": b["doc_count"]}
        for b in resp_hosts.get("aggregations", {}).get("by_host", {}).get("buckets", [])
    ]

    return {
        "hours": hours,
        "total": total,
        "severity": severity,
        "top_rules": top_rules,
        "top_hosts": top_hosts,
        "error": resp_sev.get("error"),
    }


@dashboard_app.get("/api/fleet/health")
def api_fleet_health():
    """Fleet status: hosts, last seen, event counts."""
    body = {
        "query": {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
        "aggs": {
            "by_host": {
                "terms": {"field": "winlog.computer_name", "size": 50},
                "aggs": {
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "event_count": {"value_count": {"field": "@timestamp"}},
                },
            }
        },
    }
    resp = _safe_query("tinysocs-winlog-*", body)
    hosts = []
    for b in resp.get("aggregations", {}).get("by_host", {}).get("buckets", []):
        hosts.append({
            "hostname": b["key"],
            "event_count": b.get("event_count", {}).get("value", b["doc_count"]),
            "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
        })
    return {"hosts": hosts, "error": resp.get("error")}


@dashboard_app.get("/api/events/recent")
def api_events_recent(
    limit: int = Query(50, ge=1, le=500),
    q: str = Query("", description="KQL filter"),
):
    """Recent events from tinysocs-winlog-*."""
    query: Dict[str, Any] = {"match_all": {}} if not q else {"query_string": {"query": q}}
    body: Dict[str, Any] = {
        "query": query,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    resp = _safe_query("tinysocs-winlog-*", body, size=limit)
    hits = resp.get("hits", {}).get("hits", [])
    events = []
    for h in hits:
        src = h.get("_source", {})
        events.append({
            "timestamp": src.get("@timestamp", ""),
            "channel": (src.get("winlog", {}) or {}).get("channel", ""),
            "event_id": (src.get("winlog", {}) or {}).get("event_id", src.get("event", {}).get("code", "")),
            "message": (src.get("message", "") or "")[:300],
            "host": (src.get("winlog", {}) or {}).get("computer_name", (src.get("agent", {}) or {}).get("hostname", "")),
        })
    return {"events": events, "total": len(events), "error": resp.get("error")}


@dashboard_app.get("/api/actions")
def api_actions():
    """List staged/approved/completed actions from executor."""
    try:
        from tinysocs.actions.executor import list_actions
        items = list_actions(limit=50)
        return {"actions": items}
    except Exception as exc:
        return {"actions": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# HTML dashboard (single page, inline everything)
# ---------------------------------------------------------------------------
@dashboard_app.get("/", response_class=HTMLResponse)
def dashboard_page():
    return _DASHBOARD_HTML


_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TinySocs Dashboard</title>
<style>
:root {
  --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
  --text: #e0e0e0; --muted: #888; --accent: #4a90d9;
  --red: #e74c3c; --orange: #e67e22; --yellow: #f1c40f;
  --green: #27ae60; --blue: #3498db; --gray: #555;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
       background: var(--bg); color: var(--text); font-size: 14px; }
a { color: var(--accent); text-decoration: none; }

.header { background: var(--surface); border-bottom: 1px solid var(--border);
           padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
.header h1 { font-size: 18px; font-weight: 600; }
.header .meta { color: var(--muted); font-size: 12px; }

.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 16px 24px; }
@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }

.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
        padding: 16px; min-height: 200px; }
.card h2 { font-size: 14px; color: var(--muted); text-transform: uppercase;
           letter-spacing: 0.5px; margin-bottom: 12px; font-weight: 500; }
.card.full { grid-column: 1 / -1; }

.stat-row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
.stat { background: var(--bg); border-radius: 6px; padding: 12px 16px; flex: 1; min-width: 100px; }
.stat .value { font-size: 28px; font-weight: 700; }
.stat .label { font-size: 11px; color: var(--muted); margin-top: 2px; }

table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; color: var(--muted); font-weight: 500; padding: 6px 8px;
     border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; }
td { padding: 6px 8px; border-bottom: 1px solid var(--border); }
tr:hover { background: rgba(74, 144, 217, 0.05); }

.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px;
         font-weight: 600; text-transform: uppercase; }
.badge-critical { background: rgba(231,76,60,0.15); color: var(--red); }
.badge-high { background: rgba(230,126,34,0.15); color: var(--orange); }
.badge-medium { background: rgba(241,196,15,0.15); color: var(--yellow); }
.badge-low { background: rgba(52,152,219,0.15); color: var(--blue); }
.badge-info { background: rgba(85,85,85,0.15); color: var(--gray); }

.badge-staged { background: rgba(241,196,15,0.15); color: var(--yellow); }
.badge-approved { background: rgba(52,152,219,0.15); color: var(--blue); }
.badge-executing { background: rgba(230,126,34,0.15); color: var(--orange); }
.badge-completed { background: rgba(39,174,96,0.15); color: var(--green); }
.badge-failed { background: rgba(231,76,60,0.15); color: var(--red); }

.chart { height: 160px; display: flex; align-items: flex-end; gap: 2px; padding-top: 8px; }
.chart .bar { flex: 1; min-width: 4px; border-radius: 2px 2px 0 0; transition: height 0.3s;
              position: relative; cursor: pointer; }
.chart .bar:hover::after { content: attr(data-tip); position: absolute; bottom: 100%;
  left: 50%; transform: translateX(-50%); background: var(--surface); border: 1px solid var(--border);
  padding: 4px 8px; border-radius: 4px; font-size: 11px; white-space: nowrap; z-index: 10; }
.bar-critical { background: var(--red); }
.bar-high { background: var(--orange); }
.bar-medium { background: var(--yellow); }
.bar-low { background: var(--blue); }
.bar-info, .bar-default { background: var(--gray); }

.empty { text-align: center; padding: 40px; color: var(--muted); }
.error { color: var(--muted); font-size: 12px; padding: 8px; background: rgba(255,255,255,0.03);
         border: 1px solid var(--border); border-radius: 4px; margin-bottom: 8px; }
.loading { color: var(--muted); text-align: center; padding: 20px; }
.refresh-btn { background: var(--accent); color: #fff; border: none; padding: 6px 14px;
               border-radius: 4px; cursor: pointer; font-size: 12px; }
.refresh-btn:hover { opacity: 0.9; }
.tabs { display: flex; gap: 4px; margin-bottom: 12px; }
.tab { padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px;
       color: var(--muted); background: var(--bg); border: 1px solid var(--border); }
.tab.active { background: var(--accent); color: #fff; border-color: var(--accent); }
input[type="text"] { background: var(--bg); border: 1px solid var(--border); color: var(--text);
  padding: 6px 10px; border-radius: 4px; font-size: 13px; width: 100%; margin-bottom: 8px; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>TinySocs Dashboard</h1>
    <div class="meta" id="lastUpdate">Loading...</div>
  </div>
  <div>
    <div class="tabs" style="display:inline-flex; margin-right: 8px;">
      <div class="tab active" onclick="setHours(24)">24h</div>
      <div class="tab" onclick="setHours(48)">48h</div>
      <div class="tab" onclick="setHours(168)">7d</div>
    </div>
    <button class="refresh-btn" onclick="refreshAll()">Refresh</button>
  </div>
</div>

<div class="grid">
  <!-- Alert Summary -->
  <div class="card">
    <h2>Alert Summary</h2>
    <div id="summary-content"><div class="loading">Loading...</div></div>
  </div>

  <!-- Alert Timeline -->
  <div class="card">
    <h2>Alert Timeline</h2>
    <div id="timeline-content"><div class="loading">Loading...</div></div>
  </div>

  <!-- Top Rules -->
  <div class="card">
    <h2>Top Detection Rules</h2>
    <div id="rules-content"><div class="loading">Loading...</div></div>
  </div>

  <!-- Fleet Health -->
  <div class="card">
    <h2>Fleet Health</h2>
    <div id="fleet-content"><div class="loading">Loading...</div></div>
  </div>

  <!-- Actions -->
  <div class="card">
    <h2>Staged Actions</h2>
    <div id="actions-content"><div class="loading">Loading...</div></div>
  </div>

  <!-- Event Explorer -->
  <div class="card">
    <h2>Event Explorer</h2>
    <input type="text" id="eventQuery" placeholder="KQL filter (e.g. winlog.event_id:4625)" onkeydown="if(event.key==='Enter')loadEvents()">
    <div id="events-content"><div class="loading">Loading...</div></div>
  </div>
</div>

<script>
let hours = 24;
const BASE = window.location.pathname.replace(/\\/$/, '');

function setHours(h) {
  hours = h;
  document.querySelectorAll('.tabs .tab').forEach(t => t.classList.remove('active'));
  event.target.classList.add('active');
  refreshAll();
}

function severityBadge(s) {
  const cls = {'critical':'critical','high':'high','medium':'medium','low':'low','info':'info'}[s?.toLowerCase()] || 'info';
  return `<span class="badge badge-${cls}">${s||'unknown'}</span>`;
}

function statusBadge(s) {
  const cls = {'staged':'staged','approved':'approved','executing':'executing','completed':'completed','failed':'failed'}[s] || 'info';
  return `<span class="badge badge-${cls}">${s}</span>`;
}

function barColor(sev) {
  return {'critical':'bar-critical','high':'bar-high','medium':'bar-medium','low':'bar-low','info':'bar-info'}[sev?.toLowerCase()] || 'bar-default';
}

async function fetchJSON(path) {
  try {
    const r = await fetch(BASE + path);
    return await r.json();
  } catch(e) {
    return { error: e.message };
  }
}

async function loadSummary() {
  const el = document.getElementById('summary-content');
  const d = await fetchJSON(`/api/alerts/summary?hours=${hours}`);
  if (d.error && !d.severity) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  const total = d.total || 0;
  const sev = d.severity || {};
  const sevOrder = ['critical','high','medium','low','info'];

  let html = '<div class="stat-row">';
  html += `<div class="stat"><div class="value">${total}</div><div class="label">Total Alerts</div></div>`;
  for (const s of sevOrder) {
    if (sev[s]) html += `<div class="stat"><div class="value" style="color:var(--${s==='critical'?'red':s==='high'?'orange':s==='medium'?'yellow':s==='low'?'blue':'gray'})">${sev[s]}</div><div class="label">${s}</div></div>`;
  }
  html += '</div>';

  if (d.top_hosts?.length) {
    html += '<table><tr><th>Host</th><th>Alerts</th></tr>';
    for (const h of d.top_hosts.slice(0, 5)) html += `<tr><td>${h.host}</td><td>${h.count}</td></tr>`;
    html += '</table>';
  }
  if (total === 0) html += '<div class="empty">All quiet &mdash; no alerts</div>';
  el.innerHTML = html;
}

async function loadTimeline() {
  const el = document.getElementById('timeline-content');
  const d = await fetchJSON(`/api/alerts/timeline?hours=${hours}`);
  if (d.error && !d.buckets?.length) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  const buckets = d.buckets || [];
  if (!buckets.length) { el.innerHTML = '<div class="empty">No alerts in period</div>'; return; }

  const maxCount = Math.max(1, ...buckets.map(b => b.count));
  let html = '<div class="chart">';
  for (const b of buckets) {
    const pct = Math.max(2, (b.count / maxCount) * 100);
    const topSev = Object.entries(b.severity || {}).sort((a,b) => b[1]-a[1])[0];
    const cls = topSev ? barColor(topSev[0]) : 'bar-default';
    const time = b.time ? new Date(b.time).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '';
    html += `<div class="bar ${cls}" style="height:${pct}%" data-tip="${time}: ${b.count} alerts"></div>`;
  }
  html += '</div>';
  el.innerHTML = html;
}

async function loadRules() {
  const el = document.getElementById('rules-content');
  const d = await fetchJSON(`/api/alerts/summary?hours=${hours}`);
  const rules = d.top_rules || [];
  if (!rules.length) { el.innerHTML = '<div class="empty">No rules fired</div>'; return; }

  let html = '<table><tr><th>Rule</th><th>Fires</th></tr>';
  for (const r of rules) html += `<tr><td><code>${r.rule}</code></td><td>${r.count}</td></tr>`;
  html += '</table>';
  el.innerHTML = html;
}

async function loadFleet() {
  const el = document.getElementById('fleet-content');
  const d = await fetchJSON('/api/fleet/health');
  if (d.error && !d.hosts?.length) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  const hosts = d.hosts || [];
  if (!hosts.length) { el.innerHTML = '<div class="empty">No hosts reporting</div>'; return; }

  let html = '<table><tr><th>Host</th><th>Events (24h)</th><th>Last Seen</th></tr>';
  for (const h of hosts) {
    const ago = h.last_seen ? timeAgo(h.last_seen) : 'unknown';
    html += `<tr><td>${h.hostname}</td><td>${h.event_count}</td><td>${ago}</td></tr>`;
  }
  html += '</table>';
  el.innerHTML = html;
}

async function loadActions() {
  const el = document.getElementById('actions-content');
  const d = await fetchJSON('/api/actions');
  const actions = d.actions || [];
  if (!actions.length) { el.innerHTML = '<div class="empty">No staged actions</div>'; return; }

  let html = '<table><tr><th>Action</th><th>Status</th><th>Params</th><th>Who</th></tr>';
  for (const a of actions.slice(0, 20)) {
    const params = typeof a.params === 'object' ? Object.entries(a.params).map(([k,v])=>`${k}=${v}`).join(', ') : '';
    html += `<tr><td><code>${a.action}</code></td><td>${statusBadge(a.status)}</td><td>${params}</td><td>${a.who||''}</td></tr>`;
  }
  html += '</table>';
  el.innerHTML = html;
}

async function loadEvents() {
  const el = document.getElementById('events-content');
  const q = document.getElementById('eventQuery').value;
  el.innerHTML = '<div class="loading">Loading...</div>';
  const d = await fetchJSON(`/api/events/recent?limit=30&q=${encodeURIComponent(q)}`);
  if (d.error && !d.events?.length) { el.innerHTML = `<div class="empty">${d.error}</div>`; return; }

  const events = d.events || [];
  if (!events.length) { el.innerHTML = '<div class="empty">No events found</div>'; return; }

  let html = '<table><tr><th>Time</th><th>Host</th><th>Channel</th><th>ID</th><th>Message</th></tr>';
  for (const e of events) {
    const t = e.timestamp ? new Date(e.timestamp).toLocaleString() : '';
    const msg = (e.message || '').substring(0, 120);
    html += `<tr><td style="white-space:nowrap">${t}</td><td>${e.host}</td><td>${e.channel}</td><td>${e.event_id}</td><td style="font-size:12px;color:var(--muted)">${msg}</td></tr>`;
  }
  html += '</table>';
  el.innerHTML = html;
}

function timeAgo(iso) {
  try {
    const ms = Date.now() - new Date(iso).getTime();
    const m = Math.floor(ms / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return m + 'm ago';
    const h = Math.floor(m / 60);
    if (h < 24) return h + 'h ago';
    return Math.floor(h / 24) + 'd ago';
  } catch(e) { return iso; }
}

function refreshAll() {
  document.getElementById('lastUpdate').textContent = 'Refreshing...';
  Promise.all([loadSummary(), loadTimeline(), loadRules(), loadFleet(), loadActions(), loadEvents()])
    .then(() => {
      document.getElementById('lastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
    });
}

// Auto-refresh every 30 seconds
refreshAll();
setInterval(refreshAll, 30000);
</script>
</body>
</html>
"""
