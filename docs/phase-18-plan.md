TinySocs Phase 18 Plan — Minimum Viable Federation
===================================================

Theme: "One pane of glass"


Context
-------

Phase 17 bridged TinySocs from engineering to go-to-market. The dashboard launches in demo mode on any OS, a release pipeline builds the installer and publishes GitHub Releases, and outreach materials are ready. The Sites tab shows all configured TinySocs nodes with health status, version, ledger sequence, and last anchor timestamp.

But the Sites tab is a health-check overlay, not federation. It answers "are my sites up?" — it doesn't answer "what's happening at my sites?" An MSSP looking at the Sites tab today sees:

- **acme-law: healthy, v0.8.0, ledger seq 347, last anchor 12 min ago**

What they actually need to see is:

- **acme-law: 3 critical alerts, 12 total alerts (24h), 8 hosts, top rule: brute\_force\_password — click to investigate**

The federation infrastructure already exists in substantial form. `master.py` (1,141 lines) handles async concurrent fan-out to nodes with retry and jitter. `node.py` (599 lines) exposes detection execution and evidence endpoints with HMAC-SHA256 authentication. The evidence ledger provides hash-chained tamper detection with anchor verification. The installer has Master/Node/TinyBox role selection. Live ledger files exist for test nodes. But none of this surfaces through the dashboard. The dashboard talks to one `SIEM_URL` for alert data. The Sites tab calls `/meta` and `/evidence/head` on each node — read-only health probes that return no operational data.

The result: TinySocs is a standalone SIEM with a health-check sidecar. You can see that your sites exist and are reachable, but to find out what's actually happening at any site, you have to log into that site's dashboard separately. There is no "one pane of glass." There is no aggregated view. There is no drill-through. The MSSP pitch — "manage 50 clients from one place" — is a story told with synthetic demo data, not a working product.

Phase 18 closes this gap with the minimum federation that makes the multi-site story real:

1. **Nodes report their operational state** — alert counts, severity breakdown, host counts — via new summary endpoints on `node.py`.
2. **The Sites tab shows what's happening, not just what's running** — per-site alert badges, severity dots, host counts, top firing rules.
3. **Drill-through works** — click a site card, the dashboard switches to show that site's data. Overview, Fleet, Data, and Detections tabs render remote data proxied through the master.
4. **Demo mode exercises real federation code paths** — synthetic data flows through the same aggregation and proxy logic as production, so the demo tests the real system.

After Phase 18, an operator at the master dashboard can see "acme-law has 3 critical alerts," click in, see the alert timeline and fleet health for that site, investigate with the Event Explorer, and return to the all-sites view — without ever logging into acme-law's dashboard directly. This is the product that walks into an MSSP meeting.

Design principle — **read before write**: Build federation visibility (reading data from all sites) before federation control (pushing config/rules to sites). An MSSP's first need is "show me what's happening everywhere." Distribution and control follow once you know what operators actually want to push.


M0 — Node Summary Endpoints
----------------------------

**Goal:** Nodes report their operational state — alert counts and fleet composition — so the master dashboard can show what's happening at each site, not just whether it's reachable.

**Current State**

- `node.py` exposes 5 endpoints: `/meta`, `/agg`, `/sample`, `/evidence/head`, `/evidence/append`
- `/meta` returns node\_id, version, endpoint list, HMAC config — no operational data
- `/agg` runs detection rules against the local OpenSearch and returns raw evidence — this is a rule execution engine, not a summary endpoint
- `/evidence/head` returns ledger chain state — not alert data
- The dashboard's `/api/nodes` handler calls `/meta` and `/evidence/head` on each node, then queries the local anchors index for anchor timestamps
- Result: the Sites tab shows health, version, ledger sequence, and last anchor — but zero information about alerts, hosts, or what's actually happening at the site
- `node.py` already has `_os_search()` — a working OpenSearch query helper that handles auth, TLS, and error handling

**Proposed Changes**

Files:
- `src/tinysocs/api/node.py` — Add two new read-only endpoints

**Deliverables**

1. **GET /alerts/summary** — Alert summary for the local site (last 24 hours):
   - Queries `tinysocs-alerts-*` on the local OpenSearch for alert counts by severity, top rules, and top hosts
   - Uses the same index patterns and field names as `dashboard.py`'s `api_alert_summary()`: `alert.severity.keyword`, `alert.rule_id`, `source.computer_name.keyword`
   - No HMAC required (read-only summary data, same access level as `/meta`)
   - Response shape:
     ```json
     {
       "hours": 24,
       "total": 14,
       "severity": {"critical": 2, "high": 5, "medium": 4, "low": 3},
       "top_rules": [{"rule": "brute_force_password", "count": 5}, ...],
       "top_hosts": [{"host": "RECEPTION-PC", "count": 8}, ...]
     }
     ```
   - Three aggregation queries run sequentially (matching dashboard pattern): severity terms, rule terms, host terms
   - Hours parameter defaults to 24, accepts 1-720 range

2. **GET /fleet/summary** — Fleet composition for the local site:
   - Queries `tinysocs-winlog-*` on the local OpenSearch for distinct hosts, event counts, and last-seen timestamps
   - Uses same field names as `dashboard.py`'s `api_fleet_health()`: `winlog.computer_name`, `@timestamp`
   - No HMAC required
   - Response shape:
     ```json
     {
       "host_count": 8,
       "total_events_24h": 45230,
       "hosts": [
         {"hostname": "RECEPTION-PC", "events_24h": 12847, "last_seen": "2026-03-07T15:42:00Z"},
         ...
       ]
     }
     ```
   - Single aggregation query: terms on `winlog.computer_name` with `max(@timestamp)` and `value_count(@timestamp)` sub-aggs

3. **`/meta` response updated** — Add the two new endpoints to the `endpoints` list:
   - `"/alerts/summary"` and `"/fleet/summary"` appended to the existing list

**Acceptance**

- Node running with events in OpenSearch → `GET /alerts/summary` returns JSON with total, severity, top\_rules, top\_hosts
- Node running with events in OpenSearch → `GET /fleet/summary` returns JSON with host\_count, total\_events\_24h, hosts array
- Node running with empty OpenSearch → both endpoints return zero counts and empty arrays (no errors)
- Node running with OpenSearch unreachable → both endpoints return `{"error": "..."}` with a descriptive message
- `/meta` response includes `/alerts/summary` and `/fleet/summary` in the endpoints list
- No HMAC headers required — both endpoints accessible without authentication (same as `/meta`)


M1 — Enriched Sites Tab
------------------------

**Goal:** The Sites tab shows operational data per site — alert counts with severity badges, host counts, and top firing rules — so an operator can see at a glance which sites need attention. When `TINYSOCS_NODES` is configured, an aggregate banner on the Overview tab summarises cross-site alert state.

**Current State**

- The `/api/nodes` handler calls `/meta` and `/evidence/head` on each node, then queries the local anchors index
- Each node entry in the response contains: url, node\_id, version, status, ledger\_sequence, ledger\_head, last\_anchor\_at, last\_anchor\_items, reachable, error
- The Sites tab renders site cards showing: status dot, node\_id, version (with outdated badge), ledger sequence, last anchor timestamp, detections from last run
- No alert counts, no severity breakdown, no host counts, no operational data
- The Sites tab refreshes every 30 seconds
- The `/api/nodes` handler already iterates node URLs with `httpx.AsyncClient` — adding concurrent requests to the new summary endpoints is straightforward

**Proposed Changes**

Files:
- `src/tinysocs/api/dashboard.py` — Enhance `/api/nodes` handler + Sites tab JS + aggregate Overview banner

**Deliverables**

1. **/api/nodes handler enhancement** (`dashboard.py`):
   - After calling `/meta` and `/evidence/head` on each node, also call `/alerts/summary` and `/fleet/summary`
   - All four calls per node run concurrently via `asyncio.gather` (not sequentially)
   - Merge results into the node entry:
     - `alerts_24h`: total alert count from `/alerts/summary`
     - `alerts_critical`: critical count from severity breakdown
     - `alerts_high`: high count from severity breakdown
     - `top_rule`: first rule name from top\_rules (or empty string)
     - `host_count`: host\_count from `/fleet/summary`
     - `total_events_24h`: total\_events\_24h from `/fleet/summary`
   - If `/alerts/summary` or `/fleet/summary` times out or fails, set the corresponding fields to `null` (not 0 — so the UI can distinguish "no data" from "zero alerts")
   - Existing fields unchanged — no breaking changes
   - New aggregate summary in the response:
     ```json
     {
       "nodes": [...],
       "aggregate": {
         "total_alerts_24h": 47,
         "total_critical": 5,
         "total_high": 12,
         "total_hosts": 22,
         "sites_healthy": 2,
         "sites_warning": 1,
         "sites_unreachable": 0
       }
     }
     ```
   - Aggregate sums are computed from all reachable nodes where the summary data is not null

2. **Sites tab card enhancement** (JS in `dashboard.py`):
   - Each site card now shows (in addition to existing data):
     - Alert count badge: coloured circle with total alerts (red if any critical, orange if high, grey if zero)
     - Severity breakdown line: "2 critical · 5 high · 4 medium" (only non-zero severities shown)
     - Host count: "8 hosts"
     - Top rule: "Top: brute\_force\_password" (if available)
   - Cards with critical alerts get a subtle red left border accent (2px solid var(--red))
   - Cards with only medium/low alerts keep the default border
   - Cards with null alert data (summary endpoint unreachable) show "—" for all operational fields
   - Site cards are sorted: critical alerts first, then by total alert count descending, then alphabetically by node\_id. This ensures the sites that need attention appear at the top

3. **Demo mode enhancement** (`_demo_nodes()`):
   - Add per-site alert and fleet data to the synthetic response:
     - acme-law: 14 alerts (2 critical, 5 high), 8 hosts, top rule: brute\_force\_password
     - mainst-dental: 3 alerts (0 critical, 1 high), 4 hosts, top rule: off\_hours\_logon
     - harbor-ins: 31 alerts (3 critical, 8 high), 12 hosts, top rule: suspicious\_powershell
   - harbor-ins (the warning site) has the most alerts — gives the demo a natural "investigate this one" talking point
   - Aggregate summary computed from demo data

4. **Overview tab aggregate banner** (JS in `dashboard.py`):
   - When `TINYSOCS_NODES` is configured (or in demo mode), the Overview tab shows a banner above Alert Summary:
     - "3 sites · 47 alerts (5 critical) · 22 hosts" with severity-coloured dots
     - Clicking the banner navigates to the Sites tab
   - Banner fetches data from `/api/nodes` (same endpoint, cached from Sites tab init)
   - Banner not shown when `TINYSOCS_NODES` is unconfigured (single-site deployment)
   - Banner refreshes on the same 30-second cycle as the Sites tab

**Acceptance**

- Sites tab card for a node with alerts shows: alert count badge, severity breakdown, host count, top rule
- Sites tab card for a node with no alerts shows: "0" badge (grey), "No alerts", host count
- Sites tab card for an unreachable node shows: existing error message, "—" for all operational fields
- Demo mode Sites tab shows enriched cards with per-site alert data
- Sites tab cards sorted by severity priority (critical first)
- Overview tab shows aggregate banner when nodes configured: "3 sites · 47 alerts (5 critical) · 22 hosts"
- Overview tab aggregate banner click navigates to Sites tab
- Single-site deployment (no TINYSOCS\_NODES): no aggregate banner, Sites tab hidden (existing behaviour unchanged)


M2 — Node Query Endpoints
--------------------------

**Goal:** Nodes expose the same data endpoints the dashboard uses internally — alert timeline, fired detections, fleet health, event search — so the master dashboard can proxy drill-through requests to a specific site.

**Current State**

- `node.py` has `_os_search()` — a working OpenSearch query helper (auth, TLS, error handling, result flattening)
- `dashboard.py` has `_safe_query()` / `_safe_query_async()` which query the local OpenSearch for alert timelines, fired detections, fleet health, event data, and host timelines
- These query functions use specific index patterns (`tinysocs-alerts-*`, `tinysocs-winlog-*`) and field names (`alert.severity.keyword`, `winlog.computer_name`, etc.)
- `node.py` already uses the same OpenSearch connection config (`SIEM_URL`, `SIEM_USER`, `SIEM_PASS`) as the dashboard
- The gap: these queries only exist as internal functions inside `dashboard.py` — they're not available as HTTP endpoints on the node

**Proposed Changes**

Files:
- `src/tinysocs/api/node.py` — Add query endpoints that mirror dashboard data APIs

**Deliverables**

1. **GET /alerts/timeline** — Hourly bucketed alert counts:
   - Parameters: `hours` (default 24, 1-720)
   - Queries `tinysocs-alerts-*` with date\_histogram on `timestamp` field, interval 1h
   - Each bucket includes per-severity counts via terms sub-aggregation on `alert.severity.keyword`
   - Response shape matches dashboard's `/api/alerts/timeline`:
     ```json
     {
       "hours": 24,
       "buckets": [
         {"time": "2026-03-07T14:00:00Z", "count": 3, "critical": 1, "high": 2, "medium": 0, "low": 0},
         ...
       ]
     }
     ```

2. **GET /detections/fired** — Individual fired detection alerts:
   - Parameters: `hours` (default 24), `limit` (default 30, 1-200)
   - Queries `tinysocs-alerts-*` sorted by `timestamp` desc
   - Returns array of alert documents with fields matching dashboard expectations: `alert.rule_id`, `alert.rule_name`, `alert.severity`, `source.computer_name`, `timestamp`, `alert.description`, `enrichment`
   - Response shape matches dashboard's `/api/detections/fired`:
     ```json
     {
       "hours": 24,
       "detections": [
         {
           "rule_id": "brute_force_password",
           "rule_name": "Brute Force: Password Guessing",
           "severity": "critical",
           "hostname": "RECEPTION-PC",
           "timestamp": "2026-03-07T15:42:00Z",
           "description": "...",
           "count": 8
         },
         ...
       ]
     }
     ```

3. **GET /fleet/health** — Detailed per-host fleet status:
   - Queries `tinysocs-winlog-*` and `tinysocs-alerts-*` (same dual-query pattern as dashboard's `api_fleet_health`)
   - Returns per-host: hostname, event\_count, last\_seen, first\_seen, top\_channels, alert\_count, alert\_severities
   - Response shape matches dashboard's `/api/fleet/health`:
     ```json
     {
       "hosts": [
         {
           "hostname": "RECEPTION-PC",
           "event_count": 12847,
           "last_seen": "2026-03-07T15:42:00Z",
           "first_seen": "2026-03-07T00:00:00Z",
           "top_channels": [{"channel": "Security", "count": 8921}],
           "alerts": 18,
           "alert_severity": {"critical": 2, "high": 5}
         },
         ...
       ]
     }
     ```

4. **GET /events/recent** — Event search:
   - Parameters: `limit` (default 50, 1-500), `q` (KQL filter, default ""), `index` (default "tinysocs-winlog-\*")
   - Queries the specified index with optional KQL filter via `query_string`
   - Returns array of event documents matching dashboard's `/api/events/recent` shape
   - This reuses the existing `/sample` endpoint's query logic but with response shaping to match dashboard expectations

5. **GET /host/timeline** — Per-host event timeline:
   - Parameters: `hostname` (optional — empty means fleet-wide), `hours` (default 24)
   - Queries `tinysocs-winlog-*` with date\_histogram on `@timestamp`, bucketed hourly
   - Each bucket includes per-channel counts via terms sub-aggregation on `winlog.channel`
   - Response shape matches dashboard's `/api/host/timeline`:
     ```json
     {
       "hostname": "RECEPTION-PC",
       "hours": 24,
       "buckets": [
         {"time": "2026-03-07T14:00:00Z", "Security": 142, "Sysmon": 38, "System": 12},
         ...
       ]
     }
     ```

6. **`/meta` response updated** — Add the five new endpoints to the endpoints list

**Notes:**
- All five endpoints are read-only and do not require HMAC (same policy as `/meta`, `/evidence/head`, and the M0 summary endpoints)
- All five endpoints use the existing `_os_search()` helper and `_get_siem_auth()` for OpenSearch access
- Query patterns are extracted from `dashboard.py`'s existing endpoint implementations — same index patterns, same field names, same aggregation structures
- Error handling follows `node.py`'s existing pattern: OpenSearch unreachable → return empty results with no crash

**Acceptance**

- Node with events → `GET /alerts/timeline` returns 24 hourly buckets with severity counts
- Node with events → `GET /detections/fired` returns alert documents sorted by timestamp desc
- Node with events → `GET /fleet/health` returns per-host metrics with alert counts
- Node with events → `GET /events/recent?q=EventID:4625` returns matching events
- Node with events → `GET /host/timeline?hostname=RECEPTION-PC` returns per-channel hourly buckets
- Node with empty OpenSearch → all endpoints return empty arrays/zero counts
- Response shapes match what the dashboard JS expects (same field names, same nesting)


M3 — Dashboard Site Proxy & Drill-Through
------------------------------------------

**Goal:** Click a site card on the Sites tab, and the dashboard switches to show that site's data. All tabs (Overview, Fleet, Data, Detections) render data from the selected site, proxied through the master. A "Back to all sites" button returns to the aggregated view.

**Current State**

- The dashboard talks to one `SIEM_URL` for all data
- All `fetchJSON()` calls in the JS use relative paths: `/api/alerts/summary`, `/api/fleet/health`, etc.
- `switchTab()` calls `loadTabData()` which refreshes the active tab's widgets
- There is no concept of "which site's data am I viewing"
- There is no proxy mechanism to forward API calls to a remote node
- The Sites tab renders site cards but clicking them does nothing (no `onclick` handler)

**Proposed Changes**

Files:
- `src/tinysocs/api/dashboard.py` — Proxy endpoint + JS drill-through mode

**Deliverables**

1. **Dashboard proxy endpoint** (Python):
   - `GET /api/site/{node_id}/{path:path}` — Generic proxy handler
   - Looks up the node URL from `TINYSOCS_NODES` by matching `node_id` from the cached `/api/nodes` response (or by calling `/meta` on each URL to find the match)
   - Forwards the request to `{node_url}/{path}?{query_params}`
   - Returns the node's response as-is (pass-through JSON)
   - Uses `httpx.AsyncClient` with `verify=False` and 10-second timeout
   - Security: only proxies to URLs in `TINYSOCS_NODES` — not an open proxy
   - If `node_id` is not found in configured nodes → 404
   - If the node is unreachable → 502 with `{"error": "Site unreachable: ..."}`
   - In demo mode: instead of making HTTP calls, calls the demo response functions with the appropriate site context (returns site-filtered synthetic data)

2. **Node ID resolution cache** (Python):
   - Module-level dict `_node_id_to_url: Dict[str, str]` mapping node\_id → node URL
   - Populated on first `/api/nodes` call (when we already call `/meta` on each node)
   - Updated on each `/api/nodes` refresh
   - Proxy endpoint looks up node\_id in this cache — avoids calling `/meta` on every proxied request

3. **JS drill-through mode** (JavaScript in dashboard.py):
   - New global variable: `let _focusedSite = null;` (null = all-sites view, string = node\_id of focused site)
   - New helper function: `function apiBase() { return _focusedSite ? '/api/site/' + _focusedSite : '/api'; }`
   - All `fetchJSON('/api/...')` calls updated to use `fetchJSON(apiBase() + '/...')`
   - Affected functions: `loadSummary()`, `loadTimeline()`, `loadFleet()`, `loadFleetTimeline()`, `loadEvents()`, `loadDetections()`, `loadHostTimeline()`
   - `fetchJSON()` calls that should NOT be proxied (always query the master): `loadSites()` (`/api/nodes`), `loadMitre()` (`/api/mitre/*`), `loadCompliance()` (`/api/compliance/*`), `loadSettings()` (`/api/settings`)

4. **Site card click handler** (JavaScript):
   - Each site card gets `onclick="focusSite('${n.node_id}')"` (onclick on the card div, not the header)
   - `focusSite(nodeId)` function:
     - Sets `_focusedSite = nodeId`
     - Shows the site focus banner
     - Switches to Overview tab and refreshes data
     - Stores focused site in `sessionStorage` (not localStorage — clears on tab close)
   - Clicking the currently focused site card is a no-op

5. **Site focus banner** (HTML/CSS/JS):
   - Positioned between the tab bar and the main content area (sticky, below tab bar)
   - Shows: "Viewing: **{node\_id}**" with a "← All Sites" button on the left
   - CSS: dark background with accent left border (matches the site card's status colour), compact height (~36px)
   - "← All Sites" button calls `unfocusSite()`:
     - Sets `_focusedSite = null`
     - Hides the site focus banner
     - Switches to Sites tab
     - Clears `sessionStorage` focused site
   - Banner hidden when `_focusedSite` is null

6. **Tab behaviour in focused mode**:
   - Overview: shows Alert Summary and Alert Timeline for the focused site (via proxied `/alerts/summary` and `/alerts/timeline`)
   - Fleet: shows Fleet Health and Event Flow for the focused site (via proxied `/fleet/health` and `/host/timeline`)
   - Data: shows Event Explorer querying the focused site's events (via proxied `/events/recent`)
   - Detections: shows Fired Detections for the focused site (via proxied `/detections/fired`). Alert Rules tab continues to show local rules (not proxied — rules are the same everywhere)
   - Compliance: not proxied — shows the master's compliance data. MITRE coverage is derived from rule files, not per-site data
   - Sites: always shows all sites (not affected by focused mode)

7. **Visual indicators in focused mode**:
   - Tab bar gets a subtle visual treatment when focused (e.g., a thin coloured top border matching the site's status)
   - The Overview aggregate banner (from M1) is hidden in focused mode (you're looking at one site, not all)
   - The AI Assistant remains connected to the master SIEM (known limitation — documented below)

8. **State management**:
   - `_focusedSite` stored in `sessionStorage('tinysocs_focused_site')` — restored on page reload within the same browser session
   - When a focused site is restored on load, the site focus banner renders immediately and the active tab refreshes with proxied data
   - If the stored focused site is no longer in `TINYSOCS_NODES` (e.g., node removed), clear the stored value and fall back to Sites tab
   - URL hash continues to track the active tab (not the focused site) — e.g., `#fleet` while focused on acme-law

**Acceptance**

- Sites tab → click acme-law card → site focus banner appears: "Viewing: acme-law ← All Sites"
- Overview tab shows acme-law's alert summary and timeline (not the master's)
- Fleet tab shows acme-law's hosts and event flow (not the master's)
- Data tab searches acme-law's events (not the master's)
- Detections tab shows acme-law's fired detections
- Compliance tab shows master's compliance data (not proxied)
- "← All Sites" → returns to Sites tab, all tabs show master data again
- Refresh page while focused on acme-law → focus restored (sessionStorage)
- Demo mode: clicking a demo site card → drill-through works with site-specific synthetic data
- Proxy returns 404 for unknown node\_id
- Proxy returns 502 for unreachable node
- AI Assistant continues to work (queries master SIEM regardless of focus)


M4 — Demo Mode Federation Paths
--------------------------------

**Goal:** Demo mode exercises the real aggregation and proxy code paths instead of returning hardcoded data. The demo validates the federation architecture every time someone runs `--demo`.

**Current State**

- Demo mode has 12 `_demo_*()` functions that return hardcoded dicts
- `/api/nodes` in demo mode calls `_demo_nodes()` which returns a static dict — never calls the aggregation or node health code
- The proxy endpoint (M3) doesn't exist yet in demo mode
- Demo mode tests validate response shapes but not code paths — a bug in the aggregation logic would not be caught by a demo run
- The demo scenario has 3 sites (acme-law, mainst-dental, harbor-ins) and 3 hosts (RECEPTION-PC, FILESERVER-01, DC-01)

**Proposed Changes**

Files:
- `src/tinysocs/api/dashboard.py` — Demo mode site-specific data + proxy demo handler

**Deliverables**

1. **Per-site demo data generators**:
   - Each of the 3 demo sites gets its own data context (hosts, alerts, events)
   - Site-to-host mapping:
     - acme-law: RECEPTION-PC (front desk), PARTNER-LAPTOP (attorney)
     - mainst-dental: FRONTDESK-01 (reception), XRAY-PC (imaging)
     - harbor-ins: UNDERWRITER-PC, CLAIMS-SERVER, POLICY-DB (3 hosts — larger site with more activity)
   - Each site has distinct alert scenarios and severity distributions
   - `_demo_site_alerts_summary(site_id)` — returns alert summary for a specific site
   - `_demo_site_alerts_timeline(site_id, hours)` — returns alert timeline for a specific site
   - `_demo_site_fleet_health(site_id)` — returns fleet health for a specific site
   - `_demo_site_detections_fired(site_id, hours, limit)` — returns fired detections for a specific site
   - `_demo_site_events_recent(site_id, limit)` — returns recent events for a specific site
   - `_demo_site_host_timeline(site_id, hostname, hours)` — returns host timeline for a specific site

2. **Demo mode proxy handler**:
   - When `_DEMO_MODE` is active and a request hits `/api/site/{node_id}/{path}`, the proxy handler does NOT make HTTP calls
   - Instead, it dispatches to the per-site demo data generators based on `node_id` and `path`:
     - `/api/site/acme-law/alerts/summary` → `_demo_site_alerts_summary("acme-law")`
     - `/api/site/harbor-ins/fleet/health` → `_demo_site_fleet_health("harbor-ins")`
   - Unknown site → 404 with `{"error": "Unknown site"}`
   - Unknown path → 404 with `{"error": "Unknown endpoint"}`

3. **/api/nodes demo mode enhancement**:
   - `_demo_nodes()` now includes the M1 operational fields (alerts\_24h, alerts\_critical, alerts\_high, top\_rule, host\_count, total\_events\_24h) derived from the per-site demo data generators
   - The aggregate summary is computed by summing across the 3 demo sites
   - This ensures the demo data is consistent: the site card shows the same alert count as the drill-through overview

4. **Demo scenario enrichment**:
   - acme-law (law firm): moderate activity, 14 alerts (2 critical — brute force + encoded PowerShell), 2 hosts
   - mainst-dental (dental practice): quiet site, 3 alerts (0 critical, 1 high — off-hours logon), 2 hosts
   - harbor-ins (insurance company): active site, 31 alerts (3 critical — brute force + FIM + Defender disabled), 3 hosts, version drift (0.7.9)
   - The demo narrative: harbor-ins is the site that needs attention. An MSSP demo naturally flows: "I see harbor-ins has 3 critical alerts, let me click in and investigate."

**Acceptance**

- `python -m tinysocs.api.bot --demo` → Sites tab shows 3 sites with alert badges and host counts
- Click acme-law → drill-through shows acme-law-specific alerts, fleet, events (different hosts than master)
- Click harbor-ins → drill-through shows harbor-ins data (most alerts, 3 hosts, version drift)
- "← All Sites" → returns to aggregated view
- Demo mode aggregate banner on Overview: "3 sites · 48 alerts (5 critical) · 7 hosts"
- Site card alert counts match drill-through alert summary totals (consistency check)
- All demo data has timestamps relative to now (no stale dates)


M5 — Tests
-----------

**Goal:** Unit tests for all Phase 18 changes. No regressions in existing test suite.

**Proposed Changes**

Files:
- `tests/test_nodes_api.py` — Extend with new endpoint and aggregation tests
- `tests/test_demo_mode.py` — Extend with per-site demo data and drill-through tests
- `tests/test_node_endpoints.py` — New: unit tests for node.py summary and query endpoints

**Deliverables**

1. **Node summary endpoint tests** (`test_node_endpoints.py`, new file):
   - Test `/alerts/summary` response shape: total, severity dict, top\_rules list, top\_hosts list
   - Test `/alerts/summary` with no OpenSearch data → zero counts, empty arrays
   - Test `/fleet/summary` response shape: host\_count, total\_events\_24h, hosts list
   - Test `/fleet/summary` with no data → zero counts, empty hosts
   - Test `/alerts/timeline` response shape: hours, buckets list with time/count/severity keys
   - Test `/detections/fired` response shape: hours, detections list with required fields
   - Test `/fleet/health` response shape: hosts list with required fields per host
   - Test `/events/recent` response shape: list of event dicts
   - Test `/host/timeline` response shape: hostname, hours, buckets with channel counts
   - Test `/meta` includes new endpoint names
   - Tests use FastAPI TestClient against `node.app` with mocked `_os_search` to avoid needing real OpenSearch

2. **Enriched nodes API tests** (`test_nodes_api.py`, extend existing):
   - Test `/api/nodes` response includes new fields: alerts\_24h, alerts\_critical, alerts\_high, top\_rule, host\_count, total\_events\_24h
   - Test aggregate summary computed correctly from mock node data
   - Test null handling: node summary endpoint unreachable → fields are null (not 0)
   - Test demo mode `/api/nodes` includes operational data and aggregate

3. **Demo mode per-site tests** (`test_demo_mode.py`, extend existing):
   - Test `_demo_site_alerts_summary("acme-law")` returns correct shape and acme-law-specific data
   - Test `_demo_site_fleet_health("harbor-ins")` returns 3 hosts
   - Test all 3 demo sites have distinct host lists (no overlap)
   - Test site alert counts sum to aggregate total
   - Test per-site timestamps are relative to now
   - Test proxy demo handler: `/api/site/acme-law/alerts/summary` returns acme-law data
   - Test proxy demo handler: `/api/site/unknown-site/alerts/summary` returns 404
   - Test drill-through data consistency: site card alert count matches drill-through summary total

4. **Full test suite verification**:
   - All new tests pass
   - All existing tests pass (325+ passed, 1 skipped, 1 pre-existing failure unchanged)
   - No regressions

**Acceptance**

- `PYTHONPATH=src python -m pytest tests/ -x -q` → 370+ passed, 1 skipped, 0 new failures
- All node endpoint response shapes validated against dashboard JS expectations
- Demo mode consistency validated: card counts match drill-through totals
- All new tests pass in isolation


Milestone Order
---------------

| # | Milestone | Depends On | Estimated Effort |
|---|-----------|------------|------------------|
| M0 | Node Summary Endpoints | None | 1 hour |
| M1 | Enriched Sites Tab | M0 (needs summary endpoints to call) | 2-3 hours |
| M2 | Node Query Endpoints | None | 2 hours |
| M3 | Dashboard Site Proxy & Drill-Through | M2 (needs query endpoints for proxied requests) | 3-4 hours |
| M4 | Demo Mode Federation Paths | M1, M3 (needs enriched sites + proxy to exist) | 2-3 hours |
| M5 | Tests | M0-M4 (all changes must exist) | 1-2 hours |

M0 and M2 are independent — both add endpoints to `node.py` and can be done in parallel. M1 depends on M0 (the Sites tab calls the summary endpoints). M3 depends on M2 (the proxy forwards to query endpoints). M4 depends on M1 and M3 (demo mode exercises both aggregation and proxy paths). M5 comes last.


Verification (End-to-End)
-------------------------

After Phase 18, on a multi-site deployment:

```
# Master box has TINYSOCS_NODES=http://node-a:8081,http://node-b:8081,http://node-c:8081

# Open dashboard
Start-Process "https://localhost:8090/dashboard"

# Sites tab (default when TINYSOCS_NODES configured)
# → 3 site cards with alert badges, severity dots, host counts
# → Cards sorted by severity (most critical first)
# → Aggregate banner visible if Overview tab visited

# Click the site card with critical alerts
# → Site focus banner appears: "Viewing: acme-law ← All Sites"
# → Overview tab: acme-law's alert summary and timeline
# → Fleet tab: acme-law's hosts and event flow
# → Data tab: search acme-law's events
# → Detections tab: acme-law's fired detections
# → Compliance tab: master's compliance data (not proxied)

# Click "← All Sites"
# → Returns to Sites tab
# → All tabs show master data again

# Demo mode (any OS)
python -m tinysocs.api.bot --demo
# → Sites tab: 3 sites with alert badges (acme-law, mainst-dental, harbor-ins)
# → harbor-ins has most alerts + version drift → demo talking point
# → Click harbor-ins → drill-through shows harbor-ins data
# → Overview: 31 alerts (3 critical)
# → Fleet: 3 hosts (UNDERWRITER-PC, CLAIMS-SERVER, POLICY-DB)
# → "← All Sites" → returns to aggregated view

# Tests
PYTHONPATH=src python -m pytest tests/ -x -q
# → 370+ passed, 1 skipped, 0 new failures
```


What Phase 18 Explicitly Does Not Cover
----------------------------------------

- **Centralised rule distribution**: Pushing rules from master to nodes. Phase 18 is read-only federation — the master reads from nodes but never writes to them. Rule distribution requires an update protocol, conflict resolution, and rollback. Build after MSSP feedback clarifies what operators want to push.
- **Node registration/provisioning**: Nodes are configured via `TINYSOCS_NODES` env var (comma-separated URLs). There is no self-registration, no PKI enrollment, no provisioning workflow. For 3-10 pilot sites, manual config is acceptable. Automated provisioning follows when scale demands it.
- **Cross-site correlation**: Detecting patterns that span multiple sites (e.g., same attacker IP hitting multiple clients) requires a correlation engine that merges evidence across sites. Phase 18 aggregates counts; it doesn't correlate events.
- **AI Assistant per-site context**: The AI assistant queries the master SIEM regardless of which site is focused. In drill-through mode, the assistant can see the alerts and events displayed on screen, but free-form questions ("what happened on RECEPTION-PC?") query the master's data. Per-site AI context requires proxying the chat tool functions, which adds complexity. Documented as a known limitation.
- **Auto-update delivery**: Version drift is visible (Sites tab shows version badges). Actual update delivery (pushing new agent binaries to nodes) is a separate mechanism that builds on federation but requires its own update protocol.
- **macOS/Linux collector**: Cross-platform event collection is orthogonal to federation. A Mac collector would plug into the existing node architecture but requires its own input implementation.
- **Multi-tenancy**: One TinySocs master = one operator view. If an MSSP wants per-client dashboards with separate logins, that requires RBAC. Phase 18's single-operator model is sufficient for pilot deployments.
- **Installer role automation**: The installer has Master/Node/TinyBox role selection in the UI. Automatically configuring `TINYSOCS_NODES` and `MASTER_SHARED_SECRET` based on role selection is desirable but not blocking — pilots will hand-configure these env vars.
