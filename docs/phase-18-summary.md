Phase 18 Summary — Minimum Viable Federation
Theme: "One pane of glass"

Overview

Phase 18 turned TinySocs from a standalone SIEM into a federated one. The dashboard's Sites tab now shows what's happening at each remote site — not just whether it's online, but how many alerts it has, what severity, how many hosts, and what's firing. Click a site card and the entire dashboard switches to show that site's data: Overview, Fleet, Data, and Detections tabs all render data proxied from the remote node. A "← All Sites" link returns to the aggregated view. Seven new read-only endpoints on node.py let each node report its operational state — alert summaries, timelines, fleet health, fired detections, event search, and per-host timelines — all backed by direct OpenSearch queries. A generic proxy endpoint on the master forwards drill-through requests to the correct node. Demo mode exercises the full federation stack with per-site synthetic data for three sites (head-office, branch-north, warehouse) with distinct hosts, alert scenarios, and severity distributions. The demo narrative: warehouse has 3 critical alerts and version drift — click in and investigate. Two real TinySocs boxes can now communicate today if you set TINYSOCS_NODES on the master and run node.py on the remote box. The federation backbone is production-ready for reading.

Stats: 5 files changed + 1 new file, +2,069 / -107 lines across 6 milestones (M0–M5), 389 tests (62 new), 387 passing, 1 pre-existing failure, 1 skipped.

Milestones Delivered

M0 — Node Summary Endpoints

Goal: Nodes report their operational state — alert counts and fleet composition — so the master can show what's happening at each site, not just whether it's reachable.

Files:
* src/tinysocs/api/node.py — Two new read-only endpoints: GET /alerts/summary and GET /fleet/summary. Both query local OpenSearch via the new _os_search_raw() helper which returns full OpenSearch JSON including aggregations (unlike the existing _os_search() which flattens hits). /alerts/summary queries tinysocs-alerts-* for alert counts by severity, top rules, and top hosts. /fleet/summary queries tinysocs-winlog-* for distinct host count, total events, and per-host last-seen timestamps. Both accept an hours parameter (default 24, range 1–720). No HMAC required — read-only summary data at the same access level as /meta. /meta response updated to include both new endpoints in the endpoints list.

Response shapes:
* /alerts/summary: {hours, total, severity: {critical, high, medium, low}, top_rules: [{rule, count}], top_hosts: [{host, count}]}
* /fleet/summary: {host_count, total_events_24h, hosts: [{hostname, events_24h, last_seen}]}

The _os_search_raw() helper handles URL construction, Basic Auth via SIEM_USER/SIEM_PASS, TLS verification via SIEM_SSL_VERIFY (defaults to False for self-signed clusters), 10-second timeout, and graceful error handling (returns empty results with error message if OpenSearch is unreachable, never crashes).

M1 — Enriched Sites Tab

Goal: The Sites tab shows operational data per site — alert counts with severity badges, host counts, top firing rules — so an operator can see at a glance which sites need attention.

Files:
* src/tinysocs/api/dashboard.py — /api/nodes handler enhanced to call /alerts/summary and /fleet/summary on each node concurrently (alongside existing /meta and /evidence/head calls). All four calls per node run via asyncio.gather. New per-node fields: alerts_24h, alerts_critical, alerts_high, top_rule, host_count, total_events_24h. If summary endpoints timeout or fail, fields are null (not 0) so the UI distinguishes "no data" from "zero alerts". New aggregate summary in the response: {total_alerts_24h, total_critical, total_high, total_hosts, sites_healthy, sites_warning, sites_unreachable}. Aggregate computed by summing across all reachable nodes where summary data is not null.

JavaScript: loadSites() replaced with enriched version (~100 lines). Site cards show alert count badge (red for critical, orange for high, grey for none), severity breakdown line ("2 critical · 5 high · 7 other"), host count, event count, top rule name, plus existing infrastructure metrics (status, version, ledger seq, last anchor). Cards with critical alerts get a red left border (3px solid). Cards sorted by severity priority: critical alerts first → total alerts descending → alphabetical by node_id. Aggregate banner above site cards: "3 sites · 48 alerts · 5 critical · 14 high · 7 hosts".

New functions: apiBase() returns /api (normal) or /api/site/{node_id} (focused mode). loadOverviewAggregate() populates the Overview tab's cross-site aggregate banner. initSitesTab() checks node count and caches response. Site data cached in _sitesCache for reuse by the Overview aggregate banner.

Overview tab aggregate banner: clickable div at top of Overview showing cross-site summary. Hidden when no nodes configured. Clicking navigates to Sites tab. Refreshes on the same 30-second cycle.

Demo data (3 sites):

| node_id | alerts_24h | critical | high | hosts | top_rule | status | version |
|---|---|---|---|---|---|---|---|
| head-office | 14 | 2 | 5 | 2 | brute_force_password | healthy | 0.8.1 |
| branch-north | 3 | 0 | 1 | 2 | off_hours_logon | healthy | 0.8.0 (OUTDATED) |
| warehouse | 31 | 3 | 8 | 3 | suspicious_powershell | warning | 0.7.9 |

warehouse has the most alerts and version drift — gives the demo a natural "investigate this one" talking point.

M2 — Node Query Endpoints

Goal: Nodes expose the same data queries the dashboard uses — alert timeline, fired detections, fleet health, event search, per-host timeline — so the master can proxy drill-through requests.

Files:
* src/tinysocs/api/node.py — Five new read-only endpoints, all using _os_search_raw() to query local OpenSearch:

1. GET /alerts/timeline — Hourly bucketed alert counts with per-severity breakdown. Parameters: hours (default 24). Queries tinysocs-alerts-* with date_histogram on timestamp, 1h interval, terms sub-agg on alert.severity.keyword. Response: {hours, buckets: [{time, count, critical, high, medium, low}]}.

2. GET /detections/fired — Individual fired detection alerts. Parameters: hours (default 24), limit (default 30, 1–200). Queries tinysocs-alerts-* sorted by timestamp desc. Flattens nested alert.* fields. Response: {detections: [{rule_id, rule_name, severity, host, timestamp, description, event_count, matched_events}], total}.

3. GET /fleet/health — Detailed per-host fleet status. Dual query: tinysocs-winlog-* for host activity (terms on winlog.computer_name with max/min timestamps, event counts, top channels, top event IDs) and tinysocs-alerts-* for per-host alert counts (terms on source.computer_name with severity breakdown). Merges results. Response: {hosts: [{hostname, event_count, last_seen, first_seen, alert_count, alert_severities, top_channels, top_event_ids, agent_version, uptime}]}.

4. GET /events/recent — Event search. Parameters: limit (default 50, 1–500), q (KQL filter), index (default tinysocs-winlog-*), time_range. Queries specified index with query_string filter. Response: {events: [{timestamp, host, channel, event_id, message}], total, query, index}.

5. GET /host/timeline — Per-host event timeline. Parameters: hostname (optional), hours (default 24). Queries tinysocs-winlog-* with date_histogram, 1h interval, terms sub-agg on winlog.channel. Response: {hostname, hours, interval, buckets: [{time, ...channel_counts}], channels: [list]}.

All five endpoints follow the same patterns: no HMAC required (read-only), graceful error handling on OpenSearch failure, same index patterns and field names as dashboard.py's internal queries. /meta updated to include all new endpoints. Total node.py endpoints: 12 (up from 5).

M3 — Dashboard Site Proxy & Drill-Through

Goal: Click a site card and the entire dashboard switches to show that site's data, proxied through the master.

Files:
* src/tinysocs/api/dashboard.py — New proxy endpoint + JavaScript drill-through mode.

Python proxy endpoint: GET /api/site/{node_id}/{path:path}. Looks up node URL from _node_id_to_url cache (populated by /api/nodes). Forwards request to {node_url}/{path}?{query_params} via httpx.AsyncClient (10-second timeout, verify=False). Security: only proxies to URLs in TINYSOCS_NODES and only to whitelisted paths (_PROXY_ALLOWED set: alerts/summary, alerts/timeline, fleet/summary, fleet/health, detections/fired, events/recent, host/timeline). Unknown node_id → 404. Unreachable node → 502. In demo mode, dispatches to per-site demo generators instead of making HTTP calls.

JavaScript drill-through: Global _focusedSite variable (null = all-sites view, string = node_id). apiBase() returns /api or /api/site/{node_id}. Six fetchJSON() calls updated to use apiBase(): loadSummary(), loadTimeline(), loadDetections(), loadFleet(), loadEvents(), loadHostTimeline(). Calls that always query the master (not proxied): loadSites() (/api/nodes), MITRE, compliance, settings.

focusSite(nodeId): Sets _focusedSite, shows site focus banner, resets tab cache, switches to Overview. unfocusSite(): Clears _focusedSite, hides banner, switches to Sites tab. Session persistence via sessionStorage (clears on tab close). Restored in unlockDashboard() on page reload.

Site focus banner HTML: Sticky div below tab bar with accent left border. Shows "← All Sites | Viewing: {node_id}". Clicking "← All Sites" calls unfocusSite(). Hidden when _focusedSite is null. CSS: .site-focus-banner with position:sticky, z-index:18, border-left:3px solid var(--accent).

Tab behaviour in focused mode: Overview shows focused site's alerts/timeline. Fleet shows focused site's hosts and event flow. Data searches focused site's events. Detections shows focused site's fired rules. Compliance tab not proxied (shows master data). Sites tab always shows all sites.

M4 — Demo Mode Federation Paths

Goal: Demo mode exercises the real aggregation and proxy code paths with per-site synthetic data, so the demo tests the same architecture as production.

Files:
* src/tinysocs/api/dashboard.py — ~300 lines of per-site demo data and 6 generator functions.

Per-site data structures:

_DEMO_SITE_HOSTS — Site-to-host mapping:
* head-office: RECEPTION-PC (workstation, 12,400 events), EXEC-LAPTOP (workstation, 12,180 events)
* branch-north: BRANCH-PC-01 (workstation, 4,200 events), BRANCH-PC-02 (workstation, 3,920 events)
* warehouse: SHIPPING-PC (workstation, 18,400 events), INVENTORY-SERVER (server, 22,100 events), LOGISTICS-DB (server, 11,840 events)

_DEMO_SITE_ALERTS — Per-site severity counts, top rules, and detailed alert templates:
* head-office: 14 alerts — brute force from 198.51.100.44, encoded PowerShell on attorney workstation, FIM on client files, off-hours RDP
* branch-north: 3 alerts — off-hours logon at 02:14 AM, new local account xray_service, scheduled task
* warehouse: 31 alerts — brute force (20 attempts), FIM integrity violation on master_rates.xlsx, Defender disabled, certutil downloading payload, PowerShell from pastebin, RDP from external IP

_DEMO_SITE_EVENTS — Per-site event templates with realistic Windows event log messages.

Six generator functions: _demo_site_alerts_summary(), _demo_site_alerts_timeline(), _demo_site_fleet_health(), _demo_site_detections_fired(), _demo_site_events_recent(), _demo_site_host_timeline(). All generate timestamps relative to now. Timeline functions produce bell-curve-shaped hourly buckets. Fleet health includes agent version, uptime, top channels, and alert severity breakdown per host.

_demo_site_proxy() dispatch: Routes proxy requests to generators based on path. Unknown site → 404. Unknown endpoint → 404. Replaces the stub from M3 with full dispatch logic.

_demo_nodes() enhanced: Operational fields (alerts_24h, alerts_critical, etc.) derived from per-site generators, ensuring consistency — site card alert count matches drill-through summary total.

M5 — Tests

Goal: Unit tests for all Phase 18 changes. No regressions.

Files:
* tests/test_node_endpoints.py — New file, 27 tests. Tests for all 7 node.py federation endpoints with mocked _os_search_raw(). Classes: TestAlertsSummary, TestFleetSummary, TestAlertsTimeline, TestDetectionsFired, TestFleetHealth, TestEventsRecent, TestHostTimeline, TestMetaEndpoints. Uses FastAPI TestClient against node_mod.app. Validates response shapes, field presence, empty OpenSearch handling, parameter ranges.

* tests/test_nodes_api.py — Extended with 15 new tests. TestPhase18OperationalFields: validates alerts_24h, alerts_critical, alerts_high, top_rule, host_count, total_events_24h per demo node. TestPhase18Aggregate: validates aggregate fields, totals match sum of individual sites, site status counts.

* tests/test_demo_mode.py — Extended with 20 new tests. TestDemoSiteAlertsSummary, TestDemoSiteAlertsTimeline, TestDemoSiteFleetHealth, TestDemoSiteDetectionsFired, TestDemoSiteEventsRecent, TestDemoSiteHostTimeline: shape and content validation per site. TestDemoSiteProxy: known sites dispatch correctly, unknown site/endpoint → 404. TestDemoSiteDataConsistency: card alert count matches drill-through, host count matches, aggregate matches sum. TestDemoSiteTimestampsRelative: all per-site timestamps within last 24 hours.

Bug fixes during testing:
* test_node_endpoints.py: TestDetectionsFired asserted "hours" field but endpoint returns {"detections", "total"} (no hours). Fixed to check "total".
* test_node_endpoints.py: TestFleetHealth used host["alerts"] but node.py returns host["alert_count"]. Mock missing event_count, top_channels, top_event_ids sub-aggregations. Fixed field name and mock structure.
* test_node_endpoints.py: TestHostTimeline used "timeline" as agg key but node.py uses "over_time". Fixed mock key.

Full test suite: 389 collected, 387 passed, 1 skipped, 1 pre-existing failure (test_e2e_phase12.py::test_full_approve_lifecycle — asserts "completed" but gets "acknowledged", unrelated to Phase 18).

Bug Fixes

JavaScript syntax error — login page broken:

After initial Phase 18 implementation, the dashboard login page stopped working — entering the password did nothing. Root cause: two lines in the JavaScript used \' (backslash-quote) inside a Python triple-quoted """ string to escape single quotes for JavaScript. But in Python, \' inside """...""" just produces a bare ' — the backslash is silently consumed. This produced unescaped single quotes inside single-quoted JavaScript strings, creating a SyntaxError that broke the entire <script> block. Since JavaScript parses the whole script before executing any of it, the syntax error at line ~108 (inside loadSites()) prevented every function from being defined — including doLogin(). The login page HTML rendered correctly but clicking Sign In did nothing.

Fix: Changed \' to \\' in two places:
* Line 5113: switchTab(\'overview\') → switchTab(\\'overview\\')
* Line 5147: focusSite(\'' + ... → focusSite(\\'' + ...

In Python, \\' produces \', which JavaScript correctly interprets as an escaped single quote inside a string literal.

Modified Files

| File | Changes |
|---|---|
| src/tinysocs/api/node.py | 7 new federation endpoints (M0+M2): /alerts/summary, /fleet/summary, /alerts/timeline, /detections/fired, /fleet/health, /events/recent, /host/timeline. New _os_search_raw() helper returning full OpenSearch JSON with aggregations. /meta updated with new endpoint list. +425 lines. |
| src/tinysocs/api/dashboard.py | Enriched Sites tab with operational data, aggregate banners, drill-through proxy, per-site demo data. /api/nodes enhanced with concurrent summary polling and aggregate computation. /api/site/{node_id}/{path} proxy endpoint with security whitelist. Site focus banner HTML/CSS. JavaScript: apiBase(), focusSite(), unfocusSite(), loadOverviewAggregate(), enhanced loadSites(), 6 fetchJSON calls updated for drill-through. Per-site demo data structures and 6 generator functions. JS quote-escaping fix. +891 / -107 lines. |
| tests/test_node_endpoints.py | New file: 27 tests for node.py federation endpoints with mocked OpenSearch. +464 lines. |
| tests/test_nodes_api.py | Extended: 15 new tests for operational fields and aggregate computation. +118 lines. |
| tests/test_demo_mode.py | Extended: 20 new tests for per-site demo data, proxy dispatch, data consistency, timestamps. +278 lines. |
| docs/phase-18-plan.md | New file: detailed plan document (602 lines). |

Acceptance Criteria Validation

M0 — Node Summary Endpoints

| Criterion | Status |
|---|---|
| GET /alerts/summary returns total, severity, top_rules, top_hosts | ✅ Met |
| GET /fleet/summary returns host_count, total_events_24h, hosts array | ✅ Met |
| Empty OpenSearch → zero counts, empty arrays (no errors) | ✅ Met |
| OpenSearch unreachable → {"error": "..."} with descriptive message | ✅ Met |
| /meta includes new endpoints in endpoints list | ✅ Met |
| No HMAC required on either endpoint | ✅ Met |

M1 — Enriched Sites Tab

| Criterion | Status |
|---|---|
| Site cards show alert count badge, severity breakdown, host count, top rule | ✅ Met |
| Cards with critical alerts get red left border | ✅ Met |
| Cards sorted by severity priority (critical first) | ✅ Met |
| Aggregate banner: "3 sites · 48 alerts · 5 critical · 14 high · 7 hosts" | ✅ Met |
| Overview tab aggregate banner click navigates to Sites tab | ✅ Met |
| Single-site deployment: no aggregate banner, Sites tab hidden | ✅ Met |
| Demo mode shows enriched cards with per-site alert data | ✅ Met |

M2 — Node Query Endpoints

| Criterion | Status |
|---|---|
| /alerts/timeline returns 24 hourly buckets with severity counts | ✅ Met |
| /detections/fired returns alert documents sorted by timestamp desc | ✅ Met |
| /fleet/health returns per-host metrics with alert counts | ✅ Met |
| /events/recent supports KQL filter and returns matching events | ✅ Met |
| /host/timeline returns per-channel hourly buckets | ✅ Met |
| Response shapes match dashboard JS expectations | ✅ Met |

M3 — Dashboard Site Proxy & Drill-Through

| Criterion | Status |
|---|---|
| Click site card → site focus banner appears | ✅ Met |
| Overview tab shows focused site's alert summary and timeline | ✅ Met |
| Fleet tab shows focused site's hosts and event flow | ✅ Met |
| Data tab searches focused site's events | ✅ Met |
| Detections tab shows focused site's fired detections | ✅ Met |
| "← All Sites" returns to Sites tab with master data | ✅ Met |
| Proxy returns 404 for unknown node_id | ✅ Met |
| Proxy returns 502 for unreachable node | ✅ Met |
| Page reload restores focused site from sessionStorage | ✅ Met |
| Proxy only forwards to whitelisted paths | ✅ Met |

M4 — Demo Mode Federation Paths

| Criterion | Status |
|---|---|
| Demo Sites tab shows 3 sites with alert badges and host counts | ✅ Met |
| Click head-office → drill-through shows head-office data (2 hosts) | ✅ Met |
| Click warehouse → drill-through shows warehouse data (3 hosts, most alerts) | ✅ Met |
| "← All Sites" returns to aggregated view | ✅ Met |
| Site card alert counts match drill-through alert summary totals | ✅ Met |
| All demo data timestamps relative to now | ✅ Met |
| Demo proxy dispatches to per-site generators (no HTTP calls) | ✅ Met |

M5 — Tests

| Criterion | Status |
|---|---|
| All node endpoint response shapes validated | ✅ Met (27 tests) |
| Operational fields and aggregate validated | ✅ Met (15 tests) |
| Per-site demo data and proxy validated | ✅ Met (20 tests) |
| Data consistency: card counts match drill-through totals | ✅ Met |
| Full suite: 387 passed, 1 skipped, 0 new failures | ✅ Met |

Items Not Implemented

| Item | Reason |
|---|---|
| Centralised rule distribution | Phase 18 is read-only federation — master reads from nodes but never writes. Rule distribution requires update protocol, conflict resolution, and rollback. Build after MSSP feedback. |
| Node registration / provisioning | Nodes configured via TINYSOCS_NODES env var. No self-registration, no PKI. Manual config is acceptable for 3–10 pilot sites. |
| Cross-site correlation | Detecting patterns spanning multiple sites (same attacker IP across clients) requires a correlation engine. Phase 18 aggregates counts; it doesn't correlate events. |
| AI Assistant per-site context | Assistant queries master SIEM regardless of focused site. Per-site AI context requires proxying chat tool functions. Documented as known limitation. |
| Installer role automation | Installer has Master/Node/TinyBox selection but doesn't configure TINYSOCS_NODES or start node.py as a service. Hand-config works for pilots. Planned for Phase 19. |
| TLS between master and nodes | Proxy uses verify=False. Fine on LAN/VPN. Self-signed TLS is a one-command addition, planned for Phase 19. |
| Multi-tenancy / RBAC | One master = one operator view. Per-client dashboards with separate logins require RBAC. Single-operator model sufficient for pilots. |
