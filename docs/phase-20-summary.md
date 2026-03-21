Phase 20 Summary — Security Hardening & Cross-Site Aggregation
Theme: "Secure by default, verified by cert, aggregated across sites"

Overview

Phase 20 eliminated every insecure default in the TinySocs stack and unified data from multiple sites into a single dashboard view. A new federation_certs module implements SHA-256 certificate pinning for all inter-node HTTPS connections — the Hub records each Site's TLS certificate fingerprint at registration time and rejects connections whose certificate does not match, preventing man-in-the-middle attacks on the federation mesh. The tls module was extracted as a single source of truth for SSLContext construction, replacing scattered verify=False hacks and hardcoded passwords across eight files (opensearch_client, dashboard, node, bot, anchors, check_ledger, master, daily_summary). Every OpenSearch connection now uses an explicit ssl.SSLContext with the operator's CA certificate loaded, and PyInstaller compatibility was fixed by clearing stale bundled certifi paths at startup and converting DER certificates to PEM at both installer and runtime. The installer default for SIEM_SSL_VERIFY was flipped from false to true, and the default SIEM password was removed — fresh installs now require the operator-chosen password from the wizard. Dashboard sessions were stabilised by sending the Bearer token in every fetchJSON call and adding a sliding renewal mechanism that extends the session on activity instead of logging the operator out on tab switches. Widget heights across the Fleet, Data, and Detections tabs are now dynamically computed to match the assistant panel, with pagination pinned to card bottoms and per-page counts calculated from available viewport height rather than hardcoded. The dashboard fans out queries to all registered nodes for cross-site aggregation — alert counts, event flows, fleet status, and fired detections are merged from every reachable Site into unified widgets, with a grey lock icon and graceful retry for local-only nodes. The Full-Rebuild script was hardened with auto-unlock of the setup executable before ISCC compile, SysmonDrv stop-service hang prevention, registry fallback for Sysmon driver purge, and ASCII-only source to avoid PowerShell 5.x parse errors. Site auto-registration with Hub approval, visible error reporting for registration failures, and installer ordering fixes ensure that a Site install writes critical config before the OpenSearch bootstrap runs.

Stats: 22 files changed (2 new), +3,190 / -625 lines across 8 milestones (M0-M7), 63 commits.

Commits

| Hash | Message |
|---|---|
| 94f34e6 | Phase 20: dashboard polish — layout, UX, and performance fixes |
| 440ce6a | Fill demo mode gaps: MITRE, guided response, fleet details, compliance export |
| aa7c4c3 | Add cooldown mechanism and tune detection rules for production |
| ec4e38f | Enable full Site role deployment: OpenSearch bootstrap, agent, and node management |
| fcb5141 | Add site management UI: add/remove federation nodes from dashboard |
| 48fe12a | Update remote sites page text: mention Dashboard, add IP address tip |
| dbabc8c | Dashboard polish: fix default tab, site layout, hide guided response, eager-load |
| 3addc3d | Dashboard polish round 2: full-width sticky banner, button alignment, consistent heights, Ask AI buttons |
| 6fa4590 | Fix aggregate banner sticky position: adjust top offset to clear tab bar |
| 40ba3c6 | Fix compliance button alignment and demo banner overlap |
| 2e4ca39 | Center download arrow icon in compliance header button |
| 31aaa68 | Match MITRE download button style to compliance download button for consistency |
| 7c6ead6 | Fix Site role installer: clear shared secret field, hide SIEM password section |
| 4a9f589 | Skip Assistant service on Site role, clarify finish page has no local dashboard |
| fe97c65 | Site installer opens Hub dashboard URL instead of localhost |
| 7d08442 | Phase 21: Site auto-registration with Hub approval |
| 646dc33 | Fix assistant panel dead space on Sites tab |
| 007c994 | Fix broken login: single-slash JS comment caused syntax error blocking doLogin |
| 2543194 | Fix login button: restore missing slash in JS comment that caused syntax error |
| f91437a | Fix login-breaking JS syntax error: escape quotes in Phase 21 onclick handlers |
| e89e0f5 | Fix ARM64 Sysmon detection: use registry as primary source |
| ef8cd91 | Harden Sysmon install: purge wrong-arch service and stale binaries from Windows root |
| b18d63c | Fix Sysmon purge: use Sysmon's own -u force instead of sc.exe delete |
| 52e2c41 | Add registry fallback for Sysmon purge when driver blocks sc.exe delete |
| 0d1bd53 | Fix Sites tab flash, duplicate banner, button sizing, and reduce redundant API calls |
| 1663408 | Add visible error reporting for Site registration failures |
| 32e43af | Fix Site installer: move critical config before OpenSearch bootstrap |
| 67e2b75 | Fix Sysmon arch detection order on x64 and add role-change guard to assistant.env backup restore |
| 7842d81 | Fix Full-Rebuild hanging on SysmonDrv Stop-Service |
| 91d4657 | Fix dashboard: duplicate banner, blank Viewing label, approval feedback, session expiry |
| dbca8f7 | Fix Site-Hub TLS connectivity and dashboard UI bugs |
| e993aaa | Hide overview aggregate banner when focused on a single site |
| 2864103 | Auto-unlock TinySocs-Setup.exe before ISCC compile |
| 50b13ff | Fix PS 5.x parse error: inline Add-Type C# to avoid using-statement conflict |
| 5746899 | Replace em-dash characters in Full-Rebuild.ps1 with ASCII dashes |
| 614bcec | Fix PyInstaller SSL errors, improve cert generation and node fetch logging |
| 587a62a | Security: remove default passwords and centralize TLS cert verification |
| a04a4cf | Security: remove PyInstaller SSL hack, make verify=True the default |
| b93594a | Security: add TLS certificate pinning for federation connections |
| f46fb41 | Fix Hub installer not writing node TLS cert paths to assistant.env |
| cca4178 | Fix PyInstaller SSL: clear stale bundled cert paths at startup |
| 4bd3de6 | Fix OpenSearch SSL: use Urllib3HttpConnection with explicit ssl_context |
| a33fff0 | Add post-install OpenSearch SSL fix to Full-Rebuild.ps1 |
| 7ce5d6e | Proper DER->PEM cert conversion at installer and runtime |
| 6dc35cf | Restart TinySocsAssistant after Phase 13b SSL env fix |
| fe529ca | Proper TLS for all OpenSearch connections -- no more verify=False |
| 135cd4c | Change SIEM_SSL_VERIFY default from false to true in installer |
| 4bb8a5e | Fix installer env vars, dashboard UI, and rebuild cert handling |
| 3ffc63e | Remove Event Explorer fixed-height scrollbar, use pagination only |
| 877c7a0 | Fix auth: send Bearer token in fetchJSON, add sliding session renewal |
| fe47b33 | Match widget heights to assistant panel across Fleet, Data, Detections tabs |
| a100115 | Pin Event Explorer pager to bottom of card, outside scroll area |
| 03921f8 | Increase per-page counts and pin all pagers to bottom of cards |
| 3093dda | Fix Fleet tab Event Flow to fill full height matching assistant panel |
| 152203d | Make Event Flow SVG chart fill full card height dynamically |
| 4042471 | Fix health check: try HTTPS first for Assistant API check |
| aba77d1 | Fix session logout on tab switch, remove all widget scrollbars |
| cf11f1d | Dynamic per-page counts and refined widget heights |
| 27442db | Tune dynamic per-page counts: smaller row height estimate (32px) |
| 4167de2 | Fix health check TLS, fired detections height, rules pagination, event explorer UX |
| 2100644 | Fan out dashboard queries to all nodes for cross-site aggregation |
| d961f8f | Fix Alert Rules pager: append to card not content div, allow overflow scroll |
| 324d894 | Show grey lock for local nodes, retry on initial load instead of showing errors |

Milestones Delivered

M0 — Certificate Pinning for Federation Connections

Goal: Prevent man-in-the-middle attacks on the federation mesh by pinning each Site's TLS certificate at registration time and rejecting connections whose fingerprint does not match.

Files:
* src/tinysocs/federation_certs.py — New file (273 lines). Implements SHA-256 certificate pinning for federation TLS connections. FederationCertStore manages a JSON-backed store of node_id-to-fingerprint mappings at C:\ProgramData\TinySocs\federation_certs.json. pin_certificate() records a node's certificate fingerprint on first contact. verify_certificate() compares the presented certificate against the pinned fingerprint and raises PinningViolation on mismatch. get_pinning_ssl_context() returns an ssl.SSLContext with a custom verify callback that enforces pinning. Supports trust-on-first-use (TOFU) and explicit fingerprint provisioning via the installer.
* src/tinysocs/api/dashboard.py — Dashboard node-fetch calls routed through the pinning SSLContext. Pin verification on Site registration endpoint. +63 lines for pinning integration.
* src/tinysocs/api/node.py — Node API returns its own certificate fingerprint in /meta responses so the Hub can record it during registration. +18 lines.

M1 — OpenSearch TLS: Explicit SSLContext for PyInstaller Compatibility

Goal: Eliminate all verify=False OpenSearch connections and make TLS work correctly inside PyInstaller-bundled executables where certifi paths are stale or missing.

Files:
* src/tinysocs/tls.py — New file (239 lines). Centralised TLS helper module. get_siem_ssl_context() builds an ssl.SSLContext using the operator's CA certificate from TINYSOCS_CA_CERT or the OpenSearch root-ca.pem. get_opensearch_kwargs() returns connection_class, ssl_context, and verify_certs parameters ready to unpack into any OpenSearch() constructor. convert_der_to_pem() handles DER-encoded certificates generated by the Windows CertEnroll API, converting them to PEM format at runtime. All eight OpenSearch call sites now import from tls instead of constructing their own SSL handling.
* src/tinysocs/agent/adapters/opensearch_client.py — Replaced inline SSL logic with tls.get_opensearch_kwargs(). Added Urllib3HttpConnection with explicit ssl_context for PyInstaller compatibility. +48 / -13 lines.
* src/tinysocs/launcher/quickstart.py — Clears stale SSL_CERT_FILE and REQUESTS_CA_BUNDLE environment variables left by PyInstaller's certifi bundle before any HTTPS connection is made. +20 lines.
* modules/TinySocs.Installer.psm1 — DER-to-PEM conversion at install time: after CertEnroll generates the self-signed certificate, the installer detects DER encoding and converts to PEM using certutil. SIEM_SSL_VERIFY default changed from false to true. +26 lines.
* scripts/Full-Rebuild.ps1 — Post-install OpenSearch SSL fix: patches assistant.env with correct CA cert path, restarts TinySocsAssistant service after SSL env update. +45 lines.
* src/tinysocs/api/node.py — Removed inline verify=False, uses tls module. -10 lines.
* src/tinysocs/api/bot.py — Removed PyInstaller SSL hack, uses tls module. +4 lines.
* src/tinysocs/orchestrator/anchors.py — Replaced hardcoded SSL params with tls.get_opensearch_kwargs(). +11 / -11 lines.
* src/tinysocs/orchestrator/check_ledger.py — Same centralisation. +3 / -3 lines.
* src/tinysocs/orchestrator/master.py — Same centralisation. +6 / -5 lines.
* src/tinysocs/reporting/daily_summary.py — Removed 63 lines of duplicated OpenSearch connection setup, replaced with tls import. +3 / -63 lines.

M2 — Remove Default Passwords and Hardcoded Secrets

Goal: Ensure no default or hardcoded credentials ship in the codebase. Fresh installs require operator-chosen passwords from the wizard.

Files:
* src/tinysocs/tls.py — get_opensearch_kwargs() reads SIEM_USER and SIEM_PASS from environment variables only, with no fallback defaults. Raises a clear error if credentials are missing rather than silently connecting with a known password. Part of the 239-line tls module.
* src/tinysocs/agent/config.py — Removed hardcoded default SIEM password from config fallback chain. Config now requires explicit credential provisioning. +1 / -1 lines.
* src/tinysocs/api/dashboard.py — Removed 93 lines of inline OpenSearch connection setup that contained default credential fallbacks. Replaced with tls.get_opensearch_kwargs() calls. +93 removed.
* packaging/iss/Quickstart.iss — Hub installer writes operator-entered SIEM password to assistant.env. Site installer receives SIEM credentials through the shared-secret exchange. No default passwords in any code path.

M3 — Dashboard Session Stability and Authentication

Goal: Fix session expiry on tab switches, ensure Bearer tokens are sent on every API call, and add sliding session renewal.

Files:
* src/tinysocs/api/dashboard.py — fetchJSON() helper now includes Authorization: Bearer header on every request. Added sliding session renewal: each successful API call extends the session expiry by the configured timeout (8 hours default), preventing logout during active use. Fixed tab-switch logout caused by widget refresh calls racing with session checks. Removed the old logout-on-401 behaviour that fired during normal tab navigation. Fixed duplicate aggregate banner rendering and blank "Viewing" label on site focus. Added approval feedback toast for site registration. +120 / -40 lines across commits 877c7a0, aba77d1, 91d4657, 0d1bd53.

M4 — Dashboard Widget Polish: Heights, Pagination, Interactivity

Goal: Make every widget card match the assistant panel height, pin pagers to card bottoms, calculate per-page counts dynamically, and eliminate scrollbars.

Files:
* src/tinysocs/api/dashboard.py — Widget height system: all card bodies compute their height from the assistant panel reference height minus card header and pager chrome. Per-page counts derived dynamically from available height divided by estimated row height (32px). Pagination pinned to bottom of every card via flexbox layout with the pager outside the scrollable content area. Event Flow SVG chart fills full card height dynamically using a ResizeObserver. Event Explorer scrollbar removed in favour of pagination-only navigation. Alert Rules pager appended to card container (not content div) to prevent overflow clipping. Fired Detections card height matched to other widgets. MITRE download button style matched to compliance download button. Compliance button alignment fixed. Aggregate banner sticky position adjusted to clear tab bar. Demo mode gaps filled: MITRE heatmap data, guided response placeholder, fleet detail cards, compliance CSV export. Default tab set correctly on login. Eager-load enabled for all widget data. Ask AI buttons added to widget headers. Grey lock icon shown for local-only nodes with retry on initial load. +700 / -250 lines across 20 commits.
* docs/demo-script.md — Updated demo walkthrough with new widget behaviour, pagination instructions, and cross-site aggregation steps. +39 / -17 lines.

M5 — Cross-Site Data Aggregation

Goal: Fan out dashboard queries to all registered federation nodes and merge results into unified widgets.

Files:
* src/tinysocs/api/dashboard.py — New fan-out query engine: /api/dashboard/stats, /api/dashboard/alerts, /api/dashboard/events, and /api/dashboard/fleet endpoints now iterate over all TINYSOCS_NODES entries, query each node's API in parallel using asyncio, merge the responses, and return unified aggregated data. Alert counts, severity breakdowns, event flow timelines, and fleet health statuses are summed across all reachable Sites. Unreachable nodes contribute zero counts with a visual indicator rather than breaking the entire widget. Overview aggregate banner hidden when operator focuses on a single site. +154 / -14 lines (commit 2100644 + supporting fixes).
* src/tinysocs/api/node.py — Node API extended with /api/node/alerts/aggregate and /api/node/events/aggregate endpoints that return pre-aggregated data suitable for Hub fan-out queries. Certificate fingerprint exposed in /meta for pinning verification. Site auto-registration endpoint accepts registration requests from Sites and queues them for Hub operator approval. Visible error reporting for registration failures with structured error responses. +162 / -31 lines.

M6 — Installer Reliability and Build Robustness

Goal: Fix all installer and build-script failures discovered during multi-machine deployment testing.

Files:
* scripts/Full-Rebuild.ps1 — Auto-unlock TinySocs-Setup.exe before ISCC compile to prevent "file in use" build failures. SysmonDrv Stop-Service hang prevention with timeout and forced kill. Registry fallback for Sysmon driver purge when sc.exe delete is blocked by the running driver. ASCII-only source: replaced em-dash characters that caused PowerShell 5.x parse errors. Inlined Add-Type C# to avoid using-statement conflicts in PS 5.x. +148 / -37 lines.
* packaging/iss/Quickstart.iss — Site installer ordering fix: critical config (TINYSOCS_NODE_ID, MASTER_SHARED_SECRET, SIEM credentials, TLS cert paths) written to assistant.env before the OpenSearch bootstrap runs, preventing bootstrap from failing on missing credentials. Hub installer writes node TLS cert paths to assistant.env. Site installer opens Hub dashboard URL on finish instead of localhost. Site role hides SIEM password section (credentials come from Hub). Shared secret field cleared on back-navigation. +289 / -45 lines.
* modules/TinySocs.Installer.psm1 — Sysmon hardening: ARM64 detection uses registry as primary source instead of unreliable WMI queries. Purge wrong-architecture Sysmon service and stale binaries from Windows root before install. Sysmon's own -u force used instead of sc.exe delete for clean uninstall. Registry fallback when driver blocks service deletion. Architecture detection order fixed on x64. Role-change guard for assistant.env backup restore. Health check tries HTTPS first for Assistant API. Full Site role deployment: OpenSearch bootstrap, agent config, and node service management. +317 / -23 lines.
* modules/Launch-Master.ps1 — Updated SSL parameters for master orchestrator launch. +6 / -4 lines.
* src/tinysocs/agent/config.py — Removed hardcoded default password. +1 / -1 lines.

M7 — Dashboard Loading UX

Goal: Eliminate loading errors, blank states, and visual glitches during initial dashboard load and site navigation.

Files:
* src/tinysocs/api/dashboard.py — Initial load retry: dashboard retries node queries on first load instead of showing error states, with exponential backoff. Grey lock icon displayed for local-only nodes that cannot be reached from the Hub, distinguishing them from genuinely unreachable nodes. Sites tab flash eliminated by deferring banner rendering until data is loaded. Duplicate banner suppressed with render-once guard. Blank "Viewing" label fixed by setting site name before rendering. Login JS syntax errors fixed: escaped quotes in onclick handlers and restored missing slash in JS comments that broke the doLogin function. Assistant panel dead space on Sites tab removed by adjusting panel visibility and height calculation. +58 / -25 lines across commits 324d894, 007c994, 2543194, f91437a, 646dc33.

Modified Files

| File | Changes | +/- |
|---|---|---|
| src/tinysocs/api/dashboard.py | M0-M7: Certificate pinning integration, session auth with Bearer tokens and sliding renewal, widget height system, dynamic per-page counts, pagination pinned to card bottoms, Event Flow SVG fill, cross-site fan-out aggregation, site management UI, demo mode gaps, loading UX fixes, login JS fixes, aggregate banner logic | +1,511 / -350 |
| modules/TinySocs.Installer.psm1 | M1, M6: DER-to-PEM cert conversion, SIEM_SSL_VERIFY default flipped, Sysmon ARM64 registry detection, wrong-arch purge, -u force uninstall, registry driver fallback, role-change guard, HTTPS health check, full Site deployment | +317 / -23 |
| packaging/iss/Quickstart.iss | M2, M5, M6: Config ordering fix, Hub cert path writes, Site opens Hub URL, shared secret field clear, SIEM password section hidden, Site auto-registration trigger, finish page text | +289 / -45 |
| src/tinysocs/federation_certs.py | M0: New file — SHA-256 certificate pinning store, TOFU, verify callback, pinning SSLContext | +273 / -0 |
| src/tinysocs/tls.py | M1-M2: New file — centralised SSLContext, get_opensearch_kwargs, DER-to-PEM conversion, no default credentials | +239 / -0 |
| src/tinysocs/api/node.py | M0, M1, M5: Certificate fingerprint in /meta, aggregation endpoints, registration error reporting, tls module migration | +162 / -31 |
| scripts/Full-Rebuild.ps1 | M1, M6: Post-install SSL fix, auto-unlock exe, SysmonDrv hang fix, registry fallback, ASCII dashes, PS 5.x inline C# | +148 / -37 |
| src/tinysocs/agent/adapters/opensearch_client.py | M1: Urllib3HttpConnection with explicit ssl_context, tls module migration | +48 / -13 |
| src/TinySocs.Agent/Detection/DetectionEngine.cs | M4: Alert cooldown mechanism to suppress duplicate detections within configurable window | +52 / -2 |
| docs/demo-script.md | M4: Updated demo walkthrough with pagination and cross-site steps | +39 / -17 |
| packaging/detection/rules.yml | M4: Detection rule tuning — adjusted thresholds, added cooldown_minutes, reduced false positives | +32 / -19 |
| src/tinysocs/launcher/quickstart.py | M1: Clear stale PyInstaller SSL env vars at startup | +20 / -0 |
| tests/test_detection_rules.py | M4: New tests for cooldown mechanism and tuned rule thresholds | +18 / -0 |
| src/tinysocs/orchestrator/anchors.py | M1: Migrated to tls.get_opensearch_kwargs() | +11 / -11 |
| modules/Launch-Master.ps1 | M6: Updated SSL parameters for master launch | +6 / -4 |
| src/TinySocs.Agent/Detection/DetectionRule.cs | M4: Added CooldownMinutes property to DetectionRule model | +6 / -0 |
| src/tinysocs/orchestrator/check_ledger.py | M1: Migrated to tls module | +3 / -3 |
| src/tinysocs/orchestrator/master.py | M1: Migrated to tls module | +6 / -5 |
| src/tinysocs/reporting/daily_summary.py | M1: Removed 63 lines of duplicated SSL setup, replaced with tls import | +3 / -63 |
| src/tinysocs/api/bot.py | M1: Removed PyInstaller SSL hack, tls module migration | +4 / -0 |
| .claude/launch.json | Dev server config update | +2 / -1 |
| src/tinysocs/agent/config.py | M2: Removed hardcoded default SIEM password | +1 / -1 |

Items Not Implemented

| Item | Reason |
|---|---|
| Mutual TLS (mTLS) for federation | Certificate pinning verifies the Site's identity to the Hub, but the Site does not yet verify the Hub's certificate. Mutual TLS would close this gap for zero-trust deployments. |
| Certificate rotation and revocation | Pinned certificates are static. An operator workflow for rotating Site certificates and revoking compromised ones (CRL or OCSP-style) is future scope. |
| Automated cross-site alerting | Fan-out aggregation shows unified counts but does not generate Hub-level alerts when a Site's aggregated severity crosses a threshold. Requires a Hub-side detection engine. |
| Per-site AI assistant context | The AI assistant queries the local SIEM only. Proxying chat queries to a specific Site's data for focused investigation requires additional federation plumbing. |
| Widget data caching | Each tab switch re-queries all nodes. A short-lived cache (30-60 seconds) for fan-out results would reduce load on large federations. |
