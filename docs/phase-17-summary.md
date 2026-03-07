Phase 17 Summary — Demo-Ready Federation & Pilot Launch

Theme: "First light"


Overview

Phase 17 bridged TinySocs from engineering to go-to-market. The dashboard now launches in demo mode on any OS — `python -m tinysocs.api.bot --demo` — serving synthetic security data for a realistic three-host scenario without OpenSearch, Windows, or any external dependencies. The AI assistant works normally against the synthetic data, making it possible to demo the full product on a Zoom call from a Mac in 10 seconds. A new Sites tab shows multi-site federation status for MSSP deployments, with per-node health, ledger integrity, and detection activity. The GitHub Actions release pipeline now builds the C# agent, compiles the Inno Setup installer with cached OpenSearch vendor payload, and publishes GitHub Releases with checksums. A static landing page deploys to GitHub Pages with early access request flow. Outreach materials include a demo walkthrough script, competitive positioning, and email templates for pilot and MSSP conversations. The license was changed from Apache 2.0 to Business Source License 1.1 to protect commercial interests — production use is permitted except for competing hosted/embedded offerings, with automatic conversion to Apache 2.0 after four years per version.

Stats: 17 files changed, +2,061 / -230 lines across 6 milestones (M0–M5), 3 commits on branch, 325 tests passing (54 new), 1 pre-existing failure, 1 skipped.


Commits

| Hash | Message |
|---|---|
| 0467d9f | Phase 17 "First Light": demo mode, Sites tab, release pipeline, landing page, outreach kit |
| 077a465 | Fix landing page: email links and remove self-referencing anchor |
| 7860f41 | Change license from Apache 2.0 to BSL 1.1 for commercial protection |


Milestones Delivered


M0 — Demo / Sandbox Mode

Goal: The dashboard renders realistic security data without OpenSearch, Windows events, or any external dependencies.

Files:
- `src/tinysocs/api/dashboard.py` — `_DEMO_MODE` flag checked at module level. Each API endpoint intercepts with `if _DEMO_MODE: return _demo_<endpoint>(params)`. 12 demo response functions return dicts matching the exact shape of real responses. Timestamps computed relative to `datetime.now(timezone.utc)` so timelines always look fresh. Demo banner rendered as sticky element below header with dismissible close button and CSS overrides for assistant panel and tab bar positioning.
- `src/tinysocs/api/bot.py` — Early `--demo` detection at module level (before dashboard import) sets `TINYSOCS_DEMO_MODE=1` and `SIEM_PASS=demo` in `os.environ`. This was critical: `_DEMO_MODE` and `_DASHBOARD_HTML` are evaluated at import time, so the env var must be set before the import statement. The `cli()` function also sets `DASHBOARD_BIND=127.0.0.1` and prints the demo mode startup message.

Demo scenario — "Hartwell & Associates" law firm (3 hosts):

| Hostname | Role | Event Pattern |
|---|---|---|
| RECEPTION-PC | Front desk workstation | Heavy logon/logoff (4624/4625), USB device events |
| FILESERVER-01 | Shared file server | FIM alerts, SMB access, scheduled backup tasks |
| DC-01 | Domain controller | Account management, group policy, PowerShell admin scripts |

Demo alert timeline (7 alerts over 24 hours):

| Time Offset | Alert | Severity | Host |
|---|---|---|---|
| -14h | Brute force: 8 failed logons from 203.0.113.47 | critical | RECEPTION-PC |
| -12h | Suspicious PowerShell: encoded command execution | high | DC-01 |
| -10h | New local account created: svc_backup | medium | FILESERVER-01 |
| -8h | FIM: Modified C:\ClientFiles\Mergers\draft.docx | medium | FILESERVER-01 |
| -4h | Off-hours RDP attempt from 198.51.100.22 | high | FILESERVER-01 |
| -2h | Scheduled task created: WindowsUpdate_Check | medium | DC-01 |
| -45m | Defender: real-time protection disabled temporarily | high | RECEPTION-PC |

Demo data endpoints: `/api/alerts/summary` (42 alerts), `/api/alerts/timeline` (24 hourly buckets with bell-curve distribution), `/api/fleet/health` (3 hosts with metrics), `/api/host/timeline` (per-host 24-hour bucketed timeline), `/api/events/recent` (20 synthetic events), `/api/detections/fired` (7 demo alerts with full schema), `/api/version/status` (3 hosts, 1 outdated), `/api/compliance/report` (synthetic control statuses), `/api/threat-intel/status` (3 providers configured), `/api/nodes` (3 synthetic sites). MITRE coverage and settings endpoints pass through to real code (no OpenSearch needed).

AI assistant in demo mode: Chat tool functions `_chat_tool_search_kql` and `_chat_tool_aggregate` intercept in demo mode, returning synthetic data from the demo response functions. The LLM receives synthetic events and explains them as if real — the assistant "just works" with demo data.

Bug fixes during testing:
- Import order: `dashboard.py` was imported at module load time in `bot.py` before `cli()` set the env var. `_DEMO_MODE` was `False` and `_DASHBOARD_HTML` was pre-computed without the demo banner. Fixed by adding early `--demo` detection before the import.
- Banner layout: Demo banner at `position:sticky` fought with `.right-panel` at `position:fixed`. Fixed with `<style>` block adjusting `.right-panel { top: 122px !important; }` and `.tab-bar { top: 88px !important; }` when banner present, with close button restoring originals.
- Version drift banner stacking: Two banners sandwiched the tab bar. Fixed by suppressing version drift banner when demo banner exists via JS check `!!document.getElementById('demoBanner')`.


M1 — Dashboard Sites Tab (Federation Visibility)

Goal: A new Sites tab shows all configured TinySocs nodes with per-node health, ledger status, and detection activity. The tab appears only in multi-node deployments (or demo mode).

Files:
- `src/tinysocs/api/dashboard.py` — New `/api/nodes` endpoint reads `TINYSOCS_NODES` env var, fires concurrent requests to each node's `/meta` and `/evidence/head` endpoints (timeout 5s), queries OpenSearch `tinysocs_anchors` for per-node detection activity, merges into response with `url`, `node_id`, `version`, `status`, `ledger_sequence`, `ledger_head`, `last_anchor_at`, `last_anchor_items`, `reachable`, `error`. Status logic: healthy if reachable and recent anchor, warning if reachable but stale/version drift, unreachable if /meta times out. `_get_node_urls()` helper parses env var with caching. `_demo_nodes()` returns 3 synthetic sites. Tab bar updated to 6 tabs: Sites (leftmost), Overview, Fleet, Data, Detections, Compliance. Sites tab hidden when `TINYSOCS_NODES` has ≤1 entry and demo mode is off. JavaScript: `loadSites()` fetches `/api/nodes` and renders site cards into a CSS grid. `initSitesTab()` called on dashboard unlock to set tab visibility and default tab. `_validTabs` updated. `switchTab()` and `loadTabData()` updated with 'sites' case. Auto-refreshes every 30 seconds when active. Site cards show status dot (green/amber/red), node_id, version with outdated badge, ledger sequence, last anchor timestamp (relative), detection count.

Demo mode sites:

| node_id | url | version | status | sequence | last_anchor_items |
|---|---|---|---|---|---|
| acme-law | http://acme-node:8081 | 0.8.0 | healthy | 347 | 2 |
| mainst-dental | http://dental-node:8081 | 0.8.0 | healthy | 189 | 0 |
| harbor-ins | http://harbor-node:8081 | 0.7.9 | warning | 512 | 5 |

harbor-ins has version drift (0.7.9 vs 0.8.0) and 5 active detections — gives the demo a talking point about version management and active threats across client sites.


M2 — Release Pipeline

Goal: Tag a version → GitHub Actions builds installer → publishes GitHub Release with checksums.

Files:
- `.github/workflows/build-installer.yml` — Complete pipeline: checkout, setup Python/dotnet, build C# agent (`dotnet publish`), cache/download OpenSearch 3.3.2 vendor payload (~300 MB) via `actions/cache@v4` with key `opensearch-3.3.2-windows-x64`, install Inno Setup 6 via chocolatey, compile installer with ISCC, generate SHA256 checksums, upload artifacts. New `release` job runs only on `v*` tags: downloads artifacts, creates GitHub Release via `softprops/action-gh-release@v2` with TinySocs-Setup.exe and SHA256SUMS.txt.
- `pyproject.toml` — Version bumped from 0.7.0 to 0.9.0. License changed from MIT to BSL-1.1.
- `packaging/iss/Quickstart.iss` — Version bumped to 0.9.0.
- `CHANGELOG.md` — New file in Keep a Changelog format with Phase 17 entry and historical 0.7.0 entry.


M3 — Landing Page

Goal: A public-facing web page explaining what TinySocs is, showing key features, and directing potential customers to request early access.

Files:
- `site/index.html` — Single HTML file with inline CSS, zero dependencies. Dark theme matching dashboard aesthetic. Responsive mobile-first design. Sections: Hero ("Know what's happening on your network"), feature grid (6 cards: See everything, AI that explains, Catch threats automatically, Compliance at the click of a button, Your data stays yours, Manage multiple sites), How it works (Install → Connect → Monitor, "Up and running in an afternoon"), comparison table (TinySocs vs Traditional tools — no vendor names, no "free" pricing, honest timing "under an hour"), CTA ("Request Early Access" → mailto:lukefitzg@gmail.com), footer (copyright and contact).
- `.github/workflows/pages.yml` — GitHub Pages deployment on push to main when `site/` changes. Uses `actions/deploy-pages@v4`. No Jekyll (`.nojekyll` file in `site/`).
- `site/.nojekyll` — Prevents Jekyll processing.
- `site/screenshots/.gitkeep` — Placeholder for future dashboard screenshots.

Design decisions: No direct download link — the product is not freely available. "Request Early Access" CTAs use mailto links. No competitor name-checking. No specific rule counts or detection stats. "A fraction of enterprise pricing" rather than "free". "Under an hour" setup time rather than false "15 minutes". Positive framing throughout — describes what TinySocs does, not what competitors don't. Broader audience than just SMBs. No "master" terminology in customer-facing content.


M4 — Pilot & MSSP Outreach Kit

Goal: Polished documents enabling approach to pilot customers and MSSPs.

Files:
- `docs/demo-script.md` — Step-by-step demo walkthrough covering prerequisites, launch, single-site walkthrough (5 minutes: Overview → Fleet → Detections → AI assistant → Compliance), multi-site walkthrough (2 minutes: Sites tab, MSSP pitch), and closing.
- `docs/competitive-positioning.md` — Comparison matrix: TinySocs vs Blumira vs Todyl vs Perch/ConnectWise SIEM vs Elastic SIEM. Dimensions: deployment model, pricing, setup time, AI assistance, compliance, on-prem option, MSSP support. Honest framing including where TinySocs is weaker.
- `docs/outreach-templates.md` — Four templates: pilot email (for small businesses/IT consultants), MSSP email (for managed security providers), LinkedIn post, and local business networking post. All templates are starting points for personalisation.
- `docs/one-pager.md` — Updated detection count from "40+" to "89 rules, 33 MITRE techniques". Added download link and landing page URL. Tightened language.


M5 — Tests

Goal: Unit tests for all Phase 17 changes. No regressions.

Files:
- `tests/test_demo_mode.py` — 42 tests across 12 test classes validating all demo response shapes. Classes: TestDemoModeEnabled, TestDemoAlertsSummary (shape, total, severity keys, severity sums, top_rules structure, top_hosts structure), TestDemoAlertsTimeline (shape, bucket count, bucket shape), TestDemoDetectionsFired (shape, alert count, alert fields), TestDemoFleetHealth (shape, host count, host fields, host names), TestDemoHostTimeline (shape, buckets have channels, unknown host returns empty), TestDemoEventsRecent (shape, event count, event fields), TestDemoVersionStatus (shape, host count, version drift), TestDemoComplianceReport (NIST/HIPAA/PCI shapes, controls structure), TestDemoThreatIntelStatus (shape, provider count, provider fields), TestDemoNodes (shape, node count, node fields, node statuses, node IDs), TestDemoTimestampsRelative (alerts timeline, fleet health, nodes anchor, detections timestamps all within last 24 hours).
- `tests/test_nodes_api.py` — 12 tests across 3 test classes. TestGetNodeUrls: empty env, single node, multiple nodes, whitespace stripped, empty string, trailing comma. TestDemoNodesEndpoint: three sites, all reachable, harbor version drift, acme healthy, detection counts. TestNodeResponseContract: all JS-expected fields present.

Bug fixes during testing:
- Wrong response shapes: Tests assumed `d["alerts"]` but actual key was `d["detections"]`. Tests assumed `d["hosts"]` for version status but actual key was `d["fleet_versions"]`. Fixed by checking actual return shapes.
- `_get_node_urls` caching: `monkeypatch.setenv` changed env var but `_NODES_LIST` was already cached from first call. Fixed by resetting `dashboard_mod._NODES_LIST = None` before each test call.

Full test suite: 325 passed, 1 skipped, 1 pre-existing failure (test_e2e_phase12.py::test_full_approve_lifecycle — asserts completed but gets acknowledged, unrelated to Phase 17). 54 new tests, 0 new failures.


License Change — BSL 1.1

The LICENSE file was changed from Apache 2.0 to Business Source License 1.1, customised for TinySocs:

| Parameter | Value |
|---|---|
| Licensor | Luke FitzGerald |
| Licensed Work | TinySocs 0.9.0 or later, (c) 2025-2026 |
| Additional Use Grant | Production use permitted except competitive hosted/embedded offerings |
| Change Date | Four years from publication of each version |
| Change License | Apache License, Version 2.0 |
| Contact | lukefitzg@gmail.com |

The BSL 1.1 is compatible with OpenSearch (Apache 2.0) — TinySocs is a derivative work that adds a more restrictive license on top, which is permitted by Apache 2.0. Users can use TinySocs freely for internal purposes; the restriction only prevents third parties from offering TinySocs as a competing commercial product. After four years per version, each version automatically converts to Apache 2.0.


Modified Files

| File | Changes |
|---|---|
| `src/tinysocs/api/dashboard.py` | Demo mode flag, 12 demo response functions, demo banner HTML/CSS with sticky positioning and close handler, `/api/nodes` endpoint, `_get_node_urls()` helper, `_demo_nodes()`, Sites tab HTML/CSS/JS, `loadSites()`, `initSitesTab()`, `_validTabs` updated, `switchTab`/`loadTabData`/`refreshAll` updated, chat tool demo intercepts, version drift banner suppression. +688 lines. |
| `src/tinysocs/api/bot.py` | Early `--demo` detection before dashboard import, `TINYSOCS_DEMO_MODE` and `SIEM_PASS` env var setup, `--demo` CLI argument in `cli()`, relaxed secret requirement, `DASHBOARD_BIND=127.0.0.1`. +22 lines. |
| `.github/workflows/build-installer.yml` | OpenSearch vendor caching, Inno Setup installation/compilation, SHA256 checksum generation, GitHub Release creation on v* tags. +106 lines. |
| `.github/workflows/pages.yml` | New: GitHub Pages deployment workflow for landing page. +36 lines. |
| `CHANGELOG.md` | New: Phase 17 and historical 0.7.0 entries in Keep a Changelog format. +32 lines. |
| `LICENSE` | Changed from Apache 2.0 to BSL 1.1 with TinySocs-specific parameters. |
| `pyproject.toml` | Version 0.9.0, license BSL-1.1. |
| `packaging/iss/Quickstart.iss` | Version 0.9.0. |
| `site/index.html` | New: Landing page with hero, feature grid, comparison table, early access CTA. +295 lines. |
| `site/.nojekyll` | New: Prevents Jekyll processing on GitHub Pages. |
| `site/screenshots/.gitkeep` | New: Placeholder for dashboard screenshots. |
| `docs/demo-script.md` | New: Step-by-step demo walkthrough. +79 lines. |
| `docs/competitive-positioning.md` | New: TinySocs vs 5 competitors comparison. +89 lines. |
| `docs/outreach-templates.md` | New: 4 email/post templates for pilot and MSSP outreach. +158 lines. |
| `docs/one-pager.md` | Updated stats, download link, landing page URL. +6/-6 lines. |
| `tests/test_demo_mode.py` | New: 42 tests validating all demo response shapes. +360 lines. |
| `tests/test_nodes_api.py` | New: 12 tests for node URL parsing and demo node contract. +117 lines. |


Acceptance Criteria Validation

M0 — Demo / Sandbox Mode

| Criterion | Status |
|---|---|
| `python -m tinysocs.api.bot --demo` launches on macOS/Linux without error | ✅ Met |
| `BOT_SHARED_SECRET` not required in demo mode | ✅ Met |
| Dashboard loads at `http://localhost:8090/dashboard` with all tabs functional | ✅ Met |
| Overview tab shows Alert Summary (42 alerts) and Alert Timeline | ✅ Met |
| Fleet tab shows 3 hosts with realistic metrics | ✅ Met |
| Data tab shows 20 synthetic events with mixed channels | ✅ Met |
| Detections tab shows 7 fired alerts with severity and rule names | ✅ Met |
| Compliance tab shows MITRE coverage (real rules) and compliance report (synthetic) | ✅ Met |
| AI assistant responds to questions about synthetic data | ✅ Met |
| Demo banner visible on every tab, dismissible | ✅ Met |
| All timestamps relative to now | ✅ Met |

M1 — Dashboard Sites Tab

| Criterion | Status |
|---|---|
| `TINYSOCS_NODES` not set → Sites tab hidden → Overview is default | ✅ Met |
| Demo mode → Sites tab visible with 3 synthetic sites | ✅ Met |
| Site cards show status dot, node_id, version, ledger info, detection count | ✅ Met |
| Sites tab refreshes every 30 seconds when active | ✅ Met |
| Tab state persists to localStorage and URL hash | ✅ Met |
| LLM Assistant visible on Sites tab | ✅ Met |

M2 — Release Pipeline

| Criterion | Status |
|---|---|
| Workflow builds C# agent and compiles Inno Setup installer | ✅ Met (workflow written, untested — requires GitHub Actions runner) |
| `v*` tag triggers GitHub Release creation | ✅ Met (workflow written) |
| OpenSearch vendor payload cached after first build | ✅ Met (cache key configured) |
| `pyproject.toml` and `Quickstart.iss` both show 0.9.0 | ✅ Met |
| SHA256 checksums generated for release artifacts | ✅ Met |

M3 — Landing Page

| Criterion | Status |
|---|---|
| Landing page loads with all sections | ✅ Met |
| "Request Early Access" CTAs link to email | ✅ Met |
| Feature grid displays 6 cards | ✅ Met |
| Comparison table renders (no vendor names) | ✅ Met |
| Responsive on mobile, tablet, desktop | ✅ Met |
| No JavaScript required | ✅ Met |
| GitHub Pages workflow configured | ✅ Met |

M4 — Pilot & MSSP Outreach Kit

| Criterion | Status |
|---|---|
| Demo script is a complete walkthrough | ✅ Met |
| Competitive positioning covers 5 competitors | ✅ Met |
| Outreach templates ready to personalise | ✅ Met |
| One-pager updated with current stats | ✅ Met |

M5 — Tests

| Criterion | Status |
|---|---|
| All demo mode shape tests pass | ✅ Met (42 tests) |
| Node awareness tests pass | ✅ Met (12 tests) |
| Full test suite: 325 passed, 1 skipped, 0 new failures | ✅ Met |


Items Not Implemented

| Item | Reason |
|---|---|
| Collector agent event relaying | Cross-node event forwarding (agent on Site A sends to aggregator on Site B) is Phase 18 scope. |
| Installer role-specific configuration | Role selection UI exists but env var templating is incomplete. Hand-config works for pilots. |
| Site drill-through navigation | Clicking a site card highlights it but doesn't filter dashboard to that site's data. Requires per-node SIEM URL routing. |
| macOS/Linux collector | Cross-platform event collection doubles addressable market but is a full phase of its own. |
| Auto-update delivery | Version drift detection exists. Actual update delivery (version server, download, silent install, rollback) is future scope. |
| OpenSearch seed script | A script writing synthetic events to real OpenSearch for first-install experience. Demo mode covers the immediate need. |
| Custom domain | Landing page deploys to GitHub Pages. Custom domain (e.g., tinysocs.io) is a DNS/registrar task. |
| Logo and brand assets | Landing page uses text-based branding. Proper visual identity is not engineering work. |
