# Phase 16 Summary — Post-Install Remediation & Dashboard Navigation

**Theme:** "Polish the glass"

## Overview

Phase 16 fixed four issues discovered during a fresh Phase 15 install and reorganised the dashboard from a single scrolling page into five purpose-built tabs. GreyNoise Community enrichment now works out of the box with no API key — the provider is always configured, with unauthenticated access at 10 lookups/day and an optional key upgrading to 50/week. Threat intel API keys entered during installation now appear correctly in the dashboard settings panel — the root cause was two JavaScript field arrays that were missing the three key names. The MITRE ATT&CK coverage widget now finds rule files on Windows installs via fallback path discovery, not just in the development tree. The dashboard is organised into five tabs (Overview, Fleet, Data, Detections, Compliance) with the LLM Assistant always visible. The Fleet Event Flow widget shows fleet-wide event volume by default with a custom multi-select host picker dropdown for filtering by one or more hosts. Fleet Health rows expand on click anywhere, not just on the hostname text.

**Stats:** 8 files changed, +621 / -274 lines across 5 milestones (M0–M4), 1 commit on branch, 89 detection rules covering 33 MITRE techniques across 11 tactics, 271 tests passing (1 pre-existing failure, 1 skipped).

## Commits

| Hash | Message |
|------|---------|
| 0d1d790 | Phase 16: fix post-install issues, add tab-based dashboard navigation |

## Milestones Delivered

### M0 — GreyNoise Unauthenticated Mode

**Goal:** GreyNoise Community enrichment works out of the box with no API key.

**Files:**

- `src/tinysocs/agent/threat_intel.py` — `GreyNoiseCommunityProvider` reworked: `is_configured()` now always returns `True`. Rate limit is dynamic: 50 when API key is present, 10 when absent. HTTP headers are conditional — the `key` header is only sent when an API key exists. Docstring updated to document both tiers.
- `packaging/iss/Quickstart.iss` — GreyNoise label changed from `'GreyNoise Community API key (free: 5,000 lookups/day):'` to `'GreyNoise Community API key (optional — works without, 10/day unauthenticated):'`.
- `config/assistant.env` — Comment updated from `(free: 5,000/day)` to `(optional: 10/day unauthenticated, 50/week with key)`.
- `src/tinysocs/api/dashboard.py` — GreyNoise settings field placeholder updated to match new rate limit documentation.

**How it works:** The GreyNoise Community API at `/v3/community/{ip}` accepts unauthenticated requests. Previously, `is_configured()` returned `False` when `GREYNOISE_API_KEY` was empty, causing the entire provider to be skipped by the enrichment pipeline. Now the provider is always active. When no key is present, requests are sent without the `key` header and the rate limiter is set to 10/day. When a key is provided, the `key` header is included and the rate limit increases to 50/week. This means an operator who skips the API key field in the installer still gets GreyNoise enrichment for the first 10 lookups each day.

### M1 — Threat Intel Settings Persistence

**Goal:** API keys entered during installation appear correctly in the dashboard settings panel.

**Files:**

- `src/tinysocs/api/dashboard.py` — Added `'ABUSEIPDB_API_KEY'`, `'OTX_API_KEY'`, `'GREYNOISE_API_KEY'` to both the `populateSettings()` and `saveSettings()` JavaScript field name arrays.

**Root cause:** The Python backend `_SETTINGS_KEYS` list included all three threat intel key names. The `GET /api/settings` and `POST /api/settings` endpoints correctly read and wrote these keys to `assistant.env`. But the JavaScript `populateSettings()` function iterated a hardcoded array of field names to populate the form, and the JavaScript `saveSettings()` function iterated a separate hardcoded array to collect form values — both arrays were missing the three threat intel key names. The backend round-tripped the keys correctly, but the frontend never rendered or collected them. Fix: add the three key names to both JS arrays.

### M2 — MITRE Coverage Path Fallback

**Goal:** The MITRE ATT&CK coverage widget shows correct rule counts on Windows installs.

**Files:**

- `src/tinysocs/reporting/mitre_coverage.py` — Added `import os`. Added `_find_csharp_rules()` helper: tries the dev-tree relative path first (`_PROJECT_ROOT / "packaging" / "detection" / "rules.yml"`), falls back to `%ProgramData%\TinySocs\Collector\rules\rules.yml`. Added `_find_python_rules()` helper: tries the dev-tree relative path first, falls back to `Path(__file__).resolve().parent.parent / "agent" / "detections" / "rules.yaml"` (works inside PyInstaller bundles). Updated `load_all_rules()` to use these helpers instead of hardcoded paths.

**Root cause:** `mitre_coverage.py` resolved rule file paths relative to `__file__` — walking up four parent directories to reach `packaging/detection/rules.yml`. This works in the development tree where `mitre_coverage.py` lives at `src/tinysocs/reporting/mitre_coverage.py`. On a Windows install, C# rules deploy to `C:\ProgramData\TinySocs\Collector\rules\rules.yml` and Python rules bundle inside the PyInstaller executable. The path resolution silently failed, found no rule files, and returned an empty list — the widget showed "0 techniques, 0/14 tactics". Fix: try multiple candidate paths for each rule file and use the first that exists.

### M3 — Tab-Based Dashboard Navigation

**Goal:** Replace the single scrolling page with five purpose-built tabs.

**Files:**

- `src/tinysocs/api/dashboard.py` — Major refactor (~500 lines changed). New CSS for `.tab-bar`, `.tab-pane`, `.host-picker` (custom multi-select dropdown), `.timeline-controls`. HTML restructured: tab bar with 5 buttons before `.main-layout`; cards wrapped in 5 `<div class="tab-pane">` containers. New JavaScript functions: `switchTab()`, `loadTabData()`, `toggleHostPicker()`, `_buildHostPickerMenu()`, `_onPickerAllToggle()`, `_onPickerHostToggle()`, `_applyPickerSelection()`. Updated `refreshAll()` (only refreshes active tab), `unlockDashboard()` (restores tab from URL hash or localStorage), `ensureCardExpanded()` (tab-aware).

**Tab structure:**

| Tab | Cards | Purpose |
|-----|-------|---------|
| Overview | Alert Summary, Alert Timeline | High-level situational awareness |
| Fleet | Fleet Health, Event Flow | Per-host monitoring and event volume |
| Data | Event Explorer | Log search and investigation |
| Detections | Fired Detections, Alert Rules | Detection tuning and alert management |
| Compliance | Compliance Coverage, MITRE ATT&CK Coverage | Audit and framework reporting |

**State persistence:** Active tab stored in `localStorage('tinysocs_active_tab')` and reflected in URL hash (`#overview`, `#fleet`, `#data`, `#detections`, `#compliance`). On page load, URL hash takes priority, then localStorage, then defaults to Overview. `hashchange` event listener supports browser back/forward navigation between tabs. `openHostTimeline()` switches to Fleet tab when called from other tabs (e.g., clicking a host IP in Event Explorer). Version drift banner click navigates to Fleet tab and expands Fleet Health.

### M4 — Fleet Event Flow & Interaction Polish

**Goal:** Event Flow shows fleet-wide data by default with a multi-select host picker. Fleet Health rows expand on click anywhere.

**Files:**

- `src/tinysocs/api/dashboard.py` — API endpoint `/api/host/timeline` now accepts optional `hostname` parameter (empty = fleet-wide, single hostname = single host, comma-separated = multi-host via `terms` query). Event Flow card is always visible on Fleet tab (no longer hidden/shown dynamically). Custom multi-select host picker replaces native `<select multiple>`: button shows current selection ("All Hosts", hostname, or "N hosts selected"); dropdown with checkboxes for each host; "All Hosts" checkbox resets to fleet-wide; individual host checkboxes are additive; click outside closes dropdown. Both picker button and time range `<select>` share identical CSS via combined rule with `appearance:none` and shared SVG dropdown arrow — pixel-matched height and alignment. Fleet Health hostname changed from `<a>` link with `event.stopPropagation()` to plain styled text so the row's `onclick="toggleFleetDetail()"` fires regardless of click position.
- `test_dashboard.py` — Added second mock host `TINYBOX-02` to fleet health response. Added mock `/api/host/timeline` endpoint returning 24 hourly buckets with Security, Sysmon, and FIM channel data. Version status updated to include both hosts.

**Custom host picker design:** The native `<select multiple>` was replaced because it requires Ctrl/Cmd+click for multi-selection, renders as a fixed-height scroll box, and provides poor UX. The custom picker is a button that opens a dropdown with checkboxes. "All Hosts" acts as a reset-to-everything toggle. Individual hosts are additive — check multiple to compare event volumes across specific hosts. The dropdown closes on outside click. The button label dynamically reflects the selection state.

### M5 — Tests

**Files:**

- `tests/test_threat_intel.py` — 2 new tests: `test_greynoise_configured_without_key` (no API key → `is_configured()` True, rate limit 10) and `test_greynoise_configured_with_key` (API key present → `is_configured()` True, rate limit 50).
- `tests/test_mitre_coverage.py` — 2 new tests: `test_find_csharp_rules_dev_path` (dev tree → finds `rules.yml`) and `test_find_python_rules_dev_path` (dev tree → finds `rules.yaml`).

**Full test suite:** 271 passed, 1 skipped, 1 pre-existing failure (`test_e2e_phase12.py::test_full_approve_lifecycle` — asserts `completed` but gets `acknowledged`, unrelated to Phase 16). No new failures introduced.

## Modified Files

| File | Changes |
|------|---------|
| `src/tinysocs/api/dashboard.py` | Tab bar CSS/HTML/JS (M3), host picker dropdown (M4), Event Flow always-visible with fleet-wide default (M4), fleet row click fix (M4), settings field arrays (M1), GreyNoise placeholder text (M0). ~500 lines changed. |
| `src/tinysocs/agent/threat_intel.py` | GreyNoise unauthenticated mode: `is_configured()` always True, dynamic rate limit, conditional headers (M0) |
| `src/tinysocs/reporting/mitre_coverage.py` | `_find_csharp_rules()` and `_find_python_rules()` fallback helpers, `load_all_rules()` updated (M2) |
| `packaging/iss/Quickstart.iss` | GreyNoise label updated to indicate key is optional (M0) |
| `config/assistant.env` | GreyNoise comment updated with correct rate limits (M0) |
| `test_dashboard.py` | Second mock host, mock timeline endpoint with 24 hourly buckets (M4) |
| `tests/test_threat_intel.py` | 2 new GreyNoise auth/unauth tests (M5) |
| `tests/test_mitre_coverage.py` | 2 new path fallback tests (M5) |

## Acceptance Criteria Validation

### M0 — GreyNoise Unauthenticated Mode

| Criterion | Status |
|-----------|--------|
| No API key → `is_configured()` returns `True`, rate limit 10 | ✅ Met |
| API key present → `is_configured()` returns `True`, rate limit 50 | ✅ Met |
| Unauthenticated request sends no `key` header | ✅ Met |
| Authenticated request includes `key` header | ✅ Met |
| Installer label indicates key is optional | ✅ Met |
| `assistant.env` comment matches actual API behaviour | ✅ Met |

### M1 — Threat Intel Settings Persistence

| Criterion | Status |
|-----------|--------|
| `populateSettings()` includes threat intel key names | ✅ Met |
| `saveSettings()` includes threat intel key names | ✅ Met |
| Keys entered in installer appear in dashboard settings | ✅ Met |
| Existing settings fields unaffected | ✅ Met |

### M2 — MITRE Coverage Path Fallback

| Criterion | Status |
|-----------|--------|
| Dev tree: rules found via existing relative paths | ✅ Met |
| Windows install: C# rules found at `%ProgramData%` path | ✅ Met (fallback implemented, untestable on macOS dev machine) |
| Python rules found via PyInstaller-compatible relative path | ✅ Met |
| `_find_csharp_rules()` and `_find_python_rules()` unit tests pass | ✅ Met |

### M3 — Tab-Based Dashboard Navigation

| Criterion | Status |
|-----------|--------|
| 5 tabs: Overview, Fleet, Data, Detections, Compliance | ✅ Met |
| Tab switch hides/shows correct card groups | ✅ Met |
| Active tab persists to localStorage and URL hash | ✅ Met |
| Browser back/forward navigates between tabs | ✅ Met |
| LLM Assistant visible on every tab | ✅ Met |
| `ensureCardExpanded()` switches to correct tab | ✅ Met |
| Only active tab's widgets refresh on periodic cycle | ✅ Met |

### M4 — Fleet Event Flow & Interaction Polish

| Criterion | Status |
|-----------|--------|
| Event Flow populated immediately with fleet-wide data | ✅ Met |
| Custom multi-select host picker with checkboxes | ✅ Met |
| "All Hosts" resets to fleet-wide view | ✅ Met |
| Individual hosts are additive (true multi-select) | ✅ Met |
| Picker button and time range dropdown pixel-aligned | ✅ Met |
| Click anywhere on Fleet Health row expands/collapses | ✅ Met |
| `/api/host/timeline` supports empty, single, and comma-separated hostnames | ✅ Met |

### M5 — Tests

| Criterion | Status |
|-----------|--------|
| GreyNoise auth/unauth tests pass | ✅ Met |
| MITRE path fallback tests pass | ✅ Met |
| Full test suite: 271 passed, 1 skipped, 0 new failures | ✅ Met |

## Items Not Implemented

| Item | Reason |
|------|--------|
| macOS/Linux collector | Cross-platform collection is a full phase of its own. Future scope. |
| Full auto-update delivery | Phase 15 M5 built version awareness. Delivery mechanism (version server, download, silent install, rollback) remains future scope. |
| Centralised management console | Multi-site MSSP dashboard. Major undertaking. Future scope. |
| Dashboard SSO/RBAC | Single-password auth sufficient for pilot deployments. Enterprise IAM is post-pilot scope. |
| Response automation / execution | TinySocs is read-only by design. Permanent architectural decision. |
| Event Flow per-host colour differentiation | When multiple hosts are selected, chart shows combined channel volumes. Per-host colouring would require a more complex chart. Future enhancement. |
