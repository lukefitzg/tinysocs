TinySocs Phase 15 Plan — Intelligence & Detection
Theme: "Know your enemy"

Context

Phase 14 made TinySocs pilot-ready — HTTPS dashboard, Sysmon bundling, compliance reports, Windows CI, Atomic Red Team validation infrastructure, and a deployment pack. You can now hand someone an installer and say "try it." But once they try it, the next questions are immediate:

"This IP brute-forced my server — is it known-bad?" Today the operator has to alt-tab to AbuseIPDB and look it up manually. The AI assistant can reason about alerts but has no threat context beyond what's in OpenSearch.

"Do you monitor file changes on my server?" File integrity monitoring is table-stakes for compliance (NIST CSF PR.DS-6, HIPAA §164.312(c)(2), PCI-DSS 11.5). TinySocs currently has zero FIM capability. This is a gap that every auditor and insurance carrier will flag.

"Show me your MITRE coverage." The 34 detection rules map to MITRE techniques in comments and in the external `atomic-tests.yaml`, but there's no machine-readable ATT&CK annotation on the rules themselves. No Navigator layer, no coverage matrix in the dashboard. The detection-efficacy.md from Phase 14 is a template awaiting live execution data.

"Has anyone actually tested these rules against real attacks?" Phase 14 built the Atomic Red Team test infrastructure (Test-AtomicDetection.ps1, atomic-tests.yaml, 12 technique mappings) but the tests have never been executed against a live deployment. The detection-efficacy.md is still a blank template. No one has measured actual detection rates, false positives, or latency.

And on the dashboard itself — 8 cards stacked vertically means a lot of scrolling. Operators need to collapse widgets they're not actively using, the way Event Explorer already works. Every card should have that same click-to-collapse behaviour.

Phase 15 closes these gaps. After this phase, TinySocs enriches alerts with external intelligence, monitors file integrity, presents detection coverage in the language that security buyers speak (MITRE ATT&CK), and has measured detection efficacy against real adversary techniques.

Design principle — read-only, user-assist: TinySocs deliberately has no execute permissions on any host. It observes, detects, enriches, and advises. The AI assistant suggests remediation commands as copy-paste guidance. Automated response execution is explicitly out of scope — it's a security and liability risk that doesn't fit the product's trust model.


M0 — Threat Intelligence Enrichment

Goal: Enrich alerts and events with external threat context so operators see "this IP was reported 47 times for brute-force" next to the alert, not just a raw IP address.

Current State
* `src/tinysocs/agent/enrich.py` contains only `rdns()` — reverse DNS lookup via `socket.gethostbyaddr()`
* No threat feed integration anywhere in the codebase
* The AI assistant can reason about alerts but has no external threat context
* Dashboard alert cards show raw source IPs with no reputation data
* No caching layer for external API lookups

Proposed Changes

Files:
* `src/tinysocs/agent/enrich.py` — Expand into a proper enrichment module with provider abstraction
* `src/tinysocs/agent/threat_intel.py` (new) — Threat intel provider framework: AbuseIPDB, AlienVault OTX, GreyNoise Community
* `src/tinysocs/agent/threat_cache.py` (new) — SQLite-backed TTL cache for API responses (avoid hammering free-tier APIs)
* `src/tinysocs/api/dashboard.py` — Threat intel indicators on alert cards, enrichment status in fleet health, threat intel settings panel
* `config/assistant.env` — `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY` env vars
* `modules/TinySocs.Installer.psm1` — Optional "Threat Intelligence" wizard page for API key entry
* `packaging/iss/Quickstart.iss` — Threat intel wizard page
* `tests/test_threat_intel.py` (new) — Unit tests for providers, cache, and enrichment pipeline

Architecture:

```
Alert fires (Python detection engine or C# alert ingested)
    → Enrichment pipeline extracts IOCs (IPs, domains, hashes)
    → Check SQLite cache (TTL: 24h for IPs, 7d for domains)
    → If cache miss → async API call to enabled providers
    → Store enrichment result in cache + attach to alert document
    → Dashboard renders threat badges on alert cards
```

Deliverables:

1. Provider abstraction (`threat_intel.py`):
   * Base class `ThreatIntelProvider` with `enrich_ip()`, `enrich_domain()`, `enrich_hash()` methods
   * `AbuseIPDBProvider`: IP reputation score (0-100), abuse confidence, country, ISP, total reports, last reported date. Free tier: 1,000 checks/day
   * `AlienVaultOTXProvider`: IP/domain/hash pulse count, reputation score, associated malware families. Free tier: unlimited
   * `GreyNoiseCommunityProvider`: IP classification (benign/malicious/unknown), actor name, tags. Free tier: 5,000/day
   * Each provider has `is_configured()` (checks for API key), `is_available()` (health check), and rate limit tracking
   * Graceful degradation: if a provider is down or rate-limited, skip it and return partial results

2. Enrichment cache (`threat_cache.py`):
   * SQLite database at `C:\ProgramData\TinySocs\Assistant\threat_cache.db`
   * Schema: `ioc_type` (ip/domain/hash), `ioc_value`, `provider`, `result_json`, `cached_at`, `ttl_seconds`
   * TTL: 24 hours for IP lookups, 7 days for domain/hash lookups (configurable)
   * Cache hit returns stored result without API call
   * Background cleanup of expired entries (daily)
   * Size limit: 100K entries, LRU eviction

3. Enrichment pipeline (expanded `enrich.py`):
   * `enrich_alert(alert_doc)` → extracts source IPs, destination IPs, domains, file hashes from alert fields
   * Runs enabled providers in parallel (asyncio.gather with timeout)
   * Merges results into `alert.enrichment` field:
     ```json
     {
       "enrichment": {
         "source_ip": {
           "abuseipdb": {"score": 87, "reports": 47, "country": "RU", "isp": "..."},
           "otx": {"pulses": 3, "reputation": -2},
           "greynoise": {"classification": "malicious", "actor": "...", "tags": ["scanner"]}
         },
         "threat_level": "high"
       }
     }
     ```
   * Composite `threat_level` calculation: high (any provider reports malicious + score > 75), medium (suspicious or score 25-75), low (unknown or score < 25), none (all providers report clean)
   * Enrichment runs asynchronously — alert is written immediately, enrichment updates the document when results arrive

4. Dashboard integration:
   * Alert cards: threat badge (red/orange/yellow/green shield icon) next to source IP when enrichment data exists
   * Click badge → popover with provider details (reputation score, report count, country, ISP, tags)
   * Fleet health: "Threat Intel" status row showing configured providers, cache stats, API quota remaining
   * Settings panel: "Threat Intelligence" section with API key fields for each provider, test button, enable/disable toggle per provider
   * Event Explorer: IP addresses in results are clickable → inline enrichment lookup

5. Installer integration:
   * New "Threat Intelligence (Optional)" wizard page after notifications
   * Text fields for API key entry (AbuseIPDB, OTX, GreyNoise)
   * "Skip" option (default) — works without any keys, just no enrichment
   * Keys stored in `assistant.env` alongside LLM API keys

6. LLM context enhancement:
   * When the AI assistant receives an alert to explain, enrichment data is included in the context
   * "This alert involves IP 203.0.113.5, which AbuseIPDB reports as 87% malicious with 47 abuse reports from Russia (ISP: Evil Corp Hosting). GreyNoise classifies it as a known scanner."
   * The assistant continues to suggest remediation commands as copy-paste guidance — enrichment makes those suggestions better informed

Acceptance:
* Configure AbuseIPDB key → alert fires for brute-force from external IP → alert card shows red threat badge → click shows "87/100 confidence, 47 reports, RU"
* No API keys configured → alerts display normally with no enrichment (no errors)
* Same IP queried twice within 24h → second query hits cache (no API call, verify via cache stats)
* Rate limit exceeded on AbuseIPDB → provider skipped gracefully → other providers still return results
* AI assistant asked "what do you know about this alert?" → response includes threat intel context
* `python -m tinysocs.agent.threat_intel --ip 1.2.3.4` → CLI enrichment lookup for testing
* Settings → Threat Intelligence → Test button → shows "AbuseIPDB: OK (847/1000 daily quota remaining)"


M1 — Dashboard Widget Collapsibility

Goal: Every dashboard card should be vertically collapsible with a click on the header. Cards are expanded (uncollapsed) by default. This reduces scrolling on the operator's main view and lets them focus on the widgets they care about.

Current State
* Event Explorer is the only widget with collapse/expand — it uses a `.collapse-chevron` + `max-height` transition pattern added in Phase 14
* Event Explorer is collapsed by default (opposite of what we want for all other widgets)
* The remaining 7 cards (Alert Summary, Alert Timeline, Fired Detections, Fleet Health, Alert Rules, Compliance Coverage, Actions Queue) have no collapse capability
* All cards share the same `.card` + `.card-header-sticky` structure — headers are consistent
* The Host Event Timeline card is a special case: it's hidden entirely via `display:none` and shown on demand, not a persistent collapsible card
* The AI Assistant right panel has its own separate collapse mechanism (panel slides off-screen)
* No localStorage persistence for collapse state

Proposed Changes

Files:
* `src/tinysocs/api/dashboard.py` — CSS changes, HTML header changes on all cards, new JS collapse functions, localStorage persistence

Approach:

The existing Event Explorer collapse pattern (`.collapse-chevron`, `max-height` transition, `toggleExplorerCollapse()`) is already generic CSS. The implementation generalises this pattern to all cards.

Deliverables:

1. Generalised CSS:
   * New `.card-body` class replacing per-widget body divs:
     ```css
     .card-body { overflow: hidden; transition: max-height 0.25s ease; }
     .card-body.collapsed { max-height: 0 !important; padding: 0; }
     .card-body:not(.collapsed) { max-height: 4000px; }
     ```
   * The existing `.collapse-chevron` and `.collapse-chevron.collapsed` CSS is already generic — reuse as-is
   * Ensure `.card-header-sticky` always uses `display:flex; align-items:center; gap:4px` so the chevron fits naturally next to the `<h2>`

2. HTML changes on every card header:
   * Add chevron span before the `<h2>` in each `.card-header-sticky`:
     ```html
     <div class="card-header-sticky" style="display:flex;align-items:center;gap:4px">
       <span class="collapse-chevron" onclick="toggleCardCollapse('summary')" id="chevron-summary">▼</span>
       <h2 style="margin:0;cursor:pointer;flex:1" onclick="toggleCardCollapse('summary')">Alert Summary</h2>
       <!-- any existing controls (selects, buttons) stay here -->
     </div>
     <div class="card-body" id="body-summary">
       <!-- existing content -->
     </div>
     ```
   * Chevron starts WITHOUT `.collapsed` class (expanded by default)
   * Card body starts WITHOUT `.collapsed` class (visible by default)
   * The Event Explorer changes to match the new pattern — expanded by default like all others (reverting Phase 14's collapsed-by-default behaviour since this is now uniform)

3. Widget IDs for collapse state tracking:

   | Widget | Collapse ID | Notes |
   |--------|------------|-------|
   | Alert Summary | `summary` | Half-width card |
   | Alert Timeline | `timeline` | Half-width card |
   | Fired Detections | `detections` | Full-width, has status filter dropdown in header |
   | Fleet Health | `fleet` | Full-width |
   | Event Explorer | `explorer` | Full-width, has Schema button in header — refactored to use generic pattern |
   | Alert Rules | `rules` | Full-width, has filter dropdown + buttons in header |
   | Compliance Coverage | `compliance` | Full-width, has framework/hours/status dropdowns + download link in header |

   * Host Event Timeline (`hostTimelineCard`) is excluded — it's a transient card shown/hidden by JS, not a persistent collapsible widget
   * AI Assistant right panel is excluded — it has its own distinct slide-out mechanism

4. JavaScript:
   * `toggleCardCollapse(id)` — generic function replacing `toggleExplorerCollapse()`:
     ```javascript
     function toggleCardCollapse(id) {
       const body = document.getElementById('body-' + id);
       const chevron = document.getElementById('chevron-' + id);
       if (!body || !chevron) return;
       body.classList.toggle('collapsed');
       chevron.classList.toggle('collapsed');
       // Persist to localStorage
       const collapsed = JSON.parse(localStorage.getItem('tinysocs_collapsed') || '{}');
       collapsed[id] = body.classList.contains('collapsed');
       localStorage.setItem('tinysocs_collapsed', JSON.stringify(collapsed));
     }
     ```
   * `restoreCollapseState()` — called on page load, reads localStorage and applies saved collapse state:
     ```javascript
     function restoreCollapseState() {
       const collapsed = JSON.parse(localStorage.getItem('tinysocs_collapsed') || '{}');
       for (const [id, isCollapsed] of Object.entries(collapsed)) {
         if (isCollapsed) {
           const body = document.getElementById('body-' + id);
           const chevron = document.getElementById('chevron-' + id);
           if (body) body.classList.add('collapsed');
           if (chevron) chevron.classList.add('collapsed');
         }
       }
     }
     ```
   * `ensureCardExpanded(id)` — generic version of `_ensureExplorerExpanded()`, called by data-loading functions that need their card visible:
     ```javascript
     function ensureCardExpanded(id) {
       const body = document.getElementById('body-' + id);
       const chevron = document.getElementById('chevron-' + id);
       if (body && body.classList.contains('collapsed')) {
         body.classList.remove('collapsed');
         if (chevron) chevron.classList.remove('collapsed');
         // Update localStorage
         const collapsed = JSON.parse(localStorage.getItem('tinysocs_collapsed') || '{}');
         collapsed[id] = false;
         localStorage.setItem('tinysocs_collapsed', JSON.stringify(collapsed));
       }
     }
     ```
   * Update existing callers of `_ensureExplorerExpanded()` (in `loadEvents`, `openHostTimeline`, `toggleFleetDetail`) to use `ensureCardExpanded('explorer')` instead
   * Remove the old `toggleExplorerCollapse()` and `_ensureExplorerExpanded()` functions

5. Edge cases:
   * Header controls (dropdowns, buttons) remain clickable and do not trigger collapse — only the chevron and `<h2>` text trigger it
   * Half-width cards (Alert Summary, Alert Timeline) collapse independently
   * When a card is collapsed, its data-refresh functions still run (so data is fresh when the user expands) — only the visual display is hidden
   * The `max-height: 4000px` value is generous enough for all card content including paginated tables

Acceptance:
* Load dashboard → all 7 cards expanded with visible chevrons (▼ pointing down)
* Click any card header or chevron → card body smoothly collapses (0.25s transition) → chevron rotates to point right
* Click again → card expands back → chevron points down
* Collapse 3 cards → refresh page → same 3 cards still collapsed (localStorage persistence)
* Collapse Fleet Health → an action triggers `ensureCardExpanded('fleet')` → Fleet Health auto-expands
* Event Explorer no longer starts collapsed (consistent with all other cards)
* Header controls (status filter dropdown on Fired Detections, framework dropdown on Compliance) remain functional and don't trigger collapse
* AI Assistant panel and Host Event Timeline unaffected


M2 — File Integrity Monitoring (FIM)

Goal: Monitor critical system files and directories for changes. FIM is a compliance requirement across NIST CSF, HIPAA, and PCI-DSS, and a high-value detection capability for ransomware and APT activity.

Current State
* No FIM capability anywhere in the codebase
* The C# agent has a clean `IInput` interface — FIM can be implemented as a new input type
* Sysmon Event 11 (FileCreate) monitors file creation in Startup/Temp but doesn't cover modifications or deletions
* Compliance frameworks reference FIM but currently map to "GAP" or "PARTIAL"

Proposed Changes

Files:
* `src/TinySocs.Agent/Inputs/FileIntegrityInput.cs` (new) — FIM input that monitors configured paths using `FileSystemWatcher` + periodic hash verification
* `src/TinySocs.Agent/Inputs/InputFactory.cs` — Add `type: fim` input registration
* `src/TinySocs.Agent/Configuration/FimConfig.cs` (new) — FIM-specific config model
* `config/agent-config.example.yml` — Add FIM input configuration section
* `config/fim-baseline.example.yml` (new) — Example baseline paths and expected hashes
* `packaging/detection/rules.yml` — New FIM detection rules (TS-110 through TS-115)
* `src/tinysocs/agent/detections/rules.yaml` — Python-side FIM rules
* `src/tinysocs/reporting/frameworks/nist_csf.yaml` — Update FIM control mappings
* `src/tinysocs/reporting/frameworks/hipaa.yaml` — Update FIM control mappings
* `src/tinysocs/reporting/frameworks/pci_dss.yaml` — Update FIM control mappings
* `src/tinysocs/api/dashboard.py` — FIM status widget in fleet health
* `tests/test_fim_rules.py` (new) — Python-side FIM rule tests

Architecture:

```
FileIntegrityInput (C# agent)
    ├── FileSystemWatcher (real-time change notification)
    │   └── On change → compute SHA-256 → compare to baseline → emit event
    ├── Periodic scan (every 15 minutes, configurable)
    │   └── Walk monitored paths → hash each file → diff against baseline
    └── Baseline management
        ├── Initial scan → store hashes in baseline.json
        └── Operator can re-baseline from dashboard or CLI

FIM Event → standard AgentEvent envelope
    → channel: "TinySocs-FIM"
    → event_id: 1001 (created), 1002 (modified), 1003 (deleted), 1004 (permission changed)
    → body: file_path, hash_before, hash_after, change_type, file_size, modified_by (if available)
    → Ships to tinysocs-winlog-* like any other event
    → C# detection engine evaluates FIM rules
```

Deliverables:

1. FIM input (`FileIntegrityInput.cs`):
   * Uses `FileSystemWatcher` for real-time change detection (Created, Changed, Deleted, Renamed events)
   * Periodic full scan as safety net (FileSystemWatcher can miss events under high load)
   * SHA-256 hashing for change detection (only hashes files under configurable size limit, default 50MB)
   * Baseline stored at `C:\ProgramData\TinySocs\Agent\fim-baseline.json`
   * On first run or re-baseline: scans all monitored paths, stores hashes, emits no alerts
   * On subsequent runs: compares current hashes to baseline, emits events for differences
   * Monitored paths configurable via agent config:
     ```yaml
     inputs:
       - type: fim
         paths:
           - "C:\\Windows\\System32\\drivers\\etc\\hosts"
           - "C:\\Windows\\System32\\config\\*"
           - "C:\\Program Files\\**\\*.exe"
           - "C:\\ProgramData\\TinySocs\\**\\*.yml"
         exclude:
           - "**\\*.log"
           - "**\\*.tmp"
         scan_interval_minutes: 15
         max_file_size_mb: 50
     ```
   * Default monitored paths (opinionated, security-focused):
     * `C:\Windows\System32\drivers\etc\hosts` — DNS hijacking
     * `C:\Windows\System32\config\SAM` — credential database
     * `C:\Windows\System32\GroupPolicy\**` — GPO tampering
     * `C:\ProgramData\TinySocs\**\*.yml` — TinySocs config tampering
     * `C:\Program Files\**\*.exe` — binary replacement

2. FIM detection rules (6 new rules):
   * `TS-110` — Critical file modified: hosts file, SAM database, or boot config changed
   * `TS-111` — Executable replaced: .exe or .dll in Program Files modified (not during known update windows)
   * `TS-112` — TinySocs config tampered: any TinySocs YAML/config file modified outside of installer
   * `TS-113` — Mass file modification: >20 files modified in 60 seconds (ransomware indicator)
   * `TS-114` — Sensitive file deleted: SAM, SECURITY, SYSTEM hive deletion attempt
   * `TS-115` — Permission change on monitored path: ACL modification on critical files

3. Baseline management:
   * Auto-baseline on first run (no alerts for existing state)
   * Re-baseline CLI: `TinySocs.Agent.exe --fim-rebaseline` (updates baseline without generating alerts)
   * Re-baseline API: `POST /api/fim/rebaseline` from dashboard
   * Baseline export/import for golden image deployments

4. Dashboard integration:
   * Fleet Health: "FIM Status" row per host — last scan time, files monitored count, changes detected (24h)
   * Alert cards for FIM events: show file path, change type, hash diff
   * FIM-specific alerts tagged with `source: fim` for easy filtering

5. Compliance framework updates:
   * NIST CSF PR.DS-6 (Integrity checking) → `TS-110`, `TS-111`, `TS-112` (upgrade from GAP to COVERED)
   * HIPAA §164.312(c)(2) (Integrity controls) → FIM evidence (upgrade from PARTIAL to COVERED)
   * PCI-DSS 11.5 (File integrity monitoring) → all TS-11x rules (upgrade from GAP to COVERED)

Acceptance:
* Install with FIM enabled → baseline scan completes → no false alerts
* Modify `C:\Windows\System32\drivers\etc\hosts` → alert fires within 60 seconds → alert card shows old hash vs new hash
* Create 30 files rapidly in monitored directory → TS-113 (mass modification) fires
* Dashboard fleet health → FIM Status shows "247 files monitored, last scan 3 min ago, 0 changes (24h)"
* Compliance report (PCI-DSS) → Requirement 11.5 shows COVERED with FIM evidence
* `TinySocs.Agent.exe --fim-rebaseline` → baseline updated → subsequent changes detected against new baseline


M3 — MITRE ATT&CK Native Integration

Goal: Every detection rule carries machine-readable MITRE ATT&CK annotations. The dashboard displays a coverage matrix. An ATT&CK Navigator layer is auto-generated and downloadable.

Current State
* 34 C# detection rules with MITRE technique names in comments/descriptions only
* `tests/atomic-tests.yaml` maps 12 Atomic Red Team techniques to TinySocs rules (external mapping)
* Python rules in `rules.yaml` have no MITRE annotations
* No ATT&CK Navigator layer JSON (Phase 14 deferred this)
* No dashboard coverage visualisation
* `docs/detection-coverage.md` is manually maintained

Proposed Changes

Files:
* `packaging/detection/rules.yml` — Add `mitre` field to every rule (technique_id, tactic, technique_name)
* `src/tinysocs/agent/detections/rules.yaml` — Add `mitre` field to Python rules
* `src/tinysocs/reporting/mitre_coverage.py` (new) — ATT&CK coverage calculator and Navigator layer generator
* `src/tinysocs/api/dashboard.py` — MITRE ATT&CK coverage widget with tactic heatmap, technique drill-down, Navigator layer download
* `tests/test_mitre_coverage.py` (new) — Validate all rules have MITRE annotations, Navigator layer is valid JSON
* `docs/detection-coverage.md` — Auto-generated from rule annotations

Deliverables:

1. Rule annotations — add `mitre` field to all 34 C# rules and all Python rules:
   ```yaml
   - id: TS-001
     name: auth_failed_burst
     mitre:
       technique_id: T1110.001
       technique_name: "Brute Force: Password Guessing"
       tactic: credential-access
     # ... existing fields
   ```
   * Plus the 6 new FIM rules from M2 (TS-110 through TS-115)
   * Mapping table:
     * TS-001, TS-002, TS-071 → T1110 (Brute Force) → Credential Access
     * TS-010 → T1136.001 (Create Account: Local) → Persistence
     * TS-020 → T1053.005 (Scheduled Task) → Persistence
     * TS-030, TS-082 → T1059.001 (PowerShell) → Execution
     * TS-040, TS-050 → T1106 (Native API) → Execution
     * TS-060, TS-061 → T1003.001 (LSASS Memory) → Credential Access
     * TS-062 → T1003.003 (NTDS.dit) → Credential Access
     * TS-070, TS-072 → T1021.002 (SMB/Admin Shares) → Lateral Movement
     * TS-080 → T1070.001 (Clear Event Logs) → Defence Evasion
     * TS-081 → T1562.001 (Disable Defender) → Defence Evasion
     * TS-083 → T1070.006 (Timestomp) → Defence Evasion
     * TS-090 → T1543.003 (Windows Service) → Persistence
     * TS-091 → T1547.001 (Registry Run Keys) → Persistence
     * TS-092 → T1547.001 (Startup Folder) → Persistence
     * TS-100 → T1071 (Application Layer Protocol) → Command and Control
     * TS-101 → T1048 (Exfiltration Over Alternative Protocol) → Exfiltration
     * TS-110..115 → T1565.001 (Stored Data Manipulation), T1485 (Data Destruction) → Impact
     * lolbin_execs → T1218 (System Binary Proxy Execution) → Defence Evasion

2. MITRE coverage calculator (`mitre_coverage.py`):
   * Reads all rule files, extracts `mitre` annotations
   * Calculates: techniques covered, tactics covered, coverage percentage (vs full ATT&CK Enterprise matrix)
   * Generates per-tactic summary: "Credential Access: 5/20 techniques (25%)"
   * Identifies gaps: techniques with zero rule coverage

3. ATT&CK Navigator layer generator:
   * Produces ATT&CK Navigator JSON (v4.x format) compatible with https://mitre-attack.github.io/attack-navigator/
   * Colour coding: green = detected (rule exists + tested), yellow = rule exists (not tested), grey = no coverage
   * Metadata: layer name "TinySocs v0.8 Detection Coverage", description, domain "enterprise-attack"
   * CLI: `python -m tinysocs.reporting.mitre_coverage --output navigator-layer.json`
   * Dashboard: "Download Navigator Layer" button

4. Dashboard MITRE widget:
   * New "MITRE ATT&CK Coverage" card on dashboard (collapsible like all other cards per M1)
   * Tactic columns (Reconnaissance → Impact) with technique count per tactic
   * Colour-coded heatmap: dark green (detected in Atomic test), light green (rule exists), grey (no coverage)
   * Click technique → shows which TinySocs rules detect it, last alert timestamp, Atomic test result
   * Overall coverage stat: "X/Y techniques covered across Z tactics"
   * "Download Navigator Layer" button → JSON file download

5. Detection expansion (4-6 new rules to fill critical gaps identified in Phase 14 Atomic testing):
   * Review `detection-efficacy.md` results from Phase 14 M3
   * Add rules for any MISSED techniques with available event sources
   * Target: cover at least 2 additional MITRE tactics not currently covered
   * Candidates (based on gap analysis):
     * T1105 (Ingress Tool Transfer) — large file download detection via Sysmon Event 3
     * T1055 (Process Injection) — Sysmon Event 8 (CreateRemoteThread) monitoring
     * T1087.001 (Account Discovery: Local) — net user enumeration burst
     * T1018 (Remote System Discovery) — ping sweep / net view burst
     * T1027 (Obfuscated Files) — high-entropy PowerShell ScriptBlock detection

6. Auto-generated detection-coverage.md:
   * CLI: `python -m tinysocs.reporting.mitre_coverage --output-md docs/detection-coverage.md`
   * Replaces manually-maintained file with auto-generated version
   * Per-tactic table with technique ID, name, TinySocs rule IDs, status (detected/rule-only/gap)
   * Run as part of CI to keep docs in sync

Acceptance:
* Every rule in `rules.yml` and `rules.yaml` has a `mitre` field → `test_mitre_coverage.py` validates
* `python -m tinysocs.reporting.mitre_coverage` → prints coverage summary to stdout
* `python -m tinysocs.reporting.mitre_coverage --output layer.json` → valid ATT&CK Navigator JSON → import into Navigator web tool → renders correctly with TinySocs colour coding
* Dashboard → MITRE ATT&CK Coverage widget → tactic heatmap visible → click a technique → shows rule details
* CI runs `test_mitre_coverage.py` → fails if any rule is missing `mitre` field
* At least 44 rules total (34 existing + 6 FIM from M2 + minimum 4 new) covering 10+ MITRE techniques


M4 — Atomic Red Team Detection Validation

Goal: Execute the Atomic Red Team test infrastructure built in Phase 14 against a live TinySocs deployment. Populate the detection-efficacy.md with real results. Tune rules based on findings. Generate the ATT&CK Navigator layer with tested-vs-untested colour coding. This is the evidence that a buyer, MSSP, or insurer needs to see.

Current State
* `tests/Test-AtomicDetection.ps1` exists — installs Invoke-AtomicRedTeam, runs 12 mapped techniques, queries OpenSearch for alerts, reports DETECTED/MISSED/SKIPPED/ERROR
* `tests/atomic-tests.yaml` maps 12 MITRE techniques → TinySocs rule IDs → Sysmon requirement flags
* `docs/detection-efficacy.md` is a template — "actual efficacy numbers are populated when Test-AtomicDetection.ps1 is run against a live deployment" (Phase 14 summary)
* ATT&CK Navigator layer JSON was not generated (Phase 14 explicitly deferred)
* No rule tuning has been done based on real attack data
* No false positive baseline has been measured

Proposed Changes

Files:
* `tests/Test-AtomicDetection.ps1` — Extend with new technique mappings for Phase 15 rules (FIM, new M3 rules), add false positive tracking, improve structured JSON output
* `tests/atomic-tests.yaml` — Add mappings for new rules: TS-110 through TS-115 (FIM), TS-120 (version drift), and 4-6 new M3 rules
* `docs/detection-efficacy.md` — Populated with real results (no longer a template)
* `src/tinysocs/agent/detections/rules.yaml` — Rule tuning based on MISSED results
* `packaging/detection/rules.yml` — C# rule tuning based on MISSED results
* `tests/atomic-results.json` (new) — Machine-readable test results for CI consumption and Navigator layer generation

Approach:

1. **Pre-flight**: Clean Windows VM with TinySocs installed (TinyBox role), Sysmon enabled, FIM enabled, all Phase 15 rules deployed. Allow 5-minute baseline stabilisation.

2. **Execute existing 12 technique tests**:
   | Technique | Name | Expected Rules | Sysmon Required |
   |-----------|------|---------------|-----------------|
   | T1110.001 | Brute Force | TS-001, auth_failed_burst | No |
   | T1003.001 | LSASS Memory | TS-060, lsass_access | Yes |
   | T1059.001 | PowerShell | TS-030, suspicious_powershell | No |
   | T1053.005 | Scheduled Task | TS-020, scheduled_task_creation | No |
   | T1547.001 | Registry Run Keys | TS-091, registry_run_key | Yes |
   | T1543.003 | Windows Service | TS-090, service_install_suspicious | No |
   | T1070.001 | Clear Event Logs | TS-080, event_log_cleared | No |
   | T1562.001 | Disable Defender | TS-081, defender_tamper | No |
   | T1021.002 | SMB Admin Shares | TS-070, psexec_usage | No |
   | T1136.001 | Create Local Account | TS-010, local_admin_create | No |
   | T1218.011 | Rundll32 | lolbin_execs | No |
   | T1003.003 | NTDS.dit | TS-062, ntds_dit_access | No |

3. **Execute new Phase 15 technique tests** (added to atomic-tests.yaml):
   | Technique | Name | Expected Rules | Category |
   |-----------|------|---------------|----------|
   | T1565.001 | Stored Data Manipulation | TS-110 (hosts file modify) | FIM / Impact |
   | T1485 | Data Destruction | TS-114 (sensitive file delete) | FIM / Impact |
   | T1486 | Data Encrypted for Impact | TS-113 (mass file modification) | FIM / Impact |
   | T1055 | Process Injection | New M3 rule (if implemented) | Execution |
   | T1087.001 | Account Discovery | New M3 rule (if implemented) | Discovery |

4. **For each test**:
   * Run Atomic test with cleanup
   * Wait for TinySocs ingestion window (90s, increased from Phase 14's 60s to account for FIM scan interval)
   * Query `tinysocs-alerts-*` for expected `rule_id`
   * Record: DETECTED / MISSED / SKIPPED / ERROR
   * Record detection latency (time from test execution to alert timestamp)
   * Record any false positives generated during the test window that don't correspond to the test

5. **Rule tuning based on findings**:
   * For each MISSED technique: diagnose root cause (missing event source? threshold too high? wrong field name? event not generated?)
   * Adjust rule thresholds, field patterns, or event ID filters
   * Re-run the specific test to confirm detection
   * Document the change in detection-efficacy.md

6. **False positive baseline**:
   * After all tests complete, let the system run for 30 minutes with no attack activity
   * Record any alerts that fire during idle period
   * Document FP rate per rule in detection-efficacy.md
   * Tune rules that generate FPs at rest (raise thresholds, add exclusions)

Deliverables:

1. `atomic-results.json` — Machine-readable test results:
   ```json
   {
     "run_date": "2025-07-15T14:30:00Z",
     "tinysocs_version": "0.8.0",
     "sysmon_installed": true,
     "fim_enabled": true,
     "results": [
       {
         "technique_id": "T1110.001",
         "technique_name": "Brute Force",
         "expected_rules": ["TS-001"],
         "status": "DETECTED",
         "detection_latency_seconds": 12,
         "false_positives": 0,
         "notes": ""
       }
     ],
     "summary": {
       "total": 17,
       "detected": 14,
       "missed": 2,
       "skipped": 1,
       "error": 0,
       "detection_rate": 0.875,
       "avg_latency_seconds": 18.3
     }
   }
   ```

2. Populated `detection-efficacy.md`:
   * Summary: "X/Y techniques detected (Z%)" with Sysmon and FIM enabled
   * Per-technique table: technique ID, name, status, detection latency, rule ID, notes
   * False positive analysis: per-rule FP count during idle period
   * Gap analysis: techniques with no coverage, recommended additions for Phase 16
   * Rule tuning log: what was changed and why
   * Comparison: detection rate with Sysmon vs without Sysmon

3. ATT&CK Navigator layer JSON (the deferred Phase 14 deliverable):
   * Generated by `mitre_coverage.py` (from M3) using `atomic-results.json` as input
   * Three-colour scheme: dark green = detected in Atomic test, light green = rule exists but untested, grey = no coverage
   * Downloadable from dashboard and via CLI
   * Importable into https://mitre-attack.github.io/attack-navigator/

4. Updated `Test-AtomicDetection.ps1`:
   * Extended with new technique mappings (FIM techniques, new M3 rules)
   * Structured JSON output (`atomic-results.json`) in addition to existing markdown output
   * Detection latency measurement per test
   * False positive window after test suite completes
   * `--rerun-missed` flag to re-run only previously missed techniques after rule tuning
   * Exit code: 0 if detection rate >= 80%, 1 otherwise (CI-friendly)

5. Rule tuning:
   * All MISSED techniques diagnosed and fixed where possible
   * Target: >= 85% detection rate with Sysmon + FIM enabled
   * Changes pass existing `test_detection_rules.py` (no regressions)

Acceptance:
* `.\tests\Test-AtomicDetection.ps1` runs end-to-end on a test VM without manual intervention
* `atomic-results.json` written with structured results for all tested techniques
* Detection rate >= 85% of tested techniques (with Sysmon + FIM enabled)
* Every MISSED technique documented with root cause explanation in detection-efficacy.md
* False positive rate documented (target: < 5 FPs during 30-minute idle window)
* Average detection latency documented (target: < 60 seconds for non-FIM rules)
* ATT&CK Navigator layer JSON generated and importable
* Rule tuning changes pass `test_detection_rules.py`
* `detection-efficacy.md` is no longer a template — contains real data


M5 — Agent Version Awareness & Update Notifications

Goal: Operators and MSSPs need to know when agents are outdated. Build the version awareness layer that makes agent drift visible, without implementing the full auto-update delivery mechanism yet (that's Phase 16).

Current State
* C# agent writes its assembly version to the heartbeat index (field: `agent_version`)
* Fleet health widget displays agent version per host
* No comparison against a "latest known" version
* No notification when agents are outdated
* No version manifest or update check endpoint
* `pyproject.toml` version (0.7.0) and agent assembly version are managed separately

Proposed Changes

Files:
* `src/tinysocs/api/dashboard.py` — Version drift detection in fleet health, update notification banner
* `src/tinysocs/reporting/version_check.py` (new) — Version comparison logic, optional remote version check
* `config/version-manifest.json` (new) — Local version manifest (current version, minimum compatible version, changelog URL)
* `packaging/detection/rules.yml` — New rule: TS-120 (agent version drift alert)
* `modules/TinySocs.Installer.psm1` — Write version manifest during install
* `tests/test_version_check.py` (new) — Version comparison and manifest validation tests

Deliverables:

1. Version manifest (`version-manifest.json`):
   * Written to `C:\ProgramData\TinySocs\version-manifest.json` during install
   * Contains:
     ```json
     {
       "current_version": "0.8.0",
       "minimum_compatible": "0.7.0",
       "installed_at": "2025-06-15T10:30:00Z",
       "components": {
         "agent": "0.8.0",
         "assistant": "0.8.0",
         "opensearch": "2.13.0",
         "sysmon": "15.15"
       },
       "changelog_url": "https://github.com/user/tinysocs/releases"
     }
     ```
   * Installer updates this file on every install/upgrade

2. Fleet health version drift (`dashboard.py`):
   * Read version manifest to get "expected" version
   * Compare each agent's heartbeat `agent_version` against expected
   * Colour coding: green (matches), yellow (minor drift, e.g. 0.7.x vs 0.8.0), red (major drift or unknown)
   * Fleet health widget: "Version" column with colour-coded badges
   * Summary stat: "3/5 agents up to date, 2 outdated"

3. Version drift detection rule:
   * `TS-120` — Agent version drift: fires when any agent heartbeat reports a version older than `minimum_compatible` from manifest
   * Evaluates on heartbeat events (channel: heartbeat)
   * Severity: medium (outdated agents are a security risk but not an active threat)

4. Dashboard update banner:
   * When version drift is detected, show a non-dismissible info banner at top of dashboard:
     "2 agents are running outdated versions. See Fleet Health for details."
   * Link to Fleet Health widget with pre-filtered "outdated" view

5. Optional remote version check:
   * `version_check.py`: can check a configurable URL for latest version info
   * Disabled by default (air-gapped deployments should work fine)
   * When enabled: checks once per day, compares against local manifest
   * If newer version available: dashboard shows "TinySocs X.Y.Z available" notification
   * No auto-download — just awareness (full auto-update is Phase 16)

6. Version sync:
   * Ensure `pyproject.toml` version, C# assembly version, and version manifest all stay in sync
   * Add CI check: `test_version_check.py` verifies version consistency across all three sources

Acceptance:
* Clean install → version manifest written with correct versions → fleet health shows all agents as "current" (green)
* Manually downgrade one agent's version in heartbeat → fleet health shows it as "outdated" (yellow/red)
* TS-120 fires when outdated agent detected → alert card shows version drift details
* Dashboard banner appears when any agent is outdated
* Remote version check disabled by default → no outbound network calls
* `python -m tinysocs.reporting.version_check` → prints version status summary


M6 — Documentation Update (Phase 15)

Goal: Update all existing docs to reflect Phase 15 changes.

Files:
* `docs/getting-started.md` — Update for threat intel setup, FIM, collapsible widgets
* `docs/operator-runbook.md` — Threat intel provider config, FIM baseline management, MITRE coverage generation, Atomic Red Team execution procedure
* `docs/troubleshooting.md` — Threat intel API errors, FIM false positives, version drift, widget collapse state reset
* `docs/detection-coverage.md` — Auto-generated from MITRE coverage tool (M3)
* `docs/detection-efficacy.md` — Populated with real Atomic Red Team results (M4)
* `README.md` — Update feature list with threat intel, FIM, MITRE coverage, version awareness, collapsible widgets, detection efficacy
* `docs/pilot-guide.md` — Update for new features, revised first-24-hours expectations
* `docs/mssp-guide.md` — Version drift monitoring across sites, threat intel API key management
* `docs/phase-15-summary.md` (new) — Phase summary in standard format

Acceptance:
* Getting started covers threat intel API key setup and FIM configuration
* Runbook covers all new operational procedures including Atomic Red Team test execution
* Troubleshooting covers 4+ new items (one per milestone)
* README feature list current with Phase 15 additions
* MSSP guide updated for version awareness
* detection-coverage.md is now auto-generated, not manually maintained
* detection-efficacy.md contains real test data, not a template


Milestone Order

| # | Milestone | Depends On | Estimated Effort |
|---|-----------|------------|-----------------|
| M0 | Threat Intelligence Enrichment | None | 2-3 days |
| M1 | Dashboard Widget Collapsibility | None | 3-4 hours |
| M2 | File Integrity Monitoring | None | 1-2 days |
| M3 | MITRE ATT&CK Native Integration | M2 (for FIM rule annotations) | 1-2 days |
| M4 | Atomic Red Team Validation | M2 + M3 (new rules must exist and be annotated before testing) | 1-2 days |
| M5 | Agent Version Awareness | None | 4-6 hours |
| M6 | Documentation Update | M0-M5 (for accuracy) | 3-4 hours |

M0, M1, M2, and M5 are independent — can be done in parallel.
M3 depends on M2 (FIM rules need MITRE annotations).
M4 depends on M2 + M3 (all new rules must exist and be annotated before adversary testing).
M6 comes last.


Verification (End-to-End)

After Phase 15, on a clean install:

```powershell
# Install with Sysmon + FIM enabled, threat intel API key configured
# → Sysmon running, FIM baseline created, threat intel providers connected

# Health: 16/16 PASS + FIM status + threat intel status
Test-TinySocsHealth
# → Check 15: [PASS] Sysmon Service
# → Check 16: [PASS] Dashboard TLS
# → FIM: 247 files baselined, 0 changes

# Dashboard: all widgets expanded with collapse chevrons
Start-Process "https://localhost:8090/dashboard"
# → 8+ cards visible, each with ▼ chevron in header
# → Click any chevron → card collapses smoothly
# → Refresh page → collapsed cards stay collapsed (localStorage)

# Threat intel: enrich an IP
python -m tinysocs.agent.threat_intel --ip 185.220.101.34
# → AbuseIPDB: 100/100, 892 reports, DE, Tor exit node
# → OTX: 15 pulses, known malicious
# → GreyNoise: malicious, tags: [tor, scanner]

# Trigger a brute-force alert from a known-bad IP
# → Alert fires → threat badge shows RED → enrichment details in popover
# → AI assistant explains alert with threat intel context
# → Assistant suggests remediation commands as copy-paste guidance

# FIM: modify hosts file
Add-Content C:\Windows\System32\drivers\etc\hosts "127.0.0.1 evil.com"
# → TS-110 fires within 60 seconds
# → Alert shows file path, change type, hash diff

# MITRE coverage
python -m tinysocs.reporting.mitre_coverage
# → "44 rules covering 20 techniques across 9 tactics"
# → Navigator layer downloadable from dashboard

# Atomic Red Team validation
.\tests\Test-AtomicDetection.ps1
# → 15/17 techniques DETECTED (≥85%)
# → atomic-results.json written with structured data
# → detection-efficacy.md populated with real numbers
# → ATT&CK Navigator layer coloured by test results

# Version awareness
# → Fleet health shows all agents as "current" (green)
# → Manually set one agent heartbeat to old version → yellow badge → TS-120 alert

# Compliance report with FIM coverage
python -m tinysocs.reporting.compliance_report --framework pci_dss --hours 720
# → Requirement 11.5: COVERED (was GAP in Phase 14)
```


What Phase 15 Explicitly Does NOT Cover

* **Response automation / execution**: TinySocs is read-only by design. It observes, detects, enriches, and advises. It never executes commands on hosts. The AI assistant suggests remediation as copy-paste guidance. Automated response execution is a security and liability risk that does not fit the product's trust model. This is a permanent architectural decision, not a deferral.
* **macOS/Linux collector**: The `IInput` interface is ready and the event schema can be extended, but implementing a cross-platform collector (syslog, macOS Unified Log) is a full phase of its own. Phase 16 scope.
* **Full auto-update delivery**: M5 builds version awareness and drift detection. The actual update delivery mechanism (version server, download, silent install, rollback) is Phase 16 scope.
* **Centralized management console**: Multi-site MSSP dashboard that aggregates alerts across deployments. Most valuable MSSP feature but a major undertaking. Phase 17 scope.
* **Dashboard SSO/RBAC**: Single-password auth with HTTPS and rate limiting is sufficient for pilot and small deployments. Enterprise IAM (LDAP, Azure AD, RBAC) is post-pilot scope.
* **Lightweight mode / SQLite backend**: Replacing OpenSearch with SQLite for very small deployments (1-5 machines) is a significant architectural change. Future scope.
* **Mobile push notifications**: Pushover/ntfy integration is a nice-to-have. Webhook + email covers the pilot use case.
