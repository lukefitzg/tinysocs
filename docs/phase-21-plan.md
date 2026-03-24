TinySocs Phase 21 Plan — Production Hardening
===============================================

Theme: "Lean, hardened, and operator-ready"


Context
-------

Phase 20 unified federation data into a single dashboard view, added certificate pinning for inter-node connections, centralised TLS into a dedicated module, and polished widget layouts. The product now supports two-machine federation with real-time cross-site aggregation, drill-through proxying, and site auto-registration with Hub approval. The installer handles both Hub and Site roles with TLS certificate generation, NSSM service registration, and firewall configuration.

But Phase 20 left operational gaps. The system generates too many false-positive alerts on idle Windows boxes because several detection rules have low thresholds (50 events in 5 minutes for PowerShell, process creation, and Sysmon) that fire on normal background activity. There is no way for an operator to configure data retention — indices grow indefinitely until disk fills. There is no storage visibility — an operator has no idea how much disk OpenSearch is consuming until it crashes. There is no emergency disk remediation — when disk fills, OpenSearch goes read-only and the system is dead until someone manually purges indices. The API has no rate limiting, no request body size limits, and no HEC (HTTP Event Collector) endpoint for custom log ingestion. The AI assistant has no privacy controls — it sends all event data to the configured LLM provider without consent. LLM model names are hardcoded, preventing operators from choosing their own model. The settings panel requires the master password for authentication, which is a security anti-pattern — an XSS or network sniff would capture the master credential. The codebase contains debug scripts, leaked credentials (kirk.pfx), stale log files, and no pre-commit hooks.

Phase 21 closes every one of these gaps. The result is a system that an operator can deploy, configure retention, monitor storage, receive HEC logs, manage API tokens, and trust that the AI assistant respects their privacy choices — all without touching a config file or command line.

Design principle — **harden what ships, remove what shouldn't**: Every change either removes an attack surface, adds an operational control, or fixes a deployment blocker. No new features that expand scope — only features that make the existing system production-safe.


M0 — Security Audit & Codebase Cleanup
----------------------------------------

**Goal:** Remove leaked credentials, debug scripts, stale data files, and dead code. Establish pre-commit hooks and centralise HMAC authentication. Add security test coverage.

**Current State (pre-Phase 21)**

- kirk.pfx (a PKCS#12 certificate bundle) is checked into the repository root — a leaked credential
- data/actions_queue.jsonl and logs/*.json contain runtime artifacts checked into version control
- 10 PowerShell debug/test scripts in scripts/ are development-only and should not ship (Debug-AlertDocs.ps1, Debug-DashboardAuth.ps1, Debug-DetectionEngine.ps1, Debug-FleetMapping.ps1, Fix-DashboardAuth.ps1, Pack-Repo.ps1, Send-BotAck.ps1, Send-BotExec.ps1, Stop-TinySocs.ps1, Test-Phase12.ps1)
- HMAC verification is duplicated across bot.py, bot_actions.py, node.py, and master.py with inconsistent implementations
- No pre-commit hooks — secrets can be committed without warning
- No security-focused test suite

**Proposed Changes**

Files:
- `.gitignore` — Expand to cover data/, logs/, *.pfx, *.p12, __pycache__, .env files
- `.pre-commit-config.yaml` — New: detect-secrets and trailing-whitespace hooks
- `kirk.pfx` — Delete
- `data/actions_queue.jsonl` — Delete
- `logs/` — Delete all tracked log files
- `scripts/` — Delete 10 debug/test scripts, clean up remaining scripts
- `src/tinysocs/api/auth.py` — New: centralised HMAC authentication module
- `src/tinysocs/api/bot.py` — Refactor to use auth.py
- `src/tinysocs/api/bot_actions.py` — Refactor to use auth.py
- `src/tinysocs/api/node.py` — Refactor to use auth.py
- `src/tinysocs/orchestrator/master.py` — Refactor to use auth.py
- `src/tinysocs/agent/config.py` — Remove hardcoded defaults, add validation
- `src/TinySocs.Agent/Detection/DetectionEngine.cs` — Clean up dead code paths
- `tests/test_security_auth.py` — New: comprehensive auth security tests
- `tests/test_e2e_phase12.py` — Update assertions for new auth patterns

**Deliverables**

1. **Leaked credential removal**: Delete kirk.pfx from repository. Expand .gitignore to prevent re-addition of *.pfx, *.p12, *.pem private keys, and .env files.

2. **Runtime artifact cleanup**: Delete data/actions_queue.jsonl (56 lines of queued bot actions), logs/ledger-health.json, logs/verify_ledger-*.json, logs/verify_ledger-*.raw.txt. Add data/ and logs/ to .gitignore.

3. **Debug script removal**: Delete 10 scripts totalling ~1,213 lines: Debug-AlertDocs.ps1 (97), Debug-DashboardAuth.ps1 (139), Debug-DetectionEngine.ps1 (232), Debug-FleetMapping.ps1 (63), Fix-DashboardAuth.ps1 (143), Pack-Repo.ps1 (59), Send-BotAck.ps1 (49), Send-BotExec.ps1 (96), Stop-TinySocs.ps1 (17), Test-Phase12.ps1 (315). Remove dangling references in Start-TinySocs-Agent.ps1 and Start-TinySocs-Node.ps1.

4. **Centralised HMAC authentication** (`src/tinysocs/api/auth.py`, new file, 169 lines): Three HMAC styles supported (pipe: "{ts}|{nonce}", dot: "{ts}.{nonce}", ts: "{ts}" only). Flexible verification tries all three formats. Replay protection via TTL-based dict cache with periodic garbage collection. Timing-safe comparison using hmac.compare_digest(). 5-minute replay window. Extracted from four separate implementations in bot.py, bot_actions.py, node.py, and master.py.

5. **Pre-commit hooks** (`.pre-commit-config.yaml`): detect-secrets for credential scanning, trailing-whitespace cleanup. Runs on every commit.

6. **Security test suite** (`tests/test_security_auth.py`, new file, 296 lines): Tests for HMAC verification across all three styles, replay detection, timing-safe comparison, nonce validation, expired timestamp rejection, and flexible mode acceptance.

**Acceptance**

- kirk.pfx no longer in repository
- `git ls-files data/ logs/` returns empty
- `git ls-files scripts/Debug-*` returns empty
- All HMAC verification in bot.py, bot_actions.py, node.py, master.py imports from auth.py
- pre-commit hooks configured and runnable
- 296-line security test suite passes


M1 — Detection Rule Tuning
----------------------------

**Goal:** Reduce false-positive alerts on idle Windows systems by raising thresholds, widening windows, and adding cooldown periods to noisy rules.

**Current State (pre-Phase 21)**

- Rules for PowerShell logging volume, rapid process creation, and Sysmon process flood all use threshold: 50 with window_minutes: 5
- On a normal Windows 10/11 box, background services (Windows Update, Defender, telemetry) routinely generate 50+ events in 5 minutes
- Result: idle boxes generate 10-20 false-positive alerts per day, drowning real detections
- No cooldown mechanism — once a rule fires, it fires again on the next detection cycle if the threshold is still exceeded
- The C# DetectionEngine.cs has no cooldown support

**Proposed Changes**

Files:
- `packaging/detection/rules.yml` — Adjust thresholds, windows, and add cooldown_minutes
- `src/TinySocs.Agent/Detection/DetectionEngine.cs` — Add cooldown support

**Deliverables**

1. **Threshold and window adjustments** for three high-noise rules:
   - `powershell_logging_volume`: threshold 50 -> 200, window 5min -> 10min, add cooldown_minutes: 30
   - `rapid_process_creation`: threshold 50 -> 200, window 5min -> 10min, add cooldown_minutes: 30
   - `sysmon_process_flood`: threshold 50 -> 200, window 5min -> 10min, add cooldown_minutes: 30

2. **Cooldown periods** added to six additional rules that fire on single-event triggers:
   - `new_local_account`, `new_service_installed`, `password_never_expires`, `defender_realtime_disabled`, `service_creation_via_sc`, `scheduled_task_created` — all get cooldown_minutes: 60

3. **DetectionEngine.cs cooldown support**: Read cooldown_minutes from rule YAML. After a rule fires, suppress re-firing for the cooldown period. Cooldown is per-rule, not per-host.

**Acceptance**

- Idle Windows box with only background services → zero false-positive alerts over 24 hours
- Active brute-force attack still triggers brute_force_password within 5 minutes
- Rule that fires at T=0 does not fire again until T=cooldown_minutes even if threshold is still exceeded
- All 15 rules in rules.yml parse without errors


M2 — Configurable Data Retention & Storage Monitoring
------------------------------------------------------

**Goal:** Let operators configure how long data is retained, see how much storage OpenSearch is consuming, and receive alerts when disk space is low — all without touching config files.

**Current State (pre-Phase 21)**

- OpenSearch indices grow indefinitely — no retention policy, no lifecycle management
- No visibility into disk usage or index sizes from the dashboard
- No alerting when disk fills — OpenSearch silently goes read-only
- Retention is not configurable at install time or runtime
- OpenSearch disk watermarks are at defaults (85%/90%/95%) which are too aggressive for small boxes

**Proposed Changes**

Files:
- `config/assistant.env` — New retention env vars
- `packaging/iss/Quickstart.iss` — Retention wizard page, OpenSearch watermark injection
- `src/tinysocs/api/dashboard.py` — Settings panel retention UI, Storage monitoring widget, disk alert generation
- `src/tinysocs/tinybox/opensearch_bootstrap.py` — ISM (Index State Management) policy creation
- `OpenSearch/config/opensearch.yml` — Disk watermark configuration

**Deliverables**

1. **Installer retention wizard page** (`Quickstart.iss`): New page asking "How many days should TinySocs keep data?" with dropdown: 30, 60, 90, 180, 365 days (default 90). Writes RETENTION_DAYS to assistant.env. Help text explains disk impact.

2. **OpenSearch disk watermark injection** (`Quickstart.iss` + `opensearch.yml`): Installer writes watermark settings to opensearch.yml: low=80%, high=88%, flood_stage=92% (relaxed from defaults to prevent premature read-only on small disks). Fixes em-dash character in YAML comment that caused OpenSearch keystore failure.

3. **ISM retention policies** (`opensearch_bootstrap.py`, +90 lines): On first boot, creates Index State Management policies for tinysocs-winlog-* and tinysocs-alerts-* indices. Policy transitions: hot (0 days) -> delete (RETENTION_DAYS). Rollover at 10GB or 1 day. Policies applied via index templates so new indices automatically get the lifecycle policy. Reads RETENTION_DAYS from environment (default 90).

4. **Settings panel retention UI** (`dashboard.py`): New "Data Retention" section in Settings tab. Shows current RETENTION_DAYS value. Dropdown to change retention (30/60/90/180/365 days). Save button updates assistant.env and re-applies ISM policies. Help text shows estimated disk usage per retention period.

5. **Storage monitoring widget** (`dashboard.py`, +413 lines): New widget on Overview tab showing:
   - Total disk usage (used/total with percentage bar)
   - Per-index breakdown: tinysocs-winlog-*, tinysocs-alerts-*, tinysocs-custom-* with document counts and sizes
   - OpenSearch cluster health (green/yellow/red)
   - Data ingestion rate (events/sec over last hour)
   - Estimated days until disk full at current rate
   Widget queries OpenSearch _cat/indices and _cluster/stats APIs. Uses get_opensearch_session() for TLS-safe connections. Full-width layout on Overview tab.

6. **Disk space alerting** (`dashboard.py`): When disk usage exceeds 80%, generates a high-severity alert. When disk usage exceeds 90%, generates a critical-severity alert. Alerts written to tinysocs-alerts index with 24-hour cooldown (one alert per day per threshold). Alerts appear in the normal alert timeline and fired detections list.

**Acceptance**

- Fresh install with retention=90 → ISM policy created, old indices auto-deleted after 90 days
- Settings panel shows current retention and allows changing it
- Storage widget shows disk usage, per-index sizes, cluster health, ingestion rate
- Disk at 81% usage → high alert in alert timeline (once per 24h)
- Disk at 91% usage → critical alert in alert timeline (once per 24h)
- OpenSearch watermarks set to 80/88/92% on fresh install


M3 — Emergency Disk Purge & Auto-Remediation
----------------------------------------------

**Goal:** When disk fills beyond safe thresholds, automatically purge oldest data to prevent OpenSearch from going read-only. Provide a manual purge button in the dashboard for operator-initiated cleanup.

**Current State (pre-Phase 21)**

- When disk fills to 95%, OpenSearch enters read-only mode (flood_stage watermark)
- Recovery requires manual intervention: SSH into the box, identify large indices, delete them, clear the read-only flag
- No dashboard UI for purging data
- No automatic remediation

**Proposed Changes**

Files:
- `src/tinysocs/api/dashboard.py` — Auto-purge logic, manual purge endpoint, purge UI in settings

**Deliverables**

1. **Auto-purge trigger** (`dashboard.py`, +230 lines): Background task checks disk usage every 5 minutes. When usage exceeds 90%, automatically deletes the oldest day of winlog indices (tinysocs-winlog-YYYY.MM.DD). Continues deleting oldest days until usage drops below 85%. Logs every deletion with timestamp and bytes freed. Writes a critical alert documenting the auto-purge action. Respects a minimum retention floor of 7 days — never deletes indices younger than 7 days even under disk pressure.

2. **Manual purge endpoint** (`dashboard.py`): POST /api/settings/purge — Accepts parameters: index_pattern (default tinysocs-winlog-*), older_than_days (required). Deletes indices matching the pattern that are older than the specified days. Returns count of deleted indices and bytes freed. Requires session token authentication.

3. **Purge UI in Settings** (`dashboard.py`): "Emergency Purge" section in Settings tab. Dropdown for index pattern (winlog, alerts, custom, all). Input for "older than N days". Red "Purge Now" button with confirmation dialog. Shows result after purge (indices deleted, space freed). Warning text explains the action is irreversible.

**Acceptance**

- Disk at 91% → auto-purge deletes oldest winlog day, continues until <85%
- Auto-purge never deletes indices younger than 7 days
- Auto-purge writes a critical alert documenting the action
- Manual purge via Settings → deletes specified indices, shows bytes freed
- Manual purge requires authentication


M4 — HEC Endpoint & Token Management
--------------------------------------

**Goal:** Accept custom log data via an HTTP Event Collector (HEC) endpoint so operators can ingest logs from non-Windows sources. Manage HEC tokens from the dashboard.

**Current State (pre-Phase 21)**

- TinySocs only ingests Windows event logs via the Sysmon/WinLogBeat pipeline
- No way to send arbitrary log data to the system
- No HEC-style endpoint exists
- No token management for API access

**Proposed Changes**

Files:
- `src/tinysocs/api/node.py` — HEC endpoint implementation
- `src/tinysocs/api/dashboard.py` — HEC token management UI in settings, token CRUD endpoints
- `config/assistant.env` — HEC_TOKENS env var
- `packaging/iss/Quickstart.iss` — HEC token generation during install
- `packaging/opensearch/templates/tinysocs-custom.json` — New index template for custom logs
- `packaging/opensearch/policies/tinysocs-custom-retention.json` — Retention policy for custom indices
- `src/tinysocs/tinybox/opensearch_bootstrap.py` — Bootstrap custom index template and policy

**Deliverables**

1. **HEC endpoint** (`node.py`, +125 lines): POST /hec/event — Accepts JSON event payloads. Authenticates via Bearer token in Authorization header. Validates token against HEC_TOKENS environment variable (comma-separated list). Indexes events into tinysocs-custom-YYYY.MM.DD indices. Supports single events and batched arrays. Adds @timestamp if not present. Adds metadata: source_token (hashed), ingestion_time, source_ip. Rate limited to 100 events/sec per token. Request body limited to 1MB.

2. **Custom index template** (`tinysocs-custom.json`, new file, 43 lines): OpenSearch index template for tinysocs-custom-* indices. Maps @timestamp, message, source, host, severity, and allows dynamic fields. Configured with 1 shard, 0 replicas (single-node deployment).

3. **Custom retention policy** (`tinysocs-custom-retention.json`, new file, 35 lines): ISM policy matching winlog retention. Delete after RETENTION_DAYS. Applied via index template.

4. **Bootstrap integration** (`opensearch_bootstrap.py`, +14 lines): On first boot, creates the tinysocs-custom index template and retention policy alongside existing winlog and alerts templates.

5. **HEC token management UI** (`dashboard.py`): New "HEC Tokens" section in Settings panel. Shows existing tokens (masked, with copy button). "Generate Token" button creates a new random 32-char token, adds to HEC_TOKENS in assistant.env. "Revoke" button removes a token. Shows the HEC endpoint URL for easy copy. Token list persisted in assistant.env.

6. **API security hardening** (`node.py` + `dashboard.py` + `bot.py`): Rate limiting middleware (100 req/min per IP). Request body size limit (1MB). CORS headers. All existing endpoints that were unauthenticated now optionally require HMAC when TINYSOCS_NODE_AUTH_READS is set.

**Acceptance**

- POST /hec/event with valid Bearer token → event indexed in tinysocs-custom-*
- POST /hec/event with invalid token → 401
- POST /hec/event with body >1MB → 413
- Settings panel shows HEC tokens, can generate and revoke
- HEC endpoint URL displayed in settings for copy
- Custom index template created on bootstrap
- Rate limiting enforced (>100 req/min → 429)


M5 — AI Assistant Privacy Hardening
-------------------------------------

**Goal:** Give operators control over what data the AI assistant sends to external LLM providers. Add a consent dialog, data disclosure, and privacy mode.

**Current State (pre-Phase 21)**

- The AI assistant sends event data, alert details, and hostnames to the configured LLM provider (OpenAI or Anthropic) without any disclosure or consent
- No privacy mode — all data is sent regardless of sensitivity
- Model names are hardcoded (gpt-4o-mini for OpenAI, claude-3-5-sonnet for Anthropic)
- No way for operators to choose their own model
- No consent dialog on first use
- The installer shows the LLM provider choice but doesn't explain the privacy implications

**Proposed Changes**

Files:
- `src/tinysocs/api/dashboard.py` — Consent dialog, privacy indicators, model configuration UI
- `src/tinysocs/agent/llm_openai_tools.py` — Remove hardcoded model, read from config
- `src/tinysocs/agent/llm_claude.py` — Remove hardcoded model, read from config
- `packaging/iss/Quickstart.iss` — Privacy note on LLM provider page

**Deliverables**

1. **Consent dialog** (`dashboard.py`, +129 lines): On first interaction with the AI assistant, a modal dialog appears explaining: what data is sent (event summaries, alert details, hostnames), where it goes (the configured LLM provider), that the operator can disable the assistant at any time. Two buttons: "I Understand, Enable Assistant" and "Keep Disabled". Consent state persisted in assistant.env as AI_CONSENT_GIVEN=true. Dialog does not reappear after consent is given. If consent not given, assistant panel shows a locked state with explanation.

2. **Privacy indicators** (`dashboard.py`): When the assistant is active, a small privacy badge shows in the assistant panel header: "Data sent to [provider name]". Clicking the badge opens a summary of what data types are included in each query.

3. **LLM model configuration** (`dashboard.py` + `llm_openai_tools.py` + `llm_claude.py`): Remove hardcoded model names. Read OPENAI_MODEL and CLAUDE_MODEL from assistant.env. If not configured, the assistant shows a setup prompt instead of failing silently. Settings panel includes model name input fields for each provider. Validates model name format.

4. **Installer privacy note** (`Quickstart.iss`): The LLM provider selection page now includes a note: "The AI assistant sends security event summaries to the selected provider for analysis. No credentials or raw logs are transmitted." Remove hardcoded model name from the OpenAI label text.

**Acceptance**

- First click on AI assistant → consent dialog appears with data disclosure
- Consent declined → assistant locked, explanation shown
- Consent given → assistant works, privacy badge visible
- Model not configured → assistant shows setup prompt, no silent failure
- Settings panel allows changing model name
- Installer shows privacy note on LLM provider page


M6 — AI Assistant Product Knowledge
-------------------------------------

**Goal:** Give the AI assistant comprehensive knowledge about TinySocs so it can answer operator questions about the product, not just query event data.

**Current State (pre-Phase 21)**

- The AI assistant's system prompt contains minimal product context
- When operators ask "how do I configure retention?" or "what does the Fleet tab show?", the assistant has no product knowledge to draw from
- No knowledge document exists

**Proposed Changes**

Files:
- `config/assistant-knowledge.md` — New: comprehensive product knowledge document (231 lines)
- `src/tinysocs/api/dashboard.py` — Load and inject knowledge document into system prompt
- `packaging/iss/Quickstart.iss` — Bundle knowledge document in installer

**Deliverables**

1. **Product knowledge document** (`config/assistant-knowledge.md`, new file, 231 lines): Covers all 6 dashboard tabs (Overview, Sites, Fleet, Data, Detections, Compliance), architecture (Windows agent, OpenSearch, Python API, federation model), detection rules and alert lifecycle, HEC endpoint usage, retention and storage management, common troubleshooting steps, federation concepts (Hub/Site, drill-through, aggregation).

2. **Knowledge injection** (`dashboard.py`, +39 lines): On assistant startup, reads assistant-knowledge.md from the config directory. Injects the full document into the LLM system prompt. Falls back gracefully if the file doesn't exist.

3. **Installer bundling** (`Quickstart.iss`, +5 lines): Copies assistant-knowledge.md to C:\ProgramData\TinySocs\config\ during install.

**Acceptance**

- Ask the assistant "what tabs does the dashboard have?" → accurate answer listing all 6 tabs
- Ask "how do I configure retention?" → accurate answer referencing Settings panel
- Knowledge document missing → assistant still works, just without product context


M7 — Demo Mode Enrichment
---------------------------

**Goal:** Enrich demo mode threat intelligence data with source IP addresses and MITRE ATT&CK context so demo detections look realistic for sales presentations.

**Current State (pre-Phase 21)**

- Demo mode detections have alert titles and severity but lack source IP addresses
- Threat intel panel shows no enrichment data for demo alerts
- Demo detections don't reference MITRE techniques

**Proposed Changes**

Files:
- `src/tinysocs/api/dashboard.py` — Add source IPs, geo data, and MITRE enrichment to demo detections

**Deliverables**

1. **Demo detection enrichment** (`dashboard.py`, +45 lines): Each demo detection now includes source_ip (realistic RFC 5737 documentation addresses), geo enrichment (country, city, ASN), and MITRE technique references (T1110.001 for brute force, T1059.001 for PowerShell, etc.). Threat intel panel renders enrichment data for demo alerts.

**Acceptance**

- Demo mode fired detections include source_ip, geo, and MITRE fields
- Threat intel panel shows enrichment for demo alerts


M8 — Auth Hardening: Session Tokens & Timing Safety
-----------------------------------------------------

**Goal:** Replace master-password authentication in the settings panel with session tokens. Fix timing vulnerabilities in password comparison. Handle stale session tokens gracefully.

**Current State (pre-Phase 21)**

- Settings panel API endpoints require the master password in every request
- Password comparison uses Python == operator (timing-vulnerable)
- If a session token expires mid-settings-edit, the next save silently fails
- No session token support for settings endpoints

**Proposed Changes**

Files:
- `src/tinysocs/api/dashboard.py` — Session token auth for settings, timing-safe comparison, stale token handling
- `tests/test_notifications_e2e.py` — Update test assertions for new auth patterns

**Deliverables**

1. **Session token authentication for settings** (`dashboard.py`): All /api/settings/* endpoints now accept Bearer session tokens instead of requiring the master password. Session tokens are the same tokens issued at login. Eliminates the need to send the master password after initial login.

2. **Timing-safe comparison** (`dashboard.py`): All password and token comparisons use hmac.compare_digest() instead of ==. Prevents timing side-channel attacks on authentication.

3. **Stale token detection** (`dashboard.py`, +28 lines): When a settings request arrives with an expired session token, returns 401 with a JSON body containing "expired": true. The frontend detects this and shows a re-login prompt instead of a generic error. Prevents silent save failures.

4. **Test updates** (`test_notifications_e2e.py`): Updated to use session token auth instead of password auth for settings endpoints.

**Acceptance**

- Settings panel works with session token (no password in request body)
- Expired session token → 401 with "expired": true, re-login prompt shown
- Password comparison uses hmac.compare_digest() in all code paths
- No timing difference between valid and invalid tokens


M9 — Dashboard Layout & Installer Fixes
-----------------------------------------

**Goal:** Fix remaining UI issues (settings panel width, widget scrollbars, storage widget layout) and installer bugs (OpenSearch watermarks, YAML encoding, launch dashboard checkbox, PyInstaller build).

**Current State (pre-Phase 21)**

- Settings panel uses a narrow column layout instead of full-width
- Storage widget doesn't span full width on Overview tab
- OpenSearch watermark YAML contains em-dash characters that break keystore operations
- "Launch Dashboard" checkbox on installer finish page doesn't work (direct shellexec fails)
- PyInstaller build fails when an editable install is present (stale .pth files)
- Storage widget uses raw SSLContext instead of the centralised get_opensearch_session() helper

**Proposed Changes**

Files:
- `src/tinysocs/api/dashboard.py` — Full-width settings, full-width storage, SSLContext fix
- `packaging/iss/Quickstart.iss` — Launch dashboard fix, em-dash fix, OpenSearch watermark fix
- `scripts/Full-Rebuild.ps1` — PyInstaller build fixes
- `src/tinysocs/tls.py` — Add get_siem_ssl_context alias

**Deliverables**

1. **Full-width settings panel** (`dashboard.py`): Settings tab content area uses 100% width instead of constrained column. All settings sections (retention, HEC tokens, purge, model config) rendered at full width.

2. **Full-width storage widget** (`dashboard.py`): Storage monitoring widget on Overview tab spans full width (col-span: 2 in the grid) for better readability of per-index breakdown.

3. **Storage widget TLS fix** (`dashboard.py`, -32/+26 lines): Replaced raw ssl.SSLContext construction with get_opensearch_session() helper from tls module. Consistent TLS handling across all OpenSearch connections.

4. **Launch Dashboard checkbox fix** (`Quickstart.iss`): Changed from direct shellexec to `cmd /c start` to handle URL opening correctly on all Windows versions. The finish page checkbox now reliably opens the dashboard in the default browser.

5. **OpenSearch watermark YAML fix** (`Quickstart.iss`): Replaced em-dash character in YAML comment that caused OpenSearch keystore failure. ASCII-only comments throughout.

6. **OpenSearch flood_stage.frozen fix** (`Quickstart.iss`): Removed invalid cluster.routing.allocation.disk.watermark.flood_stage.frozen setting that caused OpenSearch to crash on startup with newer versions.

7. **PyInstaller build fixes** (`Full-Rebuild.ps1`, +35 lines): Added --clean flag to PyInstaller to prevent stale module caching. Prepend build dir to PYTHONPATH to override editable install's .pth files. Uninstall editable install before building to prevent import conflicts.

8. **TLS module alias** (`tls.py`, +4 lines): Added get_siem_ssl_context as an alias for backward compatibility with code that imported the old function name.

9. **Test suite fix** (`pyproject.toml` + `tests/test_nodes_api.py`): Added pythonpath to pytest config. Updated version assertions to match v0.9.0.

**Acceptance**

- Settings panel renders full-width
- Storage widget spans full width on Overview
- Launch Dashboard checkbox opens browser correctly
- OpenSearch starts without keystore or watermark errors
- PyInstaller build succeeds with editable install present
- All tests pass


Milestone Order
---------------

| # | Milestone | Depends On | Estimated Effort |
|---|-----------|------------|------------------|
| M0 | Security Audit & Codebase Cleanup | None | 2-3 hours |
| M1 | Detection Rule Tuning | None | 1 hour |
| M2 | Configurable Retention & Storage Monitoring | M0 (clean codebase) | 3-4 hours |
| M3 | Emergency Disk Purge & Auto-Remediation | M2 (storage monitoring) | 2 hours |
| M4 | HEC Endpoint & Token Management | M0 (auth.py) | 3-4 hours |
| M5 | AI Assistant Privacy Hardening | None | 2 hours |
| M6 | AI Assistant Product Knowledge | M5 (assistant changes) | 1 hour |
| M7 | Demo Mode Enrichment | None | 1 hour |
| M8 | Auth Hardening: Session Tokens | M0 (auth.py) | 2-3 hours |
| M9 | Dashboard Layout & Installer Fixes | M2, M4 (settings panel) | 2 hours |

M0 and M1 are independent and can be done in parallel. M2 depends on M0 (needs clean codebase and auth module). M3 depends on M2 (builds on storage monitoring). M4 depends on M0 (uses centralised auth). M5 and M7 are independent. M6 depends on M5. M8 depends on M0. M9 depends on M2 and M4 (settings panel must exist).


Verification (End-to-End)
--------------------------

After Phase 21, on a fresh Windows install:

```
# Run installer — new retention page asks for retention days
# OpenSearch starts with relaxed watermarks (80/88/92%)
# ISM policies created for winlog, alerts, custom indices

# Open dashboard
Start-Process "https://localhost:8090/dashboard"

# Overview tab — Storage widget shows disk usage, per-index sizes
# Alert timeline — no false positives from idle box

# Click AI assistant — consent dialog appears
# Accept consent — assistant works, privacy badge visible
# Ask "what tabs does the dashboard have?" — accurate product knowledge answer

# Settings tab — full-width layout
# Data Retention section — shows 90 days, can change
# HEC Tokens section — generate a token, copy endpoint URL
# Emergency Purge section — manual purge with confirmation

# Send a HEC event
curl -k -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"message": "test event", "source": "curl"}' \
     https://localhost:8081/hec/event
# → 200 OK, event appears in Data tab under tinysocs-custom-*

# Session expires while on settings → re-login prompt (not silent failure)

# PyInstaller build
.\scripts\Full-Rebuild.ps1
# → Succeeds even with editable install present

# Tests
PYTHONPATH=src python -m pytest tests/ -x -q
# → All pass, no regressions
```


What Phase 21 Explicitly Does Not Cover
-----------------------------------------

- **Multi-tenancy / RBAC**: One dashboard = one operator. Per-client logins and role-based access require a user management system. Build after pilot feedback.
- **Mutual TLS (mTLS)**: Certificate pinning (Phase 20) verifies Site identity. The reverse (Site verifying Hub) is not yet implemented.
- **Certificate rotation**: Pinned certificates are static. Rotation workflow is future scope.
- **Cross-site correlation**: Phase 21 is single-site operational hardening. Cross-site pattern detection (same attacker across clients) requires a correlation engine.
- **Per-site AI context**: Assistant queries master SIEM regardless of focused site. Per-site AI proxying is deferred.
- **Linux/macOS collector**: Cross-platform event collection is orthogonal to production hardening.
- **Automated update delivery**: Version drift is visible on Sites tab. Pushing updates to nodes requires its own protocol.
- **HEC schema enforcement**: The HEC endpoint accepts any JSON structure. Schema validation (required fields, type checking) would improve data quality but adds complexity for V1.
