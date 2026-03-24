Phase 21 Summary — Production Hardening
Theme: "Lean, hardened, and operator-ready"

Overview

Phase 21 transformed TinySocs from a feature-complete prototype into a production-hardened system. A comprehensive security audit removed a leaked PKCS#12 certificate (kirk.pfx), 10 debug scripts totalling 1,213 lines, and stale runtime artifacts from version control, then consolidated four independent HMAC implementations into a single centralised auth module with replay protection and timing-safe comparison. Detection rules were retuned to eliminate false positives on idle Windows boxes — PowerShell, process creation, and Sysmon flood rules had their thresholds raised from 50 to 200 and windows widened from 5 to 10 minutes, while 9 single-event rules gained cooldown periods of 30-60 minutes. A new configurable data retention system lets operators choose retention duration at install time (30-365 days) and change it from the dashboard, backed by OpenSearch ISM policies that automatically delete expired indices. A storage monitoring widget on the Overview tab shows disk usage, per-index sizes, cluster health, ingestion rate, and estimated days until disk full. Emergency disk remediation auto-purges the oldest winlog indices when usage exceeds 90% and provides a manual purge button in the settings panel. A generic HEC endpoint on the node API accepts custom log data via Bearer token authentication, indexing into tinysocs-custom-* indices with full retention policy coverage. HEC tokens are managed from the dashboard settings panel with generate/revoke controls and a copyable endpoint URL. The AI assistant received privacy hardening — a consent dialog discloses what data is sent to the LLM provider, and hardcoded model names were removed in favour of operator-configured values. A 231-line product knowledge document was added so the assistant can answer questions about TinySocs itself. Demo mode detections were enriched with source IPs, geo data, and MITRE technique references for realistic sales presentations. Settings panel authentication was migrated from master-password-per-request to session tokens with timing-safe comparison and stale token detection. Dashboard layout fixes delivered full-width settings, full-width storage widget, and resolved installer bugs including OpenSearch watermark YAML encoding, the Launch Dashboard checkbox, and PyInstaller build failures with editable installs.

Stats: 51 files changed (5 new, 14 deleted), +2,975 / -1,782 lines across 10 milestones (M0-M9), 26 commits.

Commits

| Hash | Message |
|---|---|
| bf6565d | Fix stale session token handling in settings panel |
| 25898af | Fix PyInstaller build: uninstall editable install before building |
| 2f2e624 | Harden settings auth: session tokens only, fix timing vulnerabilities |
| 20a1455 | Settings panel improvements: full-width, fix HEC tokens, add purge + endpoint URL |
| 4812e6f | Fix Launch Dashboard checkbox: use cmd /c start instead of direct shellexec |
| 0cf623b | Make Storage widget full-width on Overview tab |
| e8a7e3c | Fix em dash in watermark YAML comment causing OpenSearch keystore failure |
| d78fe32 | Fix Storage widget: use get_opensearch_session() instead of raw SSLContext |
| 1e5cad7 | Fix PyInstaller build: prepend build dir to PYTHONPATH to override editable install |
| d8a8090 | Add --clean to PyInstaller builds to prevent stale module caching |
| 5409cff | Fix import error: add get_siem_ssl_context alias in tls module |
| 44b3948 | Fix OpenSearch crash: remove invalid flood_stage.frozen setting |
| 48eaf13 | Add source IPs and demo enrichment to demo detections for threat intel |
| f2f13d0 | Add comprehensive product knowledge document for AI assistant |
| 9dc596c | Full API security hardening: rate limiting, body size, HEC tokens, auth |
| 4a9c2a1 | Add generic HEC endpoint for custom log ingestion |
| af9c67d | Add emergency disk purge with auto-trigger and UI button |
| de7fc2e | Fix retention help text and add OpenSearch disk watermark injection |
| 4b5e134 | Fix installer: remove model name from OpenAI label, add privacy note, fix retention text |
| d8bedb8 | Remove hardcoded LLM model defaults — require user-configured model |
| 7058f83 | Add AI assistant privacy hardening and update model defaults |
| 9bdee48 | Fix test suite: add pythonpath to pytest config, update version assertions |
| b08deba | Add configurable retention settings and storage monitoring |
| e0323d2 | Tune detection rules to reduce false positives on idle systems |
| 3a84ffd | Update demo materials to match v0.9.0 release |
| 83bbde0 | Security audit and codebase cleanup |

Milestones Delivered

M0 — Security Audit & Codebase Cleanup

Goal: Remove leaked credentials, debug scripts, and stale artifacts. Centralise HMAC authentication. Establish pre-commit hooks and security test coverage.

Files:
* kirk.pfx — Deleted. PKCS#12 certificate bundle that was checked into the repository root. A leaked credential that should never have been committed.
* data/actions_queue.jsonl — Deleted. 56 lines of queued bot actions — runtime artifact, not source code.
* logs/ledger-health.json — Deleted. 10 lines of runtime health data.
* logs/verify_ledger-20251103-021505.json — Deleted. 13 lines of ledger verification output.
* logs/verify_ledger-20251103-021505.raw.txt — Deleted. 14 lines of raw verification output.
* scripts/Debug-AlertDocs.ps1 — Deleted. 97-line debug script for alert document inspection.
* scripts/Debug-DashboardAuth.ps1 — Deleted. 139-line debug script for dashboard auth testing.
* scripts/Debug-DetectionEngine.ps1 — Deleted. 232-line debug script for detection engine internals.
* scripts/Debug-FleetMapping.ps1 — Deleted. 63-line debug script for fleet host mapping.
* scripts/Fix-DashboardAuth.ps1 — Deleted. 143-line one-off fix script for auth issues.
* scripts/Pack-Repo.ps1 — Deleted. 59-line script for packaging the repository.
* scripts/Send-BotAck.ps1 — Deleted. 49-line debug script for bot acknowledgement testing.
* scripts/Send-BotExec.ps1 — Deleted. 96-line debug script for bot execution testing.
* scripts/Stop-TinySocs.ps1 — Deleted. 17-line convenience script superseded by service management.
* scripts/Test-Phase12.ps1 — Deleted. 315-line integration test script replaced by pytest suite.
* scripts/Start-TinySocs-Agent.ps1 — Removed 2 dangling lines referencing deleted scripts.
* scripts/Start-TinySocs-Node.ps1 — Removed 2 dangling lines referencing deleted scripts.
* .gitignore — Expanded with 29 new patterns: data/, logs/, *.pfx, *.p12, *.pem (private keys), .env, __pycache__, dist/, build/, *.egg-info, .pytest_cache. +29 / -3 lines.
* .pre-commit-config.yaml — New file, 9 lines. Configures detect-secrets for credential scanning and trailing-whitespace cleanup hooks.
* src/tinysocs/api/auth.py — New file, 169 lines. Centralised HMAC authentication module. Supports three HMAC styles: pipe ("{ts}|{nonce}"), dot ("{ts}.{nonce}"), and ts-only ("{ts}"). Flexible verification tries all three formats. Replay protection via TTL-based dict cache (5-minute window) with periodic garbage collection (60-second intervals). Timing-safe comparison using hmac.compare_digest(). Extracted from four separate implementations.
* src/tinysocs/api/bot.py — Refactored to import HMAC verification from auth.py. Removed inline HMAC implementation. Added rate limiting middleware integration. +89 / -57 lines.
* src/tinysocs/api/bot_actions.py — Refactored to import from auth.py. Removed 43 lines of duplicated HMAC logic. +10 / -43 lines.
* src/tinysocs/api/node.py — Refactored to import from auth.py. Removed inline HMAC verification. +8 / -64 lines (auth-related portion of larger node.py changes).
* src/tinysocs/orchestrator/master.py — Refactored to import from auth.py. +7 / -7 lines.
* src/tinysocs/agent/config.py — Removed hardcoded default credentials. Added config validation for required fields. HMAC key validation with minimum length check. +43 / -11 lines.
* src/TinySocs.Agent/Detection/DetectionEngine.cs — Cleaned up dead code paths and unused variable declarations. +24 / -17 lines.
* src/tinysocs/api/dashboard.py — Added security headers, updated auth imports. +17 / -4 lines.
* tests/test_security_auth.py — New file, 296 lines. Comprehensive security test suite covering HMAC verification across all three styles, replay detection with cache expiry, timing-safe comparison validation, nonce uniqueness, expired timestamp rejection, flexible mode cross-style acceptance, empty/malformed header handling, and concurrent replay attempts.
* tests/test_e2e_phase12.py — Updated 18 lines to match new auth patterns and response shapes.
* .github/workflows/build-installer.yml — Added 7 lines for pre-commit hook integration in CI.
* docker-compose.yaml — Security hardening: removed exposed debug ports, added read-only filesystem flags. +8 / -1 lines.
* nginx/opensearch.conf — New file, 10 lines. Reverse proxy config for OpenSearch with TLS termination.
* pyproject.toml — Updated project metadata, added security dependencies, pytest pythonpath config. +10 / -7 lines.
* requirements.txt — Added 1 dependency (python-multipart for secure file upload handling).
* .claude/launch.json — Dev server config update. +7 / -2 lines.
* scripts/Start-TinySocs-Quick.ps1 — Cleaned up references to deleted scripts. +16 / -3 lines.

M1 — Detection Rule Tuning

Goal: Reduce false-positive alerts on idle Windows systems by raising thresholds, widening windows, and adding cooldown periods.

Files:
* packaging/detection/rules.yml — Three high-noise rules retuned: powershell_logging_volume, rapid_process_creation, sysmon_process_flood all changed from threshold: 50 / window_minutes: 5 to threshold: 200 / window_minutes: 10 / cooldown_minutes: 30. Six single-event trigger rules gained cooldown_minutes: 60: new_local_account, new_service_installed, password_never_expires, defender_realtime_disabled, service_creation_via_sc, scheduled_task_created. Total: +50 / -15 lines.

M2 — Configurable Data Retention & Storage Monitoring

Goal: Let operators configure retention duration, see storage consumption, and receive disk alerts — all from the dashboard.

Files:
* config/assistant.env — Added 6 new environment variables: RETENTION_DAYS (default 90), RETENTION_WINLOG_DAYS, RETENTION_ALERTS_DAYS, RETENTION_CUSTOM_DAYS, STORAGE_ALERT_HIGH_PCT (80), STORAGE_ALERT_CRITICAL_PCT (90). +6 lines.
* packaging/iss/Quickstart.iss — New retention wizard page with dropdown (30/60/90/180/365 days). Writes RETENTION_DAYS to assistant.env. OpenSearch disk watermark injection: low=80%, high=88%, flood_stage=92% written to opensearch.yml. Help text explaining disk impact per retention period. Retention display text fixes. +72 / -5 lines (retention portion of total Quickstart.iss changes).
* src/tinysocs/api/dashboard.py — Settings panel retention UI: shows current RETENTION_DAYS, dropdown to change, save button that updates assistant.env and re-applies ISM policies. Storage monitoring widget on Overview tab: disk usage bar (used/total), per-index breakdown (winlog, alerts, custom with doc counts and sizes), cluster health indicator (green/yellow/red), ingestion rate (events/sec), estimated days until disk full. Disk space alerting: high alert at 80%, critical at 90%, 24-hour cooldown per threshold. Full-width storage widget layout. +410 / -3 lines (commit b08deba).
* src/tinysocs/tinybox/opensearch_bootstrap.py — ISM retention policy creation on first boot. Creates policies for tinysocs-winlog-* and tinysocs-alerts-* with hot -> delete lifecycle at RETENTION_DAYS. Rollover configured at 10GB or 1 day. Policies applied via index templates for automatic coverage of new indices. +90 lines.
* OpenSearch/config/opensearch.yml — Disk watermark configuration block: cluster.routing.allocation.disk.watermark.low (80%), high (88%), flood_stage (92%). +12 / -1 lines.

M3 — Emergency Disk Purge & Auto-Remediation

Goal: Automatically purge oldest data when disk fills beyond safe thresholds. Provide a manual purge button.

Files:
* src/tinysocs/api/dashboard.py — Auto-purge background task: checks disk usage every 5 minutes, triggers when >90%, deletes oldest winlog day indices until <85%, minimum 7-day retention floor, logs every deletion, writes critical alert documenting auto-purge action. Manual purge endpoint: POST /api/settings/purge accepts index_pattern and older_than_days, returns deleted count and bytes freed, requires session token auth. Purge UI in Settings: dropdown for index pattern, days input, red "Purge Now" button with confirmation dialog, result display. +230 / -1 lines (commit af9c67d).

M4 — HEC Endpoint & Token Management

Goal: Accept custom log data via HEC and manage API tokens from the dashboard.

Files:
* src/tinysocs/api/node.py — POST /hec/event endpoint: accepts JSON event payloads, authenticates via Bearer token against HEC_TOKENS env var, indexes into tinysocs-custom-YYYY.MM.DD, supports single and batched events, adds @timestamp/source_token/ingestion_time/source_ip metadata, rate limited to 100 events/sec per token, 1MB body limit. Optional HMAC auth for read endpoints when TINYSOCS_NODE_AUTH_READS is set. Rate limiting middleware (100 req/min per IP). Request body size enforcement. +312 / -64 lines (total node.py changes across commits 4a9c2a1 and 9dc596c).
* config/assistant.env — Added HEC_TOKENS and TINYSOCS_NODE_AUTH_READS variables. +1 line (HEC portion).
* packaging/iss/Quickstart.iss — HEC token generation during install: generates a random 32-char token, writes to HEC_TOKENS in assistant.env. Installer displays the generated token with copy instructions. +23 / -1 lines (HEC portion of Quickstart.iss changes).
* packaging/opensearch/templates/tinysocs-custom.json — New file, 43 lines. Index template for tinysocs-custom-* indices. Maps @timestamp (date), message (text + keyword), source (keyword), host (keyword), severity (keyword), source_token (keyword), ingestion_time (date), source_ip (keyword). Dynamic field mapping enabled. 1 shard, 0 replicas.
* packaging/opensearch/policies/tinysocs-custom-retention.json — New file, 35 lines. ISM retention policy for custom indices matching winlog retention. Hot -> delete lifecycle at RETENTION_DAYS.
* src/tinysocs/tinybox/opensearch_bootstrap.py — Extended to create tinysocs-custom index template and retention policy on first boot alongside existing templates. +14 / -2 lines (HEC portion).
* src/tinysocs/api/dashboard.py — HEC token management UI in Settings: token list (masked with copy button), "Generate Token" creates random 32-char token and updates assistant.env, "Revoke" removes token, HEC endpoint URL display. API security: rate limiting integration, body size middleware, HEC token CRUD endpoints, CORS headers. +146 lines (commit 9dc596c) + 35 / -7 lines (commit 4a9c2a1) + 86 / -10 lines (commit 20a1455).
* src/tinysocs/api/bot.py — Rate limiting middleware integration, body size enforcement. +18 lines (commit 9dc596c).

M5 — AI Assistant Privacy Hardening

Goal: Give operators control over what data the AI assistant sends to LLM providers. Add consent dialog and remove hardcoded models.

Files:
* src/tinysocs/api/dashboard.py — Consent dialog on first AI assistant interaction: modal explaining what data is sent (event summaries, alert details, hostnames), where it goes (configured LLM provider), how to disable. Two buttons: "I Understand, Enable Assistant" / "Keep Disabled". Consent state persisted as AI_CONSENT_GIVEN in assistant.env. Privacy badge in assistant panel header showing provider name. Model configuration UI in Settings with input fields per provider. +129 / -8 lines (commit 7058f83).
* src/tinysocs/agent/llm_openai_tools.py — Removed hardcoded "gpt-4o-mini" default. Now reads OPENAI_MODEL from environment. Raises clear error if model not configured. +1 / -1 lines.
* src/tinysocs/agent/llm_claude.py — Removed hardcoded "claude-3-5-sonnet-20241022" default. Now reads CLAUDE_MODEL from environment. +1 / -1 lines.
* src/tinysocs/api/dashboard.py — Settings panel model configuration: shows current model names for OpenAI and Claude providers, input fields to change, save updates assistant.env. Unconfigured model shows setup prompt instead of silent failure. +14 / -4 lines (commit d8bedb8).
* packaging/iss/Quickstart.iss — Privacy note on LLM provider selection page: "The AI assistant sends security event summaries to the selected provider for analysis. No credentials or raw logs are transmitted." Removed hardcoded model name from OpenAI label text. +10 / -4 lines (commit 4b5e134).

M6 — AI Assistant Product Knowledge

Goal: Give the AI assistant comprehensive product knowledge so it can answer questions about TinySocs itself.

Files:
* config/assistant-knowledge.md — New file, 231 lines. Comprehensive product knowledge document covering: all 6 dashboard tabs (Overview, Sites, Fleet, Data, Detections, Compliance) with feature descriptions; architecture overview (Windows agent with Sysmon, OpenSearch backend, Python FastAPI, federation Hub/Site model); detection rules and alert lifecycle (rule types, severity levels, cooldown, investigation workflow); HEC endpoint usage (authentication, payload format, curl examples); retention and storage management (ISM policies, watermarks, auto-purge); common troubleshooting (OpenSearch won't start, no alerts appearing, node unreachable, assistant not responding); federation concepts (Hub/Site roles, drill-through, cross-site aggregation, certificate pinning).
* src/tinysocs/api/dashboard.py — Knowledge injection: on assistant startup, reads assistant-knowledge.md from config directory, injects into LLM system prompt. Graceful fallback if file doesn't exist. +39 lines (commit f2f13d0).
* packaging/iss/Quickstart.iss — Copies assistant-knowledge.md to C:\ProgramData\TinySocs\config\ during install. +5 lines (commit f2f13d0).
* .gitignore — Added config/assistant-knowledge.md exception to ensure it's tracked despite config/ patterns. +2 lines.

M7 — Demo Mode Enrichment

Goal: Enrich demo detections with source IPs, geo data, and MITRE references for realistic threat intel presentation.

Files:
* src/tinysocs/api/dashboard.py — Each demo detection now includes: source_ip (RFC 5737 documentation addresses — 198.51.100.*, 203.0.113.*), geo enrichment (country, city, ASN for each source IP), MITRE ATT&CK technique references (T1110.001 for brute force, T1059.001 for PowerShell, T1053.005 for scheduled tasks, T1562.001 for defense evasion). Threat intel panel renders enrichment data for all demo alerts. +45 / -6 lines (commit 48eaf13).
* docs/demo-script.md — Updated demo walkthrough version references to match v0.9.0. +4 / -4 lines (commit 3a84ffd).
* src/tinysocs/api/dashboard.py — Updated demo alert counts and version strings to match v0.9.0 release. +12 / -12 lines (commit 3a84ffd).

M8 — Auth Hardening: Session Tokens & Timing Safety

Goal: Replace master-password authentication in settings with session tokens. Fix timing vulnerabilities. Handle stale tokens gracefully.

Files:
* src/tinysocs/api/dashboard.py — All /api/settings/* endpoints migrated from master password auth to Bearer session token auth. Password comparison across all code paths replaced with hmac.compare_digest() for timing safety. Refactored settings auth: removed inline password checks, added _require_session() helper that validates session tokens and returns 401 with {"expired": true} for stale tokens. Frontend detects expired token response and shows re-login prompt instead of generic error. Fixed race condition where concurrent settings requests could invalidate each other's tokens. +110 / -174 lines (commit 2f2e624) + 28 / -15 lines (commit bf6565d).
* tests/test_notifications_e2e.py — Updated test assertions to use session token auth instead of password auth for settings endpoints. Adjusted mock auth to match new session token flow. +32 / -33 lines.

M9 — Dashboard Layout & Installer Fixes

Goal: Fix remaining UI, installer, and build issues.

Files:
* src/tinysocs/api/dashboard.py — Settings panel full-width: content area uses 100% width instead of constrained column, all settings sections rendered at full width. Storage widget full-width: col-span: 2 in Overview grid. Storage widget TLS fix: replaced raw ssl.SSLContext with get_opensearch_session() from tls module. +86 / -10 lines (commit 20a1455) + 1 insertion (commit 0cf623b) + 26 / -32 lines (commit d78fe32).
* packaging/iss/Quickstart.iss — Launch Dashboard checkbox: changed from direct shellexec to cmd /c start for reliable URL opening on all Windows versions. Em-dash fix: replaced Unicode em-dash in watermark YAML comment with ASCII hyphen to prevent OpenSearch keystore failure. OpenSearch flood_stage.frozen: removed invalid setting that crashed newer OpenSearch versions. +4 / -2 lines (commit 4812e6f) + 1 / -1 lines (commit e8a7e3c) + 3 / -4 lines (commit 44b3948).
* scripts/Full-Rebuild.ps1 — PyInstaller --clean flag to prevent stale module caching. PYTHONPATH prepend: build dir added to PYTHONPATH before PyInstaller runs to override editable install .pth files. Editable install uninstall: pip uninstall -y tinysocs before building to prevent import conflicts between editable and built packages. +33 / -1 lines across commits d8a8090, 1e5cad7, 25898af.
* src/tinysocs/tls.py — Added get_siem_ssl_context as alias for get_opensearch_kwargs() backward compatibility. +4 lines (commit 5409cff).
* pyproject.toml — Added pythonpath = ["src"] to pytest config. Updated version assertions. +1 line (commit 9bdee48).
* tests/test_nodes_api.py — Updated version assertions from v0.8.x to v0.9.0. +3 / -3 lines (commit 9bdee48).
* packaging/iss/Quickstart.iss — OpenSearch disk watermark injection: writes cluster.routing.allocation.disk.watermark settings (low=80%, high=88%, flood_stage=92%) to opensearch.yml during install. Fixes retention help text formatting. +28 / -4 lines (commit de7fc2e).

Modified Files

| File | Changes | +/- |
|---|---|---|
| src/tinysocs/api/dashboard.py | M0-M9: Security headers, settings session-token auth with timing-safe comparison, stale token detection, retention UI, storage monitoring widget (disk usage, per-index breakdown, cluster health, ingestion rate), disk space alerting, auto-purge background task, manual purge endpoint and UI, HEC token CRUD and management UI, AI consent dialog and privacy badge, LLM model configuration, product knowledge injection, demo detection enrichment (source IPs, geo, MITRE), full-width settings, full-width storage widget, TLS fix for storage widget | +1,232 / -181 |
| src/tinysocs/api/node.py | M0, M4: Centralised auth import, HEC endpoint (POST /hec/event with Bearer token auth, batching, metadata injection), rate limiting middleware, body size enforcement, optional HMAC for reads | +312 / -64 |
| tests/test_security_auth.py | M0: New file — HMAC verification across 3 styles, replay detection, timing safety, nonce validation, expired timestamps, flexible mode, malformed headers | +296 / -0 |
| config/assistant-knowledge.md | M6: New file — Product knowledge for AI assistant: 6 dashboard tabs, architecture, detection rules, HEC usage, retention, troubleshooting, federation | +231 / -0 |
| src/tinysocs/api/auth.py | M0: New file — Centralised HMAC authentication, 3 signing styles, replay cache with TTL and GC, timing-safe comparison | +169 / -0 |
| packaging/iss/Quickstart.iss | M2, M4, M5, M9: Retention wizard page, OpenSearch watermark injection, HEC token generation, privacy note on LLM page, Launch Dashboard fix, em-dash fix, flood_stage.frozen removal | +125 / -10 |
| src/tinysocs/tinybox/opensearch_bootstrap.py | M2, M4: ISM retention policies for winlog/alerts/custom indices, custom index template and policy bootstrap | +102 / -0 |
| src/tinysocs/api/bot.py | M0, M4: Auth module migration, rate limiting middleware | +89 / -57 |
| packaging/detection/rules.yml | M1: Threshold increases (50->200) and window widening (5->10min) for 3 noisy rules, cooldown_minutes (30-60) added to 9 rules | +50 / -15 |
| src/tinysocs/agent/config.py | M0: Removed hardcoded defaults, added config validation, HMAC key minimum length | +43 / -11 |
| packaging/opensearch/templates/tinysocs-custom.json | M4: New file — Index template for custom HEC logs with dynamic field mapping | +43 / -0 |
| packaging/opensearch/policies/tinysocs-custom-retention.json | M4: New file — ISM retention policy for tinysocs-custom-* indices | +35 / -0 |
| scripts/Full-Rebuild.ps1 | M9: PyInstaller --clean, PYTHONPATH prepend, editable install uninstall | +33 / -1 |
| tests/test_notifications_e2e.py | M8: Session token auth migration for test assertions | +32 / -33 |
| .gitignore | M0, M6: Expanded patterns for data/, logs/, credentials, build artifacts, knowledge doc exception | +29 / -3 |
| src/TinySocs.Agent/Detection/DetectionEngine.cs | M0, M1: Dead code cleanup, cooldown support in detection rule execution | +24 / -17 |
| scripts/Start-TinySocs-Quick.ps1 | M0: Cleaned up references to deleted debug scripts | +16 / -3 |
| OpenSearch/config/opensearch.yml | M2: Disk watermark configuration block | +12 / -1 |
| config/assistant.env | M2, M4: Retention vars, storage alert thresholds, HEC_TOKENS, NODE_AUTH_READS | +12 / -0 |
| pyproject.toml | M0, M9: Security dependencies, pytest pythonpath, project metadata | +10 / -7 |
| src/tinysocs/api/bot_actions.py | M0: Auth module migration, removed 43 lines of duplicated HMAC | +10 / -43 |
| nginx/opensearch.conf | M0: New file — Reverse proxy config for OpenSearch with TLS termination | +10 / -0 |
| .pre-commit-config.yaml | M0: New file — detect-secrets and trailing-whitespace hooks | +9 / -0 |
| docker-compose.yaml | M0: Security hardening — removed debug ports, read-only flags | +8 / -1 |
| tests/test_e2e_phase12.py | M0: Updated assertions for new auth patterns | +8 / -10 |
| src/tinysocs/orchestrator/master.py | M0: Auth module migration | +7 / -7 |
| .github/workflows/build-installer.yml | M0: Pre-commit hook integration in CI | +7 / -0 |
| .claude/launch.json | Dev server config update | +7 / -2 |
| docs/demo-script.md | M7: Version references updated to v0.9.0 | +4 / -4 |
| src/tinysocs/tls.py | M9: get_siem_ssl_context alias for backward compatibility | +4 / -0 |
| tests/test_nodes_api.py | M9: Version assertions updated to v0.9.0 | +3 / -3 |
| src/tinysocs/agent/llm_openai_tools.py | M5: Removed hardcoded model, reads OPENAI_MODEL from env | +1 / -1 |
| src/tinysocs/agent/llm_claude.py | M5: Removed hardcoded model, reads CLAUDE_MODEL from env | +1 / -1 |
| requirements.txt | M0: Added python-multipart dependency | +1 / -0 |
| kirk.pfx | M0: Deleted — leaked PKCS#12 certificate | -binary |
| data/actions_queue.jsonl | M0: Deleted — 56 lines of runtime artifacts | -56 |
| logs/ledger-health.json | M0: Deleted — 10 lines of runtime data | -10 |
| logs/verify_ledger-20251103-021505.json | M0: Deleted — 13 lines of verification output | -13 |
| logs/verify_ledger-20251103-021505.raw.txt | M0: Deleted — 14 lines of raw verification output | -14 |
| scripts/Debug-AlertDocs.ps1 | M0: Deleted — 97-line debug script | -97 |
| scripts/Debug-DashboardAuth.ps1 | M0: Deleted — 139-line debug script | -139 |
| scripts/Debug-DetectionEngine.ps1 | M0: Deleted — 232-line debug script | -232 |
| scripts/Debug-FleetMapping.ps1 | M0: Deleted — 63-line debug script | -63 |
| scripts/Fix-DashboardAuth.ps1 | M0: Deleted — 143-line one-off fix script | -143 |
| scripts/Pack-Repo.ps1 | M0: Deleted — 59-line repo packaging script | -59 |
| scripts/Send-BotAck.ps1 | M0: Deleted — 49-line debug script | -49 |
| scripts/Send-BotExec.ps1 | M0: Deleted — 96-line debug script | -96 |
| scripts/Stop-TinySocs.ps1 | M0: Deleted — 17-line convenience script | -17 |
| scripts/Test-Phase12.ps1 | M0: Deleted — 315-line integration test script | -315 |
| scripts/Start-TinySocs-Agent.ps1 | M0: Removed 2 dangling references | -2 |
| scripts/Start-TinySocs-Node.ps1 | M0: Removed 2 dangling references | -2 |

Items Not Implemented

| Item | Reason |
|---|---|
| Multi-tenancy / RBAC | One dashboard = one operator. Per-client logins with role-based access require a user management system. Build after pilot feedback. |
| Mutual TLS (mTLS) | Certificate pinning (Phase 20) verifies Site identity to the Hub. The reverse direction (Site verifying Hub) is not yet implemented. |
| Certificate rotation | Pinned certificates are static. An operator workflow for rotating and revoking certificates is future scope. |
| Cross-site correlation | Phase 21 is single-site operational hardening. Detecting patterns spanning multiple sites requires a correlation engine. |
| Per-site AI assistant context | Assistant queries master SIEM regardless of focused site. Proxying chat queries to a specific Site requires additional federation plumbing. |
| HEC schema enforcement | The HEC endpoint accepts any JSON structure. Schema validation (required fields, type checking) would improve data quality but adds complexity for V1. |
| Linux/macOS collector | Cross-platform event collection is orthogonal to production hardening. A non-Windows collector would plug into the existing node architecture. |
| Automated update delivery | Version drift is visible on Sites tab. Pushing updates to nodes requires its own update protocol. |
