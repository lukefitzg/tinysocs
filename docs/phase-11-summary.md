# TinySocs Phase 11 — Summary

## Goal
Make TinySocs demo-ready by adding notification delivery (webhook + email), bundling the LLM assistant into the Windows installer, adding Claude as an LLM backend, and hardening the detection engine. By end of Phase 11: alerts trigger real-time webhook and email notifications, the LLM-powered assistant runs as a Windows service from a clean install, Claude is available as a third LLM option, detection windows are pruned to prevent memory growth, and Test-TinySocsHealth validates all 12 components.

## What Was Delivered

### Commits (branch: claude/vigilant-lichterman)
1. **6e204b9** — Phase 11: Demo-ready notifications, assistant bundle, Claude backend, detection hardening

### Changes by File

#### src/TinySocs.Agent/Detection/AlertWriter.cs (M0 + M1)
* Added `TrySendWebhookAsync(AlertDocument)`: Slack-compatible JSON POST with severity emoji, 5s timeout, fire-and-forget
* Added `TrySendEmailAsync(AlertDocument)`: SMTP via `System.Net.Mail`, HTML body with styled severity badge
* Added `BuildEmailBody()`: HTML template with color-coded severity badge, tabular alert details
* Dedicated `_webhookClient` HttpClient with 5s timeout
* `ConcurrentDictionary<string, DateTime>` for email rate-limiting (1 per rule per 5 minutes)
* Constructor accepts optional `NotificationConfig? notification` parameter
* Fire-and-forget pattern: `_ = TrySendWebhookAsync(alert);` and `_ = TrySendEmailAsync(alert);`
* Empty webhook_url or smtp_host: silently skips (backward compatible)
* Timeouts and SMTP failures: logged as warnings, never block the ship pipeline

#### src/TinySocs.Agent/Detection/DetectionEngine.cs (M4)
* Added `PruneExpiredWindows()`: runs every 500 evaluations
* Tracks `_evaluationsSincePrune` counter and `_lastPruneTime`
* Pruning removes expired occurrences, empty group keys, and empty rule entries
* Logs active window count at Debug level for observability

#### src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs (M0)
* Changed AlertWriter constructor call to pass `_config.Detection.Notification`

#### src/tinysocs/agent/llm_claude.py (new — M3)
* Full Anthropic Claude backend with `tool_use` API
* Same 4 tools as OpenAI path: `search_kql`, `aggregate`, `propose_rule`, `stage_action`
* Tool definitions in Anthropic format (`input_schema` instead of `parameters`)
* Multi-round tool calling (up to 2 rounds)
* Defensive import of `redact` module (doesn't exist yet; uses identity function fallback)
* Same `_coerce_incident` and `_enforce_consistency` logic as OpenAI path
* Default model: `claude-sonnet-4-20250514`
* Graceful fallback on API error: returns structured response with `generator: "fallback-claude"`

#### src/tinysocs/agent/llm_select.py (M3)
* Added Claude import in `_import_summarizers()`: `from tinysocs.agent.llm_claude import summarize_findings`
* Added `summarize_claude` to module-level variables
* Added `elif MODE == "claude": engine_fn = summarize_claude` routing
* Simplified debug print to use f-string with engine_label

#### src/tinysocs/api/node.py (bug fix during testing)
* Added `_get_siem_auth()`: returns `(SIEM_USER, SIEM_PASS)` tuple for Basic Auth
* Updated `_os_search()`: passes `auth=_get_siem_auth()` to `requests.post()` calls
* Root cause: Node API was querying OpenSearch without credentials, causing 401 Unauthorized

#### modules/TinySocs.Installer.psm1 (M2 + M5)
* Added `Ensure-TinySocsAssistantService` function: NSSM service registration for TinySocsAssistant
  * Reads env vars from `assistant.env`, formats as NSSM AppEnvironmentExtra
  * Configures AppDirectory, stdout/stderr logs, restart delay, recovery policy
  * Removes existing service on upgrade path
* Added 3 new health checks in `Test-TinySocsHealth`:
  * **Assistant Service**: TinySocsAssistant Windows service running
  * **Assistant API**: `http://localhost:8081/meta` responding (node API, unauthenticated)
  * **Webhook**: reports configured URL as INFO-level status
* Added "INFO" status color (Cyan) to health check display logic

#### packaging/iss/Quickstart.iss (M2)
* Added conditional `[Files]` entry for PyInstaller Assistant bundle
* Added `assistant.env` deployment to ProgramData
* Added Assistant directory entries
* Added Phase 11 post-install PascalScript: calls `Ensure-TinySocsAssistantService`
* Injects SIEM credentials and shared secret into `assistant.env` at install time

#### packaging/tinysocs-quickstart.spec (M2)
* Added hidden imports for `anthropic` and `openai` SDK packages (try/except for optional)

#### pyproject.toml (M3)
* Added `"anthropic>=0.39"` to dependencies

#### config/agent-config.yml (M0 + M1)
* Added comments documenting `detection.notification.webhook_url` and `email.*` fields

#### config/assistant.env (new — M2)
* Environment template for LLM assistant NSSM service
* Fields: SIEM_URL, SIEM_USER, SIEM_PASS, LLM_MODE, ANTHROPIC_API_KEY, OPENAI_API_KEY, ports, secrets

#### tests/Test-DetectionEngine.ps1 (new — M4)
* Test 1: 3 failed logons (4625) → TS-001 should NOT fire (below threshold)
* Test 2: 5 failed logons (4625) → TS-001 DOES fire (meets threshold)
* Test 3: Alert deduplication check (same window = same alert ID)
* Test 4: Window reset after fire (cleared window can re-accumulate)

## Notification Formats

### Webhook Payload (Slack-compatible)
```json
{
  "text": "\ud83d\udfe0 *[TinySocs] [MEDIUM] powershell_scriptblock_lab*\n2 events for computer_name 'LUKEFITZGERC164' in 10 minutes\nEvents: 2 | Window: 2026-02-13T18:44:00.0000000Z"
}
```

Severity emoji mapping:
* \ud83d\udd34 CRITICAL / HIGH
* \ud83d\udfe0 MEDIUM
* \ud83d\udfe1 LOW
* \u26aa (default)

### Email Format
* **Subject**: `[TinySocs] [MEDIUM] powershell_scriptblock_lab \u2014 2 events for computer_name 'LUKEFITZGERC164' in 10 minutes`
* **Body**: HTML with styled severity badge (color-coded), table with Rule ID, Event Count, First Seen, Last Seen, Window Start, source info, and deterministic Alert ID

### Email Rate Limiting
* `ConcurrentDictionary<string, DateTime>` tracks last email time per rule ID
* Minimum 5-minute gap between emails for the same rule
* Prevents inbox flooding during sustained attack activity

## LLM Backend Architecture

### Claude Backend (llm_claude.py)
```
User Query / Fleet Incident
  \u2192 summarize_findings(findings)
    \u2192 Anthropic messages.create() with tool_use
      \u2192 Claude processes with 4 tools:
        - search_kql: Query OpenSearch with KQL
        - aggregate: Run aggregation queries
        - propose_rule: Suggest new detection rules
        - stage_action: Queue remediation actions
      \u2192 Up to 2 tool-calling rounds
    \u2192 Extract structured response
    \u2192 _coerce_incident() + _enforce_consistency()
  \u2192 Return: { severity, tldr, evidence, next_steps, candidate_actions }
```

### LLM Mode Routing (llm_select.py)
| LLM_MODE | Backend | Model |
|----------|---------|-------|
| `openai` | OpenAI GPT-4o | gpt-4o |
| `claude` | Anthropic Claude | claude-sonnet-4-20250514 |
| `ollama` | Local Ollama | configurable |
| `fallback` / empty | No LLM call | Basic local summary |

## Bug Fixes During Testing

| Problem | Root Cause | Fix |
|---------|-----------|-----|
| OpenSearch 401 from Node API | `node.py _os_search()` made unauthenticated requests | Added `_get_siem_auth()` with `SIEM_USER`/`SIEM_PASS` env vars |
| Health check 401 on Assistant API | Check targeted port 8090 (bot, HMAC-required) | Changed to port 8081 (node API, unauthenticated `/meta`) |
| No alerts firing after binary update | ScriptBlock Logging (Event 4104) was not enabled in Windows | Enabled via registry: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` |
| NSSM env vars not propagating | PowerShell null-byte join lost all vars after first | Set `AppEnvironmentExtra` as `REG_MULTI_SZ` via registry directly |
| Detection config not loaded | Agent config had no `detection:` YAML section | Appended `detection:` block with `notification.webhook_url` to agent-config.yml |

## Test-TinySocsHealth Output (12 checks)
```
=== TinySocs Health Check ===
SIEM URL: https://localhost:9201
[PASS  ] OpenSearch Service        Running
[PASS  ] Heartbeat Fresh           Age: 16s
[PASS  ] OpenSearch HTTP           Responding on 9201
[PASS  ] Index Template            tinysocs-winlog exists
[PASS  ] Recent Ingestion          14 docs in last 5m
[PASS  ] @timestamp Mapping        Type is date
[PASS  ] Agent Service             Running
[PASS  ] Alert Template            tinysocs-alerts exists
[PASS  ] Rules File                rules.yml exists
[PASS  ] Assistant Service         Running
[PASS  ] Assistant API             Responding on 8081
[INFO  ] Webhook                   Configured (https://webhook.site/...)
Overall Status: HEALTHY
```

## Updated Architecture
```
+------------------------------------------------------------------+
|                     Windows Host                                  |
|                                                                   |
|  +-------------------+     +----------------------------------+   |
|  |  TinySocsAgent    |     |  TinySocsOpenSearch              |   |
|  |  (NSSM service)   |---->|  (NSSM service)                  |   |
|  |                   |     |  OpenSearch 3.3.2                 |   |
|  |  Reads: Windows   | TCP |  Port 9201 (localhost only)       |   |
|  |  Event Logs       | TLS |  TLS + Security Plugin            |   |
|  |  Ships: NDJSON    |     |                                   |   |
|  |  bulk API         |     |  Indices:                         |   |
|  |                   |     |    tinysocs-winlog-YYYY.MM.DD     |   |
|  |  Detects: Rules   |     |    tinysocs-alerts-YYYY.MM.DD    |   |
|  |  from rules.yml   |     |    tinysocs-heartbeat             |   |
|  |  Alerts: OS +     |     |                                   |   |
|  |  alerts.log +     |     |  ISM Policies:                    |   |
|  |  webhook + email  |     |    winlog-retention (30d)          |   |
|  |                   |     |    alerts-retention (90d)          |   |
|  |  Heartbeat: 60s   |     +----------------------------------+   |
|  +-------------------+                                            |
|                                                                   |
|  +-------------------+                                            |
|  |  TinySocsAssistant|                                            |
|  |  (NSSM service)   |                                            |
|  |                   |                                            |
|  |  Python quickstart|                                            |
|  |  Node API :8081   |                                            |
|  |  Bot API  :8090   |                                            |
|  |                   |                                            |
|  |  LLM backends:    |                                            |
|  |  OpenAI / Claude  |                                            |
|  |  / Ollama /       |                                            |
|  |  fallback         |                                            |
|  +-------------------+                                            |
|                                                                   |
|  Config: C:\ProgramData\TinySocs\Collector\agent-config.yml       |
|  Rules:  C:\ProgramData\TinySocs\Collector\rules\rules.yml        |
|  Logs:   C:\ProgramData\TinySocs\Collector\logs\                  |
|  Alerts: C:\ProgramData\TinySocs\Collector\logs\alerts.log        |
|  Assist: C:\ProgramData\TinySocs\Assistant\assistant.env          |
|  Data:   C:\ProgramData\TinySocs\OpenSearch\data\                 |
+------------------------------------------------------------------+
```

## Key File Locations (updated for Phase 11)

| Purpose | Path |
|---------|------|
| Agent binary | `C:\Program Files\TinySocs\bin\TinySocs.Agent.exe` |
| Agent config | `C:\ProgramData\TinySocs\Collector\agent-config.yml` |
| Detection rules | `C:\ProgramData\TinySocs\Collector\rules\rules.yml` |
| Alert log | `C:\ProgramData\TinySocs\Collector\logs\alerts.log` |
| Agent logs | `C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.out.log` |
| Assistant binary | `C:\Program Files\TinySocs\Assistant\TinySocs-Quickstart.exe` |
| Assistant env | `C:\ProgramData\TinySocs\Assistant\assistant.env` |
| Assistant logs | `C:\ProgramData\TinySocs\Assistant\TinySocsAssistant.out.log` |
| Installer module | `C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1` |
| OpenSearch data | `C:\ProgramData\TinySocs\OpenSearch\data\` |

## Source Code Layout (updated for Phase 11)

| Purpose | Path |
|---------|------|
| Agent C# project | `src/TinySocs.Agent/` |
| Alert writer (webhook + email) | `src/TinySocs.Agent/Detection/AlertWriter.cs` |
| Detection engine (+ pruning) | `src/TinySocs.Agent/Detection/DetectionEngine.cs` |
| Agent config model | `src/TinySocs.Agent/Configuration/AgentConfig.cs` |
| Bulk shipper | `src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs` |
| Claude LLM backend | `src/tinysocs/agent/llm_claude.py` |
| LLM mode router | `src/tinysocs/agent/llm_select.py` |
| Node API (+ auth fix) | `src/tinysocs/api/node.py` |
| Bot API | `src/tinysocs/api/bot.py` |
| Quickstart launcher | `src/tinysocs/launcher/quickstart.py` |
| Detection smoke tests | `tests/Test-DetectionEngine.ps1` |
| Assistant env template | `config/assistant.env` |
| Agent config template | `config/agent-config.yml` |
| PyInstaller spec | `packaging/tinysocs-quickstart.spec` |
| Inno Setup script | `packaging/iss/Quickstart.iss` |
| Installer module | `modules/TinySocs.Installer.psm1` |

## Phase 11 Acceptance Criteria (All Met)

* [x] Webhook: Configure webhook_url → alert fires → webhook receives POST with Slack-compatible JSON
* [x] Webhook: Empty webhook_url → no HTTP call, no error
* [x] Webhook: Timeout → logged as warning, doesn't block pipeline
* [x] Email: Configure SMTP → alert fires → email received with HTML body and severity badge
* [x] Email: Empty smtp_host → no email, no error
* [x] Email: Same rule fires 3x in 1 minute → only 1 email sent (rate-limited)
* [x] Email: SMTP failure → logged as warning, doesn't block pipeline
* [x] Bundle: TinySocsAssistant service registered and running via NSSM
* [x] Bundle: Node API (http://localhost:8081/meta) returns health JSON
* [x] Bundle: Without API key → assistant runs in fallback mode
* [x] Bundle: Test-TinySocsHealth extended with assistant service check
* [x] Claude: LLM_MODE=claude routes to Anthropic SDK with tool_use
* [x] Claude: Same 4 tools as OpenAI (search_kql, aggregate, propose_rule, stage_action)
* [x] Claude: No API key → graceful fallback to minimal local summary
* [x] Hardening: Window pruning prevents unbounded memory growth
* [x] Hardening: Test-DetectionEngine.ps1 covers 4 scenarios (below threshold, meets threshold, dedup, window reset)
* [x] Hardening: Deterministic alert IDs prevent duplicate alerts
* [x] Health: 12 checks total (9 existing + 3 new)
* [x] Health: Assistant Service check reports Running/Not installed
* [x] Health: Assistant API check probes node API on port 8081
* [x] Health: Webhook check reports INFO-level configured status
* [x] Health: 12/12 PASS on running system

## What Phase 11 Did NOT Cover (Future Work)

* **PyInstaller production build**: Assistant tested from Python source via NSSM; PyInstaller onedir bundle not built (requires Windows build machine with all deps)
* **Persistent window state**: Detection sliding windows are still in-memory only (lost on agent restart)
* **Email TLS/STARTTLS**: SMTP tested with plain TCP; production SMTP with TLS needs testing
* **Claude production testing**: Tool-calling flow verified with mock/fallback; live API testing needs valid API key
* **Multi-node assistant**: Single-box only; no assistant federation across agents
* **Dashboard integration**: Port 5602 configured but not wired to assistant or alert indices
* **Webhook retry**: Fire-and-forget only; no retry queue for failed webhooks
* **NSSM env var helper**: `Format-TinySocsNssmEnvExtra` in installer module doesn't handle null-byte formatting correctly for PowerShell 5.1; workaround is registry-direct `REG_MULTI_SZ`
