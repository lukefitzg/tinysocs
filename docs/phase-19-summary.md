Phase 19 Summary — Federation Deployment
Theme: "Installer role support"

Overview

Phase 19 made TinySocs federation deployable by a non-technical operator. The Inno Setup installer now presents two roles — Hub and Site — replacing the old TinyBox/Node/Master trichotomy. A Hub install generates a shared secret, configures the dashboard and AI assistant, and opens firewall ports. A Site install collects the Hub address, shared secret, and site name, generates a self-signed TLS certificate, writes federation config to assistant.env, registers a TinySocsNode NSSM service with TLS and SIEM credentials baked into environment variables, creates a firewall rule for port 8081, and runs a post-install health check against https://127.0.0.1:8081/meta. Both the node API and dashboard API now start with TLS when certificates are present — no more plaintext HTTP on any port. The quickstart launcher (PyInstaller bundle) passes ssl_certfile and ssl_keyfile to both uvicorn servers and picks the URL scheme based on whether certs exist. Post-install dashboard fixes resolved three classes of bugs: severity aggregations that silently returned empty buckets because the queries used a nonexistent .keyword sub-field on a keyword-mapped field, medium/low severity counts that were missing from every code path, and nodes showing "Unreachable" because the node API wasn't binding TLS. The AI chat assistant was also fixed — it now queries OpenSearch for real hostnames and injects live environment context into the system prompt so it stops generating placeholder queries like source.computer_name:"your_computer_name". All 399 tests pass. Two machines can now form a federation by running the same installer with different role selections.

Stats: 11 files changed (2 new), +1,273 / -131 lines across 6 milestones (M0-M5), 399 tests (35 new), all passing.

Commits

| Hash | Message |
|---|---|
| ccbf18b | Phase 19 post-install fixes: TLS, severity, node reachability, dashboard polish |
| 33fa1b9 | Fix AI assistant using placeholder hostnames in queries |

Milestones Delivered

M0 — Installer Role Simplification

Goal: Replace the confusing TinyBox/Node/Master role selection with two clear roles — Hub (central dashboard) and Site (remote monitored location).

Files:
* packaging/iss/Quickstart.iss — Role constants replaced: ROLE_HUB = 0, ROLE_SITE = 1 (lines 324-325). Role selection page shows two radio buttons with plain-English descriptions: "Hub (recommended) — Central dashboard that collects and displays security data from all your sites" and "Site — Remote location that monitors local computers and reports to your Hub". GetSelectedRole() and all conditional branching updated throughout the installer. Old TinyBox/Node/Master terminology removed from all user-visible strings.

M1 — Site Role Configuration

Goal: When the operator selects Site, the installer collects Hub connection details and site identity through guided wizard pages.

Files:
* packaging/iss/Quickstart.iss — Three new wizard pages for Site role:
  1. Hub Connection — "Enter the address of your Hub server" with text input for Hub IP/hostname. Validates format and reachability.
  2. Security — "Enter the shared secret from your Hub" with password-masked input. Validates non-empty and minimum length.
  3. Site Identity — "Give this site a name" with text input pre-filled from computer name. Sanitised for use as node_id (alphanumeric + hyphens, max 63 chars).

Config written to assistant.env: TINYSOCS_NODE_ID, MASTER_SHARED_SECRET, SIEM_URL, SIEM_USER, SIEM_PASS, TINYSOCS_HUB_URL, TINYSOCS_TLS_CERT, TINYSOCS_TLS_KEY.

* tests/test_installer_config.py — New file: 28 tests for site name sanitisation, shared secret validation, URL config, hub address validation.

M2 — Hub Role Configuration

Goal: Hub install generates and displays a shared secret, configures federation node URLs, and provides a summary page.

Files:
* packaging/iss/Quickstart.iss — Hub wizard pages: shared secret auto-generated (32-char base64), displayed with copy-to-clipboard button, persisted as MASTER_SHARED_SECRET. TINYSOCS_NODES written to assistant.env with default https://127.0.0.1:8081. Remote site URLs configurable. Summary page shows all federation settings before install proceeds.

M3 — Mandatory Self-Signed TLS

Goal: Every TinySocs service communicates over HTTPS. No plaintext HTTP on any port.

Files:
* modules/TinySocs.Installer.psm1 — New-TinySocsNodeCert generates self-signed certificates (tinysocs-node-cert.pem, tinysocs-node-key.pem) in C:\ProgramData\TinySocs\certs. New-TinySocsDashboardCert does the same for the dashboard. Both called during install if certs don't already exist. +111 lines.
* src/tinysocs/launcher/quickstart.py — Both uvicorn servers receive ssl_certfile and ssl_keyfile. Scheme-aware default: _scheme = "https" if (tls_cert and tls_key) else "http". TINYSOCS_NODES default uses the detected scheme.
* src/tinysocs/api/node.py — TLS-aware startup. Node API serves HTTPS when certs are configured.
* src/tinysocs/api/bot.py — TLS-aware startup for bot/dashboard API.
* tests/test_tls_config.py — New file: 7 tests for TLS cert handling, HTTPS startup, default URL verification.

M4 — Service Registration & Startup

Goal: The installer registers Windows services with correct environment, display names, firewall rules, and health checks.

Files:
* packaging/iss/Quickstart.iss — Site install post-script:
  1. NSSM service registration: TinySocsNode with DisplayName "TinySocs Site Node", Description "TinySocs federation node for remote site monitoring".
  2. Environment variables baked into NSSM AppEnvironmentExtra: PORT, SIEM_URL, SIEM_SSL_VERIFY, PRIVACY_MODE, TINYSOCS_NODE_ID, MASTER_SHARED_SECRET, TINYSOCS_TLS_CERT, TINYSOCS_TLS_KEY.
  3. Firewall rule: New-NetFirewallRule "TinySocs Node API" — TCP 8081 inbound, idempotent (checks before creating).
  4. Firewall rule: New-NetFirewallRule "TinySocs Dashboard" — TCP 8090 inbound (in Phase 14 network extras section).
  5. Health check: probes https://127.0.0.1:8081/meta via curl, 15 attempts x 2 seconds = 30 seconds max. Warns on failure (non-fatal).

* modules/TinySocs.Installer.psm1 — Ensure-TinySocsAssistantService enhanced with health probe on port 8090 after service start. 10-second wait with service status polling.

M5 — Tests

Goal: Unit tests for all Phase 19 changes. No regressions.

Files:
* tests/test_installer_config.py — New file: 28 tests. Site name sanitisation (spaces, special chars, Unicode, length limits), shared secret validation (empty, short, valid), URL configuration (scheme defaults, port handling), hub address validation (IP, hostname, reachability).
* tests/test_tls_config.py — New file: 7 tests. TLS cert path resolution, HTTPS startup with certs, HTTP fallback without certs, default URL scheme detection, cert file existence checks.
* tests/test_demo_mode.py — Extended: 24 additional lines for medium/low severity in demo data.

Full test suite: 399 passed, 0 failed, 0 skipped.

Post-Install Dashboard Fixes

Three classes of bugs discovered during Windows VM rebuild cycles:

Fix 9 — Severity aggregations returning empty buckets:
Root cause: All 7 OpenSearch aggregation queries used alert.severity.keyword, but the index template maps alert.severity directly as type: keyword — there is no .keyword sub-field. Changed to alert.severity in node.py (3 locations) and dashboard.py (4 locations).

Fix 8B — Medium/low severity missing from display:
The dashboard only tracked critical and high. Added alerts_medium and alerts_low to: node_info initialisation, primary extraction path, fallback code for unreachable nodes, aggregate computation (total_medium, total_low), both aggregate banners (Sites + Overview), site card JavaScript rendering (medium in orange, low in yellow), and demo mode data.

Fix 10 — Node showing "Unreachable" on Sites tab:
Root cause: Installer wrote TINYSOCS_NODES=https://127.0.0.1:8081 but the node API wasn't binding TLS. Fixed by passing ssl_certfile and ssl_keyfile to the node's uvicorn server in quickstart.py. Added unreachable-node fallback in dashboard.py that queries OpenSearch directly for alert and fleet data when a node can't be reached.

Fix 11 — AI assistant using placeholder hostnames:
Root cause: The chat system prompt had no context about which hosts exist in the environment. When a user asked "anything going on?", the LLM generated literal placeholder queries (source.computer_name:"your_computer_name") that matched nothing. Fixed by adding _chat_get_environment_context() which queries OpenSearch for real hostnames and alert summary, injecting the results into the system prompt. Added query strategy guidance telling the LLM to search all alerts for broad questions and never invent hostnames.

Modified Files

| File | Changes |
|---|---|
| packaging/iss/Quickstart.iss | M0-M4: Role constants (Hub/Site), 3 Site wizard pages, Hub secret generation, service registration, NSSM env vars with TLS paths, firewall rules, health check. +515 / -93 lines. |
| modules/TinySocs.Installer.psm1 | M3-M4: TLS cert generation functions, assistant service health probe. +111 lines. |
| src/tinysocs/api/dashboard.py | Fix 8B-11: Severity aggregation field fix, medium/low display, unreachable-node fallback, AI assistant environment context injection. +244 / -17 lines. |
| src/tinysocs/api/node.py | Fix 9: Severity aggregation field fix (3 locations). +68 / -13 lines. |
| src/tinysocs/launcher/quickstart.py | M3: TLS for both uvicorn servers, scheme-aware URL default. +6 / -3 lines. |
| src/tinysocs/api/bot.py | M3: TLS-aware startup. +22 / -5 lines. |
| src/tinysocs/reporting/mitre_coverage.py | Minor adjustments. +41 lines. |
| packaging/tinysocs-quickstart.spec | PyInstaller spec updates for TLS cert bundling. +5 lines. |
| tests/test_installer_config.py | New file: 28 tests for installer config validation. +190 lines. |
| tests/test_tls_config.py | New file: 7 tests for TLS configuration. +178 lines. |
| tests/test_demo_mode.py | Extended: medium/low severity in demo data. +24 lines. |

Items Not Implemented

| Item | Reason |
|---|---|
| Two-machine federation end-to-end test | Code complete. Requires second Windows PC with installer to validate Hub-Site communication. Next step. |
| Node auto-registration | Nodes configured manually via installer wizard. Auto-registration (node phones home, Hub approves) is future scope for large deployments. |
| Cross-site AI assistant | Assistant queries local SIEM only. Per-site AI context (proxy chat tool calls to focused site) requires additional proxy plumbing. |
| Certificate authority chain | Each node generates independent self-signed certs. A shared CA for mutual TLS between Hub and Sites would improve security for WAN deployments. |
| Installer upgrade path | Fresh installs work. Upgrading an existing Hub or Site (preserving config, rotating secrets) needs testing and may need migration logic. |
