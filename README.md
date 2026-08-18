# TinySocs

A tiny, self-hosted SIEM for small Windows networks. One installer stands up event
collection, a detection engine, a bundled OpenSearch backend, and a web dashboard with
an optional AI assistant — on your own hardware, with your data staying on-prem.

**Free to use. No account, no waitlist, no tiers.** TinySocs is a solo side project
provided **as-is with no support** — see [SUPPORT.md](SUPPORT.md) before filing an
issue, and [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) for the honest list of rough
edges. If it's useful to you, a GitHub star is plenty.

Built for homelabs, tinkerers, students, and small IT shops that want to see what's
happening on a handful of Windows boxes without spending a week standing up Wazuh or
Security Onion. Windows-only agent; caps out around ~100 endpoints per node.

## Architecture

```
 Windows Events                    OpenSearch         OpenSearch Dashboards
      |                                |                      |
  TinySocs Agent  -->  Bulk API  -->  SIEM  <--  Dashboards UI (port 5602)
      |                                |
  Detection Engine                 Alert Indices
      |                                |
  LLM Assistant   <--  query  <--  tinysocs-alerts-*
      |                            tinysocs-winlog-*
  Action Staging  -->  Operator Approval  -->  Execution
      |
  Notifications (Webhook / Email)
```

**Components**:
- **TinySocs Agent** (C#) — Collects Windows events, ships to OpenSearch, runs detection rules
- **Detection Engine** — YAML-based threshold rules with grouping, enrichment, and alerting
- **LLM Assistant** (Python) — Analyzes alerts via Claude/OpenAI/Ollama, recommends actions
- **Bot Bridge** (FastAPI) — Stages actions, manages approval workflow, executes with audit trail
- **OpenSearch Dashboards** — Pre-built dashboards for alerts, rules, fleet health, and event exploration
- **Daily Summary** — Automated email digest of alert activity

## Quick Start

### Windows Installer

1. Download `TinySocs-Setup.exe` from the [latest release](https://github.com/lukefitzg/tinysocs/releases)
2. Run as Administrator; pick the **Hub** role (the default — **Site** is only for
   multi-node setups, which are experimental)
3. Follow the wizard (secrets are auto-generated; configure notifications if you want them)
4. Verify: run `Test-TinySocsHealth` in an elevated PowerShell (see
   [Getting Started](docs/getting-started.md) — most checks should PASS; a few report
   INFO/WARN on a minimal install and that's expected, the guide says which)
5. Open the dashboard: `http://localhost:8090` (or `https://<ip>:8090` in network mode —
   read the network-mode caveats in [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) first)

### Development Setup

```bash
git clone https://github.com/lukefitzg/tinysocs.git
cd tinysocs
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
cp .env.example .env       # then CHANGE the placeholder passwords/secrets
docker compose up -d       # start OpenSearch + Dashboards first
python -m tinysocs.api.node  # node API (port 8081)
python -m tinysocs.api.bot   # bot API + dashboard (port 8090)
```

## Detection rules — the honest numbers

The agent's C# engine defines **39 threshold rules**, of which **19 ship enabled**
(the rest are off by default — they're noisy or environment-specific; turn them on if
they fit your network). The 19 enabled rules cover **16 MITRE ATT&CK techniques across
8 tactics**; all 39 cover 27 techniques across 10 tactics. There is also a 50-rule
KQL catalogue in the Python tree that **does not run** in a default install — it's a
rule library, not live detection. Counts verified against
`packaging/detection/rules.yml`, 2026-08-18.

Every enabled rule has an Atomic Red Team test defined and an xUnit firing/silent test
pair. As of the last harness run (2026-07-08), 8 of the 19 have been proven end-to-end
against a live attack on a real Windows VM; the rest are proven on synthetic events or
blocked by environment prerequisites. Details, including the misses:
[docs/pilot-ruleset.md](docs/pilot-ruleset.md).

**Rules are yours to edit.** They're plain YAML
(`C:\ProgramData\TinySocs\Collector\rules\rules.yml`), hot-reloaded, and there's a
Rule Builder in the dashboard for custom KQL rules. Tinker away.

## Configuration

| Setting | Location | Purpose |
|---------|----------|---------|
| Agent config | `C:\ProgramData\TinySocs\Collector\agent-config.yml` | Event collection, detection, notifications |
| Detection rules | `C:\ProgramData\TinySocs\Collector\rules\rules.yml` | YAML detection rules |
| Assistant env | `C:\ProgramData\TinySocs\Assistant\assistant.env` | LLM API keys, SIEM credentials |
| Docker env | `.env` | OpenSearch credentials for dev |

## Key Features

- **Detection Engine**: YAML-based rules with threshold grouping, rDNS enrichment, hot reload
- **Multi-LLM Support**: Claude (Anthropic), GPT-4o (OpenAI), local models (Ollama)
- **Action Execution**: `block_ip`, `disable_user`, `isolate_host` with dry-run and audit trail
- **Operator Dashboard**: web UI with alerts, detection rules, fleet health, event explorer, AI assistant
- **Compliance Reports**: NIST CSF, HIPAA, PCI DSS coverage reports
- **Sysmon Integration**: Auto-deploy Sysmon with optimised configuration
- **Notifications**: Slack/Teams webhooks, SMTP email alerts with retry queue
- **Daily Summaries**: Automated HTML email digests with alert trends
- **Privacy-First**: Field redaction, hashing, truncation; data stays on-prem
- **File Integrity Monitoring**: SHA-256 baseline + change detection for critical system files
- **Threat Intelligence**: AbuseIPDB, AlienVault OTX, GreyNoise enrichment with SQLite cache
- **Federation** (experimental): multi-node architecture with HMAC-authenticated evidence ledger
- **Schema-Defined**: JSON Schema for events and alerts, with compliance tests
- **CI/CD**: GitHub Actions with Windows + Linux test runners

## Documentation

- [Getting Started](docs/getting-started.md) — Install and verify in under an hour
- [Operator Runbook](docs/operator-runbook.md) — Day-to-day operations reference
- [Troubleshooting](docs/troubleshooting.md) — Common issues and fixes
- [FAQ](docs/faq.md) — Common questions and answers
- [Known Limitations](KNOWN-LIMITATIONS.md) — Read this before exposing anything to a network
- [Detection Coverage](docs/detection-coverage.md) — MITRE ATT&CK coverage, enabled vs defined
- [Validation ledger](docs/pilot-ruleset.md) — Rule-by-rule evidence of what fires
- [Event Schema](schema/event-schema.json) / [Alert Schema](schema/alert-schema.json)

## Env Toggles

| Variable | Values | Default |
|----------|--------|---------|
| `LLM_MODE` | `claude`, `openai`, `ollama` | `claude` |
| `SIEM_BACKEND` | `opensearch` | `opensearch` |
| `SIEM_URL` | URL | `https://localhost:9201` |
| `BOT_PORT` | port | `8090` |
| `NODE_PORT` | port | `8081` |

See `.env.example` for the full list.

## License

Business Source License 1.1 (BSL-1.1) — **source-available, not OSI open source**.
You can use it in production for free, read and modify all the code, and each released
version converts to Apache 2.0 four years after its public release. What you can't do
is offer TinySocs itself to third parties as a competing hosted or embedded service.
Full text in [LICENSE](LICENSE). Third-party components keep their own licences
(see attributions in `vendor/` and the docs).
