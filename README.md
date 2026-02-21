# TinySocs

A lightweight, privacy-first, federated SIEM assistant. Wraps OpenSearch and uses an LLM (Claude, OpenAI, or local Ollama) to query, analyze, and summarize security events — then recommends and executes response actions with operator approval.

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
- **Detection Engine** — YAML-based rules with threshold grouping, enrichment, and alerting
- **LLM Assistant** (Python) — Analyzes alerts via Claude/OpenAI/Ollama, recommends actions
- **Bot Bridge** (FastAPI) — Stages actions, manages approval workflow, executes with audit trail
- **OpenSearch Dashboards** — Pre-built dashboards for alerts, rules, fleet health, and event exploration
- **Daily Summary** — Automated email digest of alert activity

## Quick Start

### Windows Installer

1. Download `TinySocs-Setup.exe`
2. Run as Administrator, select **TinyBox** role
3. Follow the wizard (configure secrets, notifications)
4. Verify: `Test-TinySocsHealth` (expect 16/16 PASS)
5. Open dashboard: `http://localhost:8090` (or `https://<ip>:8090` in network mode)

See the full [Getting Started Guide](docs/getting-started.md).

### Development Setup

```bash
git clone <repo>
cd tinysocs
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
cp .env.example .env  # fill in values
docker compose up -d  # start OpenSearch + Dashboards
python -m tinysocs.api.node  # start node API (port 8081)
python -m tinysocs.api.bot   # start bot API (port 8090)
```

## Configuration

| Setting | Location | Purpose |
|---------|----------|---------|
| Agent config | `C:\ProgramData\TinySocs\Collector\agent-config.yml` | Event collection, detection, notifications |
| Detection rules | `C:\ProgramData\TinySocs\Collector\rules\rules.yml` | YAML detection rules |
| Assistant env | `C:\ProgramData\TinySocs\Assistant\assistant.env` | LLM API keys, SIEM credentials |
| Docker env | `.env` | OpenSearch credentials for dev |

## Key Features

- **Detection Engine**: YAML-based rules with KQL queries, threshold grouping, rDNS enrichment
- **Multi-LLM Support**: Claude (Anthropic), GPT-4o (OpenAI), local models (Ollama)
- **Action Execution**: `block_ip`, `disable_user`, `isolate_host` with dry-run and audit trail
- **Operator Dashboard**: HTTPS-capable web UI with alerts, detection rules, fleet health, event explorer, AI assistant
- **Compliance Reports**: One-click NIST CSF, HIPAA, PCI DSS coverage reports
- **Sysmon Integration**: Auto-deploy Sysmon with optimised configuration for enhanced endpoint telemetry
- **Notifications**: Slack/Teams webhooks, SMTP email alerts with retry queue
- **Daily Summaries**: Automated HTML email digests with alert trends
- **Privacy-First**: Field redaction, hashing, truncation; data stays on-prem
- **Federated**: Multi-node architecture with HMAC-authenticated evidence ledger
- **Schema-Defined**: JSON Schema for events and alerts, with compliance tests
- **40+ Detection Rules**: MITRE ATT&CK mapped across 8 categories
- **CI/CD**: GitHub Actions with Windows + Linux test runners

## Documentation

- [Getting Started](docs/getting-started.md) — Install and verify in <15 minutes
- [Operator Runbook](docs/operator-runbook.md) — Day-to-day operations reference
- [Troubleshooting](docs/troubleshooting.md) — Common issues and fixes
- [Detection Coverage](docs/detection-coverage.md) — Rules matrix with MITRE ATT&CK mapping
- [Pilot Guide](docs/pilot-guide.md) — Pilot evaluation walkthrough
- [FAQ](docs/faq.md) — Common questions and answers
- [MSSP Guide](docs/mssp-guide.md) — Multi-client deployment for MSSPs
- [Event Schema](schema/event-schema.json) — JSON Schema for `tinysocs-winlog-*` documents
- [Alert Schema](schema/alert-schema.json) — JSON Schema for `tinysocs-alerts-*` documents

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

MIT
