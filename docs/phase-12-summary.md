# Phase 12 Summary — Operator Experience & Visibility

**Theme**: "See it, understand it, act on it"

## Overview

Phase 12 closes the operator experience gaps left by Phase 11. Operators can now see what's happening (dashboards), get notified (webhook/email), act on LLM recommendations (action execution), and receive daily summaries. New documentation makes the system accessible to operators who haven't read the source code.

## Milestones Delivered

### M0 — OpenSearch Dashboards: Alert & Fleet Visibility

**Files**:
- `packaging/opensearch/dashboards/tinysocs-dashboards.ndjson` — Saved objects (NDJSON export)
- `modules/TinySocs.Installer.psm1` — `Import-TinySocsDashboards` function
- `packaging/iss/Quickstart.iss` — Dashboard file bundling + auto-import

**Dashboards**:
1. **Alert Timeline** — Bar chart of alerts over time by severity, with severity pie chart and top hosts by alert count
2. **Detection Rules** — Tables of active rules with fire counts in last 24h and 7d
3. **Fleet Health** — Agent heartbeat status table and event throughput line chart per host
4. **Event Explorer** — Saved search for `tinysocs-winlog-*` with pre-configured columns (timestamp, channel, event_id, message)

**Index Patterns**: `tinysocs-winlog-*`, `tinysocs-alerts-*`, `tinysocs-heartbeat`

**Import**: POST to `/_dashboards/api/saved_objects/_import` during post-install, with retry logic for Dashboards startup delay.

### M1 — Installer Wizard: Notification Configuration

**Files**:
- `packaging/iss/Quickstart.iss` — New wizard pages (Notifications, Email Alerts)

**Wizard Pages**:
1. **Notifications** page (after Schedules): Webhook URL field
2. **Email Alerts** page: Enable toggle, SMTP host/port, from/to fields

**Post-install**: Values written to `agent-config.yml` via `Set-TinySocsYamlScalar`. Skipping both pages leaves config empty (backward compatible).

### M2 — Action Execution Engine

**Files**:
- `src/tinysocs/actions/executor.py` — Action execution engine with state machine
- `src/tinysocs/actions/handlers/block_ip.py` — Firewall rule handler via `netsh advfirewall`
- `src/tinysocs/actions/handlers/disable_user.py` — Account disable via `net user` / `Disable-LocalUser`
- `src/tinysocs/actions/handlers/isolate_host.py` — Outbound deny-all with SIEM exception
- `src/tinysocs/api/bot.py` — New endpoints: `/bot/approve`, `/bot/actions/{id}/status`
- `src/tinysocs/api/bot_actions.py` — `write_action()` function + executor integration

**Action States**: `staged` -> `approved` -> `executing` -> `completed` | `failed`

**Safety**:
- All actions default to `dry_run: true`
- Operator must explicitly POST `/bot/approve` to execute
- Protected accounts list prevents disabling `Administrator`, `SYSTEM`, etc.
- Loopback IP blocking is refused
- Every action logged to `actions_audit.jsonl`

**Handlers**:
| Handler | Command | Reversible |
|---------|---------|------------|
| `block_ip` | `netsh advfirewall firewall add rule` (in + out) | Delete rules |
| `disable_user` | `net user /active:no` or `Disable-LocalUser` | `net user /active:yes` |
| `isolate_host` | Deny-all outbound + allow SIEM exception | Delete rules |

### M3 — Daily Summary Report

**Files**:
- `src/tinysocs/reporting/daily_summary.py` — Report generator + email sender
- `src/tinysocs/reporting/templates/daily_summary.html` — HTML email template
- `modules/TinySocs.Installer.psm1` — `Register-TinySocsDailySummaryTask` function

**Report Contents**:
- Total alerts by severity with trend indicator (up/down vs yesterday)
- Top 5 rules that fired
- Top 5 hosts with alerts
- New hosts seen (first appearance)
- "All quiet" message when no alerts

**Delivery**: SMTP email via `smtplib` with STARTTLS. Falls back to stdout if no SMTP configured.

**CLI**: `python -m tinysocs.reporting.daily_summary --to admin@company.com`

**Scheduled Task**: `TinySocs\DailySummary` runs daily at 07:00 via `Register-TinySocsDailySummaryTask`.

### M4 — Operator Documentation

**Files**:
- `docs/getting-started.md` — Installation + first 10 minutes guide
- `docs/operator-runbook.md` — Day-to-day operations reference
- `docs/troubleshooting.md` — 10 common issues with fixes
- `README.md` — Updated with architecture diagram, feature list, documentation links

## Files Changed

| File | Change |
|------|--------|
| `packaging/opensearch/dashboards/tinysocs-dashboards.ndjson` | **New** — Dashboard saved objects |
| `src/tinysocs/actions/__init__.py` | **New** — Package init |
| `src/tinysocs/actions/executor.py` | **New** — Action execution engine |
| `src/tinysocs/actions/handlers/__init__.py` | **New** — Package init |
| `src/tinysocs/actions/handlers/block_ip.py` | **New** — block_ip handler |
| `src/tinysocs/actions/handlers/disable_user.py` | **New** — disable_user handler |
| `src/tinysocs/actions/handlers/isolate_host.py` | **New** — isolate_host handler |
| `src/tinysocs/reporting/__init__.py` | **New** — Package init |
| `src/tinysocs/reporting/daily_summary.py` | **New** — Daily summary generator |
| `src/tinysocs/reporting/templates/daily_summary.html` | **New** — HTML email template |
| `src/tinysocs/api/bot.py` | **Modified** — Added /bot/approve, /bot/actions/{id}/status, executor integration |
| `src/tinysocs/api/bot_actions.py` | **Modified** — Added write_action(), executor integration |
| `modules/TinySocs.Installer.psm1` | **Modified** — Added Import-TinySocsDashboards, Register-TinySocsDailySummaryTask |
| `packaging/iss/Quickstart.iss` | **Modified** — Dashboard files, notification wizard pages, post-install hooks |
| `pyproject.toml` | **Modified** — Version bump to 0.7.0, added daily-summary entry point |
| `README.md` | **Modified** — Complete rewrite with architecture, features, docs |
| `docs/getting-started.md` | **New** — Getting started guide |
| `docs/operator-runbook.md` | **New** — Operator runbook |
| `docs/troubleshooting.md` | **New** — Troubleshooting guide |
| `docs/phase-12-summary.md` | **New** — This summary |
