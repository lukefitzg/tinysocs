# Phase 13: Hardening, Schema & Operator Control

> Theme: "Lock it down, write it down."

## Overview

Phase 13 strengthened TinySocs across authentication, notifications, detection coverage, reliability, installer polish, formal schemas, and documentation. The version is bumped from 0.7.1 to 0.8.0.

## Milestones

### M0: Password & Authentication Overhaul

**Goal**: Unify the dashboard and OpenSearch passwords into a single credential.

- `SIEM_PASS` now serves as the dashboard admin password (single-password model)
- Dashboard shows a first-time password setup view when `SIEM_PASS` is empty
- Added API endpoints: `/api/settings/password-status`, `/api/settings/setup-password`, `/api/settings/change-password`
- Installer messaging updated to clarify the dual-purpose password
- Settings API returns 403 `password_not_set` when no password is configured

### M1: Dashboard Notification Configuration

**Goal**: Allow operators to configure webhook and email notifications from the dashboard UI.

- Added `agent-config.yml` read/write helpers to the dashboard
- New API endpoints: `GET/POST /api/settings/notifications`, `POST /api/settings/test-webhook`, `POST /api/settings/test-email`
- Dashboard Settings page now includes webhook URL, SMTP host/port/from/to fields
- Test buttons for both webhook and email (sends a real test message)
- Saves directly to `agent-config.yml` with proper YAML nesting

### M2: E2E Notification Tests

**Goal**: Automated tests for webhook, email, and password API flows.

- 15 tests in `tests/test_notifications_e2e.py`
- Local HTTP server captures webhook POSTs
- Local aiosmtpd captures SMTP email
- Tests cover: delivery success, invalid URLs, missing config, auth, payload format, MIME encoding, rate limiting
- Password API regression tests for setup/change/status

### M3: Detection Coverage Expansion

**Goal**: Expand from ~19 rules to 40+ with full MITRE ATT&CK mapping.

- Added 15 new production KQL rules to `rules.yaml`
- Added 15 matching C# `threshold_by_key` rules to `rules.yml`
- Added action snippets for all new rules to `actions.yaml`
- Categories added: Credential Access, Lateral Movement, Defence Evasion, Persistence, Exfiltration
- 19 validation tests in `tests/test_detection_rules.py`

### M4: Webhook Retry Queue

**Goal**: Disk-backed retry for failed webhook and email notifications.

- New `RetryQueue.cs` — JSONL-backed at `%ProgramData%\TinySocs\Collector\notification_queue.jsonl`
- Background timer processes queue every 30 seconds
- Exponential backoff: `base * 2^attempts`
- Entries older than `max_age_seconds` are discarded
- `AlertWriter.cs` updated to enqueue on webhook/email failure
- `AgentConfig.cs` extended with `NotificationRetryConfig`
- `agent-config.yml` extended with `retry:` section

### M5: Installer & Operational Polish

**Goal**: Robust upgrade path, extended health checks, smoke testing, clean uninstall.

- **Uninstaller extended**: Scheduled task removal (`TinySocs\DailySummary`), CredMan cleanup, NSSM service removal
- **Health checks 13-14**: Webhook delivery POST test, SMTP EHLO handshake
- **`Invoke-TinySocsSmokeTest`**: Generates test events, waits, verifies alerts in index
- **Upgrade path validation**: `PrepareToInstall` backs up configs, stops services; post-install restores any clobbered configs via hash comparison
- AppVersion bumped to 0.8.0

### M6: Event Schema Formalisation

**Goal**: Machine-readable schemas for all document types.

- `schema/event-schema.json` — JSON Schema (draft 2020-12) for `tinysocs-winlog-*` documents
- `schema/alert-schema.json` — JSON Schema for `tinysocs-alerts-*` documents
- `tests/test_schema_compliance.py` — 31 tests covering schema validity, sample document validation, OpenSearch template consistency, C# model alignment
- `docs/detection-coverage.md` — Full MITRE ATT&CK coverage matrix with data source requirements

### M7: Documentation

**Goal**: Keep all docs current with Phase 13 changes.

- Updated `docs/getting-started.md`: health check count (14), password setup step, smoke test, detection coverage link
- Updated `docs/operator-runbook.md`: health check count, webhook retry queue, notification logs, upgrade procedure, smoke test
- Updated `docs/troubleshooting.md`: 3 new items (dashboard password, retry queue stuck, upgrade config clobber)
- Updated `README.md`: health check count, new feature bullets, documentation links
- Created `docs/phase-13-summary.md` (this file)

## Files Changed

### New Files

| File | Purpose |
|---|---|
| `schema/event-schema.json` | JSON Schema for event documents |
| `schema/alert-schema.json` | JSON Schema for alert documents |
| `tests/test_schema_compliance.py` | Schema compliance tests (31 tests) |
| `tests/test_notifications_e2e.py` | Notification E2E tests (15 tests) |
| `tests/test_detection_rules.py` | Detection rule validation tests (19 tests) |
| `src/TinySocs.Agent/Notification/RetryQueue.cs` | JSONL-backed notification retry queue |
| `docs/detection-coverage.md` | MITRE ATT&CK detection coverage matrix |
| `docs/phase-13-summary.md` | This summary |

### Modified Files

| File | Changes |
|---|---|
| `src/tinysocs/api/dashboard.py` | Password overhaul, notification config UI and APIs |
| `src/tinysocs/agent/detections/rules.yaml` | 15 new production rules |
| `packaging/detection/rules.yml` | 15 new C# agent rules |
| `src/tinysocs/agent/actions.yaml` | Action snippets for all new rules |
| `src/TinySocs.Agent/Detection/AlertWriter.cs` | Retry queue integration |
| `src/TinySocs.Agent/Configuration/AgentConfig.cs` | NotificationRetryConfig class |
| `config/agent-config.yml` | Notification retry config section |
| `config/assistant.env` | SIEM_PASS comment |
| `modules/TinySocs.Installer.psm1` | Health checks 13-14, Invoke-TinySocsSmokeTest |
| `modules/TinySocs.Uninstall.ps1` | Scheduled tasks, CredMan, NSSM cleanup |
| `packaging/iss/Quickstart.iss` | Upgrade path validation, version bump to 0.8.0 |
| `docs/getting-started.md` | Updated for Phase 13 |
| `docs/operator-runbook.md` | Updated for Phase 13 |
| `docs/troubleshooting.md` | 3 new troubleshooting items |
| `README.md` | Updated features and docs links |

## Test Summary

| Test File | Count | Notes |
|---|---|---|
| `test_schema_compliance.py` | 31 | Requires `jsonschema` for full coverage (13 without) |
| `test_notifications_e2e.py` | 15 | Requires `aiosmtpd` for email tests |
| `test_detection_rules.py` | 19 | Pure YAML validation, no dependencies |
| **Total new tests** | **65** | |
