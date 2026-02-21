# Phase 14 — Pilot Readiness

Phase 14 closes the gaps for external pilot deployment. After Phase 13 hardened TinySocs internally (auth, schema, retry queues, 65 tests, 34 rules), Phase 14 adds HTTPS dashboard access, Windows CI, Sysmon bundling, adversary simulation validation, compliance reports, and pilot documentation.

## Milestones

### M0 — Dashboard HTTPS & Network Access

**Files changed**: `dashboard.py`, `bot.py`, `quickstart.py`, `TinySocs.Installer.psm1`, `Quickstart.iss`, `assistant.env`

- Dashboard supports TLS when bound to network (`DASHBOARD_BIND=0.0.0.0`)
- Refuses to start in network mode without TLS certificates
- Localhost mode (`127.0.0.1`) allows HTTP for local-only access
- Login rate limiting: 5 attempts per 60 seconds per IP, HTTP 429 on exceed
- `New-TinySocsDashboardCert` generates server cert signed by existing CA
- Installer wizard page for localhost vs network mode
- Health check #16: Dashboard TLS validation

**Acceptance criteria**:
- [ ] Network mode requires TLS certs — refuses to start without them
- [ ] 6 rapid wrong passwords return HTTP 429
- [ ] `New-TinySocsDashboardCert` creates valid PEM cert and key
- [ ] Installer wizard offers localhost/network choice

### M1 — Windows CI/CD Pipeline

**Files created/changed**: `ci.yml`, `build-installer.yml`, `Build-Agent.ps1`, `Test-InstallerModule.ps1`

- GitHub Actions `windows-test` job runs in parallel with Linux tests
- Windows runner: Python 3.11, .NET 8.0, pytest, Pester 5
- C# agent build script (`Build-Agent.ps1`) with deterministic output
- Pester smoke tests for PowerShell installer module
- Installer binary build workflow (artifacts only — ISCC requires vendor payload)

**Acceptance criteria**:
- [ ] `windows-test` job passes pytest and dotnet build
- [ ] Pester tests validate module imports and key function exports
- [ ] `Build-Agent.ps1` produces self-contained exe

### M2 — Sysmon Auto-Deployment

**Files created/changed**: `TinySocs.Installer.psm1`, `Quickstart.iss`, `TinySocs.Uninstall.ps1`, `Download-Sysmon.ps1`

- `Install-TinySocsSysmon` installs or updates Sysmon with TinySocs config
- Verifies Microsoft Authenticode signature before installation
- `Uninstall-TinySocsSysmon` removes Sysmon cleanly
- Installer wizard page with Sysmon install checkbox
- `Download-Sysmon.ps1` for build-time Sysmon download with hash verification
- Full uninstall removes Sysmon (not during upgrade)
- Health check #15: Sysmon service status

**Acceptance criteria**:
- [ ] Sysmon64 service running after install with checkbox checked
- [ ] `Microsoft-Windows-Sysmon/Operational` events flowing
- [ ] `Uninstall-TinySocsSysmon` removes Sysmon cleanly
- [ ] Health check reports PASS when running, INFO when not installed

### M3 — Atomic Red Team Detection Validation

**Files created**: `tests/atomic-tests.yaml`, `tests/Test-AtomicDetection.ps1`, `docs/detection-efficacy.md`

- 12 MITRE ATT&CK technique mappings to TinySocs rules
- PowerShell test runner: installs ART, executes tests, queries OpenSearch, reports results
- Generates `docs/detection-efficacy.md` with DETECTED/MISSED/SKIP per test
- Cleanup after each test execution

**Acceptance criteria**:
- [ ] Dry run lists 12 techniques with expected rules
- [ ] Full run (on Windows VM) reports detection results
- [ ] `detection-efficacy.md` generated with structured results

### M4 — Compliance Report Templates

**Files created/changed**: `compliance_report.py`, `nist_csf.yaml`, `hipaa.yaml`, `pci_dss.yaml`, `dashboard.py`, `test_compliance_reports.py`

- Three compliance frameworks: NIST CSF 2.0 (17 controls), HIPAA (11 controls), PCI DSS v4.0 (12 controls)
- Report generator queries OpenSearch for rule fire counts, maps to framework controls
- Control statuses: Active (rules fired), Deployed (rules exist), Not Mapped (no rules)
- Dashboard API: `/api/compliance/frameworks`, `/api/compliance/report`, `/api/compliance/report/html`
- Dashboard UI: Compliance Coverage card with framework dropdown, summary stats, controls table
- CLI: `python -m tinysocs.reporting.compliance_report --framework nist_csf --hours 720`
- HTML report export with download link
- 27 unit tests covering framework loading, report generation, and HTML rendering

**Acceptance criteria**:
- [ ] All 3 frameworks load and validate
- [ ] Report shows coverage percentage with control-level detail
- [ ] Dashboard card displays compliance data with framework selector
- [ ] HTML report download works
- [ ] 27/27 tests pass

### M5 — Pilot Deployment Pack

**Files created**: `docs/pilot-guide.md`, `docs/mssp-guide.md`, `docs/one-pager.md`, `docs/faq.md`

- Pilot guide: prerequisites, 15-min install, first 24h, week 1 checklist, feedback template
- MSSP guide: per-client deployment, webhook aggregation, credential management, monitoring patterns
- One-pager: problem/solution/differentiators/specs
- FAQ: common questions covering architecture, data residency, compliance, troubleshooting

**Acceptance criteria**:
- [ ] Pilot guide covers install through week 1
- [ ] MSSP guide covers multi-client deployment
- [ ] One-pager fits a single page when rendered
- [ ] FAQ addresses top 15+ questions

### M6 — Documentation Update

**Files changed**: `getting-started.md`, `operator-runbook.md`, `troubleshooting.md`, `detection-coverage.md`, `README.md`
**Files created**: `docs/phase-14-summary.md`

- Getting started: HTTPS default, Sysmon option, 16 health checks, updated dashboard section
- Operator runbook: Dashboard TLS config, Sysmon management, compliance reports, Atomic Red Team
- Troubleshooting: Dashboard cert issues, Sysmon conflicts, rate limiting lockout, compliance report empty
- Detection coverage: Sysmon-enabled rules note, efficacy data reference, compliance mapping
- README: Feature list update (HTTPS, Sysmon, compliance, CI), new doc links

**Acceptance criteria**:
- [ ] All docs reference 16/16 health checks
- [ ] Dashboard access instructions updated for HTTPS/localhost modes
- [ ] Sysmon management documented
- [ ] Compliance reporting documented

## Test Results

- **152 Python tests pass** (all milestones)
- **27 compliance report tests** (M4 specific)
- Pre-existing `test_e2e_phase12.py` failure unrelated to Phase 14

## Verification Checklist

On a Windows test VM:

- [ ] Clean TinyBox install with Sysmon checkbox checked
- [ ] HTTPS dashboard at port 8090 with self-signed cert (network mode)
- [ ] 6 rapid wrong passwords return HTTP 429
- [ ] Sysmon service running with TinySocs configuration
- [ ] `Test-TinySocsHealth` returns 16/16 PASS
- [ ] Compliance report generation from dashboard and CLI
- [ ] `Test-AtomicDetection.ps1 -DryRun` lists 12 techniques
- [ ] GitHub Actions CI passes on push (Linux + Windows)
