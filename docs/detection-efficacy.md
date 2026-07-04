# Detection Efficacy Report

> **⚠️ SUPERSEDED (2026-07-04).** This report is from the 2026-03-01 harness run and
> does **not** describe the current pilot base pack (2026.27). Since it was generated:
> several rules were restricted with `field_match` (June), and 17 noisy/dead/duplicate
> rules were disabled for the pilot (see [pilot-ruleset.md](pilot-ruleset.md)). The
> "100% (15/15)" figure below was earned by rule definitions that no longer ship as-is
> and **must not be quoted**. Six techniques (T1003.001, T1547.001, T1218.011, T1055,
> T1027, T1047) now have no firing rule in the pilot pack by design. A fresh run of
> `tests/Test-AtomicDetection.ps1` against the 2026.27 pack — which requires a Windows
> host and cannot run in the current build environment — is the release gate that will
> replace this report.

Generated: 2026-03-01 19:30:00 UTC

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | 19 |
| Detected | 15 |
| Missed | 0 |
| Skipped | 3 |
| Errors | 1 |
| **Efficacy** | **100%** (15/15) |

## Detailed Results

| Technique | Name | Status | Expected Rules | Detected Rules |
|-----------|------|--------|----------------|----------------|
| T1110.001 | Brute Force - Password Guessing | PASS | TS-001, TS-001-lab, TS-002 | TS-001-lab, TS-001 |
| T1003.001 | OS Credential Dumping - LSASS Memory | PASS | TS-060, TS-061 | TS-061 |
| T1059.001 | Command and Scripting Interpreter - PowerShell | PASS | TS-030, TS-030-lab, TS-082 | TS-082, TS-030-lab, TS-030 |
| T1053.005 | Scheduled Task/Job - Scheduled Task | PASS | TS-020, TS-061, TS-132 | TS-061, TS-132 |
| T1547.001 | Boot or Logon Autostart Execution - Registry Run Keys | PASS | TS-091 | TS-091 |
| T1543.003 | Create or Modify System Process - Windows Service | PASS | TS-090, TS-072 | TS-072, TS-090 |
| T1070.001 | Indicator Removal - Clear Windows Event Logs | PASS | TS-080 | TS-080 |
| T1562.001 | Impair Defenses - Disable or Modify Tools | SKIP | TS-081 | &mdash; |
| T1021.002 | Remote Services - SMB/Windows Admin Shares | PASS | TS-070, TS-072 | TS-070, TS-072 |
| T1136.001 | Create Account - Local Account | PASS | TS-010 | TS-010 |
| T1218.011 | System Binary Proxy Execution - Rundll32 | PASS | TS-135, TS-061, TS-132 | TS-061, TS-132 |
| T1003.003 | OS Credential Dumping - NTDS | SKIP | TS-062 | &mdash; |
| T1087.001 | Account Discovery - Local Account | ERR | TS-130 | &mdash; |
| T1018 | Remote System Discovery | PASS | TS-131 | TS-131 |
| T1105 | Ingress Tool Transfer | PASS | TS-132 | TS-132 |
| T1055 | Process Injection | PASS | TS-133 | TS-133 |
| T1027 | Obfuscated Files or Information | PASS | TS-134 | TS-134 |
| T1565.001 | Data Manipulation - Stored Data Manipulation | SKIP | TS-110 | &mdash; |
| T1047 | Windows Management Instrumentation | PASS | TS-136, TS-061, TS-132, TS-134 | TS-061, TS-132, TS-134 |

## Notes

- **T1070.001** (previously MISSED): Fixed via direct-alert fast-path in EventLogInput.
  Event 1102 is now detected immediately and a TS-080 alert is written directly to
  OpenSearch, bypassing the queue/shipper pipeline latency.
- **T1087.001** (ERROR): Test infrastructure issue — ART fallback command fails when
  running from a UNC path (`\\Mac\Home\...`). The detection rule (TS-130) itself is
  functional; this is a test-execution problem, not a detection gap.
- **Skipped tests** require environment prerequisites not present on the test VM:
  - T1562.001: Tamper Protection must be disabled
  - T1003.003: Requires a Domain Controller
  - T1565.001: Requires TinySocs FIM module

## Environment

- Sysmon installed: True
- Test config: `tests/atomic-tests.yaml`
- Atomic Red Team: Invoke-AtomicRedTeam module

## How to Run

```powershell
# Full run (requires admin, Atomic Red Team, and running TinySocs instance)
.\tests\Test-AtomicDetection.ps1

# Dry run (list tests without executing)
.\tests\Test-AtomicDetection.ps1 -DryRun

# Skip ART install (if already installed)
.\tests\Test-AtomicDetection.ps1 -SkipInstall
```

## Tuning Guidance

For any MISSED detections:
1. Check that the relevant Windows event log channels are enabled
2. Verify Sysmon is installed and configured (for Sysmon-dependent rules)
3. Review rule thresholds in `packaging/detection/rules.yml`
4. Check the detection pipeline latency — increase `timeout_seconds` in `atomic-tests.yaml`
