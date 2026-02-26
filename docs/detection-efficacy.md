# Detection Efficacy Report

Generated: 2026-02-26 23:09:18 UTC

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | 19 |
| Detected | 14 |
| Missed | 3 |
| Skipped | 2 |
| Errors | 0 |
| **Efficacy** | **82.4%** (14/17) |

## Detailed Results

| Technique | Name | Status | Expected Rules | Detected Rules |
|-----------|------|--------|----------------|----------------|| T1110.001 | Brute Force - Password Guessing | PASS | TS-001, TS-001-lab, TS-002 | TS-001-lab, TS-001 |
| T1003.001 | OS Credential Dumping - LSASS Memory | PASS | TS-060, TS-061 | TS-061 |
| T1059.001 | Command and Scripting Interpreter - PowerShell | PASS | TS-030, TS-030-lab, TS-082 | TS-082, TS-030-lab, TS-030 |
| T1053.005 | Scheduled Task/Job - Scheduled Task | FAIL | TS-020 | &mdash; |
| T1547.001 | Boot or Logon Autostart Execution - Registry Run Keys | PASS | TS-091 | TS-091 |
| T1543.003 | Create or Modify System Process - Windows Service | PASS | TS-090, TS-072 | TS-072, TS-090 |
| T1070.001 | Indicator Removal - Clear Windows Event Logs | FAIL | TS-080 | &mdash; |
| T1562.001 | Impair Defenses - Disable or Modify Tools | FAIL | TS-081 | &mdash; |
| T1021.002 | Remote Services - SMB/Windows Admin Shares | PASS | TS-070, TS-072 | TS-070, TS-072 |
| T1136.001 | Create Account - Local Account | PASS | TS-010 | TS-010 |
| T1218.011 | System Binary Proxy Execution - Rundll32 | PASS | TS-135, TS-061, TS-132 | TS-061, TS-132 |
| T1003.003 | OS Credential Dumping - NTDS | SKIP | TS-062 | &mdash; |
| T1087.001 | Account Discovery - Local Account | PASS | TS-130 | TS-130 |
| T1018 | Remote System Discovery | PASS | TS-131 | TS-131 |
| T1105 | Ingress Tool Transfer | PASS | TS-132 | TS-132 |
| T1055 | Process Injection | PASS | TS-133 | TS-133 |
| T1027 | Obfuscated Files or Information | PASS | TS-134 | TS-134 |
| T1565.001 | Data Manipulation - Stored Data Manipulation | SKIP | TS-110 | &mdash; |
| T1047 | Windows Management Instrumentation | PASS | TS-136, TS-061, TS-132, TS-134 | TS-061, TS-132, TS-134 |

## Environment

- Sysmon installed: True
- Test config: `Microsoft.PowerShell.Core\FileSystem::\\Mac\Home\tinysocs\.claude\worktrees\zen-varahamihira\tests\..\tests\atomic-tests.yaml`
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
4. Check the detection pipeline latency â€” increase `timeout_seconds` in `atomic-tests.yaml`
