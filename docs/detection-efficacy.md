# Detection Efficacy Report

Generated: 2026-02-25 19:33:50 UTC

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | 19 |
| Detected | 0 |
| Missed | 16 |
| Skipped | 0 |
| Errors | 3 |
| **Efficacy** | **0%** (0/16) |

## Detailed Results

| Technique | Name | Status | Expected Rules | Detected Rules |
|-----------|------|--------|----------------|----------------|| T1110.001 | Brute Force — Password Guessing | FAIL | TS-001, auth_failed_burst | &mdash; |
| T1003.001 | OS Credential Dumping — LSASS Memory | ERR | TS-060, lsass_access | &mdash; |
| T1059.001 | Command and Scripting Interpreter — PowerShell | ERR | TS-030, suspicious_powershell, ps_script_block | &mdash; |
| T1053.005 | Scheduled Task/Job — Scheduled Task | FAIL | TS-020, scheduled_task_creation | &mdash; |
| T1547.001 | Boot or Logon Autostart Execution — Registry Run Keys | FAIL | TS-091, registry_run_key | &mdash; |
| T1543.003 | Create or Modify System Process — Windows Service | FAIL | TS-090, service_install_suspicious | &mdash; |
| T1070.001 | Indicator Removal — Clear Windows Event Logs | FAIL | TS-080, event_log_cleared | &mdash; |
| T1562.001 | Impair Defenses — Disable or Modify Tools | FAIL | TS-081, defender_tamper | &mdash; |
| T1021.002 | Remote Services — SMB/Windows Admin Shares | FAIL | TS-070, psexec_usage | &mdash; |
| T1136.001 | Create Account — Local Account | FAIL | TS-010, local_admin_create | &mdash; |
| T1218.011 | System Binary Proxy Execution — Rundll32 | ERR | proc_creation_lolbins, lolbin_execs | &mdash; |
| T1003.003 | OS Credential Dumping — NTDS | FAIL | TS-062, ntds_dit_access | &mdash; |
| T1087.001 | Account Discovery — Local Account | FAIL | TS-130, account_discovery | &mdash; |
| T1018 | Remote System Discovery | FAIL | TS-131, system_network_discovery | &mdash; |
| T1105 | Ingress Tool Transfer | FAIL | TS-132, ingress_tool_transfer, powershell_web_dl | &mdash; |
| T1055 | Process Injection | FAIL | TS-133, process_injection_sysmon | &mdash; |
| T1027 | Obfuscated Files or Information | FAIL | TS-134, obfuscated_command_line, scriptblock_base64 | &mdash; |
| T1565.001 | Data Manipulation — Stored Data Manipulation | FAIL | TS-110, fim_critical_file_modified | &mdash; |
| T1047 | Windows Management Instrumentation | FAIL | wmi_process_creation | &mdash; |

## Environment

- Sysmon installed: True
- Test config: `C:\Mac\Home\tinysocs\tests\atomic-tests.yaml`
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
