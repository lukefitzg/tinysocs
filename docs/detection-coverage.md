# TinySocs Detection Coverage Matrix

> Phase 13 M6 deliverable. Last updated: 2026-02-20.

## Overview

TinySocs ships two detection engines that run in parallel:

| Engine | Location | Rule Format | Runtime |
|---|---|---|---|
| **Dashboard KQL** | `src/tinysocs/agent/detections/rules.yaml` | KQL + threshold | Python (FastAPI dashboard) |
| **C# Agent** | `packaging/detection/rules.yml` | `threshold_by_key` + `match_single` | .NET 8 (TinySocs.Agent) |

Both engines evaluate Windows Event Log data against their respective rule sets and emit alerts to the `tinysocs-alerts-*` index.

---

## MITRE ATT&CK Coverage

### Credential Access (TA0006)

| Rule ID (KQL) | Rule ID (C#) | Name | Severity | MITRE | Windows Events |
|---|---|---|---|---|---|
| `lsass_access` | `TS-060` | Process accessing LSASS memory | critical | T1003.001 | Sysmon EID 10 |
| `credential_dumping_tools` | `TS-061` | Known credential dumping tool detected | critical | T1003 | Sysmon EID 1 |
| `ntds_dit_access` | `TS-062` | Access to ntds.dit or SYSTEM hive | critical | T1003.003 | Sysmon EID 11 |

### Lateral Movement (TA0008)

| Rule ID (KQL) | Rule ID (C#) | Name | Severity | MITRE | Windows Events |
|---|---|---|---|---|---|
| `psexec_usage` | `TS-070` | PsExec service installation | high | T1021.002 | System EID 7045 |
| `rdp_brute_force` | `TS-071` | Multiple RDP logon failures | high | T1110 | Security EID 4625 (LogonType 10) |
| `remote_service_install` | `TS-072` | Service installed remotely | high | T1021.002 | System EID 7045 |
| `wmi_process_creation` | -- | WMI-spawned process | medium | T1047 | Sysmon EID 1 |

### Defence Evasion (TA0005)

| Rule ID (KQL) | Rule ID (C#) | Name | Severity | MITRE | Windows Events |
|---|---|---|---|---|---|
| `event_log_cleared` | `TS-080` | Security/System event log cleared | high | T1070.001 | Security EID 1102, System EID 104 |
| `defender_tamper` | `TS-081` | Defender real-time protection disabled | high | T1562.001 | Defender EID 5001 |
| `amsi_bypass` | `TS-082` | AMSI bypass patterns detected | critical | T1562.001 | PowerShell EID 4104 |
| `timestomp_detected` | `TS-083` | File creation time modified | medium | T1070.006 | Sysmon EID 2 |
| `ps_transcription_off` | -- | PowerShell transcription disabled | medium | T1562.001 | PowerShell EID 4104 |

### Persistence (TA0003)

| Rule ID (KQL) | Rule ID (C#) | Name | Severity | MITRE | Windows Events |
|---|---|---|---|---|---|
| `scheduled_task_creation` | `TS-020` | Scheduled task created | medium | T1053.005 | Security EID 4698 |
| `service_install_suspicious` | `TS-090` | Service installed with suspicious path | high | T1543.003 | System EID 7045 |
| `registry_run_key` | `TS-091` | Run/RunOnce registry modification | high | T1547.001 | Sysmon EID 13 |
| `startup_folder_write` | `TS-092` | File written to Startup folder | high | T1547.001 | Sysmon EID 11 |
| `local_admin_create` | `TS-010` | Local admin account created | high | T1136.001 | Security EID 4720 + 4732 |

### Brute Force / Initial Access (TA0001)

| Rule ID (KQL) | Rule ID (C#) | Name | Severity | MITRE | Windows Events |
|---|---|---|---|---|---|
| `auth_failed_burst` | `TS-001` | Multiple failed Windows logons | medium | T1110 | Security EID 4625 |
| -- | `TS-002` | Brute force logon by source IP | high | T1110 | Security EID 4625 |

### Execution (TA0002)

| Rule ID (KQL) | Rule ID (C#) | Name | Severity | MITRE | Windows Events |
|---|---|---|---|---|---|
| `proc_creation_powershell_suspicious` | -- | PowerShell with suspicious flags | high | T1059.001 | Sysmon EID 1 |
| `suspicious_powershell` | -- | Suspicious PowerShell flags (encoded/hidden) | high | T1059.001 | PowerShell EID 4104 |
| `ps_script_block` | `TS-030` | PowerShell ScriptBlock burst | medium | T1059.001 | PowerShell EID 4104 |
| `proc_creation_lolbins` | -- | Possible LOLBIN execution | high | T1218 | Sysmon EID 1 |
| `lolbin_execs` | -- | Multiple LOLBIN executions in short window | medium | T1218 | Sysmon EID 1 |
| `suspicious_svchost` | -- | svchost spawning scripting processes | high | T1218 | Sysmon EID 1 |
| `powershell_web_dl` | -- | PowerShell web download | medium | T1059.001 | PowerShell EID 4104 |
| `scriptblock_base64` | -- | Large base64 in ScriptBlock | medium | T1027 | PowerShell EID 4104 |
| `sysmon_proc_creation` | `TS-040` / `TS-050` | Process creation burst | low | -- | Sysmon EID 1 |

### Exfiltration (TA0010)

| Rule ID (KQL) | Rule ID (C#) | Name | Severity | MITRE | Windows Events |
|---|---|---|---|---|---|
| `dns_tunnel_volume` | `TS-100` | High volume DNS queries | high | T1048.001 | Sysmon EID 22 |
| `large_outbound_transfer` | `TS-101` | Unusual outbound traffic volume | medium | T1048 | Sysmon EID 3 |

### Cloud / Identity (no C# equivalent)

| Rule ID (KQL) | Rule ID (C#) | Name | Severity | MITRE | Windows Events |
|---|---|---|---|---|---|
| `vpn_geo_impossible` | -- | Logins from far-apart locations | medium | T1078 | VPN/logon events |
| `firewall_deny_burst` | -- | Burst of firewall denies | low | -- | Firewall events |
| `m365_mfa_fatigue` | -- | Multiple MFA denials | medium | T1110 | M365 audit |
| `m365_mail_forward_rule` | -- | Mailbox forwarding rule created | medium | T1114 | M365 audit |

---

## Rule Counts Summary

| Category | KQL Rules | C# Rules | MITRE Techniques |
|---|---|---|---|
| Credential Access | 3 | 3 | T1003 |
| Lateral Movement | 4 | 3 | T1021, T1047, T1110 |
| Defence Evasion | 5 | 4 | T1070, T1562 |
| Persistence | 5 | 5 | T1053, T1136, T1543, T1547 |
| Brute Force / Initial Access | 1 | 2 | T1110 |
| Execution | 8 | 3 | T1027, T1059, T1218 |
| Exfiltration | 2 | 2 | T1048 |
| Cloud / Identity | 4 | 0 | T1078, T1110, T1114 |
| **Total (production)** | **32** | **22** | -- |

Lab variants add 8 KQL + 2 C# rules for development/testing.

---

## Data Source Requirements

For full detection coverage, ensure these Windows event sources are enabled:

| Data Source | Event IDs | Rules Dependent |
|---|---|---|
| Security event log | 1102, 4624, 4625, 4698, 4720, 4732 | auth, persistence, identity, evasion |
| System event log | 104, 7045 | persistence, lateral movement |
| PowerShell Operational | 4104 | powershell, evasion |
| Sysmon | 1, 2, 3, 10, 11, 13, 22 | endpoint, credential, lateral, persistence, exfiltration |
| Windows Defender Operational | 5001 | evasion |

**Sysmon is strongly recommended.** Without it, 14 rules (credential access, many persistence, exfiltration) will have no events to evaluate.

---

## Severity Distribution

| Severity | Count (KQL) | Count (C#) |
|---|---|---|
| Critical | 3 | 3 |
| High | 14 | 10 |
| Medium | 12 | 5 |
| Low | 3 | 4 |

---

## Adding Custom Rules

### KQL Rules (Dashboard engine)

Add to `src/tinysocs/agent/detections/rules.yaml`:

```yaml
- id: my_custom_rule
  name: My Custom Detection
  description: Fires when ...
  severity: high
  category: custom
  kql: "winlog.event_data.Something: bad_value"
  threshold: 3
  window_minutes: 10
  group_by: winlog.event_data.TargetUserName
```

### C# Agent Rules

Add to `packaging/detection/rules.yml` (or the deployed copy at
`%ProgramData%\TinySocs\Collector\rules\rules.yml`):

```yaml
- id: TS-200
  name: my_custom_rule
  description: Fires when ...
  severity: high
  enabled: true
  type: threshold_by_key
  condition:
    event_id: 1234
    channel: Security
    group_by: winlog.event_data.TargetUserName
    threshold: 3
    window_minutes: 10
```

Rules are hot-reloaded every 60 seconds (configurable via `detection.reload_interval_seconds`).
