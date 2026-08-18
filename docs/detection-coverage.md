# TinySocs Detection Coverage — MITRE ATT&CK Mapping

**Generated**: 2026-08-18, by hand from `packaging/detection/rules.yml` (the ruleset
that actually runs in the C# agent). The previous version of this doc was generated
from the Python rule catalogue, which does not run in a default install, and
overstated coverage (32 techniques / 11 tactics). `tinysocs.reporting.mitre_coverage`
still reads the wrong source — regenerate this doc only after repointing it.

## Headline (the honest split)

| Scope | Rules | Techniques | Tactics |
|---|---|---|---|
| **Enabled by default** | 19 | **16** | **8** |
| Defined in the engine (incl. disabled) | 39 | 27 | 10 |

The 50-rule Python KQL catalogue is a rule library, not live detection — it is
deliberately excluded from these numbers. See `docs/pilot-ruleset.md` for
rule-by-rule validation evidence.

## Enabled rules (19 rules, 16 techniques, 8 tactics)

| Technique | Name | Tactic | Rules |
|---|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | credential-access | TS-061 |
| T1003.003 | OS Credential Dumping: NTDS | credential-access | TS-062 |
| T1018 | Remote System Discovery | discovery | TS-131 |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | lateral-movement | TS-070 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | persistence | TS-020 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | execution | TS-082 |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | defense-evasion | TS-080, TS-080-sys |
| T1087.001 | Account Discovery: Local Account | discovery | TS-130 |
| T1105 | Ingress Tool Transfer | command-and-control | TS-132 |
| T1110.001 | Brute Force: Password Guessing | credential-access | TS-001, TS-002, TS-071 |
| T1136.001 | Create Account: Local Account | persistence | TS-010 |
| T1485 | Data Destruction | impact | TS-114 |
| T1486 | Data Encrypted for Impact | impact | TS-113 |
| T1543.003 | Create or Modify System Process: Windows Service | persistence | TS-090 |
| T1562.001 | Impair Defenses: Disable or Modify Tools | defense-evasion | TS-081 |
| T1565.001 | Data Manipulation: Stored Data Manipulation | impact | TS-110 |

## Disabled-by-default rules (20 rules)

Held back because they are noisy or environment-specific on a typical small network.
Enable the ones that fit yours — they are the same YAML, one `enabled: true` away.

| Technique | Name | Tactic | Rules |
|---|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | credential-access | TS-060 |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | lateral-movement | TS-072 |
| T1027 | Obfuscated Files or Information | defense-evasion | TS-134 |
| T1047 | Windows Management Instrumentation | execution | TS-136 |
| T1048 | Exfiltration Over Alternative Protocol | exfiltration | TS-101 |
| T1055 | Process Injection | defense-evasion | TS-133 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | execution | TS-030, TS-030-lab |
| T1070.006 | Indicator Removal: Timestomp | defense-evasion | TS-083 |
| T1071 | Application Layer Protocol | command-and-control | TS-100 |
| T1106 | Native API | execution | TS-040, TS-050 |
| T1110.001 | Brute Force: Password Guessing | credential-access | TS-001-lab |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | initial-access | TS-120 |
| T1218.011 | System Binary Proxy Execution: Rundll32 | defense-evasion | TS-135 |
| T1222 | File and Directory Permissions Modification | defense-evasion | TS-115 |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | persistence | TS-091, TS-092 |
| T1565.001 | Data Manipulation: Stored Data Manipulation | impact | TS-111, TS-112 |
