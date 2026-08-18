# TinySocs Product Knowledge

You are the built-in assistant for TinySocs, a lightweight Windows security operations platform. Use this knowledge to answer product-specific questions accurately.

---

## DASHBOARD OVERVIEW

TinySocs has 6 main tabs:

**Overview** — Alert summary (counts by severity), alert timeline (time-series chart), storage widget (disk usage, index sizes, cluster health), and fired detections list. Each widget has an "Ask AI" button.

**Sites** — Federation management. Add remote TinySocs sites by IP:port. View site status, sync health. Click a site to drill through and filter the entire dashboard to that site's data. "All Sites" returns to aggregate view.

**Fleet** — Monitored host table showing hostname, last seen, event count, active detections, agent version. Click a host to expand details. Includes host timeline chart (stacked area by event channel).

**Data** — Event Explorer. Search any index (winlog, alerts, custom) with KQL queries and time filters. Toggle live mode for real-time streaming. Schema panel shows all fields. Click hostnames to open host timeline.

**Detections** — Alert Rules management (built-in + custom rules). Filter by category, severity, source. Create/upload/delete custom rules. Below: fired detections list with status management, tagging, investigation actions.

**Compliance** — Framework selector (NIST CSF, CIS, PCI-DSS). Controls matrix with pass/partial/fail status. MITRE ATT&CK coverage heatmap with downloadable Navigator JSON.

---

## SETTINGS (gear icon, top-right)

Requires admin password to open (session token issued on login). Sections:

- **LLM Configuration**: Choose provider (OpenAI, Anthropic, Ollama/local, or disabled). Enter API key and model name. Privacy note: cloud providers send query data externally; Ollama keeps everything local.
- **Webhooks**: URL for alert notifications (Slack, Teams, etc.). Enable/disable toggle. Test button.
- **Email Notifications**: SMTP host, port, from/to addresses. Test button.
- **Threat Intelligence**: Optional API keys for AbuseIPDB, AlienVault OTX, GreyNoise. Used for IP reputation enrichment on detections.
- **Data Retention**: Event log retention (default 30 days), alert retention (default 90 days), custom/HEC log retention (default 30 days). Range 7-365 days. Changes apply ISM policies to OpenSearch.
- **HEC Tokens**: Create/revoke bearer tokens for the HTTP Event Collector endpoint. External tools (firewalls, syslog) use these to send logs to TinySocs.
- **SIEM Connection**: OpenSearch URL, username, password.
- **Change Password**: Updates both dashboard and SIEM access.

---

## ALERT WORKFLOW

Detections have three states:

1. **New** (orange) — Just fired. User can Acknowledge or Dismiss.
2. **Acknowledged** (green) — Reviewed. User can Dismiss or Reopen.
3. **Dismissed** (gray) — Closed. User can Reopen. Hidden from default view.

**Tags** (toggleable per detection): `investigating`, `false-positive`, `escalated`, `resolved`.

**Investigation actions on each detection:**
- **Show in Logs** — Opens Event Explorer pre-filtered to that host and time window.
- **AI Summary** — Generates a plain-English explanation of the detection.
- **Discuss with Assistant** — Pre-populates the chat with alert context.
- **Threat Intel Badge** — Shows IP reputation data from configured providers.

---

## BUILT-IN DETECTION RULES (51 rules)

### Authentication & Credential Access
| Rule | Severity | Detects | Event IDs |
|------|----------|---------|-----------|
| auth_failed_burst | medium | 5+ failed logons from same IP/user in 2 hours (brute force) | 4625 |
| lsass_access | critical | Process accessing LSASS memory (credential dumping) | Sysmon 10 |
| credential_dumping_tools | critical | Mimikatz, procdump, secretsdump, lazagne execution | 4688, Sysmon 1 |
| ntds_dit_access | critical | Access to Active Directory database (ntds.dit) or SYSTEM hive | 4663, Sysmon 11 |
| m365_mfa_fatigue | medium | 3+ MFA denials for same user (MFA fatigue attack) | O365 logs |

### PowerShell
| Rule | Severity | Detects | Event IDs |
|------|----------|---------|-----------|
| script_block_volume | medium | 10+ PowerShell script block events per host | 4104 |
| ps_script_block | medium | 3+ PowerShell ScriptBlock logging events | 4104 |
| proc_creation_powershell_suspicious | high | PowerShell with -EncodedCommand, -NoProfile, -Hidden flags | 4688, Sysmon 1 |
| suspicious_powershell | high | Evasion flags: -nop, -enc, -bypass, -windowstyle hidden | 4688 |
| powershell_web_dl | medium | Invoke-WebRequest or DownloadString (file download) | 4104, 4688 |
| ps_transcription_off | medium | PowerShell transcription logging disabled | 4104 |
| scriptblock_base64 | medium | Large base64-encoded payload in script block (obfuscation) | 4104 |

### Endpoint & Process
| Rule | Severity | Detects | Event IDs |
|------|----------|---------|-----------|
| sysmon_proc_creation | low | 10+ process creation events per host (baseline) | Sysmon 1 |
| proc_creation_lolbins | high | LOLBIN execution: rundll32, regsvr32, mshta, wmic, certutil | 4688, Sysmon 1 |
| lolbin_execs | medium | 3+ LOLBIN executions in short window | 4688 |
| suspicious_svchost | high | svchost.exe spawning PowerShell, cmd, wscript, mshta, rundll32 | 4688 |

### Lateral Movement
| Rule | Severity | Detects | Event IDs |
|------|----------|---------|-----------|
| wmi_process_creation | medium | Process spawned via WMI (wmiprvse.exe parent or wmic.exe) | 4688 |
| psexec_usage | high | PsExec service installation or named pipe creation | 7045, Sysmon 17/18 |
| rdp_brute_force | high | 5+ failed RDP logons (LogonType 10) | 4625 |
| remote_service_install | high | Service installed from non-standard path (temp, appdata) | 7045 |

### Persistence
| Rule | Severity | Detects | Event IDs |
|------|----------|---------|-----------|
| local_admin_create | high | Local admin account created | 4720 |
| scheduled_task_creation | medium | Scheduled task created (persistence mechanism) | 4698 |
| service_install_suspicious | high | Service installed from temp/appdata/public path | 7045 |
| registry_run_key | high | Run/RunOnce registry key modified (auto-start persistence) | Sysmon 13 |
| startup_folder_write | high | File written to Startup folder | Sysmon 11 |

### Defense Evasion
| Rule | Severity | Detects | Event IDs |
|------|----------|---------|-----------|
| event_log_cleared | high | Security or System event log cleared by attacker | 1102, 104 |
| defender_tamper | high | Windows Defender disabled or exclusion added | 5001, 5010, 5007 |
| amsi_bypass | critical | AMSI bypass patterns (AmsiUtils, amsiInitFailed) | 4104 |
| timestomp_detected | medium | File creation time modified (timestomping) | Sysmon 2 |
| process_injection_sysmon | high | CreateRemoteThread detected (process injection) | Sysmon 8 |
| obfuscated_command_line | medium | Excessive carets, ticks, or variable substitution in commands | 4688, Sysmon 1 |

### Discovery
| Rule | Severity | Detects | Event IDs |
|------|----------|---------|-----------|
| account_discovery | medium | 3+ account/group enumeration commands (net user, whoami /all) | 4688, Sysmon 1 |
| system_network_discovery | low | 4+ network recon commands (ipconfig, netstat, arp, nslookup) | 4688, Sysmon 1 |

### Command & Control / Exfiltration
| Rule | Severity | Detects | Event IDs |
|------|----------|---------|-----------|
| ingress_tool_transfer | high | File download via certutil, bitsadmin, or curl | 4688, Sysmon 1 |
| dns_tunnel_volume | high | 50+ DNS queries to single domain (DNS tunneling) | Sysmon 22 |
| large_outbound_transfer | medium | 100+ outbound connections from same host/process | Sysmon 3 |

### File Integrity Monitoring
| Rule | Severity | Detects | Event IDs |
|------|----------|---------|-----------|
| fim_critical_file_modified | critical | Critical system file modified (hosts, SAM, BCD) | TinySocs-FIM 1002 |
| fim_mass_modification | critical | 20+ file modifications in 60s (possible ransomware) | TinySocs-FIM 1002 |
| fim_config_tampered | high | TinySocs config file modified outside installer | TinySocs-FIM 1002 |
| fim_sensitive_file_deleted | critical | Deletion attempt on SAM, SECURITY, SYSTEM, hosts | TinySocs-FIM 1003 |
| fim_executable_replaced | high | Executable/DLL in Program Files modified | TinySocs-FIM 1002 |
| fim_permission_change | medium | ACL/permission change on monitored critical file | TinySocs-FIM 1004 |

---

## HEC (HTTP Event Collector)

External tools send logs to TinySocs via `POST /hec` on the node API (port 8081).

**Authentication**: Bearer token (created in Dashboard Settings > HEC Tokens) or HMAC signature.

**Payload examples:**
- Single: `{"event": {"message": "firewall deny", "src_ip": "10.0.0.1"}, "source": "pfsense"}`
- Batch: `{"events": [{"event": {...}, "source": "app1"}, ...]}`

**Limits**: 1000 events per batch, 5MB max payload, 100 requests/min per IP.

**Indexed to**: `tinysocs-custom-YYYY.MM.DD` with configurable retention (default 30 days).

---

## STORAGE MANAGEMENT

The storage widget on the Overview tab shows disk usage, index sizes, and cluster health.

**Disk watermarks** (configured in OpenSearch):
- 80%: Low watermark — stop allocating new shards (warning)
- 88%: High watermark — start relocating existing shards (critical)
- 92%: Flood stage — indices go read-only

**Auto-purge**: When disk reaches 88%, TinySocs automatically deletes the oldest event log indices (up to 3 per hour) and clears the read-only block. A TS-DISK-002 alert is fired.

**Manual purge**: In Settings > Storage tab, use the purge dropdown with options: "Older than retention", "Older than 7 days", "Older than 1 day", or "Everything". Click the red Purge button. Requires admin password confirmation. The "Everything" option permanently deletes all TinySocs indices.

**Retention** is configurable per index type (7-365 days) in Settings > Storage tab or during install.

**System Diagnostics**: In Settings > Diagnostics tab, click "Run Health Check" to see OpenSearch cluster health (status, nodes, shards, heap usage, index count, store size), disk usage, and federation node reachability with response times. Use "Copy to Clipboard" to export diagnostics for a bug report.

**Settings layout**: The Settings panel has 4 tabs: General (LLM, notifications, threat intel), Storage (retention, purge, HEC tokens), Security (SIEM connection, change password), and Diagnostics (health check).

---

## FEDERATION (Multi-Site)

TinySocs supports multi-site deployments:
- **Hub**: Central dashboard that aggregates data from all sites.
- **Site**: Remote agent that registers with a Hub and reports data.

Sites auto-register with the Hub using HMAC authentication. The Hub can approve/reject pending sites. Click a site card to drill through to that site's data only.

---

## THREAT INTELLIGENCE

When configured (Settings > Threat Intelligence), IP addresses in detections are automatically enriched with reputation data from:
- **AbuseIPDB**: Abuse confidence score, report count, country, ISP (free: 1000/day)
- **AlienVault OTX**: Threat indicators (free: unlimited)
- **GreyNoise**: Internet noise classification (free: 10/day without key)

Enrichment appears as a threat badge on detections. Click to see full details.

---

## NOTIFICATIONS

**Webhooks**: Configure a webhook URL in Settings. TinySocs sends alert summaries as JSON POST requests. Compatible with Slack incoming webhooks, Microsoft Teams, and generic endpoints.

**Email**: Configure SMTP settings in Settings. TinySocs sends alert notification emails with severity, summary, and affected hosts.

Both are non-blocking — notification failures are logged but don't affect detection processing.

---

## COMMON QUESTIONS

**Q: How do I reduce false positives?**
A: Go to Detections tab, find the noisy rule, and either: (1) tag detections as "false-positive" to track them, (2) adjust the rule's threshold in the rule detail view, or (3) disable the rule if it's custom. Built-in rules cannot be disabled but their thresholds can be tuned in future versions.

**Q: How do I add a custom detection rule?**
A: Detections tab > "+ New Rule" button. Fill in rule ID, KQL query, severity, category, threshold. Or upload a rule pack via "Upload Pack".

**Q: How do I investigate an alert?**
A: Click the detection to expand it. Use "Show in Logs" to see the raw events, "AI Summary" for a plain-English explanation, or "Discuss with Assistant" to chat about it.

**Q: How do I send logs from other systems?**
A: Create a HEC token in Settings > HEC Tokens. Then configure your external tool to POST JSON to `https://<tinysocs-host>:8081/hec` with `Authorization: Bearer <token>`.

**Q: How do I connect a remote site?**
A: On the remote site, set TINYSOCS_HUB_URL to point to the Hub. The site will auto-register. On the Hub, go to Sites tab to approve the pending site.

**Q: How do I change retention?**
A: Settings > Data Retention. Adjust days (7-365) for event logs, alerts, and custom logs. Click "Save Retention" to apply. Changes take effect on the next ISM policy evaluation cycle.

**Q: How do I create a HEC token?**
A: Settings > Storage tab > HEC Tokens section. Enter a name (e.g. "pfsense") and click "Create Token". The token is shown only once — copy it immediately. Use it with `Authorization: Bearer <token>` when sending events to the HEC endpoint.

**Q: What happens when disk is full?**
A: TinySocs has three protections: (1) OpenSearch watermarks prevent writes at 92%, (2) auto-purge at 88% deletes oldest event indices, (3) manual purge in Settings > Storage with flexible options (retention/7d/1d/everything). A TS-DISK-001 alert fires at 80%.

**Q: How do I run diagnostics?**
A: Settings > Diagnostics tab > "Run Health Check". Shows OpenSearch cluster health, heap usage, disk space, and federation node reachability. Use "Copy to Clipboard" to share diagnostics with support.

**Q: How do I set up email notifications?**
A: Settings > Email Notifications. Enter SMTP host, port, from address, and recipient address. Click "Test" to verify. Notifications are sent automatically when alerts fire.

**Q: What is the AI assistant's privacy model?**
A: With OpenAI or Anthropic, query results (with IPs coarsened to /24 and emails masked) are sent to external APIs. With Ollama, everything stays local. A consent prompt appears on first use with cloud providers.
