# TinySocs Demo Script

## Prerequisites
- Python 3.9+
- TinySocs repo cloned
- (Optional) LLM API key for AI assistant demo (ANTHROPIC_API_KEY, OPENAI_API_KEY, or local Ollama)

## Launch Demo Mode
```bash
python -m tinysocs.api.bot --demo
```
Opens at http://localhost:8090/dashboard
Default credentials: admin / demo

## Part 1: Single-Site Walkthrough (5 minutes)

Walk through each tab:

### Overview Tab
- **Alert Summary**: 42 alerts in last 24 hours — 3 critical, 8 high, 17 medium, 14 low
  - Total Alerts card spans full width on its own row; 4 severity cards share the row below
- **Alert Timeline**: 24-hour stacked bar chart with visible spike at ~14 hours ago (brute force attack)
- Show top hosts and top rules
- Point out the severity color coding
- **Ask AI button**: click to pre-fill the assistant with context about the current alert distribution

### Fired Detections (scroll down on Overview)
- 7 fired alerts matching the demo scenario:
  - Brute force: 8 failed logons from 203.0.113.47 (critical, RECEPTION-PC)
  - Suspicious PowerShell: encoded command execution (high, DC-01)
  - New local account created: svc_backup (medium, FILESERVER-01)
  - FIM: Modified C:\ClientFiles\Mergers\draft.docx (medium, FILESERVER-01)
  - Off-hours RDP attempt from 198.51.100.22 (high, FILESERVER-01)
  - Scheduled task created: WindowsUpdate_Check (medium, DC-01)
  - Defender: real-time protection disabled (high, RECEPTION-PC)
- Host field shows actual hostnames (not N/A)
- Filter by status with the dropdown (Active, Acknowledged, All)
- Show threat intel enrichment on the brute force alert: AbuseIPDB confidence 87%, GreyNoise: malicious

### Fleet Tab
- 3 hosts reporting: RECEPTION-PC, FILESERVER-01, DC-01
- Click a host row to expand — **details lazy-load** with top channels, event IDs, alert severities, active detections, FIM status, threat intel providers
- Event Flow chart shows per-host timeline with channel breakdown (Security, Sysmon, TinySocs-FIM)
- Use host picker to filter to a single host
- **Ask AI button** on Fleet Health header

### Data Tab (Event Explorer)
- 20 synthetic events with mix of Event IDs: 4624 (logon), 4625 (failed logon), 1 (Sysmon process create), 4104 (PowerShell), FIM events
- Show event detail expansion
- Demonstrate query filtering

### Detections Tab (Guided Response)
- Shows **4 staged actions** with remediation runbooks:
  - **block_ip** (staged): Block 203.0.113.47 — brute force source IP
  - **isolate_host** (staged): Isolate RECEPTION-PC — Defender disabled
  - **disable_user** (acknowledged): Disable svc_backup — suspicious local account
  - **open_ticket** (staged): RDP brute force from 198.51.100.22
- Click an action to expand its **remediation runbook** with step-by-step guidance
- Demonstrate Acknowledge/Dismiss workflow buttons

### AI Assistant
- Type: "what happened on RECEPTION-PC in the last hour?"
- The assistant queries the synthetic data and returns a natural language narrative
- Type: "is the brute force attack still ongoing?"
- Show how it correlates events across the timeline
- **Ask AI buttons** on each widget header pre-fill contextual prompts

### Compliance Tab
- **MITRE ATT&CK coverage**: 33 techniques across 11 tactics — full heatmap grid
  - Click a tactic cell to expand and see covered technique IDs
  - Navigator layer export available
- **Compliance frameworks**: select NIST CSF 2.0, HIPAA, or PCI DSS
  - Show control mapping with pass/partial/fail status
  - **Download Report** button generates a standalone HTML compliance report
- **Ask AI buttons** on both Compliance and MITRE headers

## Part 2: Multi-Site Walkthrough (2 minutes)

### Sites Tab
- 3 client sites visible: acme-law, mainst-dental, harbor-ins
- acme-law: healthy (green), version 0.9.0, 347 ledger entries, 2 detections in last run
- mainst-dental: healthy (green), version 0.9.0, 189 ledger entries, 0 detections
- harbor-ins: warning (amber), version 0.8.9 (outdated), 512 ledger entries, 5 detections in last run
- Talk through: "This is the MSSP view. One dashboard, all your clients. Alert aggregation, ledger integrity verification, centralized version tracking."
- Point out harbor-ins version drift as a talking point about fleet management
- **Click a site** to drill into its Overview/Data tabs — in single-node mode, data filters by hostname automatically

## Part 3: Closing (1 minute)
- Recap: "This is a 15-minute install from a single .exe. No cloud, no subscription per GB, no security analyst required."
- Key differentiators: on-premises privacy, AI assistant built-in, compliance reporting out of the box, federated architecture for MSSPs
- Download at: https://github.com/lukefitzg/tinysocs/releases/latest
- Landing page: https://lukefitzg.github.io/tinysocs/

## Demo Tips
- The demo banner ("Demo Mode — showing synthetic data") is intentional and builds trust with prospects
- All timestamps are relative to the current time — the demo always looks fresh
- The AI assistant works best with an API key set (Claude recommended). Without one, other tabs still work perfectly.
- If demoing to an MSSP, start with the Sites tab. If demoing to an SMB, start with Overview.
- The scenario is a law firm ("Hartwell & Associates") — relatable for professional services prospects.
- Every widget header has an **Ask AI** button — use these to show natural-language querying in context.
- The **guided response actions** on the Detections tab showcase the operator workflow — a great demo closer.
