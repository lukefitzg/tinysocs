# TinySocs Demo Script (v0.9.0)

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

---

## Part 1: Single-Site Walkthrough (5 minutes)

Walk through each tab:

### Overview Tab
- **Alert Summary**: 42 alerts in last 24 hours — 3 critical, 8 high, 17 medium, 14 low
  - Total Alerts card spans full width on its own row; 4 severity cards share the row below
- **Alert Timeline**: 24-hour stacked bar chart with visible spike at ~14 hours ago (brute force attack)
- Show top hosts and top rules
- Point out the severity color coding
- **Storage Widget** (full width): Disk usage bar with percentage, per-index breakdown (Event Logs, Alerts, Custom/HEC), cluster health indicator (green), retention periods shown per index
- **Ask AI button**: click to pre-fill the assistant with context about the current alert distribution

### Fired Detections (scroll down on Overview)
- 7 fired alerts matching the demo scenario:
  - Brute force: 8 failed logons from 203.0.113.47 (critical, RECEPTION-PC)
  - Suspicious PowerShell: encoded command execution (high, DC-01)
  - New local account created: svc_backup (medium, FILESERVER-01)
  - FIM: Modified C:\ClientFiles\Mergers\draft.docx (medium, FILESERVER-01)
  - Off-hours RDP attempt from 198.51.100.22 (high, FILESERVER-01)
  - Scheduled task created: WindowsUpdate_Check (medium, DC-01)
  - Defender: real-time protection disabled after connection from 192.0.2.15 (high, RECEPTION-PC)
- Host field shows actual hostnames (not N/A)
- Filter by status with the dropdown (Active, Acknowledged, All)
- **Threat intel enrichment**: Expand the brute force alert to see:
  - AbuseIPDB: confidence 87%, 342 reports, country RU
  - GreyNoise: malicious classification, tagged as brute-forcer
  - OTX: 14 pulses, reputation 72
- Also show the RDP alert (198.51.100.22): AbuseIPDB 45%, GreyNoise unknown, Tencent Cloud
- Pagination — no scroll bars, clean navigation

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
- Pagination fills viewport dynamically — no dead space

### Detections Tab
- **Alert Rules**: 19 high-fidelity rules enabled in the base pack (39 defined in the engine) with MITRE ATT&CK annotations, organised by category (Auth, Identity, Credential Access, Persistence, Lateral, Defence Evasion, Impact, etc.)
  - Pagination controls (no scrollbar)
  - Filter by category
  - "+ New Rule" and "Upload Pack" buttons
- **Fired Detections** below with status management
- Shows **4 staged actions** with remediation runbooks:
  - **block_ip** (staged): Block 203.0.113.47 — brute force source IP
  - **isolate_host** (staged): Isolate RECEPTION-PC — Defender disabled
  - **disable_user** (acknowledged): Disable svc_backup — suspicious local account
  - **open_ticket** (staged): RDP brute force from 198.51.100.22
- Click an action to expand its **remediation runbook** with step-by-step guidance
- Demonstrate Acknowledge/Dismiss workflow buttons

### Compliance Tab
- **MITRE ATT&CK coverage**: heatmap grid with technique counts per tactic
  - Click a tactic cell to expand and see covered technique IDs
  - Navigator layer export available
- **Compliance frameworks**: select NIST CSF 2.0, HIPAA, or PCI DSS
  - Show control mapping with pass/partial/fail status
  - **Download Report** button generates a standalone HTML compliance report
- **Ask AI buttons** on both Compliance and MITRE headers

### AI Assistant
- **Privacy consent**: On first click, a consent dialog appears explaining what data is sent to the LLM provider. Accept to continue. This builds trust with privacy-conscious prospects.
- **Privacy badge**: Once active, the assistant header shows which provider is in use
- Type: "what happened on RECEPTION-PC in the last hour?"
- The assistant queries the synthetic data and returns a natural language narrative
- Type: "is the brute force attack still ongoing?"
- Show how it correlates events across the timeline
- Type: "how do I configure data retention?" — the assistant has full product knowledge and can answer questions about TinySocs itself
- **Ask AI buttons** on each widget header pre-fill contextual prompts

---

## Part 2: Settings Walkthrough (2 minutes)

### Settings Panel (gear icon, top-right)
- **Tabbed layout** with 4 tabs: General, Storage, Security, Diagnostics
- **General tab**:
  - LLM Configuration: provider dropdown, model fields — operator chooses their own model, no hardcoded defaults
  - Notifications: webhook URL and email SMTP config
  - Threat Intelligence: API key fields for AbuseIPDB, OTX, GreyNoise
- **Storage tab**:
  - Data Retention: Event Log (30d), Alert (90d), Custom/HEC (30d). Configurable 7-365 days.
  - Purge controls: dropdown with "Older than retention", "Older than 7 days", "Older than 1 day", "Everything". Red Purge button with confirmation.
  - HEC Tokens: endpoint URL (https://localhost:8081/hec), create/revoke tokens, "shown only once" banner
  - Talk through: "This is how you'd connect a firewall, syslog server, or any tool that can send JSON over HTTP."
- **Security tab**:
  - SIEM Connection: OpenSearch URL, user, password fields
  - Change Password: unified password for dashboard and SIEM
- **Diagnostics tab**:
  - "Run Health Check" button — shows OpenSearch cluster health (status, nodes, shards, heap %, indices, docs, store size), disk usage, federation node reachability with response times
  - "Copy to Clipboard" exports diagnostics as text for support/troubleshooting
  - Talk through: "Operators can run diagnostics without SSH access or command-line knowledge."

---

## Part 3: Multi-Site Walkthrough (2 minutes)

### Sites Tab
- 3 client sites visible: acme-law, mainst-dental, harbor-ins
- acme-law: healthy (green), version 0.9.0, 347 ledger entries, 2 detections in last run
- mainst-dental: healthy (green), version 0.9.0, 189 ledger entries, 0 detections
- harbor-ins: warning (amber), version 0.8.9 (outdated), 512 ledger entries, 5 detections in last run
- Talk through: "This is the MSSP view. One dashboard, all your clients. Alert aggregation, ledger integrity verification, centralized version tracking."
- Point out harbor-ins version drift as a talking point about fleet management
- **Certificate pinning**: Each approved site's TLS certificate fingerprint is pinned — green lock icon. If a cert changes unexpectedly, the Hub refuses the connection.
- **Click a site** to drill into its Overview/Data tabs — data filters to that site automatically
- Click "All Sites" to return to the aggregated view

---

## Part 4: Closing (1 minute)

- Recap: "This is a 15-minute install from a single .exe. No cloud, no subscription per GB, no security analyst required."
- Key differentiators:
  - **Privacy-first**: Data never leaves the box. AI consent flow. Ollama for fully offline AI.
  - **AI assistant**: Explains alerts in plain English, knows the product, suggests remediation
  - **Compliance**: NIST CSF, HIPAA, PCI DSS reports out of the box
  - **Federation**: Multi-site with certificate pinning for MSSPs
  - **Custom ingestion**: HEC endpoint accepts logs from any source
  - **Operational controls**: Configurable retention, storage monitoring, auto-purge, token management
- Download at: https://github.com/lukefitzg/tinysocs/releases/latest
- Landing page: https://lukefitzg.github.io/tinysocs/

---

## Demo Tips
- The demo banner ("Demo Mode — showing synthetic data") is intentional and builds trust with prospects
- All timestamps are relative to the current time — the demo always looks fresh
- The AI assistant works best with an API key set (Claude recommended). Without one, other tabs still work perfectly.
- If demoing to an MSSP, start with the Sites tab. If demoing to an SMB, start with Overview.
- The scenario is a law firm ("Hartwell & Associates") — relatable for professional services prospects.
- Every widget header has an **Ask AI** button — use these to show natural-language querying in context.
- The **guided response actions** on the Detections tab showcase the operator workflow — a great demo closer.
- Show the **Settings panel** to demonstrate operational maturity — retention, HEC tokens, storage monitoring, and purge controls show this is a production-ready system, not a prototype.
- The **AI consent dialog** is a selling point for privacy-conscious prospects. Don't skip it.
- The **threat intel enrichment** on fired detections is visually impressive — expand at least one alert to show the provider breakdown.
