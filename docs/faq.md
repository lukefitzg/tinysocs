# TinySocs FAQ

## General

### How is TinySocs different from Splunk / Elastic / Sentinel?

TinySocs is designed for small teams that need security monitoring without dedicated security engineers. It installs in 15 minutes, includes an AI assistant that explains alerts in plain English, and generates compliance reports with one click. Enterprise SIEMs require weeks of setup, custom dashboards, and specialised staff.

### What events does TinySocs collect?

The agent collects Windows Security events (logon, process creation, privilege use, account management), Sysmon events (detailed process creation with command lines, network connections, file system changes, registry modifications), and Windows Defender events. All events are stored locally in OpenSearch.

### Does any data leave my network?

Event data stays 100% on-premises in the local OpenSearch instance. The only external communication is:
- **LLM API calls**: Alert summaries and queries are sent to your chosen LLM provider (Anthropic, OpenAI, or local Ollama). Use Ollama for fully air-gapped operation.
- **Webhook notifications**: If configured, alert summaries are sent to your Slack/Teams/email endpoints.
- **No telemetry**: TinySocs does not phone home or send usage data.

### Which LLM providers are supported?

- **Anthropic Claude** (recommended) — Best analysis quality
- **OpenAI GPT-4o** — Good alternative
- **Ollama** (local) — Fully offline, no data leaves the machine. Quality depends on the model.

### What are the system requirements?

Minimum: Windows 10/Server 2019, 8 GB RAM, 20 GB disk, 2 CPU cores. Recommended: 16 GB RAM, 50 GB disk, 4 cores. For monitoring more than 50 endpoints, increase RAM to 32 GB.

## Detection

### How many detection rules are included?

40+ built-in rules across 8 categories: authentication, PowerShell, process execution, credential access, lateral movement, persistence, defence evasion, and exfiltration. All rules are mapped to MITRE ATT&CK techniques.

### Can I write custom detection rules?

Yes. Use the Rule Builder in the dashboard to create rules with KQL queries, or upload YAML/JSON rule packs. Custom rules support threshold grouping, field enrichment, and severity levels.

### What is Sysmon and do I need it?

Sysmon is a free Microsoft tool that provides detailed endpoint telemetry (process creation with command lines, network connections, file changes, registry modifications). TinySocs works without Sysmon but has significantly better detection coverage with it installed. The installer can deploy Sysmon automatically.

### How do I validate detection coverage?

Use the Atomic Red Team test runner (`tests/Test-AtomicDetection.ps1`) to simulate attack techniques and verify that TinySocs detects them. See [Detection Efficacy](detection-efficacy.md) for details.

## Operations

### How do I update TinySocs?

Run the new installer over the existing installation. The installer detects existing installs and preserves your data, configuration, and credentials during upgrade.

### How do I add monitoring to a new endpoint?

Install the TinySocs Agent on the new machine and configure it to point to the TinyBox instance's OpenSearch URL. The agent will start sending events immediately.

### How do I back up my data?

Back up the `C:\ProgramData\TinySocs` directory. This contains the OpenSearch data, agent configuration, detection rules, and assistant settings. For OpenSearch-level backups, use the snapshot API.

### How do I change the dashboard password?

Open the dashboard, click the gear icon, enter the current admin password, then use "Change Password" in the settings panel.

## Compliance

### Which compliance frameworks are supported?

- **NIST CSF 2.0** — 17 controls mapped to detection rules
- **HIPAA Security Rule** — 11 controls (technical safeguards)
- **PCI DSS v4.0** — 12 requirements mapped

### How do compliance reports work?

Each framework defines controls that map to TinySocs detection rules. The report shows which controls have active detections (rules that fired), deployed detections (rules exist but haven't fired), and unmapped controls (no rule coverage). Reports can be generated from the dashboard or CLI.

### Can I add custom framework mappings?

Yes. Create a YAML file in `src/tinysocs/reporting/frameworks/` following the existing format (see `nist_csf.yaml` as an example). The framework will automatically appear in the dashboard dropdown.

## Troubleshooting

### The dashboard shows "SIEM not connected"

Check that OpenSearch is running: `Get-Service TinySocsOpenSearch`. If stopped, start it and wait 30 seconds for initialization. See [Troubleshooting](troubleshooting.md) for more details.

### No events are appearing

Verify the agent is running: `Get-Service TinySocsAgent`. Check the agent log at `C:\ProgramData\TinySocs\Collector\logs\`. Ensure the agent configuration points to the correct OpenSearch URL.

### The AI assistant is not responding

Check that a valid LLM API key is configured in `assistant.env`. Verify network connectivity to the LLM provider. For Ollama, ensure the Ollama service is running locally.
