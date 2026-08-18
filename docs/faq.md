# TinySocs FAQ

## General

### Who is TinySocs for?

Homelabbers, tinkerers, students, and small IT shops who want to see what's actually
happening on a handful of Windows machines — logons, process creation, persistence
attempts, ransomware-shaped file activity — without spending a week standing up an
enterprise SIEM. If you run a Windows homelab or look after a small office network and
you're curious what your event logs would tell you if anything ever read them, this is
for you.

### Is it really free? What's the catch?

Free to use, no account, no tiers, no trial clock. The licence is BSL-1.1
(source-available, not OSI open source): you can run it in production, read and modify
everything, and each version converts to Apache 2.0 after four years. The one
restriction: you can't offer TinySocs itself to third parties as a competing hosted or
embedded service. The other catch is stated plainly in [SUPPORT.md](../SUPPORT.md):
this is a solo side project provided as-is, with no support obligation.

### How is TinySocs different from Wazuh / Security Onion / Elastic?

Those are more capable and better staffed — if you have the time and hardware, use
them. TinySocs trades breadth for time-to-first-signal: one Windows installer stands
up collection, detection, storage, and a dashboard in one shot, and the whole thing is
small enough to read the source of. It's Windows-only and caps out around ~100
endpoints per node.

### What events does TinySocs collect?

The agent collects Windows Security events (logon, process creation, privilege use,
account management), Sysmon events (detailed process creation with command lines,
network connections, file system changes, registry modifications), and Windows
Defender events. All events are stored locally in OpenSearch.

### Does any data leave my network?

Event data stays on-premises in the local OpenSearch instance. The only external
communication is:
- **LLM API calls**: Alert summaries and queries are sent to your chosen LLM provider
  (Anthropic, OpenAI, or local Ollama). Use Ollama for fully air-gapped operation.
- **Webhook notifications**: If configured, alert summaries go to your
  Slack/Teams/email endpoints.
- **No telemetry**: TinySocs does not phone home or send usage data.

### Which LLM providers are supported?

- **Anthropic Claude** — best analysis quality
- **OpenAI GPT-4o** — good alternative
- **Ollama** (local) — fully offline, no data leaves the machine; quality depends on the model

### What are the system requirements?

Minimum: Windows 10/Server 2019, 8 GB RAM, 20 GB disk, 2 CPU cores. Recommended:
16 GB RAM, 50 GB disk, 4 cores. For monitoring more than 50 endpoints, increase RAM
to 32 GB.

## Detection

### How many detection rules are included?

Honest answer, three numbers: **19 rules ship enabled** (the high-signal,
low-false-positive cut — covering 16 MITRE ATT&CK techniques across 8 tactics);
**39 are defined** in the C# engine (the other 20 are off by default because they're
noisy or environment-specific — enable the ones that fit your network); and there's a
**50-rule KQL catalogue** in the Python tree that does **not** run in a default
install — it's a library, not live detection. Counts as of pack 2026.27
(2026-08-18). Rule-by-rule evidence of what actually fires:
[pilot-ruleset.md](pilot-ruleset.md).

### Are the rules actually tested?

Every enabled rule has an Atomic Red Team test defined and an xUnit test pair proving
it fires on synthetic events. As of the last live harness run (2026-07-08), 8 of the
19 enabled rules were proven end-to-end — real attack technique on a real Windows VM
through to a dashboard alert. The rest are synthetic-proven or blocked on environment
prerequisites (e.g. needing a domain controller or Defender tamper settings).
Misses and skips are documented, not hidden — see
[pilot-ruleset.md](pilot-ruleset.md).

### Can I edit the detection rules?

Yes — please do. Rules are plain YAML at
`C:\ProgramData\TinySocs\Collector\rules\rules.yml`, hot-reloaded on change. Raise a
threshold that's noisy on your network, enable one of the 20 held-back rules, or write
your own. There's also a Rule Builder in the dashboard for custom KQL rules. Tuning
to your own environment is the intended way to run this.

### What is Sysmon and do I need it?

Sysmon is a free Microsoft tool that provides detailed endpoint telemetry (process
creation with command lines, network connections, file changes, registry
modifications). TinySocs works without Sysmon but has significantly better detection
coverage with it installed. The installer can deploy Sysmon automatically.

### How do I validate detection coverage myself?

Use the Atomic Red Team test runner (`tests/Test-AtomicDetection.ps1`) to simulate
attack techniques on a **test machine** and verify TinySocs detects them. Don't run
attack simulations on machines you care about.

## Operations

### How do I update TinySocs?

Run the new installer over the existing installation. The installer detects existing
installs and preserves your data, configuration, and credentials during upgrade.
Updates ship when they ship — there is no promised cadence.

### How do I add monitoring to a new endpoint?

Install the TinySocs Agent on the new machine and configure it to point at the Hub's
OpenSearch URL. The agent starts sending events immediately.

### How do I back up my data?

Back up the `C:\ProgramData\TinySocs` directory. This contains the OpenSearch data,
agent configuration, detection rules, and assistant settings. For OpenSearch-level
backups, use the snapshot API.

### How do I change the dashboard password?

Open the dashboard, click the gear icon, enter the current admin password, then use
"Change Password" in the settings panel.

### How do I uninstall completely?

Add/Remove Programs → TinySocs → Uninstall removes services and binaries but **keeps
your data** in `C:\ProgramData\TinySocs` by default. To remove data too, create the
file `C:\ProgramData\TinySocs\remove_on_uninstall.flag` before uninstalling. Known
issue: some scheduled tasks can survive uninstall — see
[KNOWN-LIMITATIONS.md](../KNOWN-LIMITATIONS.md).

## Compliance

### Which compliance frameworks are supported?

- **NIST CSF 2.0** — 17 controls mapped to detection rules
- **HIPAA Security Rule** — 11 controls (technical safeguards)
- **PCI DSS v4.0** — 12 requirements mapped

These are coverage-mapping reports, not audit attestations.

### Can I add custom framework mappings?

Yes. Create a YAML file in `src/tinysocs/reporting/frameworks/` following the existing
format (see `nist_csf.yaml` as an example). The framework will automatically appear in
the dashboard dropdown.

## Troubleshooting

### The dashboard shows "SIEM not connected"

Check that OpenSearch is running: `Get-Service TinySocsOpenSearch`. If stopped, start
it and wait 30 seconds for initialization. See [Troubleshooting](troubleshooting.md).

### No events are appearing

Verify the agent is running: `Get-Service TinySocsAgent`. Check the agent log at
`C:\ProgramData\TinySocs\Collector\logs\`. Ensure the agent configuration points to
the correct OpenSearch URL.

### The AI assistant is not responding

Check that a valid LLM API key is configured in `assistant.env`. Verify network
connectivity to the LLM provider. For Ollama, ensure the Ollama service is running
locally.

### Something else is broken

Run the diagnostics before filing an issue — [SUPPORT.md](../SUPPORT.md) lists the
three commands that produce everything a bug report needs.
