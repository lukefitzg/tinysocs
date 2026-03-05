# TinySocs — Lightweight AI-Powered SIEM

## The Problem

Small and mid-sized organisations need security monitoring but face:

- **Enterprise SIEM complexity**: Splunk, Sentinel, and Elastic require dedicated security teams
- **Cloud-only solutions**: Data leaves your network; per-GB pricing is unpredictable
- **Alert fatigue**: Too many alerts, not enough context to act on them
- **Compliance gaps**: Frameworks require log monitoring, but proving coverage is manual

## The Solution

TinySocs is a privacy-first, self-hosted SIEM with an AI assistant that deploys in 15 minutes.

**Install** a single executable on a Windows machine. **Collect** Windows security events from endpoints. **Detect** threats with 89 built-in rules mapped to 33 MITRE ATT&CK techniques across 11 tactics — 100% validated against Atomic Red Team. **Investigate** with an AI assistant that speaks plain English. **Report** compliance coverage against NIST CSF 2.0, HIPAA, and PCI DSS v4.0. **Manage** multiple client sites from one federated dashboard.

**Download:** [GitHub Releases](https://github.com/lukefitzg/tinysocs/releases/latest) | **Landing page:** [lukefitzg.github.io/tinysocs](https://lukefitzg.github.io/tinysocs/)

## Key Differentiators

| Feature | TinySocs | Enterprise SIEM |
|---------|----------|-----------------|
| Deployment time | 15 minutes | Weeks to months |
| Data residency | 100% on-premises | Cloud or hybrid |
| Pricing | Flat (no per-GB) | Usage-based |
| AI assistant | Built-in (Claude/GPT/Ollama) | Add-on or none |
| Compliance reports | One-click generation | Custom development |
| Operator skill level | IT generalist | Security engineer |

## Technical Specs

- **Platform**: Windows 10/11, Server 2019+
- **Data store**: Bundled OpenSearch (single-node)
- **Agent**: C# .NET 8.0, collects Windows + Sysmon events
- **Detection**: 89 rules (33 techniques, 11 tactics, 100% Atomic Red Team efficacy), KQL + threshold-based, MITRE ATT&CK mapped
- **AI**: Claude (Anthropic), GPT-4o (OpenAI), or local Ollama
- **Dashboard**: Web UI with alerts, timeline, fleet health, event explorer, rule management
- **Notifications**: Slack, Teams, email (with retry queue)
- **Compliance**: NIST CSF 2.0, HIPAA Security Rule, PCI DSS v4.0

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8 GB | 16 GB |
| Disk | 20 GB | 50 GB |
| CPU | 2 cores | 4 cores |
| Endpoints | 1 | Up to 100 |
