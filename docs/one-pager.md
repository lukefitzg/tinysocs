# TinySocs — Always-On Security Monitoring for Companies Without a Security Team

## The Problem

A customer sent you a security questionnaire and you can't tick the monitoring box. Your cyber-insurance renewal now requires it. An audit is coming. And you don't have — and can't hire — a security team.

- **You need to answer three questions**: Are we being attacked? Are we covered? Can I prove it to a customer, insurer, or auditor?
- **The enterprise tools aren't for you**: they assume dedicated security engineers and weeks of setup
- **Doing nothing is no longer an option**: the questionnaire, the renewal, or the audit has a date on it

## The Solution

TinySocs watches your Windows machines 24-7, tells you in plain English when something needs attention, and gives you the proof — installed in 15 minutes, running entirely on your own hardware.

**Install** a single executable on a Windows machine. **Detect** real attack behaviour — password guessing, ransomware activity, attacker persistence — with detections that are tested against real attacks before they ship and tuned to stay quiet in a normal office. **Understand** every alert with an AI assistant that speaks plain English, not security jargon. **Prove it** with one-click compliance reports (NIST CSF 2.0, HIPAA, PCI DSS v4.0). The detections stay current automatically — you never touch a rule.

For IT providers and MSPs: **manage** multiple client sites from one federated dashboard.

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
- **Detection**: 19 high-fidelity rules enabled in the free base pack (16 techniques, 8 tactics), threshold-based, MITRE ATT&CK mapped and Atomic Red Team-validated. The engine defines 39 rules total (18 more held back for per-environment tuning, 2 lab-only); a further 50-rule catalogue is roadmapped for the backend engine.
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
