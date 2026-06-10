# TinySocs Competitive Positioning

## Market Context

Small and mid-sized businesses face the same threats as enterprises but lack the budget, headcount, and expertise to deploy traditional SIEM platforms. Most commercial SIEMs price per GB of ingested data or per endpoint, making them prohibitively expensive for organizations with 10-100 endpoints. Open-source alternatives like Elastic SIEM offer power but demand dedicated security engineers to deploy, tune, and maintain. The result is a gap: SMBs either run nothing, rely on basic antivirus, or overpay for cloud platforms they barely use. TinySocs targets this gap directly with a self-hosted, privacy-first SIEM that installs in 15 minutes, costs nothing, and requires no security expertise to operate.

## Comparison Matrix

| Feature | TinySocs | Blumira | Todyl | Perch / ConnectWise | Elastic SIEM | MS Sentinel |
|---|---|---|---|---|---|---|
| **Deployment model** | On-premises (single .exe) | Cloud-hosted | Cloud-hosted | Cloud-hosted (sensor on-prem) | Self-hosted or Elastic Cloud | Azure cloud-native |
| **Pricing model** | Free core (BSL-1.1 license) | Per-user/month ($144+/user/yr) | Per-user/month | Per-endpoint/month (MSSP pricing) | Free (OSS) or per-GB (Cloud) | Pay-per-GB ingestion |
| **Setup time** | ~15 minutes | ~1 hour (cloud onboarding) | ~1-2 hours | Hours to days (partner-led) | Days to weeks | Hours to days (Azure ecosystem) |
| **AI assistance** | Built-in (Claude, GPT, Ollama) | Limited (automated recommendations) | None (rule-based) | None | AI Assistant (Elastic AI) | Copilot for Security (add-on cost) |
| **Compliance reporting** | NIST CSF 2.0, HIPAA, PCI DSS v4.0 | SOC 2 mapping, limited frameworks | Basic compliance dashboards | Compliance reporting for MSPs | Kibana dashboards (manual) | Regulatory compliance dashboards |
| **On-premises option** | Yes (only option) | No | No | Sensor only (data in cloud) | Yes (self-managed) | No |
| **MSSP / multi-tenant** | Federated multi-site architecture | MSP portal available | Partner program | Built for MSPs/MSSPs | Spaces (manual config) | Lighthouse multi-tenant |
| **Detection rule count** | 89 (100% validated) | ~200+ (proprietary) | ~150+ (proprietary) | ~300+ (ConnectWise-managed) | 1,000+ (community + Elastic) | 300+ (Microsoft + community) |
| **Threat intelligence** | AbuseIPDB, OTX, GreyNoise | Proprietary threat intel | Proprietary threat intel | ConnectWise threat feeds | Elastic Threat Intel module | Microsoft Threat Intelligence |
| **Operator skill level** | IT generalist | IT generalist | IT generalist | MSP technician | Security engineer | Security engineer / Azure admin |
| **Open source** | Source-available (BSL-1.1 → Apache 2.0) | No | No | No | Yes (Elastic License 2.0 / AGPL) | No |
| **Data residency** | Customer-controlled (on-prem) | Blumira cloud (US regions) | Todyl cloud | ConnectWise cloud | Customer-controlled (self-hosted) or Elastic Cloud | Azure region (Microsoft-managed) |

## TinySocs Differentiators

- **Fully on-premises -- data never leaves the network.** Every byte of log data, every alert, every compliance report stays on hardware the customer owns. There is no cloud telemetry, no phoning home, no third-party data processor. For businesses subject to data residency requirements or simply unwilling to send security logs to a vendor, this is non-negotiable.

- **AI assistant built-in -- explains alerts in plain English, not just generates them.** TinySocs ships with an integrated AI assistant supporting Claude, GPT, and local Ollama models. It does not just correlate events; it explains what an alert means, why it matters, and what to do about it. An IT generalist can triage a credential-dumping alert without a SOC analyst on staff.

- **15-minute install from a single .exe -- no containerization, no cloud accounts, no security expertise.** There are no Docker containers, no Kubernetes clusters, no Terraform scripts. One executable, one Windows machine, 15 minutes. The install wizard handles log source configuration, rule deployment, and dashboard provisioning automatically.

- **Source-available (BSL-1.1) -- no per-GB, per-user, or per-endpoint pricing on the core platform.** TinySocs carries a Business Source License 1.1: commercial rights are reserved, and each released version converts to Apache 2.0 four years after its public release. The Additional Use Grant permits production use except for competing hosted/embedded offerings. There is no usage ceiling on the core platform, no surprise invoices at the end of the month, and no sales call required to get started.

- **Compliance reporting out of the box -- NIST CSF 2.0, HIPAA, PCI DSS v4.0 with one-click reports.** Each compliance framework is mapped to detection rules and evidence artifacts. Reports generate with a single click, producing PDF-ready output suitable for auditors. No manual mapping, no spreadsheet gymnastics, no consulting engagement required.

- **Federated MSSP architecture -- manage N client sites from one dashboard with tamper-proof evidence ledgers.** Each client site runs its own TinySocs node (data stays on-prem at the client), while the MSSP aggregates alert summaries and compliance status into a central management dashboard. Evidence ledgers are append-only and cryptographically chained, providing tamper-proof audit trails across the entire client portfolio.

## Where TinySocs Is Weaker (Honest Assessment)

- **Windows-only.** There is no Linux or macOS agent. Organizations with heterogeneous fleets will have blind spots on non-Windows endpoints. Linux server monitoring and macOS endpoint coverage are on the roadmap but not yet available.

- **Single-developer project with a smaller community.** TinySocs does not have the contributor base, ecosystem, or vendor support structure of Elastic or Microsoft. Bug fixes, feature requests, and documentation improvements depend on a small team. Enterprise buyers who require SLAs, 24/7 vendor support, or a large community knowledge base will find this limiting.

- **Smaller detection library than enterprise platforms.** TinySocs ships 89 detection rules covering 33 MITRE ATT&CK techniques across 11 tactics. Elastic SIEM ships over 1,000. The difference matters for coverage breadth -- though every TinySocs rule is validated at 100% efficacy against Atomic Red Team, whereas large rule libraries often contain rules that have never been tested against live attack simulations.

- **No cloud-native deployment option.** TinySocs runs on-premises only. Organizations that have gone fully cloud-native or prefer SaaS delivery will need to maintain a Windows host to run it. There is no managed cloud offering.

- **No SOAR or automated response capabilities.** TinySocs detects and alerts but does not automatically quarantine hosts, block IPs, or trigger remediation playbooks. Response is manual. Organizations that need automated containment will need to pair TinySocs with a separate SOAR tool or handle response workflows externally.

- **Single-box architecture limits scale to approximately 100 endpoints per node.** TinySocs is designed for small environments. A single node handles roughly 100 endpoints before performance degrades. Larger environments require multiple federated nodes rather than vertical scaling, which adds operational complexity.

## Positioning by Audience

### For IT Consultants / MSPs

IT consultants and MSPs typically serve SMB clients who have no dedicated security staff. The current options are unappealing: sell the client a cloud SIEM subscription they cannot afford, deploy Elastic and spend billable hours maintaining it, or skip security monitoring entirely and hope nothing happens.

TinySocs changes the conversation. An MSP can install TinySocs on a single Windows machine at the client site in 15 minutes, hand the client a compliance report the same day, and offer ongoing monitoring as a managed service. Because TinySocs is free and open source, the MSP's margin comes from the service -- not from reselling a vendor subscription. The federated architecture means the MSP can manage every client's TinySocs instance from a single pane of glass without co-mingling client data.

Position TinySocs as: "The tool that lets you offer security monitoring to every client, not just the ones with big budgets."

### For MSSPs

MSSPs need multi-tenant architecture, evidence integrity, and operational efficiency across dozens or hundreds of client sites. TinySocs provides federated multi-site management where each client node is autonomous (data stays on-prem at the client) but alert summaries, compliance status, and health telemetry roll up to a central MSSP dashboard.

The tamper-proof evidence ledger is a key differentiator for MSSPs operating in regulated verticals. Every alert, every rule match, and every compliance assessment is recorded in an append-only, cryptographically chained ledger. This provides defensible evidence in the event of a breach investigation or regulatory inquiry -- without requiring the MSSP to store raw client logs centrally.

TinySocs is source-available under BSL-1.1. The Additional Use Grant permits production use except for offering a competing hosted or embedded SIEM product, and each version converts to Apache 2.0 four years after release. There are no per-seat fees eating into margin and no vendor lock-in.

Position TinySocs as: "Your private-label SIEM platform -- deploy it everywhere, brand it as yours, keep all the margin."

### For SMB IT Managers

An SMB IT manager wearing multiple hats does not need another complex platform. They need answers to three questions: "Are we being attacked?", "Are we compliant?", and "Can I explain this to my boss?"

TinySocs answers all three. The AI assistant translates security alerts into plain-English explanations that a non-technical executive can understand. Compliance reports for NIST CSF 2.0, HIPAA, and PCI DSS v4.0 generate with one click -- no consultant required. And because everything runs on-premises, the IT manager never has to explain to leadership why security logs are being sent to a third-party cloud.

The 15-minute install means the IT manager can have TinySocs running before their next meeting. The zero-cost licensing means there is no budget approval process, no procurement cycle, and no vendor negotiation.

Position TinySocs as: "Security monitoring you can set up before lunch, explain to your boss after lunch, and never pay a dime for."

## Key Proof Points

- **89 detection rules** covering **33 MITRE ATT&CK techniques** across **11 tactics** -- providing broad coverage of the most common attack patterns targeting SMB environments.
- **100% efficacy on Atomic Red Team** -- 15 out of 15 tested techniques detected successfully. Every detection rule has been validated against real attack simulations, not just written against documentation.
- **3 compliance frameworks** (NIST CSF 2.0, HIPAA, PCI DSS v4.0) with automated rule-to-control mapping and one-click report generation.
- **3 threat intelligence providers** integrated (AbuseIPDB, AlienVault OTX, GreyNoise) -- including one provider (GreyNoise) that requires no API key, enabling threat enrichment out of the box with zero configuration.
- **Sub-15-minute install time** from download to first alert, verified repeatedly across clean Windows environments.
- **Zero external dependencies at runtime** -- everything runs in a single box with no cloud services, no containers, and no external databases required after installation.
