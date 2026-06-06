# TinyDocs — Per-Rule Knowledge Base

Plain-English explainers for detection rules, written for an SMB IT generalist
with no SOC background. One file per rule (`TS-XXX.md`). Every v2 rule pins a
`docs: tinydocs/<id>.md` path; the pack build copies the referenced docs into
the signed pack so customers get the rule *and* its explanation together
(see `docs/design/rule-format-v2.md` and `docs/design/signed-feed.md`).

This is strategic gap #5. It is the customer-visible face of the content feed:
when an alert fires, the dashboard links to the matching TinyDoc so the customer
can answer "what is this and do I care" without us on the phone.

## Structure

- `_TEMPLATE.md` — the authoring template (front-matter + section headers).
- `TS-XXX.md` — one doc per rule. Front-matter carries `status: draft | published`.
- Generate stubs from a pack with `scripts/scaffold_tinydocs.py` — it pre-fills
  front-matter, the detection summary, allowlist scopes, and tuning knobs from
  the rule's own metadata, so authoring starts from facts. It never overwrites
  an existing doc.

Each doc answers the same six questions: what it detects, why it matters, what a
true positive looks like, common false positives **and how to allowlist them**,
tuning knobs, and references. The false-positive section deliberately ties to
the rule's `allowlist_scopes` — TinyDocs are how a customer learns to tune via
allowlists instead of editing rule files, which is the whole v2 premise.

## Priority 20 (most customer-visible rules)

Selected for severity + how often they show up in demos, validation, and real
intrusions. Lead with these; the rest of the 37 base rules get docs over time
(`scripts/scaffold_tinydocs.py --all`).

| Rule | Name | Severity | Status |
|------|------|----------|--------|
| TS-061 | credential_dumping_tools | critical | published |
| TS-062 | ntds_dit_access | critical | published |
| TS-113 | fim_mass_modification (ransomware) | critical | published |
| TS-114 | fim_sensitive_file_deleted | critical | published |
| TS-001 | brute_force_logon | high | published |
| TS-002 | brute_force_logon_by_ip | high | published |
| TS-060 | lsass_access | high | published |
| TS-071 | rdp_brute_force | high | published |
| TS-070 | psexec_usage | high | published |
| TS-080 | event_log_cleared | high | published |
| TS-081 | defender_tamper | high | published |
| TS-082 | amsi_bypass | high | published |
| TS-090 | service_install_suspicious | high | published |
| TS-010 | local_account_created | high | published |
| TS-100 | dns_tunnel_volume | high | published |
| TS-133 | process_injection_sysmon | high | published |
| TS-135 | lolbin_proxy_execution | high | published |
| TS-020 | scheduled_task_created | medium | published |
| TS-132 | ingress_tool_transfer | medium | published |
| TS-130 | account_discovery | medium | published |

All 20 priority docs published. The remaining 17 base rules (`--all`) get docs
over time via the content cadence.

## Authoring / content cadence

This dir is also the home of the weekly content cadence (gap #6): a new rule
lands → run `scripts/scaffold_tinydocs.py` → fill the stub → flip `status` to
`published` → it ships in the next pack version. Keep the prose plain; the reader
is a busy generalist, not an analyst.
