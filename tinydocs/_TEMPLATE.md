---
rule_id: TS-XXX
name: rule_name
severity: low | medium | high | critical
mitre: TXXXX.XXX (Technique Name)
tactic: tactic-name
pack: base
runs_on: agent
status: draft
---

# TS-XXX — Human Title

> One-sentence plain-English statement of what fires this rule. An SMB IT
> generalist with no SOC background should understand it.

## What it detects

What event(s) and pattern trip this rule, in concrete terms. Name the Windows
Event ID / channel and the threshold so the reader can reason about it.

## Why it matters

The attacker behaviour behind the signal. What stage of an intrusion this is,
and what it means if it's real. Two or three sentences — this is the "should I
care at 2am" answer.

## What a true positive looks like

A concrete example of a real detection: the kind of process, account, or host
pattern that means this is a genuine attack, not noise.

## Common false positives

The benign activity that also trips this rule, and — crucially — **how to tune
it without editing the rule**. Reference the allowlist scopes this rule honours
(from `allowlist_scopes`), e.g.:

- *Backup service account fails auth nightly* → allowlist `user: svc_backup` on this rule.
- *Vuln scanner sweeps the subnet* → allowlist `source_ip_cidr: 10.50.0.0/24`.

## Tuning knobs

If the rule exposes a `tuning` knob (e.g. `threshold`), say what raising/lowering
it trades off. If none, say "none — single-event trigger" or similar.

## References

- MITRE ATT&CK: link
- Relevant Atomic Red Team test(s): `tests/atomic-tests.yaml` entry
