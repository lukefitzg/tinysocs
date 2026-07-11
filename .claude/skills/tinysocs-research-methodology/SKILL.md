---
name: tinysocs-research-methodology
description: The discipline for turning a candidate detection idea into a shipped, enabled TinySocs rule (or a documented, retained retirement) — not the mechanics of writing the test (tinysocs-detection-validation-toolkit) or what counts as quotable evidence (tinysocs-validation-and-qa). Load this when deciding whether a rule should be enabled/disabled/tuned, writing the inline `pilot:` rationale for a rule, judging a rule against real FP risk, reviewing an existing enabled/disabled call for soundness, planning the weekly "1 rule + 1 tuning patch" content-cadence unit, or asking "would this fire on normal SMB behaviour", "why is TS-NNN off", "what evidence do I need before flipping enabled: true", or "is this atomic test actually testing anything". Contains the worked pilot-cut example (docs/pilot-ruleset.md, 2026-07-04/07-08), the three named evidence classes that got 17 rules disabled and 2 more retired later, the hypothesis-predicts-numbers-before-running discipline with the TS-002 cautionary tale, the rule lifecycle state machine, and the FP-tuning judgment call including the OpenSearch query pattern for pulling real event volume before deciding.
---

# TinySocs research methodology

This is the judgment layer above the mechanics. Someone else can teach you how to write an
Atomic test or an xUnit pair (`tinysocs-detection-validation-toolkit`) and how to read a harness
result (`tinysocs-validation-and-qa`). This skill teaches the harder thing: **when a rule
deserves to fire in a customer's environment at all**, demonstrated by the one time this repo
did it rigorously — the 2026-07-04 pilot cut (`docs/pilot-ruleset.md`) and its 2026-07-08
follow-up.

Glossary (first use): **`threshold_by_key`** — the one C# rule type: count matching events per
`group_by` key within `window_minutes`, fire at `threshold`, gate repeats with
`cooldown_minutes` (mechanics: `detection-engineering-reference`). **`field_match`** — an
optional narrowing clause (`field`, `values`, `match: exact|contains`) that restricts which
events count at all — without one, a rule counts *every* event of that `event_id`/`channel`,
regardless of what its name or description claims. **Atomic Red Team** — the public MITRE-derived
attack-simulation library the validation harness replays. **SMB** — small/medium business (the
ICP), not to be confused with the SMB network protocol also referenced by some rule names
(TS-070/TS-072 lateral-movement rules key off actual SMB-protocol services).

## When NOT to use this skill

- Writing the actual Atomic test YAML or the xUnit fire/silent pair → `tinysocs-detection-validation-toolkit`.
- Deciding what counts as a quotable efficacy number, reading `atomic-results.json`, or the
  curated-vs-raw denominator rules → `tinysocs-validation-and-qa`.
- Event-ID prerequisites, exact `field_match` semantics, MITRE mapping, threshold/window theory
  → `detection-engineering-reference`.
- Gating the change itself (does this even belong in scope, does it need a PR, does it touch a
  locked decision) → `tinysocs-change-control` — **every enable/disable/tune this skill leads you
  to still has to pass through that gate before it lands.**
- Deferred-gap inventory (allowlist runtime, FP telemetry, KQL runner) as open research problems
  in their own right → `tinysocs-research-frontier`.

---

## 1. The evidence bar

Per `docs/icp.md`, the pilot buyer is a 20–150-person Windows/M365 shop with **zero security
staff** — one IT generalist or an outsourced MSP, pushed into monitoring by an insurer, an audit,
or a customer questionnaire. Every alert in week one is read by someone who has never triaged a
security alert before. `docs/pilot-ruleset.md:36-42` sets the bar as three questions, in order:

1. **Low FP in a normal SMB estate** — standard business software, auto-updaters, maybe an RMM
   (remote monitoring and management) agent. No red team, no dev-tooling assumptions.
2. **High signal when it fires** — the alert should be worth a phone call.
3. **Explainable in one sentence** to a non-technical person.

> "A first pilot that cries wolf on day one kills the 'someone competent is watching' promise the
> subscription is built on. **When in doubt, a rule stays off.**" (`docs/pilot-ruleset.md:42`)

That last sentence is the actual decision rule. It is asymmetric on purpose: a false negative in
week one is invisible; a false positive in week one is the whole pitch, dead. Treat "I'm not
sure" as "disable it," not as "ship it and see."

Verified outcome of applying this bar (2026-07-04, `packaging/detection/rules.yml`,
`grep -c "enabled: true/false"` both re-confirmed 2026-07-11): **19 of 39 C# rules enabled**, 20
disabled with an inline `pilot:` reason on 17 of them (`grep -c "pilot:" packaging/detection/rules.yml`
→ 17; the other 3 disabled entries are the pre-existing `TS-001-lab`/`TS-030-lab` demo-threshold
variants plus TS-120, which carries a longer block comment instead of an inline `pilot:` tag —
see §3.3).

---

## 2. Hypothesis-predicts-numbers-before-running

Before you run a harness test or an xUnit case, **write down the number you expect, and why a
different number would mean the rule is broken.** A test whose pass/fail can't distinguish
"the rule works" from "the rule is untested" is not evidence — it's decoration.

### The cautionary tale: TS-002's 18-vs-20 non-test

`docs/pilot-ruleset.md:51,117` (cross-checked against `packaging/detection/rules.yml` — TS-002's
condition is `threshold: 20` per `detection-content.md`'s rule table): the March harness run fired
**18** failed-logon attempts against TS-002's group-by-IP brute-force rule, whose threshold is
**20**. Eighteen is below the line. The test could not have detected the rule either way:

- If TS-002's logic were completely broken, the result is "no alert" — 18 events, 0 alerts.
- If TS-002's logic were perfectly correct, the result is *also* "no alert" — 18 < 20, no alert
  expected.

Both worlds produce an identical outcome. The run told you nothing about TS-002 and was later
correctly reclassified as "not individually exercised," not "validated" and not "failed." This
is the single cleanest example in the repo of the difference between *running a test* and
*generating evidence*. Before authoring or reviewing any test:

1. State the expected count/threshold relationship explicitly (`N events against a threshold of
   M, N ≥ M` for a fire case, `N < M` for a silent case — with margin, not exactly at the line
   unless you're specifically testing the boundary).
2. State what a wrong implementation would produce instead, concretely.
3. If you can't articulate step 2, you don't have a test yet — you have a demo.

This generalizes past TS-002. Any harness or xUnit case that happens to pass "for free" because
the input never reached the rule's actual threshold, filter, or group key is a non-test wearing
a green checkmark. `tinysocs-validation-and-qa` owns what counts as *quotable* evidence once a
real test exists; this section is about not fooling yourself before you get there.

---

## 3. Three evidence classes (the pilot-cut taxonomy)

The 2026-07-04 cut didn't disable 17 rules on vibes — each falls into one of three named failure
modes, each with a distinct fix path. Learn the taxonomy; it's the reusable part.

### 3.1 Will-alarm-on-normal-behaviour (disable, no fix planned for pilot)

The condition is technically correct but the *shipped prerequisite* (a Sysmon include list, an
audit policy) makes it fire on routine desktop activity. No `field_match` addition alone rescues
these — they need parent-process/command-line context that the schema doesn't carry yet (v2
backlog).

| Rule | Why it storms | Verified against |
|---|---|---|
| TS-092 `startup_folder_write` | Condition counts *every* Sysmon FileCreate event; description says "Startup folder" but has no `TargetFilename` filter. Shipped Sysmon config logs Downloads, Outlook attachments, every `.exe`/`.dll`/`.ps1`/`.bat` write. | `integrations/sysmon/sysmon-config.xml` FileCreate (event 11) include list is populated — this is a genuine unfiltered-condition bug, not a dead-event problem (`detection-content.md` §4, §7.4). |
| TS-091 `registry_run_key` | Counts every Sysmon registry event (13); the shipped config's include list runs ~113 entries deep (services, Winlogon, IFEO, RDP settings). | Same distinction: sysmon-side data is fine and *does* narrow to autorun-relevant keys; the rule itself has zero `field_match`. |
| TS-134 `obfuscated_command` | Matches `-enc`, `Invoke-Expression`, `iex(` in any 4688 command line, threshold 1. | **Named as the single most dangerous rule for pilot credibility** — legitimate vendor installers, deployment scripts, and *especially RMM agents* (the exact tooling of the MSP channel in the ICP) use encoded PowerShell constantly. See §5's RMM hazard pattern below. |
| TS-135 `lolbin_proxy_execution` | 3× rundll32/regsvr32/mshta/wmic in 5 min. Windows spawns rundll32 routinely (printing, control panel, thumbnails) — 3-in-5-min is normal desktop noise. | Not validated under current definition either — compounding the risk. |
| TS-136 `wmi_process_creation` | Threshold 1 on any process with a WMI parent. RMM, SCCM, and monitoring agents spawn via WMI all day. | Same RMM-collision pattern as TS-134/135. |
| TS-083 `timestomp_detected` | Sysmon Event 2; browsers and installers legitimately set file creation times (Chrome updater is the canonical FP). | Low severity, low value even if quiet. |
| TS-040 / TS-050 process-creation bursts | Volumetric "200 processes in 10 min" — fires on builds, updates, login storms. | Low severity by design; not part of the pilot promise regardless of tuning. |

**Reusable method**: when a rule's noise complaint is "the *description* implies a narrow
condition but the YAML has no `field_match`," check whether the underlying event source
(Sysmon include list, audit policy) is itself narrow. If the event source is narrow but the rule
condition isn't, that's §3.2 (mislabeled — fixable). If the event source is wide open by design
(FileCreate, registry autorun watch, WMI process spawn) *and* the rule adds no filter, it's §3.1
(disable, v2 backlog) — the fix requires new schema capability (command-line/parent context),
not just a values list.

### 3.2 Mislabeled — condition doesn't match the description (fix with a real `field_match`)

These are the highest-leverage fixes: the rule's *story* was already good, it just never had the
filter that would make the story true. Four fixes shipped in the same commit, each verified live
in `packaging/detection/rules.yml` (2026-07-11):

| Rule | Description claimed | Condition as shipped (before fix) | `field_match` added | Verified at |
|---|---|---|---|---|
| **TS-071** `rdp_brute_force` | LogonType 10 (RDP) filtering | None — was literally TS-002 with a lower threshold, double-alerting on every 4625 burst | `winlog.event_data.LogonType`, exact match `"10"` | `packaging/detection/rules.yml:300-322` (comment: *"Without this filter the rule was just TS-002 with a lower threshold and double-alerted on every 4625 burst"*) |
| **TS-070** `psexec_usage` | PsExec service name | None — duplicate of generic TS-072, matched every 7045 | `winlog.event_data.ServiceName` contains `[PSEXESVC, PSEXEC, PAExec, RemCom, CSExec]` | `packaging/detection/rules.yml` TS-070 block (comment: *"PsExec (and clones) install a service literally named PSEXESVC by default"*) |
| **TS-090** `service_install_suspicious` | Suspicious ImagePath (temp/appdata/public) | None — also matched every 7045 | `winlog.event_data.ImagePath` contains `[\Temp\, \Windows\Temp, \AppData\, \Users\Public, \ProgramData\, \Downloads\, \Public\]` | `packaging/detection/rules.yml` TS-090 block (comment: *"Legitimate services install under Program Files / System32... Without this filter the rule matched every 7045, same as the now-disabled generic TS-072"*) |
| **TS-062** `ntds_dit_access` | ntds.dit / SYSTEM hive access | None — matched *any* 4663 object-access event, threshold 1 per machine | `winlog.event_data.ObjectName` contains `[ntds.dit, \config\SAM, \config\SYSTEM, \config\SECURITY]` | `packaging/detection/rules.yml` TS-062 block (comment: *"Without this filter the rule matched EVERY 4663 object-access audit event, which storms on any host with broad file-system SACLs"*) |

**The tradeoff this forced**: TS-070/TS-072/TS-090 all keyed off the same 7045 event (new service
installed) and, unfiltered, all three fired on one legitimate install — three differently-named
alerts for one event. The original 2026-07-04 draft proposed the opposite of what shipped:
keep the generic TS-072, disable TS-070/TS-090. The implementation flipped that — TS-070 and
TS-090 got real filters and stayed; the now-genuinely-redundant generic TS-072 (which matched
*every* 7045, including routine software installs) was disabled. **This is strictly higher
fidelity**: the two malicious 7045 patterns are named specifically, and routine install noise no
longer alerts at all. When a "keep the generic, drop the specific" instinct and a "fix the
specific with a filter, drop the generic" option are both on the table, prefer the filter — it's
almost always higher signal per alert.

**Reusable method**: read the rule's `description` field as a promise. Read its `condition` block
as what it actually checks. If they diverge, the fix is almost always adding the missing
`field_match` — cheap, mechanical, and it converts a duplicate/noisy rule into a real one without
touching the schema. Always grep for whether another enabled rule already covers the same event
unfiltered (the 7045 case) — you may be able to retire a sibling instead of just narrowing this
one.

### 3.3 Dead or unverifiable as shipped (disable, and say why precisely)

Different from §3.1: these rules aren't noisy, they're **silent** — the event source itself
never fires under what TinySocs ships, or the harness has no way to prove them.

| Rule | Why it's dead/unverifiable | Distinguish from |
|---|---|---|
| TS-060 `lsass_access` | `integrations/sysmon/sysmon-config.xml`'s ProcessAccess (Sysmon Event 10) include block is **empty** — confirmed at the XML level, not inferred. Nothing is ever logged for this event ID under the shipped config. | This is the one rule in the whole set that's dead for a *sysmon-config* reason, not a rule-logic reason — don't conflate it with TS-091/TS-092/TS-133, whose sysmon-side data is fine (see §3.1's distinction). |
| TS-020 `scheduled_task_created` | March notes suspected a 4698 XML-parsing bug. The 2026.27 harness run **disproved this** — TS-020 fired cleanly. Resolved, not disabled; kept enabled. Listed here as the negative case: don't assume "looked broken once" means "is broken." | — |
| TS-030 `powershell_scriptblock_burst` | Needs the ScriptBlockLogging policy, which nothing in the install/deploy path enables. **Disabled** (`enabled: false`, inline `pilot:` reason at `packaging/detection/rules.yml:113`) — one of the 17 `pilot:`-tagged disabled rules from §1, not a separate "left enabled" category; not part of the pilot promise. | — |
| TS-100/TS-101 (DNS/outbound volume) | Sysmon-dependent volumetrics whose actual firing behaviour is entirely a function of the config's include/exclude lists — unvalidated in this shape. | — |
| TS-111/TS-112 (FIM) | Byte-identical condition to TS-110 (same event 1002, same `FilePath` group_by, no discriminator) — every FIM modify event fires all three if all three are enabled. Keep TS-110 only. | Good canonical example of "why `threshold_by_key` needs `field_match` to mean anything" (`detection-content.md` §7.9). |

#### The two later dead-rule finds (2026-07-08, same PR/#9 as the pilot cut — see provenance note)

Pushing for full xUnit proof of all 19 enabled rules surfaced two more:

- **TS-113 `fim_mass_modification`** (the ransomware canary, T1486) grouped by
  `winlog.computer_name`, a field the FIM emitter never populated — the engine couldn't form a
  group key at all, so the rule was dead regardless of file-modification volume. **Fixed at the
  source, not the rule**: `src/TinySocs.Agent/Inputs/FileIntegrityInput.cs:575-582` now stamps
  `winlog.computer_name` onto every FIM event ("without this, FIM events have no host" per the
  inline comment). Verified live: `packaging/detection/rules.yml:687-702` shows TS-113's
  `group_by: "winlog.computer_name"` today. This was the headline rule of the whole pack — it
  mattered more than any of the noise-reduction disables.
- **TS-120 `agent_version_drift`** had no event source at all: nothing feeds an
  `event_id:0 / channel:heartbeat` event into `EvaluateEvent` — the agent's heartbeat is written
  straight to an index and never touches the detection engine. Verified: `packaging/detection/rules.yml:954-970`,
  `enabled: false`. **Deferred**, not fixed — this needs a new v2 version-drift emitter, and it's
  operational hygiene rather than an attack detection anyway (don't count it in "detections"
  messaging even once it's wired). This drop is why the enabled count went from 20 to 19.

**Reusable method distinguishing §3.1 from §3.3**: ask "if I fed this rule a perfect, textbook
attack, would it fire?" If the answer is "no, because the event never reaches the engine at all"
(empty Sysmon include, no emitter wiring, missing group-by field), that's §3.3 — dead, needs a
plumbing fix, not a filter. If the answer is "yes, but so would routine business software," that's
§3.1 — noisy, needs schema capability that doesn't exist yet. Conflating them produces the wrong
fix: adding a `field_match` to a dead rule does nothing; trying to "wire the event source" for a
noisy-but-live rule is solving a problem that doesn't exist.

---

## 4. The rule lifecycle (state machine)

Every rule — the 39 in the C# engine, the 50 in the dormant Python KQL catalogue, and anything
new — moves through these states. **Never silently delete a rule.** Disabled rules are retained
assets: CLAUDE.md's own instruction is *"Treat the existing 39 rules + 50-rule catalogue as
assets, not legacy."* A `enabled: false` entry with an inline reason is documentation of a
decision, not dead weight.

```
 idea
   │
   ▼
 candidate — added to rules.yml as `enabled: false`, with an inline `pilot:` (or block) comment
   │          stating WHY it's not live yet. This is the minimum bar to even exist in the file.
   ▼
 test-authored — an Atomic test case (tests/atomic-tests.yaml) AND an xUnit fire/silent pair
   │              (tests/TinySocs.Agent.Tests/DetectionEngineTests.cs) both exist.
   │              Mechanics: tinysocs-detection-validation-toolkit.
   ▼
 harness-validated — the Atomic test actually ran and DETECTED, under a definition equivalent
   │                  to what's currently shipped (not a stale credit from an old rule shape —
   │                  see the TS-061 warning below). Definition owned by tinysocs-validation-and-qa.
   ▼
 pilot-pack-enabled — flipped to `enabled: true`, gated through tinysocs-change-control
   │                   (this is a detection-behavior change — it always routes through the gate).
   ▼
 ┌─────────────────────────────┐
 │ steady state: live in a     │◄──── FP evidence from the field (or a lab observation,
 │ shipped, signed pack        │       pre-customer — see §6) triggers a revisit
 └──────────────┬──────────────┘
                │
      ┌─────────┴─────────┐
      ▼                   ▼
  tuned/field_matched   disabled-with-reason
  (stays enabled, gets   (flips back to false,
  a narrower condition   inline reason updated —
  — a new signed pack    NEVER a silent delete)
  version, not a live
  file edit — see
  content-cadence.md)
```

Two illustrations already in the repo:

- **TS-002** sits at `harness-validated`-pending — candidate and test exist, but the 18-vs-20 gap
  (§2) means it has never actually reached `harness-validated`. It's enabled anyway (shares
  TS-001's mechanism, judged low-risk), but the state machine says the validation step is still
  owed.
- **TS-061** is the sharpest warning against trusting old harness credit: it passed in March
  because it *then* matched any process creation. It has since been restricted to named dump
  tools via `field_match`. The March pass does not carry forward — the current definition has
  never been harness-validated. **A rule's validated status is tied to a specific condition
  shape, not to the rule ID.** Any time a `field_match` or threshold changes, the rule drops back
  to `test-authored` until re-run.

---

## 5. FP-tuning judgment

This judgment call is delegated to you (the founder or the session standing in for them) — there
is no formula that outputs "enable" or "disable." What follows is the internalizable reasoning,
extracted from the per-rule notes in `docs/pilot-ruleset.md` (§79-165), not a checklist to
mechanically apply.

### Recurring reasoning patterns worth internalizing

**Threshold-as-human-vs-automation-detector.** TS-001 (`brute_force_logon`, threshold 15/5min):
"a human mistyping stops at 3–5. Fifteen failures in five minutes against one account is
automation." The threshold isn't chosen to catch *an* attacker, it's chosen to sit clearly above
the noise floor of ordinary human error and clearly below what would require an unreasonable
coincidence to hit by accident. When you see a threshold, ask what the honest floor of *benign*
repetition looks like in this ICP, then set the bar comfortably above it — not at the theoretical
minimum an attacker needs.

**The RMM/encoded-PowerShell credibility hazard.** TS-134's disable reason names this explicitly:
RMM (remote monitoring and management) tooling — the exact software stack the MSP channel of the
ICP runs — uses encoded PowerShell (`-enc`, `Invoke-Expression`) constitutively, not
occasionally. Any rule that pattern-matches on PowerShell obfuscation primitives without process
or vendor context will alarm on the customer's own management tooling before it ever alarms on an
attacker. This is a standing hazard class, not a one-off — check any new PowerShell-content rule
against "would a Datto/ConnectWise/N-able agent trip this" before shipping it.

**Alert-on-scan as a customer-relationship framing question, not just a detection question.**
TS-002's open question (`docs/pilot-ruleset.md:221`): on an estate with internet-exposed RDP,
background scanner noise legitimately fires TS-002 — "which is signal about their exposure, but
may read as noise to the customer." The detection is *correct*; the question is how it's
presented. This is a case where the fix isn't a `field_match`, it's product/communication design
(kickoff-call framing, a threshold bump, or reframing as a one-time "your RDP is exposed" finding
instead of a recurring alert). Not every FP problem has a YAML solution — some have a
conversation-design solution, and conflating the two wastes engineering effort on the wrong
layer.

**A "false positive" can be a feature, reframed.** TS-010 (`local_account_created`): "in a
20–150-person company, account creation happens a few times a month and the IT contact either did
it or wants to know who did. Even a 'false' positive is a useful audit touchpoint, not noise."
Before disabling a rule for FP risk, check whether the alert is actually unwelcome, or whether
it's technically-a-false-positive-but-still-useful-information. These stay enabled even with
known repeat triggers (MSP-managed estates where the MSP creates accounts remotely will fire
TS-010 routinely — "again, arguably a feature").

### What data to pull before judging

Don't judge FP risk from the rule's YAML alone — pull the actual event volume for the
`group_by` key over a representative window on a real or representative estate. The established
query pattern (matches the `curl.exe -sk` convention in `tinysocs-diagnostics-and-tooling`,
against the raw winlog index on OpenSearch REST — port **9201**, not 9200, see the 9200 trap in
`tinysocs-debugging-playbook`):

```bash
# macOS/Windows — adjust event_id/channel/group_by field to the rule under review.
# Example: how often does TS-092's underlying event (Sysmon FileCreate, event_id 11)
# actually occur per source image, over the last 7 days?
curl.exe -sk -u admin:<password> "https://localhost:9201/tinysocs-winlog-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {
      "bool": {
        "filter": [
          { "term": { "event.code": 11 } },
          { "term": { "winlog.channel": "Microsoft-Windows-Sysmon/Operational" } },
          { "range": { "@timestamp": { "gte": "now-7d" } } }
        ]
      }
    },
    "aggs": {
      "by_group_key": {
        "terms": { "field": "winlog.event_data.Image.keyword", "size": 20, "order": { "_count": "desc" } }
      }
    }
  }'
```

Read the top-N terms bucket, not just the total count: a rule with low total volume but one
process name accounting for 90% of it (e.g. an auto-updater) tells you exactly what a
`field_match` exclusion needs to target, or confirms the rule needs schema capability
(command-line/parent context) the exclusion approach can't reach — which routes you to §3.1
rather than §3.2. This is the same `terms` aggregation shape already used in
`src/tinysocs/api/node.py` (`by_rule`, `by_host`, `by_severity` aggregations, `node.py:762-960`)
— reuse that pattern rather than inventing a new query style.

---

## 6. Content-cadence tie-in

`docs/design/content-cadence.md` is **status: draft** (as of 2026-07-11, verified header) — the
aspiration is **one new rule + one tuning patch, packed and signed, once per ISO week**
(strategic gap #6). Every increment that ships through that weekly cadence is expected to have
already walked the lifecycle in §4:

- The "1 new rule" half starts at `candidate` and needs to reach `pilot-pack-enabled` — sourced
  pre-customer from a MITRE coverage gap (`reporting/mitre_coverage.py`) or an undetected Atomic
  technique; sourced post-customer by what real customer environments actually face.
- The "1 tuning patch" half is a rule moving from steady-state back through
  `tuned/field_matched` — pre-customer this is founder-sourced from lab/validation observations
  (there is **no FP telemetry channel yet** — that's deferred gap #8, gated on paying customers
  giving consent; don't pitch a closed FP loop that doesn't exist, per content-cadence.md's own
  explicit caveat).
- Per content-cadence.md's own gate: **"a rule with no Atomic test does not ship"** — this is §4's
  `test-authored` state made into a hard release gate, not a suggestion.
- Tuning patches ship as a **new signed pack version**, never as a live file edit a customer
  applies — "the customer never edits a rule file" is a pivot-thesis-level constraint, not a
  style preference.

If asked to plan or execute a weekly content-cadence unit, use this skill to pick and justify the
rule/patch (the "what and why"); use `tinysocs-detection-validation-toolkit` for authoring the
test; use `tinysocs-change-control` before any of it lands.

---

## Provenance and maintenance

Authored 2026-07-11, TinySocs branch `fix/ci-green`, HEAD `37005ad`.

**Primary sources** (read in full or spot-verified against live repo state, not taken from a
digest alone):
- `docs/pilot-ruleset.md` (222 lines) — read in full; the worked example this entire skill is
  built from.
- `docs/design/content-cadence.md` — read in full for §6.
- `packaging/detection/rules.yml` — grepped/spot-checked directly for TS-070, TS-071, TS-090,
  TS-062, TS-113, TS-120 condition blocks (not taken from a digest quote alone).
- `tests/TinySocs.Agent.Tests/DetectionEngineTests.cs` — counted directly (`[Fact]`/`[Theory]`/
  `[InlineData]`) to cross-check the pilot-ruleset.md prose claim.
- `src/tinysocs/api/node.py:762-960` — confirmed the `terms` aggregation query shape used in §5.
- Prior discovery-pass digests (session-local scratch files — not re-derivable,
  ignore if absent) — cross-referenced, not quoted as sole authority; every fact
  pulled from these was re-verified against the live file where the fact was
  rule-content-specific.

**Re-verification commands** for the volatile facts in this skill:

```bash
# Enabled/disabled rule counts (§1)
grep -c "enabled: true" packaging/detection/rules.yml   # expect 19
grep -c "enabled: false" packaging/detection/rules.yml  # expect 20

# How many disabled rules carry an inline pilot: reason (§1)
grep -c "pilot:" packaging/detection/rules.yml           # expect 17

# The four field_match fixes are still in place (§3.2)
grep -A3 'field: "winlog.event_data.LogonType"' packaging/detection/rules.yml   # TS-071
grep -A5 'field: "winlog.event_data.ServiceName"' packaging/detection/rules.yml | grep PSEXESVC  # TS-070
grep -A8 'field: "winlog.event_data.ImagePath"' packaging/detection/rules.yml   # TS-090
grep -A5 'field: "winlog.event_data.ObjectName"' packaging/detection/rules.yml | grep ntds.dit  # TS-062

# TS-113 grouped by winlog.computer_name (the 2026-07-08 fix), TS-120 still deferred (§3.3)
grep -A15 'id: "TS-113"' packaging/detection/rules.yml | grep group_by
grep -A5 'id: "TS-120"' packaging/detection/rules.yml | grep enabled

# xUnit method/case count sanity check (§4 cross-reference)
grep -c "\[Fact\]" tests/TinySocs.Agent.Tests/DetectionEngineTests.cs
grep -c "\[InlineData" tests/TinySocs.Agent.Tests/DetectionEngineTests.cs

# content-cadence.md still draft (§6)
grep -m1 "Status" docs/design/content-cadence.md
```

**Known limitation**: the §5 OpenSearch query example is written against the `tinysocs-winlog-*`
index and event-11/Sysmon shape as an illustration; adjust `event.code`/`winlog.channel`/the
`terms` field per the rule actually under review. It has not been executed against a live cluster
in this session — it follows the established pattern in `tinysocs-diagnostics-and-tooling` and
`src/tinysocs/api/node.py`, not a freshly-run query.
