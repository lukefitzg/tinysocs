---
name: tinysocs-detection-validation-toolkit
description: Step-by-step recipe for taking ONE detection rule from candidate to "harness-validated" — writing an honest field_match, authoring the tests/atomic-tests.yaml entry (with a real field-by-field template), writing a fallback_command that clears the threshold with margin, adding the xUnit firing/silent pair to DetectionEngineTests.cs, staging a build to the Windows VM, running Test-AtomicDetection.ps1 scoped to one technique, and reading DETECTED/MISSED/SKIP/ERROR results honestly. Load this when asked to "validate rule X", "add an atomic test for TS-NNN", "prove this rule fires", "why did TS-NNN MISS/SKIP/ERROR", "the harness never exercised this rule", or when authoring/fixing an entry in tests/atomic-tests.yaml. Contains the TS-002 margin worked example (18 attempts vs threshold 20 — never cleared) and current per-rule validation status as of the 2026-07-08 run. Does NOT cover normalizing a completed run into results/, rebuilding the public dashboard, or restarting weekly cadence — that's tinysocs-validation-publication-campaign. Does NOT cover deciding whether a rule should exist at all or graduate from candidate — that's tinysocs-research-methodology.
---

# TinySocs detection validation toolkit

This is the per-rule "prove it" recipe. It ends when one rule has: an honest
`field_match`, an xUnit fire/silent pair, an Atomic Red Team test entry with a
fallback that actually clears the rule's threshold, and a VM run result you can
read correctly. It does not cover publishing that result to the public dashboard —
that pipeline-wide job is `tinysocs-validation-publication-campaign`.

Two independent proof mechanisms exist in this repo; know which one you're doing:

| Mechanism | What it proves | Where | Needs |
|---|---|---|---|
| xUnit (`DetectionEngineTests.cs`) | The rule, loaded from the real `rules.yml`, fires on a synthetic matching event and stays silent on a non-matching one | `tests/TinySocs.Agent.Tests/DetectionEngineTests.cs` | Nothing to run it locally — works on macOS, no Windows, no OpenSearch. **Not wired into CI**: `.github/workflows/ci.yml` builds the agent via `dotnet publish` but never runs `dotnet test` — someone has to run this suite by hand |
| Atomic Red Team harness | The rule fires end-to-end: real attack → Windows event log → agent → OpenSearch → alert doc | `tests/Test-AtomicDetection.ps1` + `tests/atomic-tests.yaml` | A Windows VM with TinySocs installed and running |

**Both are required for "harness-validated."** xUnit alone proves the rule logic is
correct against a hand-built event; it says nothing about whether the real Windows
audit pipeline actually produces that event under a real attack. As of 2026-07-11,
all 19 enabled rules have xUnit coverage; only 8 have been proven end-to-end by a
live attack in the 2026-07-08 Atomic run (see §2 and §3).

## When NOT to use this skill

- Normalizing a raw harness run into `results/<iso-week>.json`, rebuilding
  `site/validation/data/summary.json`, restarting the weekly cadence, or stamping a
  signed pack's `metadata.validation` block → `tinysocs-validation-publication-campaign`.
- Deciding whether a rule is worth building at all, what evidence justifies
  enabling/disabling it, or the pilot-cut FP-vs-coverage tradeoff reasoning →
  `tinysocs-research-methodology`.
- Windows event ID meanings, MITRE mapping, `threshold_by_key`/`field_match`
  semantics in the abstract, SMB false-positive theory → `detection-engineering-reference`.
- Rule counts, which rules are enabled/disabled and why, the sysmon-config
  dead-event story (TS-060) → `detection-engineering-reference` and `docs/pilot-ruleset.md`.
- Building the agent binary itself, YamlDotNet gotchas, the macOS+Windows-VM dev
  topology → `tinysocs-build-and-env`.
- Any step here that changes shipped detection behavior (flipping `enabled`,
  changing a threshold, changing a `field_match`) is a detection-behavior change —
  gate it through `tinysocs-change-control` before it ships.

---

## 1. The full recipe: candidate → harness-validated

Do these in order. Each step's artifact is checked into the repo except the raw VM
run JSON (gitignored `logs/`).

### Step 1 — Write the honest `field_match`

A `threshold_by_key` rule with no `field_match` counts *every* event matching
`event_id`/`channel`, grouped by `group_by`. If the rule's description implies a
narrower target ("PsExec install", "RDP brute force"), that narrowing must live in
`field_match` or the rule is lying about what it detects. `packaging/detection/rules.yml`
carries real examples of both the honest and dishonest versions — use them as your
template, not a hypothetical:

**Honest** — TS-071 `rdp_brute_force` (`packaging/detection/rules.yml:298-323`):
```yaml
  - id: "TS-071"
    name: "rdp_brute_force"
    description: "Multiple RDP logon failures (4625 LogonType 10)"
    severity: "high"
    enabled: true
    type: threshold_by_key
    mitre:
      technique_id: "T1110.001"
      technique_name: "Brute Force: Password Guessing"
      tactic: "credential-access"
    condition:
      event_id: 4625
      channel: Security
      group_by: "winlog.event_data.IpAddress"
      threshold: 10
      window_minutes: 10
      # LogonType 10 = RemoteInteractive (RDP). Without this filter the rule was
      # just TS-002 with a lower threshold and double-alerted on every 4625 burst.
      field_match:
        field: "winlog.event_data.LogonType"
        values:
          - "10"
        match: "exact"
    actions:
      - write_alert_doc
      - append_alert_log
```
`match` is `"exact"` (`string.Equals(..., OrdinalIgnoreCase)`) or the default
`"contains"` (substring). Use `exact` for enum-like fields (LogonType, ServiceName);
use `contains` for path/filename fields where you're matching a class of tool
(`NewProcessName contains [mimikatz, procdump, ...]` — see TS-061).

**Dishonest counter-example, worth knowing so you don't reproduce it**: TS-113 has
*no* `field_match` at all (`packaging/detection/rules.yml:687-705`) — legitimate,
because its whole job is "count everything on this key past a volumetric
threshold," not narrow to a signature. The tell for whether a rule *needs*
`field_match` is in its own description: if the description names a specific
tool/path/type and the condition block doesn't filter on it, that's a pilot-cut-style
bug (see the TS-070/TS-090/TS-072 "three rules match every 7045" case in
`docs/pilot-ruleset.md`, fixed 2026-07-04). Check the description against the
condition block every time you touch a rule.

`group_by` field convention: Windows-native rules use dotted `winlog.event_data.X`
paths (see TS-071 above) or `winlog.computer_name`; FIM rules use a flat top-level
`FilePath` (capital F, capital P — a body-level field, not `winlog.event_data.*`,
per `FileIntegrityInput.cs:569`). Mixing these conventions on a new rule is an easy
copy-paste bug — copy from a rule with the same event source, not just any rule.

### Step 2 — Author the `tests/atomic-tests.yaml` entry

Field-by-field template with a real worked example. `tests/atomic-tests.yaml` header
(lines 1-23) documents the schema; here is a complete entry taken from the file
(T1053.005 → TS-020, `tests/atomic-tests.yaml:56-64`, verified 2026-07-11):

```yaml
  - atomic_technique: "T1053.005"
    technique_name: "Scheduled Task/Job - Scheduled Task"
    atomic_test_number: 1
    expected_rules: ["TS-020"]
    sysmon_required: false
    prefer_fallback: true
    timeout_seconds: 120
    fallback_command: "schtasks /create /tn \"TinySocs-ART-Test\" /tr \"cmd /c whoami\" /sc once /st 23:59 /f; Start-Sleep -Seconds 3; ...; schtasks /delete /tn \"TinySocs-ART-Test\" /f"
    notes: "Creates a scheduled task, generating event 4698. TS-020 targets 4698 directly. ..."
```

Field meanings and how to set each one for a new entry:

| Field | Meaning | How to choose it |
|---|---|---|
| `atomic_technique` | MITRE ATT&CK technique ID | Pull from the rule's `mitre.technique_id` |
| `technique_name` | Human-readable technique name | From MITRE ATT&CK or the rule's `mitre.technique_name` |
| `atomic_test_number` | 1-based index into the ART atomic's test list for that technique | Check `C:\AtomicRedTeam\atomics\<TECHNIQUE>\<TECHNIQUE>.yaml` on the VM, or use 1 if you're only using the fallback |
| `expected_rules` | TS-IDs the harness should see fire | Include every rule this event could trigger, not just the one you're adding — e.g. TS-001 lists `["TS-001", "TS-001-lab", "TS-002"]` because the same 4625 burst is visible to all three |
| `sysmon_required` | Whether the test needs Sysmon installed | `true` only if the rule's event source is a `Microsoft-Windows-Sysmon/Operational` channel |
| `requires` | Environment gate — see §4 for the exact 4 values and what each checks | Omit unless the technique genuinely can't run without a specific host state |
| `timeout_seconds` | How long the harness polls OpenSearch for a matching `alert.rule_id` after the test starts | Default 300 for anything volumetric or threshold-driven; §2's TS-130 note below is why 300, not 120, is now the safe default even for "should be fast" rules |
| `prefer_fallback` | Skip the ART atomic entirely and run `fallback_command` | Set `true` whenever the ART atomic doesn't exercise your rule's `field_match`/threshold on a non-domain, non-AD workstation (see T1018 and T1218.011 notes in the file for two documented cases of ART running the *wrong* workload) |
| `fallback_command` | A PowerShell one-liner/block that faithfully reproduces the attack behavior standalone | See Step 3 — this is the part most likely to be wrong |
| `pilot_status: "deferred"` | The technique's only rule is `enabled: false` in the pilot pack | Set this, not a skip in `expected_rules`, when the gap is intentional (see `docs/pilot-ruleset.md`) — the harness treats it as SKIP, not MISS |
| `notes` | Changelog of why the test looks the way it does | Always write this — it's the only place a future session learns *why* the fallback runs 18 times and not 6 |

### Step 3 — Write a fallback that clears the threshold, with margin

**The TS-002 gap — the canonical example of getting this wrong.** The T1110.001
entry's `fallback_command` (`tests/atomic-tests.yaml:29-34`) runs 18 failed logons
against one nonexistent account, `victimacct`, from the loopback address. That
clears TS-001's threshold (15 by `TargetUserName`, 5 min) with margin — but TS-002
groups by `IpAddress` at threshold 20. All 18 attempts share one IP, so **TS-002's
own threshold is never reached — it has never been individually exercised by this
test**, confirmed live in `tests/atomic-results.json` (`"expected_rules": ["TS-001",
"TS-001-lab", "TS-002"]` but `"detected_rules": ["TS-001"]` only, 2026-07-08 run) and
called out explicitly in `docs/pilot-ruleset.md:51`. This is still true as of
2026-07-11 — nobody has raised the attempt count.

The lesson: **a fallback must clear the threshold of every rule in `expected_rules`,
not just the first one you're thinking about, and should clear it with margin, not
exactly at it** — a same-second race against the harness's own event ingestion can
turn an exact-threshold pass into a flaky MISS. The T1053.005 note (Step 2 example)
documents the same lesson from the other direction: an earlier version of that
fallback hammered 6 *distinct* usernames, producing only 1 event per `TargetUserName`
group — never enough to trip TS-001 (15) *or* TS-002 (20) even though 6×3=18 events
were generated. Grouping key, not raw event count, is what a fallback must satisfy.

To fix the TS-002 gap the fix is mechanical: bump the fallback's attempt count from
18 to 20+ (same margin discipline as TS-001's 18-vs-15), or add a second targeted
fallback entry. This is flagged here as an open, fixable gap — not yet done as of
2026-07-11.

`ErrorActionPreference` is deliberately relaxed to `Continue` during fallback
execution (`Test-AtomicDetection.ps1:855-857`, per the digest) because native tools
like `net.exe` write "System error 1326" (expected — that's the failed logon) to
stderr, which PS 5.1 promotes to a terminating error under `Stop`. If you write a
fallback using `net.exe`, `schtasks`, `sc.exe`, or similar, don't wrap it in
`try { ... } catch { throw }` — a working simulation will get miscounted as a
harness ERROR.

### Step 4 — Write the xUnit firing/silent pair

Every rule with a filter or threshold needs two `[Fact]`s in
`tests/TinySocs.Agent.Tests/DetectionEngineTests.cs`: one that fires on-target, one
that proves it stays silent off-target. Real pattern, TS-071
(`DetectionEngineTests.cs:104-123`):

```csharp
// ---- TS-071 rdp_brute_force: LogonType 10 filter -----------------

[Fact]
public void Ts071_FiresOnRdpLogonType10()
{
    var engine = EngineWith("TS-071");
    // threshold 10 within 10 min, grouped by IP, LogonType must be 10.
    int alerts = FireN(engine, () => WinEvent(4625, "Security",
        new() { ["IpAddress"] = "203.0.113.9", ["LogonType"] = "10" }), 10);
    Assert.True(alerts >= 1, "RDP (LogonType 10) brute force should fire TS-071");
}

[Fact]
public void Ts071_DoesNotFireOnNetworkLogonType3()
{
    var engine = EngineWith("TS-071");
    // Same volume, but LogonType 3 (network) — must NOT fire. This is the
    // fidelity fix: before the filter, TS-071 double-alerted on any 4625 burst.
    ...
}
```

Helpers already in the file, reuse them rather than re-deriving:
- `EngineWith("TS-071")` — loads the real shipped `rules.yml` via `RuleLoader`,
  filters to the rule(s) you name.
- `WinEvent(eventId, channel, eventData, computer)` — builds a Windows-style event
  with nested `winlog.event_data`.
- `FimEvent(eventId, filePath, computer)` — builds a FIM event the way
  `FileIntegrityInput` actually emits it (`FilePath` top-level, host under
  `winlog.computer_name`) — use this, not `WinEvent`, for any FIM rule (TS-110/113/114
  and disabled TS-111/112/115), or your test will pass against a shape the agent
  never produces.
- `FireN(engine, makeEvent, n)` — fires the same event `n` times, returns the alert
  count. For threshold rules, call it once at `threshold - 1` (assert 0) and once at
  `threshold` (assert ≥1) — see TS-002's pair (`DetectionEngineTests.cs:222-235`)
  and TS-113's mass-modification pair (`:316-330`, threshold 50, fires unique
  filenames per iteration since `FilePath` isn't the group key here but distinct
  filenames avoid an unrelated dedupe concern).

If the rule's enabled/disabled state changed, also update
`PilotSet_EnablesExactlyTheHighFidelityRules` (asserts the exact 19-ID enabled set,
`DetectionEngineTests.cs:419-431`) and `PilotSet_ExcludesNoisyRules`
(`InlineData`-driven, asserts specific IDs are *absent*, `:434-451`) — both will
fail loudly (by design) if you enable a rule without updating them, which is the
intended guardrail against a silent scope-creep on the pilot pack.

### Step 5 — Stage to the VM

Detection-content changes (rules.yml edits) don't need a signed pack or installer
rebuild to validate — the agent reads `rules.yml` directly. Build and stage:

```bash
# On macOS/Linux dev host, from repo root
scripts/stage-deploy-bundle.sh
```
This publishes a self-contained win-x64 build, copies `packaging/detection/rules.yml`,
`Deploy-AgentUpdate.ps1`, `Test-AtomicDetection.ps1`, and `atomic-tests.yaml` into
`dist/deploy-bundle/` (gitignored), and writes a `RUN-ON-VM.md` with the exact
enabled-rule count baked in (via `python3` reading `rules.yml` at bundle time) so
you can sanity-check the deploy landed correctly.

Copy `dist/deploy-bundle/` to the Windows VM, then in an **elevated** PowerShell:
```powershell
.\scripts\Deploy-AgentUpdate.ps1 -SourceDir .
```
This does 9 steps (`scripts/Deploy-AgentUpdate.ps1:1-294`, verified 2026-07-11):
1. **Stops the `TinySocs-Quickstart` process first, then the `TinySocsAgent` service
   (step 2), in that order.** The full mechanics and why — including the 2026-07-11
   correction that `TinySocs-Quickstart.exe` is *not* itself an agent respawn path
   (NSSM is) — live in **tinysocs-run-and-operate §2/§9**; don't re-derive them here.
2. Stops the `TinySocsAgent` service (30s wait, falls back to `sc.exe`), then kills
   any lingering process.
3. Replaces the binary (backs up the old one to `.bak` first).
4. Copies the new `rules.yml` into `C:\ProgramData\TinySocs\Collector\rules\`.
5. Clears stuck queue segments (`agent\queue\segment-*.jsonl`).
6. Runs `auditpol /set` for 9 subcategories (Logon, Process Creation, Object
   Access, Account Mgmt, etc.) and enables 4688 command-line logging via registry
   — this is the fix CLAUDE.md/`docs/pilot-ruleset.md` reference as landing in the
   installer too (2026-07-04), so a fresh customer install now gets the same audit
   policy without a manual `Deploy-AgentUpdate.ps1` run.
7. Starts the service (NSSM relaunches the new binary), restarts the watchdog.
8. Waits 15s, greps the agent log for `"Detection engine updated with (\d+) rule(s)"`
   — **this is your confirmation the new rules.yml actually loaded**; a stale count
   here means the deploy silently used an old file.
9. Re-verifies the audit policies with `auditpol /get`.

If you only touched `rules.yml` and not the binary, you can skip straight to
copying the file into `C:\ProgramData\TinySocs\Collector\rules\` — `RuleLoader`
hot-reloads on a 60s poll (see `tinysocs-run-and-operate` for the hot-reload
mechanics); `Deploy-AgentUpdate.ps1` exists for when the binary also changed.

### Step 6 — Run the harness scoped to one technique

Don't run the full ~50-minute suite while iterating on one rule. Two diagnostic
switches on `Test-AtomicDetection.ps1` exist for exactly this (verified
`tests/Test-AtomicDetection.ps1:39-48`):

```powershell
# Run only your technique (~3 min instead of ~50)
.\tests\Test-AtomicDetection.ps1 -SkipInstall -OnlyTechnique T1053.005

# Isolate the OpenSearch read path for one rule with zero attack execution —
# reproduces the exact query the poll loop uses against alerts already in the
# index, with the same -Since floor. Use this to tell "my rule doesn't fire" from
# "my rule fires but the harness can't see it" before re-running the whole attack.
.\tests\Test-AtomicDetection.ps1 -SelfTestRule TS-130 -SelfTestLookbackHours 3

# List what would run without executing anything
.\tests\Test-AtomicDetection.ps1 -DryRun
```
`env:TSDEBUG=1` turns on verbose OpenSearch query tracing if a result looks wrong.

The harness needs **Administrator** PowerShell (it flips audit policy + registry),
a running TinySocs with OpenSearch reachable at `https://localhost:9201` (default;
override via `assistant.env`'s `SIEM_URL`/`SIEM_USER`/`SIEM_PASS`), and auto-installs
Invoke-AtomicRedTeam via `git clone` on first run (`-SkipInstall` if already present).

### Step 7 — Read the result honestly

Four statuses, defined in `scripts/validation_lib.py:34-43` and used consistently
by the PowerShell harness and the Python normalizer:

| Status | Meaning | What it tells you about the rule |
|---|---|---|
| `DETECTED` | A matching `alert.rule_id` appeared in OpenSearch within `timeout_seconds` of the attack starting | Rule works end-to-end, today, on this build |
| `MISSED` | The attack ran, but no matching alert appeared before the timeout | Could be a real rule defect **or** a timeout-too-short false negative (see TS-130 below) — check `duration_seconds` against `timeout_seconds` before concluding the rule is broken |
| `SKIP` | Test didn't run at all — either `pilot_status: deferred` (rule disabled by design) or a `requires:` gate failed (see §4) | Not a rule verdict either way — an intentional non-attempt |
| `ERROR` | Harness-level failure (network, ART install, query exception) — not a rule defect | Fix the harness/environment, don't touch the rule |

**Timeout false-negatives are real and already happened once.** TS-130
(`account_discovery`, T1087.001) fired cleanly in 16.8s on one run and MISSED at
the then-120s cutoff on a re-run under OpenSearch index-latency pressure — the
alert existed, the poll just gave up first. `timeout_seconds` was raised 120→300
for that entry (`tests/atomic-tests.yaml`, T1087.001 notes) precisely because of
this. This is why the 2026-07-08 run (`tests/atomic-results.json`) still shows
T1087.001 as **MISSED at 126.9s** — the timeout fix landed *after* that run, not
before it; the note in `docs/pilot-ruleset.md:63` calls this "a timeout
false-negative to watch, not a failure." **Rule of thumb: before treating any
MISSED as a rule bug, check whether `duration_seconds` is close to
`timeout_seconds` — if so, it's probably a race, not a defect. Bump the timeout
and re-run before writing a postmortem.**

### Step 8 — Normalize and commit

Normalizing the raw run into `results/<iso-week>.json`, rebuilding the public
dashboard, and stamping the signed pack's `metadata.validation` block are **out of
scope for this skill** — that's the pipeline-wide job in
`tinysocs-validation-publication-campaign`. What belongs here: commit your
`rules.yml`/pack changes, the new `tests/atomic-tests.yaml` entry, and the new
xUnit pair together, with the rule ID in the commit message (per CLAUDE.md commit
convention). Gate any `enabled:` flip through `tinysocs-change-control` — it's a
detection-behavior change.

---

## 2. Worked examples from the 2026-07-08 validation notes

Per-rule state as recorded in `docs/pilot-ruleset.md` and confirmed live against
`tests/atomic-results.json` (generated 2026-07-08T20:45:00Z, 88.9%, 19 total
entries; re-verified 2026-07-11 — nothing has changed since). Note: `docs/pilot-ruleset.md`
itself has an internal date inconsistency (parts of its "Validation status" section
still describe a stale 2026-03-01/100% file that no longer exists in the tree) —
treat its 2026-07-06/2026-07-08-dated sections as current, its "read this first"
March-dated section as historical noise. **The March "100%" figure is banned from
all quoting anywhere** (`docs/pilot-ruleset.md:208`).

| Rule | State as of 2026-07-08 | Why |
|---|---|---|
| TS-061 `credential_dumping_tools` | **Stale credit** | The March pass was earned by the pre-pilot-cut definition that matched *any* process creation. The current `field_match` (named dump tools: mimikatz, procdump, nanodump, pwdump, gsecdump, wce.exe, sqldumper.exe, dumpert, lsassy) has never individually fired in a harness run against a named tool. Enabled and xUnit-covered (`Ts061_FiresOnNamedDumpTool`, `DetectionEngineTests.cs:261-274`), but not attack-validated under today's rule. Needs a mimikatz/procdump atomic test before quoting it externally. |
| TS-002 `brute_force_logon_by_ip` | **Never exercised** | See §1 Step 3 — the T1110.001 fallback runs 18 attempts, all from one IP; TS-002's threshold is 20. Confirmed unfixed as of 2026-07-11 by re-reading `tests/atomic-tests.yaml:29-34`. |
| TS-081 `defender_tamper` | **Blocked by Tamper Protection** | `requires: "tamper_protection_disabled"` (`tests/atomic-tests.yaml:99`); the harness's own `requires` check (`Test-AtomicDetection.ps1:790-796`) queries `Get-MpComputerStatus`, finds Tamper Protection ON on the test VM, and SKIPs before attempting `Set-MpPreference`. Confirmed live: `tests/atomic-results.json` T1562.001 entry, `"reason": "Requires Tamper Protection disabled (currently enabled, blocks Defender config changes)"`. The event source (Defender Operational 5001) is well-understood and the rule is unfiltered/simple, so this is an environment gap, not a design risk — but it remains formally unvalidated. |
| TS-110 / TS-113 / TS-114 (FIM) | **Need the FIM channel** | `requires: "fim_module"` on T1565.001 (`tests/atomic-tests.yaml:197`); the harness checks `Get-WinEvent -ListLog 'TinySocs-FIM'` and SKIPs if the channel doesn't exist. FIM was not enabled on the test VM for the 2026-07-08 run. TS-113 in particular is xUnit-proven to fire (post the 2026-07-08 `winlog.computer_name` fix — see `docs/pilot-ruleset.md`'s "Two dead rules found while proving all 19" section) but has *never* been attack-validated end-to-end. To close this: deploy `config/agent-config.yml` (FIM-enabled) per `RUN-ON-VM.md`'s ransomware-demo section, wait for canary seeding (~20s), then either run `Demo-Ransomware.ps1` manually or add/re-run the T1565.001 atomic. |
| TS-020 `scheduled_task_created` | **Resolved, not a gap** | An earlier note suspected a 4698 TaskContent XML-parsing issue as the cause of a March non-detection. The 2026-07-06/07-08 runs disprove this — TS-020 detected cleanly in 21.3s (`tests/atomic-results.json`, T1053.005 entry, status DETECTED). **Important scoping correction**: there is no dedicated XML-parsing subsystem for 4698 anywhere in the codebase — TS-020 is a plain `threshold_by_key` rule with `event_id: 4698`, no XML handling of any kind (`packaging/detection/rules.yml`, TS-020 block). The "suspected parsing bug" was pointing at the wrong layer from the start; if a 4698-adjacent detection issue ever resurfaces, look at the event ingestion/shipper pipeline (`EventLogInput`/`OpenSearchBulkShipper`), not a nonexistent XML parser, and not the rule's own logic. |
| TS-130 `account_discovery` | **Timeout false-negative, watched not failed** | See §1 Step 7. 16.8s DETECTED on one run, 126.9s MISSED on the re-run that used the pre-fix 120s timeout. `timeout_seconds` now 300 in the current `tests/atomic-tests.yaml`; the 2026-07-08 result predates that fix landing in a clean re-run. |

## 3. Env-limited SKIPs — the full 2026-07-08 accounting

From `tests/atomic-results.json` (19 total entries): 8 DETECTED, 1 MISSED, 6 SKIP
(`pilot_status: deferred` — T1003.001/TS-060, T1547.001/TS-091, T1218.011/TS-135,
T1055/TS-133, T1027/TS-134, T1047/TS-136), 4 SKIP (env-gated — T1059.001/TS-082,
T1562.001/TS-081, T1003.003/TS-062, T1565.001/TS-110). Denominator for the quoted
88.9% is executed-only: 8/(8+1)=8/9. The raw first run (before deferred→SKIP
accounting existed) was 57.1% and **must not be quoted** — it counted intentionally
disabled rules as failures.

---

## 4. Environment prerequisites table

The harness is deliberately better-instrumented than a production install — **any
efficacy claim implicitly assumes the harness's own setup, not what a customer's
box has out of the box.** State this caveat whenever quoting a number externally.

| Prerequisite | Harness (`Test-AtomicDetection.ps1`) | Customer / VM deploy (`Deploy-AgentUpdate.ps1` / installer) | Rules affected |
|---|---|---|---|
| `auditpol` subcategories (Logon failure, Process Creation, Object Access, Account Mgmt, Audit Policy Change, Security State Change, File System, Special Logon, Logoff) | Sets all 9 itself before running (`Test-AtomicDetection.ps1:664-681`) | Also sets all 9 (`Deploy-AgentUpdate.ps1:165-181`) — **and since 2026-07-04 the installer does this too**, so this axis is no longer harness-only | TS-001/002/010/020/061/062/070/071/090/113/114/130/131/132 (everything keyed on 4625/4688/4698/4720/4663/7045) |
| 4688 command-line logging (`ProcessCreationIncludeCmdLine_Enabled` registry value) | Sets it (`:684-687`) | Sets it (`Deploy-AgentUpdate.ps1:184-187`) — installer parity as above | Rules that key on `NewProcessName`/cmdline content (TS-061, TS-130, TS-131, TS-132) |
| **PowerShell ScriptBlockLogging policy** (needed for 4104) | **Sets it** (`Test-AtomicDetection.ps1:694-701`, `EnableScriptBlockLogging` registry key) | **Not set anywhere in `Deploy-AgentUpdate.ps1` or the installer** | TS-030 (disabled anyway, "near-silent without policy"), TS-082 (`amsi_bypass` — currently rides on Windows' own automatic "suspicious script block" logging, which fires even without this policy, so TS-082 still worked in the harness; but this is a coincidence of what Windows logs by default, not something the product enables) |
| Sysmon (any Sysmon event) | Auto-detected via services `Sysmon64a`/`Sysmon64`/`Sysmon`; Sysmon-required tests SKIP if absent | Bundled in installer as an **optional checkbox** — off by default | All Sysmon-keyed rules (TS-050/060/083/091/092/100/101/133) |
| Sysmon Event 10 (ProcessAccess / LSASS) | N/A — irrelevant, shipped `sysmon-config.xml` has an empty include block regardless of harness setup | Same empty include block — **dead in both environments** | TS-060 (confirmed dead by design; see `detection-engineering-reference`) |
| TinySocs-FIM channel | **Not present unless separately deployed** — the harness's default run doesn't enable FIM, hence the 4 env-gated SKIPs including T1565.001 | Ships with the agent; requires the FIM-enabled `agent-config.yml` to be deployed (see `RUN-ON-VM.md`'s ransomware-demo steps) and takes ~20s to seed the canary + baseline after restart | TS-110, TS-113, TS-114 (and disabled TS-111/112/115) |
| Defender Real-Time Protection | Checked via `requires: defender_rtp_disabled`; SKIPs if on | On by default on a fresh Windows install; nothing in the product turns it off | TS-082 (AMSI bypass atomic gets blocked by Defender scanning the script before 4104 logging captures it — a genuine test-fidelity constraint, not a rule flaw) |
| Defender Tamper Protection | Checked via `requires: tamper_protection_disabled`; SKIPs if on | On by default | TS-081 |
| Domain Controller role | Checked via `requires: domain_controller` (`Get-WmiObject Win32_ComputerSystem`, `DomainRole -ge 4`); SKIPs if not a DC | The pilot ICP (per `docs/icp.md`) is explicitly not DC-centric | TS-062 |

**Takeaway for anyone quoting efficacy**: the harness enables ScriptBlockLogging
and full audit policy that a stock customer install (pre-2026-07-04) did not; the
2026-07-04 installer fix closed the audit-policy gap but *not* the ScriptBlockLogging
gap. A number produced on the harness VM is not automatically reproducible on a
customer's unmodified box for the rules that depend on ScriptBlockLogging.

---

## 5. `requires` / `prefer_fallback` / `timeout_seconds` semantics — reference

`requires:` (checked at `Test-AtomicDetection.ps1:776-813`) accepts exactly 4
string values; anything else SKIPs with `"Unknown requirement: $requires"`
(the `default` switch arm, line 812-813) — a typo silently produces a SKIP, not an
error, so double-check spelling against this list:

| Value | Check performed | SKIP condition |
|---|---|---|
| `domain_controller` | `(Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4` | Machine is not a DC |
| `fim_module` | `Get-WinEvent -ListLog 'TinySocs-FIM'` | Channel doesn't exist (FIM not deployed/enabled) |
| `tamper_protection_disabled` | `(Get-MpComputerStatus).IsTamperProtected` | True, or the check itself throws (fails closed — assumes enabled) |
| `defender_rtp_disabled` | `-not (Get-MpPreference).DisableRealtimeMonitoring` | RTP is on, or the check throws (fails closed) |

`prefer_fallback: true` skips the ART atomic library entirely and runs only
`fallback_command`. Set it whenever the ART atomic's default behavior doesn't
exercise your rule's actual filter/threshold on a non-domain standalone
workstation — two documented real cases: T1018 (`tests/atomic-tests.yaml`, System
Network Discovery) where ART's atomic runs `net view`, which trips TS-130's
*account*-discovery filter but not TS-131's *network*-discovery filter — a
false-miss in disguise, diagnosed by running the fallback directly and confirming
it fired correctly (2026-06-06 diagnostic note in the file); and T1218.011
(rundll32 LOLBin) where the ART atomic is intermittent — sometimes denied access
before it spawns anything, sometimes spawns exactly once (below TS-135's
threshold-3), so the fallback is the only reliable exercise of the rule regardless
of ART's mood that run.

`timeout_seconds` is how long the harness polls OpenSearch (every 15s) for a
matching `alert.rule_id` at/after the test's start timestamp before declaring
MISSED. Default-safe value is **300** — this became the de facto floor after the
TS-130 false-negative (§1 Step 7); anything volumetric, threshold-driven, or that
depends on index refresh latency should start at 300, not the lower legacy values
(120/180) still present on several older entries. Don't copy a 120s timeout onto a
new entry just because a neighboring entry has one — check whether that neighbor
has actually been proven not to need more headroom.

---

## Provenance and maintenance

Authored 2026-07-11 against branch `fix/ci-green`, HEAD `37005ad`. Primary sources,
all re-read directly in this session (not taken on digest authority alone):
- `tests/atomic-tests.yaml` (schema header lines 1-23, entries verified for
  T1110.001/T1003.001/T1059.001/T1053.005/T1547.001/T1543.003/T1070.001/T1562.001/
  T1021.002/T1136.001/T1218.011/T1003.003/T1087.001/T1018/T1105/T1055/T1027/
  T1565.001/T1047)
- `tests/atomic-results.json` (generated_at 2026-07-08T20:45:00Z, full results array
  read for status/reason/duration_seconds per entry)
- `tests/Test-AtomicDetection.ps1` (param block lines 30-49; audit-policy +
  ScriptBlockLogging setup lines 655-706; `requires` switch lines 770-815)
- `tests/TinySocs.Agent.Tests/DetectionEngineTests.cs` (full file read: helpers
  lines 1-101, TS-071 pair 104-123, TS-002 pair 222-235, TS-061 pair 261-274,
  TS-113 pair 316-330, `PilotSet_EnablesExactlyTheHighFidelityRules` 419-431,
  `PilotSet_ExcludesNoisyRules` 434-451, `SignedBasePack_VerifiesAndLoadsInCSharp` 455-482)
- `scripts/stage-deploy-bundle.sh` (full file)
- `scripts/Deploy-AgentUpdate.ps1` (full file, 294 lines)
- `packaging/detection/rules.yml` (TS-071 block lines 298-323, TS-113 block
  lines 687-705)
- `docs/pilot-ruleset.md` (full file — note its internal March/July date
  inconsistency, flagged above)
- `scripts/validation_lib.py` (status/category constants lines 34-43)
- Prior discovery-pass digests (session-local scratch files — not re-derivable,
  ignore if absent) — used for triage/orientation; every fact carried forward
  was independently re-verified against the files above, not trusted as-is

Re-verification commands for the volatile facts in this skill:
```bash
# Current enabled-rule count and IDs (should be 19; compare to xUnit's expected[])
python3 -c "import yaml; d=yaml.safe_load(open('packaging/detection/rules.yml')); print(sorted(r['id'] for r in d['rules'] if r.get('enabled')))"

# Is the TS-002 fallback gap still unfixed? (look for attempt count vs 20)
grep -A6 'atomic_technique: "T1110.001"' tests/atomic-tests.yaml

# Latest raw harness run headline numbers
python3 -c "import json; d=json.load(open('tests/atomic-results.json')); print(d['generated_at'], d['efficacy_pct'], d['total_tests'])"

# Per-status counts in the latest run
python3 -c "import json,collections; d=json.load(open('tests/atomic-results.json')); print(collections.Counter(r['status'] for r in d['results']))"

# Has ScriptBlockLogging been added to the customer deploy path yet?
grep -n "ScriptBlockLogging" scripts/Deploy-AgentUpdate.ps1 packaging/iss/Quickstart.iss 2>/dev/null

# xUnit test count (methods, not cases)
grep -c '\[Fact\]\|\[Theory\]' tests/TinySocs.Agent.Tests/DetectionEngineTests.cs

# Does DetectionEngineTests.cs's enabled-set assertion still say 19?
grep -A6 "PilotSet_EnablesExactlyTheHighFidelityRules" tests/TinySocs.Agent.Tests/DetectionEngineTests.cs
```
