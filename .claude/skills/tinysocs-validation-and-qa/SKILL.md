---
name: tinysocs-validation-and-qa
description: What counts as evidence that a TinySocs detection rule actually works. Load this when asked "does rule X fire", "is this validated", "what's our detection efficacy", "why does the dashboard disagree with atomic-results.json", "run the xUnit tests", "what does 88.9% mean", or when about to quote an efficacy number, add a rule without a test, or touch tests/atomic-tests.yaml, tests/TinySocs.Agent.Tests/, scripts/validation_lib.py, or results/*.json. Defines the two independent validation mechanisms (xUnit synthetic-event tests vs. the Atomic Red Team live-attack harness), the atomic-tests.yaml schema, the definition of "harness-validated", the numbers-discipline rules (curated vs. raw denominator, banned figures), and the harness's deliberate scar-tissue engineering that must not be "cleaned up". Does not cover running the publication pipeline (tinysocs-validation-publication-campaign) or the mechanics of authoring a new atomic test (tinysocs-detection-validation-toolkit).
---

# TinySocs validation and QA

Two independent mechanisms answer two different questions. Neither alone proves a rule is
production-ready. Confusing them is the single most common way a false claim ends up in a
pilot conversation.

| Mechanism | Question it answers | Runs where | In CI? |
|---|---|---|---|
| xUnit (`tests/TinySocs.Agent.Tests/DetectionEngineTests.cs`) | Can this rule fire on a synthetic event, and stay silent otherwise? | macOS/Linux/Windows, no OpenSearch needed | **No** (verified 2026-07-11: `.github/workflows/ci.yml` runs `dotnet publish` at line 76 but never `dotnet test`) |
| Atomic Red Team harness (`tests/Test-AtomicDetection.ps1` + `tests/atomic-tests.yaml`) | Did a real attack technique produce a real alert through the live pipeline? | Windows VM only, live TinySocs + OpenSearch | No — manual/VM-scheduled |

Both validate **only the C# engine** (`packaging/detection/rules.yml`, queried via `tinysocs-alerts-*`
in OpenSearch). Neither exercises the Python KQL catalogue
(`src/tinysocs/agent/detections/rules.yaml`) — there is no harness for it, full stop. That's
correct behavior, not a gap: per CLAUDE.md's dual-engine honesty rule, the Python catalogue
doesn't run in production, so validating it would be validating nothing. If someone asks "is
rule X in the Python catalogue validated," the answer is "there is no validation harness for
the Python catalogue — it's a documented roadmap library, not a running detection."

For what the two rule files/engines mean generally, see tinysocs-architecture-contract. For
threshold/window semantics inside a rule, see detection-engineering-reference.

---

## 1. xUnit tests — proves a rule CAN fire

File: `tests/TinySocs.Agent.Tests/DetectionEngineTests.cs`, 484 lines.

Run it (macOS dev machine, from repo root):
```bash
dotnet test tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj
```
(net8.0 target, xunit 2.9.2 — verified via the `.csproj`.)

**Counts (verified 2026-07-11 by direct grep AND a live `dotnet test` run, not the sibling `PackLoaderTests`/`LicenceReaderTests` files — no `Ed25519TestKit` test class exists)**: 30 `[Fact]` + 2 `[Theory]` = 32 test methods, 18 `InlineData` rows → **48 executable cases**, confirmed exactly by `dotnet test --filter FullyQualifiedName~DetectionEngineTests` ("Passed: 48, Total: 48"). `docs/pilot-ruleset.md:15` says "(`tests/TinySocs.Agent.Tests/DetectionEngineTests.cs`) (61 xUnit tests, all green)" — note the doc explicitly attributes 61 to *this file*, not the whole project. That figure is simply stale: it matches neither this file's actual count (48) nor the whole project's actual count (`dotnet test tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj` → 70 passed — same number independently recorded in tinysocs-build-and-env, see that skill for the CI-gating context). Current whole-project breakdown: DetectionEngineTests.cs=48, PackLoaderTests.cs=10, LicenceReaderTests.cs=12 (48+10+12=70). Don't repeat pilot-ruleset.md's "61" as if it reconciles to either reading — it doesn't.

**Approach**: loads the real shipped `packaging/detection/rules.yml` through `RuleLoader`,
builds a live `DetectionEngine`, and fires synthetic `AgentEvent` objects at it — no Windows
Event Log, no OpenSearch, no VM. `WinEvent()` builds nested `winlog.event_data`; `FimEvent()`
mimics `FileIntegrityInput`'s shape (`FilePath` top-level, host under `winlog.computer_name`).
`FireN()` fires n times and counts resulting alerts — this is how threshold tests prove
"14 fires produces nothing, 15 fires produces one alert."

What it proves, concretely:
- **The 4 pilot-cut fidelity fixes** fire on-target and stay silent off-target: TS-071
  (LogonType 10 vs 3), TS-070 (PSEXESVC vs an ordinary service), TS-090 (Temp path vs Program
  Files), TS-062 (ntds.dit/SAM vs an ordinary file).
- **Thresholds**: TS-001 (15 not 14), TS-002 (20 not 19), TS-132 (2 not 1), TS-130 (5),
  TS-131 (4), TS-113 (50 not 49).
- **Signature matches**: TS-082 (AMSI string vs benign), TS-061 (named dump tool vs notepad).
- **Direct event-ID fires**: TS-010 (4720), TS-020 (4698), TS-080 (1102), TS-080-sys (104),
  TS-081 (5001), TS-110/TS-114 (FIM).
- **FIM anti-feedback-loop** (`Fim_WatcherPatternMatch_...`, 8 `InlineData` cases: 4 must-match
  rows — canary file, hosts, SAM, GPO Registry.pol — plus 4 must-NOT-match rows): proves the
  agent's own queue files, FIM baseline, and bundled OpenSearch data/logs are invisible to FIM
  — i.e. FIM cannot watch itself into an infinite alert loop.
- **`PilotSet_EnablesExactlyTheHighFidelityRules`** (line 420): asserts the enabled set is
  *exactly* the 19 pilot IDs, with an inline comment `// TS-120 deferred 2026-07-08: no event
  source feeds it (unwired)` (line 430) and `Assert.Equal(19, result.Rules.Count)` (line 479).
- **`PilotSet_ExcludesNoisyRules`** (line 447, 10 `InlineData` rows): TS-060/072/091/092/134/
  135/136/111/112/120 must be absent from the enabled set.
- **`SignedBasePack_VerifiesAndLoadsInCSharp`**: if `packs/base/2026.27/pack.yml.canonical`
  exists locally, proves the C# `PackLoader` accepts the Python-signed bytes, loads exactly 19
  rules, excludes TS-134, and confirms TS-071 carries a `FieldMatch`. This is skipped in CI
  because the pack artifact is gitignored — the equivalent assertion runs via `PackLoaderTests`
  there instead.

**What it does NOT prove**: that the event actually reaches the agent from real Windows
telemetry, that OpenSearch ingests and indexes it in time, or that the alert query finds it.
That gap is exactly what the Atomic harness closes.

---

## 2. Atomic Red Team harness — proves a rule DOES fire, live

**Atomic Red Team (ART)**: an open-source library (`redcanaryco/invoke-atomicredteam` +
`atomic-red-team` on GitHub) of small, scoped attack simulations ("atomics"), one or more per
MITRE ATT&CK technique. Running an atomic reproduces the real attacker behavior (e.g. an actual
brute-force logon attempt, an actual LSASS-adjacent tool execution) rather than a synthetic
stand-in — that's what makes it a stronger evidence bar than the xUnit layer.

Files: `tests/Test-AtomicDetection.ps1` (1180 lines, PowerShell, Windows-VM-only) +
`tests/atomic-tests.yaml` (the technique→rule mapping, input to the harness).

Invocation (Windows VM):
```powershell
.\tests\Test-AtomicDetection.ps1                              # full run: admin, installs ART, live TinySocs
.\tests\Test-AtomicDetection.ps1 -DryRun                      # list tests, execute nothing
.\tests\Test-AtomicDetection.ps1 -SkipInstall                  # ART already installed
.\tests\Test-AtomicDetection.ps1 -SkipInstall -SysmonAvailable
.\tests\Test-AtomicDetection.ps1 -SelfTestRule TS-130          # isolate the OpenSearch read path for one rule, no attacks
.\tests\Test-AtomicDetection.ps1 -OnlyTechnique T1087.001       # ~3 min vs ~50 min for the full suite
.\tests\Test-AtomicDetection.ps1 -OutputJson <path>             # default: tests/atomic-results.json — see trap below
```
`TSDEBUG=1` env var turns on verbose query tracing.

Prerequisites: admin PowerShell (flips audit policy + registry), a running TinySocs agent
against OpenSearch at `https://localhost:9201` (override via
`%ProgramData%\TinySocs\Assistant\assistant.env`), Sysmon optional (auto-detected via service
name, Sysmon-required tests SKIP if absent).

For the full mechanics of authoring a new atomic test entry and fallback, and the VM run
procedure end to end, see tinysocs-detection-validation-toolkit — this skill only covers what
the harness proves and how to read its output honestly.

### The harness's scar-tissue engineering — do not "clean this up"

Every one of these looks like it could be simplified. Each was a real false-negative bug that
cost hours to find. Respect them:

- **`curl.exe -sk`, never `Invoke-RestMethod`.** PS 5.1's Schannel TLS handshake fails against
  this OpenSearch endpoint; `Invoke-RestMethod` swallowed the exception into an empty result,
  turning real detections into silent false MISSES. `--max-time 30` caps hangs (observed
  80+ minute stalls before this fix).
- **`_source` projection to `["alert.rule_id","timestamp"]` only.** Alert docs carry a large
  `matched_events` array; fetching it made `ConvertFrom-Json` pathologically slow on PS 5.1
  (a 30-45 minute hang), blowing past curl's timeout into a false MISS. The script's own
  comment calls this "the single most important correctness fix in the read path."
- **Day-scoped index list, not the `tinysocs-alerts-*` wildcard.** The wildcard matches ~40
  daily indices / 80 shards; on a 1GB-heap single node under ingest load that exceeded the
  client timeout, another false-MISS source. Queries only today + yesterday with
  `ignore_unavailable=true`.
- **Detection floor `-Since $testStart`.** The alert index accumulates 15k+ alerts over months;
  without a start-time floor, a rule that fired yesterday registers as "detected" today for an
  unrelated test. A removed "Strategy 3" (`match_all size:500` + client-side filter) was the
  original source of the 30-45 minute hangs — don't reintroduce that shape.
- **`@()` array-wrap on the poll result.** PowerShell unwraps a single-item array to a bare
  object; `.Count` on a scalar fails `-gt 0`, so the single-rule-fires case (the common case)
  silently became a false MISS until this wrap was added.
- **Readiness gate fails CLOSED, exit code 2.** `Wait-OpenSearchReady` polls `/_cluster/health`
  for up to 300s and accepts green OR yellow-with-zero-initializing/relocating (a single-node
  cluster sits yellow forever — replicas can never allocate). If the cluster never reaches that
  state, the harness aborts rather than publish a number against a half-ready cluster.
- **Fallback commands drop `ErrorActionPreference` from `Stop` to `Continue`.** Native tools
  (e.g. `net.exe`'s "System error 1326" on the very failed logons the brute-force test needs)
  write to stderr, which PS 5.1 promotes to a terminating error under `Stop` — a working
  simulation was being miscounted as a harness ERROR.

If you're tempted to "simplify" any of the above, you are about to reintroduce a false MISS or
false ERROR that already cost real debugging time once. Don't.

### Two output traps

1. **Default output path IS the committed file.** `-OutputJson` defaults to
   `tests/atomic-results.json` — the same path checked into git. Running the harness locally
   without redirecting `-OutputJson` will silently overwrite the committed run. If you're
   experimenting, always pass an explicit `-OutputJson <scratch-path>`.
2. **The harness regenerates `docs/detection-efficacy.md`** (lines 1006-1074) as a thin
   templated report, clobbering the hand-authored version. The current file (verified
   2026-07-11: header says `**Status**: current. Supersedes the 2026-03-01 report (obsolete)
   and the interim 2026-07-06 run.`) is a polished narrative with two-run coverage tables — a
   manual artifact, not what the script produces. Don't run the harness against that path
   without expecting to hand-restore the narrative content afterward, or diff before committing.

---

## 3. `tests/atomic-tests.yaml` structure

**19 technique entries** (verified 2026-07-11: `grep -c 'atomic_technique:' tests/atomic-tests.yaml`
excluding the header comment line = 19; entries run from `T1110.001` at line 26 to `T1047` at
line 202, file ends at line 210). **6 are `pilot_status: "deferred"`** (verified via
`grep -n 'pilot_status:'`): T1003.001 (TS-060), T1547.001 (TS-091), T1218.011 (TS-135),
T1055 (TS-133), T1027 (TS-134), T1047 (TS-136).

The file's own header (lines 20-23) is stale — it still says "ships **20** high-fidelity rules
and disables **17**." The real pilot pack count, verified directly against
`packaging/detection/rules.yml` (2026-07-11: `grep -c 'enabled: true'` = 19, `grep -c 'enabled:
false'` = 20, total `- id:` entries = 39), is **19 enabled / 20 disabled (39 total)** — not the
18-disabled figure `docs/pilot-ruleset.md:14`'s prose list names. The 2-rule gap is
`TS-001-lab` and `TS-030-lab` (lines 585, 605 of `rules.yml`): both `enabled: false` lab/
low-threshold test fixtures that pilot-ruleset.md's disabled-rules prose omits but that are
still present in the same file. Don't trust either doc's rule-count prose; trust
`packaging/detection/rules.yml` directly, or `DetectionEngineTests.cs:479`'s
`Assert.Equal(19, result.Rules.Count)` for the enabled side.

Per-entry fields: the field-by-field schema (with an authoring template and a worked
example) is owned by **tinysocs-detection-validation-toolkit**, Step 2 — go there when
writing or editing an entry. The two fields that matter most when *reading* results are
`pilot_status: "deferred"` (the technique's only rule is `enabled: false` in the pilot
pack — an intentional coverage gap, not a failure) and `notes` (often a rich changelog of
test-fidelity fixes — read it before assuming a test is naive).

**Why `fallback_command` exists**: most ART atomics assume a domain-joined, fully-instrumented
enterprise environment. On a standalone pilot-representative workstation, many atomics simply
don't produce the event shape the rule expects (e.g. a multi-username brute-force atomic
spreads failures across 6 accounts — 1 event per account-threshold-group — and never trips a
threshold that counts failures *per username*). The fallback is a hand-written, faithful
standalone-host simulation of the same technique that DOES exercise the rule's actual filter.
Read the `notes` field before trusting a fallback superficially resembles the real atomic — two
documented rewrites: T1110.001 (line 34, now 18× against one nonexistent username) and T1105
(line 171, now downloads twice-each per tool to trip TS-132's threshold-2).

**`pilot_status` has zero code consumers outside the harness itself.** Confirmed: it's read by
`Test-AtomicDetection.ps1` to decide SKIP, but nothing else in the pipeline (not
`validation_lib.py`'s `categorize()`, not the site build) treats "deferred" as a distinct
category — the SKIP reason string falls through pattern matching into `SKIP_PLATFORM` (see
section 5). Anyone rebuilding the public dashboard from a fresh run needs to re-verify this
fall-through still produces a benign-looking SKIP and not a red MISS — a known trap for
tinysocs-validation-publication-campaign.

---

## 4. "Harness-validated" — the actual definition

Per `docs/pilot-ruleset.md:53`: **validated means fired in a harness run under a definition
equivalent to today's rule.** A rule that passed under an old, looser rule definition (no
`field_match`, lower threshold) does not count — the definition has to match what ships today.

Current state (2026-07-08 run, `tests/atomic-results.json`):

| Bucket | Rules |
|---|---|
| **Validated end-to-end, attack→alert** (9 techniques, across the two 2026.27 runs) | TS-001, TS-010, TS-020, TS-070, TS-080, TS-090, TS-130, TS-131, TS-132 |
| **Stale / partial credit** — enabled and xUnit-proven, but the current rule definition has not itself fired live | TS-061 (current `field_match` on named dump tools never fired live; March credit predates the filter), TS-002 (never individually exercised — harness generates 18 failures against threshold 20, one short of triggering) |
| **Untested / env-limited** — covered by design and xUnit, unproven live | TS-082 (needs Defender RTP off), TS-081 (needs Tamper Protection off), TS-062 (needs a domain controller), TS-110/TS-113/TS-114 (FIM channel), TS-080-sys, TS-120 (deferred, no event source at all) |

Net position to state honestly to anyone asking "is rule X validated": xUnit proves all 19
enabled rules fire on synthetic events. The Atomic harness proves 9 of those 19 fire in a live
attack→pipeline→alert loop. 6 more are covered-by-design (FIM/system-event rules whose event
source is well understood) but not attack-validated in this environment. TS-061 and TS-002
carry credit that predates the current rule definition and should be re-earned before being
quoted.

---

## 5. The numbers discipline

- **88.9% (8/9) is the only quotable figure**, and it is a **curated denominator**: 8 DETECTED
  out of 9 *executed enabled-rule techniques* (excludes the 6 `pilot_status: deferred` SKIPs
  and the 4 env-gated SKIPs). Source: `tests/atomic-results.json`
  (`generated_at: 2026-07-08T20:45:00Z`, `efficacy_pct: 88.9`, `total_tests: 19`).
- **57.1% is the raw first-run number and is BANNED from external quoting** (`pilot-ruleset.md:65`:
  "must not be quoted"). It counted the 6 deliberately-deferred (disabled) rules as MISSES —
  an artifact of not yet having the deferred→SKIP accounting logic, not a real detection gap.
  A fresh raw run without that accounting will reproduce a similarly scary, similarly
  misleading number — don't be surprised by it, and don't publish it.
- **The March "100%" figure is BANNED, full stop.** It predates the June test-fidelity overhaul;
  several of its "DETECTED" credits were earned by rule definitions that no longer exist (TS-061
  matched *any* process creation back then; TS-135/TS-136 were credited off TS-061/TS-132 noise).
  The 2026-03-01 results file itself no longer exists in the tree — only the caveat about it
  survives in `pilot-ruleset.md`. If you see "100%" anywhere (a doc, a generated page, a stale
  cache), it is wrong on its face; flag it.
- **None of these numbers go to a customer, prospect, or public page without clearing
  tinysocs-external-positioning.** That skill owns the banned-figures list and the honest
  rule-count triad (19/39/89) for external use — this skill only owns what the harness itself
  can honestly claim.
- **Same-week re-runs silently clobber `run_id`.** `run_id` format is `<iso-week>-<seq>`, and
  `normalize_validation_run.py` defaults `seq` to `001`. Re-running the harness in the same ISO
  week without bumping the sequence overwrites the prior week's normalized result with no
  warning. Verified: `results/latest.json` and `site/validation/data/summary.json` both claim
  `run_id 2026-W23-001` yet disagree with each other (8 detected/5 missed/61.5% vs. 7 detected/
  6 missed/53.85%, different `generated_at` and different git commit) — direct evidence of this
  trap having already fired once. As of 2026-07-11 the public dashboard is ~5 weeks stale and
  still shows the pre-pilot-cut 39-rule unfiltered set (TS-134/135/136/072 as PASS, all now
  disabled) — the 2026-07-08 88.9% run was never normalized into `results/` or rebuilt into the
  site. Fixing that is the job of tinysocs-validation-publication-campaign, not this skill.
- **The signed pack ships with no validation metadata.** `packs/base/2026.27/pack.yml`
  (verified 2026-07-11, lines 7-11): `validation: {atomic_red_team_run: null, passing: null,
  failing: null, pending: null}`. The pipeline that produces 88.9% does not currently feed back
  into the artifact a customer would download.

---

## 6. New-rule evidence checklist

Gate any of this through **tinysocs-change-control** first — adding or changing a detection
rule is a pivot-relevant, gated change, not a drive-by edit.

1. **Write an honest `field_match`** in `packaging/detection/rules.yml` — match the rule's
   actual description, not "any event of this type." Include `mitre:{technique_id,
   technique_name, tactic}` (the dashboard build depends on it).
2. **Add a `tests/atomic-tests.yaml` entry** whose `fallback_command` exercises *that specific
   filter* with real threshold margin (not exactly-at-threshold — leave margin so pipeline
   jitter doesn't produce a flaky false MISS). Default `timeout_seconds: 300` for new rules per
   CLAUDE.md. Mark `pilot_status: "deferred"` if the rule ships `enabled: false`.
3. **Add an xUnit pair** to `DetectionEngineTests.cs`: a fire-on-match `[Fact]` and, if the rule
   has any filter or threshold, a stay-silent `[Fact]` proving the filter actually excludes the
   near-miss case. Update `PilotSet_EnablesExactlyTheHighFidelityRules` and
   `PilotSet_ExcludesNoisyRules` if the enabled set changes.
4. **Run the Atomic harness on a Win11 VM.** Raw JSON → `scripts/normalize_validation_run.py`
   → `results/<iso-week>.json` → rebuild `site/validation/data/summary.json`. See
   tinysocs-validation-publication-campaign for the full pipeline mechanics.
5. **Postmortem any MISS** under `results/postmortems/` before treating the run as closed —
   `run_weekly_validation.ps1` logs a WARN reminder for this but does not block the commit
   (a MISS still commits as an honest record).
6. **Re-sign the pack** (`packs/base/<ver>/pack.yml{,.canonical,.sig}`) so
   `SignedBasePack_VerifiesAndLoadsInCSharp` picks up the new count.

**Never weaken a rule's filter or threshold to make a test pass.** If a test fails, the honest
moves are: fix the test's fallback to exercise the rule faithfully, or accept the MISS and
write a postmortem. Loosening `field_match` or lowering a threshold to chase a green checkmark
reintroduces the exact noise the pilot cut (`docs/pilot-ruleset.md`) spent real FP-tuning effort
removing — see tinysocs-research-methodology for the evidence bar a rule change has to clear.

---

## When NOT to use this skill

- **Running the actual publication pipeline** (normalize → `results/` → rebuild
  `site/validation/data/summary.json` → restart weekly cadence → fix the deferred-SKIP
  attribution bug → stamp pack validation metadata) — that's the executable campaign in
  tinysocs-validation-publication-campaign. This skill defines what the numbers mean; that one
  fixes the pipeline that produces them.
- **Authoring the mechanics of a single new atomic test** (writing the fallback command itself,
  running it step-by-step on the VM, closing a specific named validation gap) — see
  tinysocs-detection-validation-toolkit.
- **Deciding whether a candidate rule is even worth adding** (FP-tuning judgment, the pilot-cut
  worked example, hypothesis-predicts-numbers reasoning) — see tinysocs-research-methodology.
- **Deciding what efficacy figures are safe to say to a prospect** — see
  tinysocs-external-positioning for the banned-figures list and honest rule-count triad.
- **General rule semantics** (`threshold_by_key`, `field_match` syntax, MITRE tactic mapping) —
  see detection-engineering-reference.
- **Whether the C# engine is even the one that runs** (dual-engine split, which files are live)
  — see tinysocs-architecture-contract.

---

## Provenance and maintenance

Authored 2026-07-11 against `fix/ci-green` @ `37005ad`. Primary sources (all read/grepped
directly, not taken solely from the discovery digest):

- `tests/TinySocs.Agent.Tests/DetectionEngineTests.cs` (484 lines)
- `tests/atomic-tests.yaml` (210 lines)
- `tests/atomic-results.json`
- `tests/Test-AtomicDetection.ps1` (referenced by line number per the discovery digest;
  structure not independently re-walked line-by-line here)
- `scripts/validation_lib.py`
- `docs/pilot-ruleset.md`
- `docs/detection-efficacy.md`
- `packs/base/2026.27/pack.yml`
- `results/2026-W09.json`, `results/2026-W23.json`, `results/latest.json`
- `.github/workflows/ci.yml`
- `tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj`
- A prior discovery-pass digest (2026-07-11, a session-local scratch file — not
  re-derivable, ignore if absent) — used as a map, cross-checked against the
  repo; two figures in it were corrected below.

**Corrections made against the source digest** (repo wins): the digest's "22 technique
mappings" is wrong — direct count is **19** (`grep -c 'atomic_technique:' tests/atomic-tests.yaml`
minus the header comment line). The task brief's "21 tests" for the xUnit file is also wrong —
it's 32 methods / 48 executable cases (confirmed by a live `dotnet test` filter run, not just
grep). Both corrected above from direct verification.

Re-verification commands (run from repo root on macOS dev machine unless noted):

```bash
# xUnit method/case count (grep is a lower bound; the dotnet test filter below is ground truth)
grep -cE '(\[Fact\]|\[Theory\])' tests/TinySocs.Agent.Tests/DetectionEngineTests.cs
grep -c 'InlineData' tests/TinySocs.Agent.Tests/DetectionEngineTests.cs
dotnet test tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj --filter FullyQualifiedName~DetectionEngineTests
dotnet test tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj --filter FullyQualifiedName~PackLoaderTests
dotnet test tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj --filter FullyQualifiedName~LicenceReaderTests

# atomic-tests.yaml entry count and deferred count
grep -c 'atomic_technique:' tests/atomic-tests.yaml   # subtract 1 for the header comment line
grep -c 'pilot_status:' tests/atomic-tests.yaml

# current enabled/disabled rule counts (ground truth the xUnit assertion mirrors)
grep -c 'enabled: true' packaging/detection/rules.yml
grep -c 'enabled: false' packaging/detection/rules.yml

# latest atomic run headline number
grep -E '"generated_at"|"efficacy_pct"|"total_tests"' tests/atomic-results.json

# is dotnet test wired into CI? (should currently return nothing)
grep -n 'dotnet test' .github/workflows/*.yml

# is the public dashboard still stale?
python3 -c "import json; d=json.load(open('results/latest.json')); print(d.get('run_id'), d.get('generated_at'))"
python3 -c "import json; d=json.load(open('site/validation/data/summary.json')); print(d.get('built_at'))"

# signed pack validation metadata (should currently be all null)
grep -A4 'validation:' packs/base/2026.27/pack.yml

# banned-number sanity check (should return nothing anywhere it'd be quoted externally)
grep -rn '100% efficacy\|100 % efficacy' docs/ site/ 2>/dev/null
```

Run `dotnet test tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj` on a machine with
.NET 8 SDK installed (see tinysocs-build-and-env for macOS/.NET setup) to re-confirm the whole
suite is still green before relying on any of the "proven to fire" claims above.
