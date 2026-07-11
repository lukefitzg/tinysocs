---
name: tinysocs-validation-publication-campaign
description: The FLAGSHIP executable campaign that makes TinySocs' public validation story truthful and alive again — fixing the harness's noise-blind attribution bug, deciding how pilot_status:deferred techniques render, normalizing the 2026-07-08 88.9% run into results/, rebuilding the stale public dashboard (currently W23, 53.85%, showing disabled rules as PASS), restarting the dead weekly cadence (no run committed since 2026-W23, ~5 weeks as of 2026-07-11), stamping validation metadata into the signed pack (currently all-null), and clearing the number for external use. Load this when asked to "fix the validation dashboard", "publish the real numbers", "why does the site disagree with atomic-results.json", "restart the weekly validation run", "stamp the pack with validation results", "the dashboard is stale", or any request to run normalize_validation_run.py / build_validation_summary.py / run_weekly_validation.ps1 for real. This is a multi-session campaign with numbered phases and a status-assessment preamble — read that first, every time, since a fresh session may be resuming mid-campaign. Does not cover what the numbers mean or the two validation mechanisms in the abstract (tinysocs-validation-and-qa), authoring a single new atomic test (tinysocs-detection-validation-toolkit), or deciding whether a rule deserves to exist (tinysocs-research-methodology).
---

# TinySocs validation publication campaign

This is the executable, multi-session campaign that turns the validation pipeline from
"mostly built, quietly lying" into "true and current." It is the flagship skill in this
library because gap #2 (`docs/roadmap.md`) is explicitly the biggest credibility lever before
first paying customer, and right now it is actively hurting the pitch: the public dashboard at
`https://lukefitzg.github.io/tinysocs/validation/` shows a **worse and staler** number
(2026-W23, 53.85% technique pass rate, disabled rules counted as PASS) than the true internal
state (2026-07-08 run, 88.9%, 9/19 rules attack-proven). Anyone who clicks through from
outreach lands on the wrong story.

**Read `tinysocs-validation-and-qa` before starting any phase.** It defines what the harness
proves, the numbers-discipline rules (curated vs. raw denominator, banned figures), and the
harness's deliberate scar-tissue engineering. This skill assumes you already know that and
covers only *running the pipeline for real*.

**Every phase that changes a public-facing number or detection behavior gates through
`tinysocs-change-control`.** That is not optional ceremony — P1 changes what counts as a pass,
P4/P7 change what a stranger reads on a public page, P6 changes what ships inside a signed
artifact a paying customer's agent will trust. Treat each as a gated change, not a drive-by
edit.

---

## Status-assessment preamble — run this FIRST, every session

This campaign spans many sessions. Before doing anything, work out which phases are already
done. Run these checks in order (macOS dev machine, from repo root) and use the table to find
your starting phase.

```bash
# P0 — CI and branch state
git status --porcelain                                          # working tree clean?
git log --oneline main..HEAD                                    # commits not yet on main
gh pr checks fix/ci-green 2>/dev/null || echo "no open PR / gh not configured"

# P1 — has the attribution fix landed?
grep -n "primary_rule\|SKIP_DEFERRED\|attribution" scripts/validation_lib.py
ls tests/test_validation_lib.py 2>/dev/null && echo "regression test exists"

# P2 — is pilot_status:deferred a first-class category yet?
grep -n "pilot_status\|deferred" scripts/validation_lib.py

# P3 — has the 2026-07-08 run been normalized?
ls results/ | sort                                              # look for a file newer than 2026-W23.json
python3 -c "import json; d=json.load(open('results/latest.json')); print(d['run_id'], d['generated_at'])"

# P4 — is the public summary rebuilt and does it match results/?
python3 -c "import json; d=json.load(open('site/validation/data/summary.json')); print(d['latest']['run_id'], d['latest']['summary'])"
diff <(python3 -c "import json;print(json.load(open('results/latest.json'))['summary'])") \
     <(python3 -c "import json;print(json.load(open('site/validation/data/summary.json'))['latest']['summary'])")

# P5 — is the weekly cadence alive? (only answerable from the VM — see P5)
#   On the Win11 VM: Get-ScheduledTaskInfo -TaskName "TinySocs Weekly Validation"
#   From the repo: is there a results/<week>.json newer than 8 days ago?
python3 -c "
import json, datetime
d = json.load(open('results/latest.json'))
gen = datetime.datetime.fromisoformat(d['generated_at'].replace('Z','+00:00'))
age = (datetime.datetime.now(datetime.timezone.utc) - gen).days
print(f'latest.json is {age} days old (run_id {d[\"run_id\"]})')"
find scripts -iname "*freshness*"                                # should be empty until P5 ships it

# P6 — has the signed pack been stamped with real validation data?
grep -A4 "validation:" packs/base/2026.27/pack.yml               # look for non-null fields

# P7 — has any GTM doc been cleared to quote a live figure?
grep -rn "88.9\|technique_pass_rate" docs/one-pager.md docs/faq.md docs/competitive-positioning.md docs/outreach-templates.md 2>/dev/null
```

| Check returns | Read as |
|---|---|
| P1 grep empty, no test file | P1 not started |
| P2 grep shows only the harness-side `pilot_status` check (`tests/Test-AtomicDetection.ps1`), nothing in `validation_lib.py` | P2 not started |
| `results/` has no file newer than `2026-W23.json` | P3 not started |
| `site/validation/data/summary.json`'s `latest.run_id` is `2026-W23-001` and its `summary` block disagrees with `results/latest.json`'s | P4 not started (and you've just re-confirmed the run_id-clobber trap in `tinysocs-validation-and-qa` §5) |
| VM `Get-ScheduledTaskInfo` errors "not found", or `latest.json` age > 8 days with no `check_validation_freshness.py` in `scripts/` | P5 not started |
| `packs/base/2026.27/pack.yml`'s `validation:` block is all `null` | P6 not started |
| No GTM doc references the number | P7 not started (expected — P7 is gated on P4 being live) |

Do not skip ahead. P4 reads P3's output; P6 reads P3/P4's output; P7 is gated on P4. Working out
of order produces exactly the kind of disagreement documented above.

---

## P0 — Preconditions

**Goal**: confirm you're building on solid ground before touching the pipeline.

1. Check CI state on the working branch with `gh pr checks fix/ci-green` (check current branch
   name with `git branch --show-current` — don't assume it's still `fix/ci-green`). **Do not
   assume green.** As of 2026-07-11 it is red: `gh pr checks fix/ci-green` shows `test (3.10)
   fail`, `windows-test fail`, `test (3.11) fail` on PR #10 (run `29130731479`, completed
   2026-07-10T23:37). Treat red as the default state to check for, not a surprise — this
   campaign should not compound onto a broken base. Gate through `tinysocs-change-control`'s
   CI-green rule.
2. Check for uncommitted changes: `git status --porcelain`. As of 2026-07-11 there is one dirty
   file (`tests/test_feed_server.py`) — and it is very likely the (uncommitted) fix for the CI
   failure above, not unrelated noise. `gh run view 29130731479 --log-failed` shows the failures
   are `FileNotFoundError: .../keys/licensing-2026.key` in
   `test_pro_token_unlocks_live`/`test_webhook_issues_usable_key`/`test_subscription_deleted_revokes`;
   `git diff tests/test_feed_server.py` shows a new `_ensure_test_signing_key()` helper that
   generates exactly that missing key on a clean checkout. Investigate and, if it checks out,
   commit that diff (or otherwise resolve the missing-key gap) as part of getting CI green —
   don't sideline it as something to keep separate from this campaign's edits, and don't start
   P1 until CI is actually green.
3. Read `tinysocs-validation-and-qa` in full if you haven't this session. It defines the exact
   numbers you'll be working with (88.9%/9, the banned 57.1% and 100% figures) and the harness
   internals you must not "clean up" (curl.exe transport, `_source` projection, day-scoped
   index list, the `@()` array-wrap, the fail-closed readiness gate, `ErrorActionPreference`
   drop in fallbacks — see that skill §2 "scar-tissue engineering").

**EXPECTED OBSERVATION**: `gh pr checks fix/ci-green` all-green, clean tree (the
`test_feed_server.py` fix committed), `tinysocs-validation-and-qa` loaded.

**If CI is red** → stop. Fix CI first (that's this branch's own name); publishing new validation
claims on top of a red build undermines the "continuously validated" pitch before it starts. As
of 2026-07-11 this is the actual state — the missing `keys/licensing-2026.key` in CI/clean-checkout
environments is the live blocker, and the dirty `test_feed_server.py` diff is the candidate fix
to verify and land.

---

## P1 — Fix the noise-blind attribution bug

**Goal**: a test's PASS must credit the technique-specific rule, not any rule that happens to
share its `expected_rules` list.

**The bug, precisely** (verified 2026-07-11): `tests/Test-AtomicDetection.ps1`'s
`Query-TinySocsAlerts` (line ~413) is called with `-RuleIds $rules` where `$rules =
$test.expected_rules` — the *entire* list for that technique, which can have 2-3 members (e.g.
`T1110.001` → `["TS-001", "TS-001-lab", "TS-002"]`, `T1105` → `["TS-080", "TS-080-sys"]`). The
query filters OpenSearch by `should` over all of them with `minimum_should_match: 1` (line
~477). If **any one** of those rule IDs fires within the timeout, the harness marks the whole
technique `DETECTED` (line 956) — it never checks *which* member of `expected_rules` actually
fired against *this* technique's attack. `docs/roadmap.md:87` names this directly: "a test
passes if any co-listed rule fires; it must validate the technique-specific rule
(`tests/atomic-tests.yaml` `expected_rules`)." `docs/design/continuous-validation.md:170`
documents the current (buggy) behavior as intentional design — that design decision is what
you're overturning here, not a stray implementation error.

Why it matters concretely: a noisy rule (the roadmap names TS-061/TS-130/TS-131 as
over-fire-prone, `docs/roadmap.md:86`) sharing a co-listed slot with the "real" rule for a
technique can produce a false PASS even when the real rule never fired — the dashboard would
show green for the wrong reason. Conversely a genuinely correct multi-rule technique (TS-001 OR
TS-001-lab is a legitimate "either is acceptable" pairing) must **not** regress to MISS once
you tighten this.

**Per `tinysocs-research-methodology`'s hypothesis-predicts-numbers discipline: write down what
the fix should change BEFORE writing the fix.** Using the current committed
`tests/atomic-results.json` (2026-07-08 run) as your fixture:

```bash
# Reproduce today's (buggy) numbers as your baseline
python3 scripts/normalize_validation_run.py tests/atomic-results.json --dry-run 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['summary'])"
# Expect: technique_pass_rate 0.8889 (8/9), rule_pass_rate 0.3636 — this is today's baseline,
# reproduced from the unmodified pipeline as of 2026-07-11.
```

Then, per-result, work out by hand which `detected_rules` entry is the "real" rule for that
technique vs. an incidental co-listed one, and predict the new `technique_pass_rate` /
`rule_pass_rate` your fix should produce. Only then implement.

**Implementation shape** (this is a founder design decision — the schema doesn't currently
distinguish "the rule this technique is really testing" from "an acceptable alternate," so you
are choosing one):

- **Option A — narrow `expected_rules` to one canonical entry per technique** in
  `tests/atomic-tests.yaml`, keeping alternates in a new `acceptable_rules` (or similar) field
  that is recorded but doesn't count toward the pass. Simplest, but loses the "either TS-001 or
  TS-001-lab is fine" nuance for tests that are legitimately multi-valid.
- **Option B — add a `primary_rule` field alongside `expected_rules`** and change
  `categorize()`/`normalize_result()` in `scripts/validation_lib.py` to require
  `primary_rule in detected_rules` for `CATEGORY_PASS`, while still recording all
  `detected_rules` for transparency.

Either way, the code that needs to change is `scripts/validation_lib.py`'s `normalize_result()`
and `categorize()` (the categorisation is deliberately centralized there per the module's own
docstring — "so the categorisation rules never drift between code paths" — don't duplicate the
fix into the PowerShell harness too). You may also need to adjust
`tests/Test-AtomicDetection.ps1`'s `Query-TinySocsAlerts` call site if you want the *query
scope* narrowed too (currently it queries for any of `$rules`, which is a separate, milder
version of the same issue — it affects what counts as `detected_rules` at all, not just what
counts as a pass).

Write `tests/test_validation_lib.py` (does not exist yet — new file) with cases built from the
real 2026-07-08 `tests/atomic-results.json` fixture: at least one case proving a co-listed noisy
rule firing does NOT flip an unrelated technique to PASS, and one proving a legitimate
alternate-rule pass still works.

**EXPECTED OBSERVATION**: `pytest tests/test_validation_lib.py -v` green; re-running
`normalize_validation_run.py tests/atomic-results.json --dry-run` produces a
`technique_pass_rate` that matches your written-down prediction, not necessarily 0.8889 (it
could stay the same if no co-listed rule actually misfired in this specific run — that's a
valid outcome, not a failure of the fix).

**If the predicted and actual numbers disagree** → do not adjust the fix to match the number you
wanted. Re-derive by hand which rule fired for which technique from `tests/atomic-results.json`'s
`detected_rules` field and figure out whether your prediction or your implementation was wrong.

**Gate through `tinysocs-change-control`** — this changes what "PASS" means pipeline-wide.

---

## P2 — Decide how `pilot_status: deferred` renders

**Goal**: make deferred-by-design techniques visibly distinct from genuine environment blocks,
without turning them into red MISSes.

**Current state** (verified 2026-07-11): `pilot_status: deferred` has exactly one consumer —
`tests/Test-AtomicDetection.ps1` line 767, which turns a deferred technique into a `SKIP` with
reason `"Deferred from pilot pack (rule disabled; see docs/pilot-ruleset.md)"` before any attack
runs. That's correct and already shipped — deferred techniques do **not** render as MISS today.
The gap is one layer down: `scripts/validation_lib.py`'s `categorize()` has no pattern that
matches that reason string. It falls through `_PLATFORM_SKIP_RE` / `_PREREQ_SKIP_RE` (neither
matches "Deferred from pilot pack...") into the catch-all at line 90-92 — "Unclassified skip:
treat as platform skip (benign)... an unexpected skip reason is worth eyeballing in review." So
today, a deferred technique is indistinguishable in the dashboard from a genuine "needs a domain
controller" skip. A reader can't tell "we chose not to test this yet" from "the test environment
can't exercise this."

**The founder decision** (gate through `tinysocs-change-control` — this changes dashboard
semantics):

- **Render as deferred** — add `CATEGORY_SKIP_DEFERRED` to `scripts/validation_lib.py`, match
  it via a new regex pattern (e.g. `r"deferred from pilot pack"`) ahead of the platform/prereq
  checks, and give the dashboard (`site/validation/validation.js` + `build_validation_summary.py`)
  a fourth grey-ish bucket with its own label ("intentionally deferred — see
  `docs/pilot-ruleset.md`"). More honest, more dashboard/JS work.
- **Exclude entirely** — deferred techniques don't appear in the per-technique table at all
  (filter them out in `build_validation_summary.py` before building `rule_entries`/history).
  Simpler, but a visitor sees fewer rows than 19 with no explanation of the gap, which cuts
  against the "coverage gap honesty" principle `docs/design/continuous-validation.md:204-208`
  already commits to for untested rules generally.

Whichever you pick, keep it consistent with how the dashboard already handles "15 of 39 rules
do not yet have an Atomic Red Team test" (the coverage-gap section design) — deferred rules are
a documented, named gap, not a silent one.

**EXPECTED OBSERVATION**: `python3 scripts/normalize_validation_run.py tests/atomic-results.json --dry-run`
shows the 6 deferred results with your new category (or absent, if you chose exclusion) —
verify against `grep -c '^\s*pilot_status: "deferred"' tests/atomic-tests.yaml` (currently 6:
T1003.001/TS-060, T1547.001/TS-091, T1218.011/TS-135, T1055/TS-133, T1027/TS-134, T1047/TS-136).
Note: a plain `grep -c 'pilot_status: "deferred"'` (no anchor) returns 7, not 6 — it also
matches the schema-doc comment at line 14 (`#   - pilot_status: "deferred" if the technique's
only rule is disabled in the...`), which is not one of the 6 real per-test entries. Use the
anchored pattern above, or subtract 1 from the raw count.

---

## P3 — Normalize the 2026-07-08 run into `results/`

**Goal**: get the true, current run into the file the dashboard actually reads.

**Machine**: macOS dev (the normalizer is pure Python, no VM needed — the raw data is already
committed in `tests/atomic-results.json`).

**Two traps, both verified in the actual code — read before running anything:**

1. **The run_id clobber trap.** `scripts/normalize_validation_run.py`'s `--run-seq` flag
   (default `"001"`) only changes the `run_id` *string inside* the JSON
   (`f"{iso_week}-{run_seq}"`, line 73). The **output filename** is
   `results_dir / f"{record['iso_week']}.json"` (line 152) — it does **not** include
   `run_seq`. So running the normalizer twice against the same ISO week, with or without
   bumping `--run-seq`, silently overwrites the previous file. This is exactly what already
   happened to `2026-W23.json` — `results/latest.json` (technique_pass_rate 0.6154) and
   `site/validation/data/summary.json`'s `latest.summary` (0.5385) both claim `run_id
   2026-W23-001` yet disagree, because a second run clobbered the file `build_validation_summary.py`
   hadn't yet consumed. If you need to preserve more than one run per week, that's new code
   (change the output filename to include `run_seq`) — don't assume `--run-seq` alone protects
   you.
2. **`tests/atomic-results.json` is both the input and a historical record.** It's the real,
   committed 2026-07-08 run — the thing you're about to normalize. It is also
   `Test-AtomicDetection.ps1`'s **default** `-OutputJson` target. Do not re-run the harness
   locally without an explicit `-OutputJson <scratch-path>` or you will overwrite this exact
   file before you've normalized it. (`run_weekly_validation.ps1` already avoids this — it
   writes to gitignored `logs/validation-raw.json` — but a manual harness invocation does not.)

Run:

```bash
# From repo root, macOS dev machine
python3 scripts/normalize_validation_run.py tests/atomic-results.json --dry-run
# Read the printed summary line and the JSON. Confirm the numbers match what P1/P2 predicted
# BEFORE writing anything.

python3 scripts/normalize_validation_run.py tests/atomic-results.json
# Writes results/2026-W28.json and overwrites results/latest.json.
```

**The output filename is derived from the raw file's `generated_at` timestamp, not from
today's date.** `vl.iso_week_label()` computes the ISO week from `2026-07-08T20:45:00Z` (the
run's own timestamp), so it writes `2026-W28.json` — which happens to equal today's ISO week
too (2026-07-11 is also `W28`) purely because the run is only three days old relative to when
this campaign runs. Don't assume that coincidence holds later — if you normalize an older
backlog run, the filename will reflect *that run's* week, not the day you happen to execute the
script. Confirm the derived week explicitly before trusting the output filename:

```bash
python3 -c "
import sys; sys.path.insert(0,'scripts')
import validation_lib as vl
print(vl.iso_week_label(vl.parse_timestamp('2026-07-08T20:45:00Z')))"
```

**EXPECTED OBSERVATION**: `results/<that-week>.json` and `results/latest.json` both show
`atomic_tests_detected: 8`, `atomic_tests_missed: 1` (TS-130 — a pipeline-latency
false-negative that fired cleanly in the prior run per `docs/detection-efficacy.md`, not a real
rule defect), and a `technique_pass_rate`/`rule_pass_rate` consistent with your P1/P2 fixes.
`git status` shows exactly the new/changed files under `results/` — nothing else.

**If the normalizer errors "contains only dry-run results"** → you pointed it at a `-DryRun`
harness output by mistake; re-check the input file's `results[].status` values aren't all
`DRY_RUN`.

**Commit** results/ separately from the P1/P2 code changes if they haven't already been
committed — keeps the "here is a new validated run" commit legible on its own, per this repo's
commit-message convention of referencing what changed and why.

---

## P4 — Rebuild the public dashboard summary

**Goal**: `site/validation/data/summary.json` reflects the run you just normalized, and no
longer disagrees with `results/latest.json`.

**Machine**: macOS dev, or let CI do it (see below).

```bash
python3 scripts/build_validation_summary.py \
  --results-dir results \
  --rules packaging/detection/rules.yml \
  --output site/validation/data/summary.json
```

**Current stale state you're replacing** (verified 2026-07-11): `latest.run_id
2026-W23-001`, `technique_pass_rate 0.5385` (53.85%), weeks `["2026-W09", "2026-W23"]`, built
against `packaging/detection/rules.yml`'s full 39-rule set undifferentiated — TS-134/135/136/072
(now `enabled: false`, disabled in the 2026-07-04/07-08 pilot cut) show as PASS from a stale
pre-pilot-cut run. This is the single most damaging live artifact in the GTM story: a visitor
following an outreach link sees a worse, older number than the true 88.9%.

**EXPECTED OBSERVATION**: the diff command from the status-assessment preamble now shows no
difference between `results/latest.json`'s `summary` and
`site/validation/data/summary.json`'s `latest.summary`:

```bash
diff <(python3 -c "import json;print(json.load(open('results/latest.json'))['summary'])") \
     <(python3 -c "import json;print(json.load(open('site/validation/data/summary.json'))['latest']['summary'])")
# Expect: empty diff
```

`weeks` should now include the new ISO week; `rules[].latest_category` for TS-134/135/136/072
etc. should reflect their pilot-cut `enabled: false` state (verify against
`packaging/detection/rules.yml`, not memory — the pilot cut disabled 18 rules for v2 tuning,
see `docs/pilot-ruleset.md`).

**If numbers still disagree after rebuilding** → you're reading a cached copy. Re-run the exact
`build_validation_summary.py` invocation `.github/workflows/pages.yml` uses (verified 2026-07-11,
step "Build validation summary") — the flags must match exactly (`--results-dir results --rules
packaging/detection/rules.yml --output site/validation/data/summary.json`) or you'll rebuild
against a different default and get a legitimately different — not stale — result.

**Do not hand-edit `summary.json`.** It's a generated artifact (`build_validation_summary.py`'s
own docstring: "everything is precomputed here and deployed as a flat file"). A hand edit will
be silently overwritten by the next `pages.yml` run or the next person who runs the builder, and
it breaks the "the dashboard is exactly what the pipeline computed" guarantee that makes it
credible in the first place. If a number looks wrong, fix the *pipeline* (P1-P3), not the JSON.

**Deploying**: pushing `results/**` or `site/**` changes to `main` triggers `.github/workflows/pages.yml`
("Deploy Landing Page") automatically — it re-runs `build_validation_summary.py` itself and
deploys via `actions/deploy-pages`. You don't strictly need to commit a locally-built
`summary.json` at all (CI will overwrite it); building locally first is for verification before
you push, per the diff check above. `workflow_dispatch` is also wired — you can trigger a
rebuild-only run (no new validation data) from the Actions tab if you only changed
`build_validation_summary.py` itself.

---

## P5 — Restart the weekly cadence + add the freshness check

**Goal**: a real Windows VM commits a real weekly run again, and a missed week becomes visible
automatically instead of silently.

**Machine**: the Windows test VM (the one running TinySocs + OpenSearch + Sysmon 24/7 per
`docs/design/continuous-validation.md`'s architecture diagram).

The cadence has been dead since `2026-W23` — **~5 weeks as of 2026-07-11** (current ISO week is
`2026-W28`; confirm with `date +%G-W%V` or `python3 -c "import datetime;
print(datetime.date.today().isocalendar())"`). The full setup procedure already exists and is
documented step by step in `docs/operator/weekly-validation-setup.md` — this phase is "verify it
still works and actually runs," not "design it from scratch."

1. **On the VM, check whether the scheduled task exists and its last result:**
   ```powershell
   Get-ScheduledTaskInfo -TaskName "TinySocs Weekly Validation"
   ```
   - Task not found → it was never registered on this VM, or the VM was rebuilt. Follow
     `docs/operator/weekly-validation-setup.md` §1-3 in full (deploy key, first manual run,
     `Register-ScheduledTask`).
   - Task found, `LastTaskResult` non-zero → check the newest `logs\validation-*.log` on the VM
     for the failing step (git pull conflict, SSH auth, harness error — the wrapper aborts
     *before* committing on any failure, so a broken run never publishes a bad result, but it
     also silently stops the cadence).
   - Task found, `LastTaskResult` 0, but `results/` on `main` hasn't moved → the run succeeded
     locally but the push failed, or nothing changed to commit (re-run of an identical week —
     check the log for "No result changes to commit").
2. **Confirm the deploy key still authenticates**: `ssh -i $HOME\.ssh\tinysocs_deploy -T
   git@github.com` should greet you by username with write access. Deploy keys and PATs both
   expire/get revoked; this is the single most likely silent-failure cause after a multi-week
   gap.
3. **Trigger one real run by hand** to re-prove the chain before trusting the schedule again:
   ```powershell
   pwsh C:\tinysocs\scripts\run_weekly_validation.ps1
   ```
   This pulls `main`, runs the full harness (~50 min), normalizes, commits, and pushes — same
   trap-free path `run_weekly_validation.ps1` already uses (raw output to gitignored
   `logs\validation-raw.json`, not the `tests/atomic-results.json` you're protecting from P3).
4. **Add the never-built freshness check.** `docs/design/continuous-validation.md`'s own open
   question #1 names this and it does not exist (verified 2026-07-11: `find scripts -iname
   "*freshness*"` returns nothing). Write `scripts/check_validation_freshness.py`: reads
   `results/latest.json`'s `generated_at`, and if it is more than 8 days stale, exits non-zero
   (for a CI job to catch) and/or opens a GitHub issue via `gh issue create` (needs a `GITHUB_TOKEN`
   with issue-write scope — check what's already available to `.github/workflows/pages.yml`
   before assuming you need a new secret). Wire it as a new scheduled GitHub Actions workflow
   (`workflow: schedule: cron:` — separate from `pages.yml`, since this doesn't touch `site/`)
   so staleness is caught even if the VM stays silent indefinitely, not only when someone happens
   to check by hand.

**EXPECTED OBSERVATION**: `Get-ScheduledTaskInfo` shows `LastTaskResult 0` and a recent
`LastRunTime`; a new `results/<current-week>.json` lands on `main` within the run's duration;
`scripts/check_validation_freshness.py` exits 0 against the fresh `results/latest.json` and
non-zero against a synthetic 9-day-old fixture (write a quick manual test for that, don't just
trust it).

**If the VM itself is gone or reimaged** → this phase becomes VM provisioning, which is
operations territory (`tinysocs-run-and-operate`), not validation-pipeline territory. Don't
try to solve VM provisioning inside this skill.

---

## P6 — Stamp `metadata.validation` into the next signed pack

**Goal**: the artifact a customer's agent actually downloads and trusts carries real validation
provenance, not `null`.

**Current state** (verified 2026-07-11): `packs/base/2026.27/pack.yml` lines 7-11:
```yaml
validation:
  atomic_red_team_run: null
  passing: null
  failing: null
  pending: null
```
`scripts/migrate_rules_to_v2.py` (`build_pack()`, lines ~188-193) **always** writes this block
as all-`null`, with the comment "Filled by the validation pipeline at release time" — but no
code anywhere fills it in later. This is a real, unbuilt seam, not a bug in existing code: the
"continuously-validated" claim (the whole thesis, `docs/roadmap.md:11`) isn't stamped into the
artifact a customer's agent verifies.

**This is undefined schema, not a wiring bug — found no shape specified in
`docs/design/signed-feed.md` beyond a passing filename mention (`validation.json`).** Decide
(gate through `tinysocs-change-control`, since this is new schema surface a customer-side agent
will eventually read):

- What goes in `passing` / `failing` / `pending` — rule IDs? technique IDs? counts only? Given
  `results/<week>.json`'s existing `summary` block already has the counts and
  `rule_category_for_week()` in `validation_lib.py` already computes a per-rule verdict, the
  natural shape is `passing: [rule IDs with category PASS this week]`, `failing: [rule IDs with
  category MISS]`, `pending: [rule IDs with no Atomic test yet]` — but this is a call to make
  deliberately, not infer silently.
- `atomic_red_team_run` is presumably the `run_id` (e.g. `"2026-W28-001"`) of the run the
  stamp is sourced from — cheap to decide, do it first.

**Implementation**: this needs new code — either a `--stamp-validation <results/week.json>` flag
added to `scripts/migrate_rules_to_v2.py`, or a small new script that patches an already-generated
`pack.yml`'s `metadata.validation` block from a `results/<week>.json` file, run *before*
`pack_sign.py sign` (signing covers `metadata.validation` — it's part of `canonical_bytes()`'s
input — so the stamp must land before the signature, not after, or the signature won't cover it).

Re-sign per `tinysocs-build-and-env`'s documented flow:
```bash
python3 scripts/pack_sign.py sign packs/base/2026.27/pack.yml --key-id tinysocs-2026
python3 scripts/pack_sign.py verify packs/base/2026.27/pack.yml --key-id tinysocs-2026
```
This regenerates `pack.yml.canonical` and `pack.yml.sig` and rewrites the in-band
`metadata.signature` block. Confirm `SignedBasePack_VerifiesAndLoadsInCSharp` in
`DetectionEngineTests.cs` still passes afterward (per `tinysocs-validation-and-qa` §6, step 6 of
the new-rule checklist covers the same re-sign-and-reverify step).

**EXPECTED OBSERVATION**: `grep -A4 'validation:' packs/base/2026.27/pack.yml` shows non-null
fields; `pack_sign.py verify` reports a valid signature; the xUnit pack-loader test still passes.

**Do not stamp a pack.yml that predates the fixes in P1-P3** — the whole point is that the
number stamped in is the honest, attribution-correct one.

---

## P7 — Clear the number for external use

**Goal**: get 88.9% (or whatever P1's fix produces) actually usable in a pitch, not just true in
a JSON file.

This phase is entirely a handoff, not new engineering. **Gate through `tinysocs-external-positioning`**
for the exact conditions that must hold before any figure goes in front of a prospect — as of
2026-07-11 that skill documents specific outstanding preconditions from
`docs/detection-efficacy.md:80-83` (one more clean single-run pass for a cleaner artifact —
optional per that skill, coverage is already proven across two runs; targeted runs for the four
environment-limited rules TS-082/081/062/110 before they're individually claimed as
attack-validated) **plus** "the public dashboard must actually be live and consistent with the
number" (P4, done by this point in the campaign) before treating a number as customer-ready.

Do not independently decide a number is "good enough to quote" from inside this skill — that
judgment call, and the banned-figures list (57.1%, the March "100%"), belong to
`tinysocs-external-positioning`.

**EXPECTED OBSERVATION**: `tinysocs-external-positioning`'s own checklist is satisfied; a GTM doc
update (if any) happens as a separate, explicitly-approved change — not bundled into this
campaign's commits.

---

## Fenced-off wrong paths — do not do these, even if they look faster

- **Do not weaken or re-scope a rule's `field_match`/threshold to make a number look better.**
  This is a `tinysocs-change-control` violation on its face — loosening a filter to chase a
  green dashboard cell reintroduces exactly the FP noise the pilot cut spent real effort
  removing (`docs/pilot-ruleset.md`; see `tinysocs-research-methodology` for the evidence bar).
  If a test MISSes honestly, the correct move is a postmortem under `results/postmortems/`, not
  a rule edit.
- **Do not quote the raw, unfiltered denominator anywhere** (the historical 57.1% number that
  counted deferred/disabled rules as misses, or any fresh number computed the same naive way).
  It is BANNED per `tinysocs-validation-and-qa` §5 and `docs/pilot-ruleset.md:65`. If P1/P2
  produce a new "everything counted" number as a side effect of your regression tests, that
  number stays internal-diagnostic only.
- **Do not hand-edit `site/validation/data/summary.json`.** It's a build artifact
  (`build_validation_summary.py`'s docstring is explicit: "no backend, no API calls at view
  time" — everything is precomputed and deployed flat). A hand edit is silently clobbered by the
  next pipeline run and breaks the guarantee that the dashboard is exactly what the pipeline
  computed. Fix the pipeline, rebuild the artifact.
- **Do not "clean up" the harness's scar-tissue transport.** `curl.exe -sk` instead of
  `Invoke-RestMethod`, the `_source` projection to two fields, the day-scoped index list instead
  of the `tinysocs-alerts-*` wildcard, the `@()` array-wrap, the fail-closed readiness gate, and
  the `ErrorActionPreference` drop in fallback commands are all load-bearing fixes for real
  false-negative bugs that cost hours to find (full list and reasoning:
  `tinysocs-validation-and-qa` §2). Touching any of them "to simplify" during this campaign will
  reintroduce a false MISS or false ERROR silently.
- **Do not touch rule definitions in this campaign at all** — not `packaging/detection/rules.yml`,
  not `enabled` flags, not thresholds. Authoring or fixing a specific rule's evidence is
  `tinysocs-detection-validation-toolkit` territory; deciding whether a rule deserves to exist is
  `tinysocs-research-methodology` territory. This campaign only touches the pipeline that scores
  and publishes results against whatever rules already exist.
- **Do not run the full harness locally on macOS.** It's Windows-VM-only (PowerShell 5.1,
  Windows Event Log, Sysmon, Windows audit policy). P1/P2/P3's Python-side work is all testable
  against the already-committed `tests/atomic-results.json` fixture without touching a VM; only
  P5 needs the VM.

---

## When NOT to use this skill

- **Understanding what the two validation mechanisms prove, the numbers-discipline rules, or
  the harness's scar-tissue engineering in the abstract** — `tinysocs-validation-and-qa`. Read
  it first regardless of which phase you're in.
- **Authoring a brand-new atomic test for a specific rule, writing its fallback command, or
  running a single-technique VM validation** — `tinysocs-detection-validation-toolkit`.
- **Deciding whether a candidate rule should be enabled at all, or judging FP risk** —
  `tinysocs-research-methodology`.
- **Deciding what's safe to say to a prospect once the number is true and live** —
  `tinysocs-external-positioning` (P7 hands off here explicitly).
- **General change-classification and gating mechanics** — `tinysocs-change-control` (referenced
  throughout; read it if you're unsure whether a specific edit needs a gate).
- **VM provisioning, NSSM services, ports, or general ops** if the VM itself is missing or
  broken — `tinysocs-run-and-operate` / `tinysocs-diagnostics-and-tooling`.
- **Rebuilding the C# agent or re-signing keys from a totally clean checkout** —
  `tinysocs-build-and-env` has the exact `pack_sign.py`/`migrate_rules_to_v2.py` commands this
  skill's P6 assumes you already know.

---

## Provenance and maintenance

Authored 2026-07-11 against branch `fix/ci-green` @ `37005ad` (2 commits ahead of `main`:
`279e4d6`, `37005ad`; re-verify with `git log --oneline main..HEAD`). CI on this branch is
**red as of 2026-07-11** (`gh pr checks fix/ci-green`: `test (3.10)`/`windows-test`/`test (3.11)`
all `fail`, PR #10, run `29130731479`) — the failures are `FileNotFoundError` on the missing
`keys/licensing-2026.key` in `tests/test_feed_server.py`, and the working tree's one dirty file
(`tests/test_feed_server.py`, adding `_ensure_test_signing_key()`) is very likely the uncommitted
fix. Re-check this before trusting P0's green-CI assumption — it may already be resolved by the
time you read this. Primary sources, all read directly:

- `scripts/validation_lib.py` (287 lines) — `categorize()`, `normalize_result()`,
  `build_summary()`, the SKIP pattern regexes.
- `scripts/normalize_validation_run.py` (171 lines) — the run_id/filename mismatch (line 152 vs.
  line 73) confirmed by direct read.
- `scripts/build_validation_summary.py` (192 lines).
- `scripts/run_weekly_validation.ps1` (139 lines) — confirmed it writes raw output to gitignored
  `logs/validation-raw.json`, not `tests/atomic-results.json`.
- `scripts/migrate_rules_to_v2.py` (`build_pack()`, ~line 179-198) — confirmed the
  all-null `validation` block and its stale "filled at release time" comment.
- `scripts/pack_sign.py` — sign/verify/gen-key CLI.
- `tests/Test-AtomicDetection.ps1` (1179 lines) — `Query-TinySocsAlerts` (line ~413),
  the `pilot_status` SKIP branch (line 767), the main result loop (line ~938-964).
- `tests/atomic-tests.yaml` (210 lines) — confirmed `expected_rules` multi-member entries
  (T1110.001, T1105) and the 6 `pilot_status: "deferred"` entries. Note: a plain
  `grep -c 'pilot_status: "deferred"'` returns 7, not 6 — it also matches the schema-doc comment
  at line 14; the anchored `grep -c '^\s*pilot_status: "deferred"'` correctly returns 6.
- `tests/atomic-results.json` — the 2026-07-08 run (19 total: 8 DETECTED, 1 MISSED, 10 SKIP).
- `results/2026-W09.json`, `results/2026-W23.json`, `results/latest.json`,
  `site/validation/data/summary.json` — confirmed the W23 staleness and the `run_id`-clobber
  disagreement (results/latest.json: 8 detected/5 missed/61.5%; site summary: 7 detected/6
  missed/53.85%; both claim `run_id 2026-W23-001`).
- `.github/workflows/pages.yml` — confirmed trigger paths and the exact
  `build_validation_summary.py` invocation CI uses.
- `docs/design/continuous-validation.md` (331 lines) — design intent, including the
  currently-buggy "any expected rule fired = PASS" behavior documented as-designed at line 170,
  and open question #1 (freshness check, never built).
- `docs/operator/weekly-validation-setup.md` — deploy key + `Register-ScheduledTask` (Sunday
  02:00, `SYSTEM`) procedure.
- `docs/roadmap.md` (lines 80-91) — "Nearest milestone" section naming the attribution bug and
  the publish sequencing.
- `packs/base/2026.27/pack.yml` — confirmed the all-null `validation:` block.
- Sibling skills read for boundary-setting (not re-stated here): `tinysocs-validation-and-qa`,
  `tinysocs-detection-validation-toolkit`, `tinysocs-external-positioning`.

Re-verification commands (macOS dev machine, repo root, unless noted):

```bash
# Is the attribution fix in yet?
grep -n "primary_rule\|SKIP_DEFERRED" scripts/validation_lib.py

# Reproduce today's baseline numbers against the committed 2026-07-08 run
python3 scripts/normalize_validation_run.py tests/atomic-results.json --dry-run 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['summary'])"

# Is results/ still stuck at W23?
ls results/*.json | sort

# Do results/latest.json and the public summary still disagree?
diff <(python3 -c "import json;print(json.load(open('results/latest.json'))['summary'])") \
     <(python3 -c "import json;print(json.load(open('site/validation/data/summary.json'))['latest']['summary'])")

# Current ISO week (for naming the next results file / judging cadence staleness)
python3 -c "import datetime; print(datetime.date.today().isocalendar())"

# Is the pack still stamped null?
grep -A4 "validation:" packs/base/2026.27/pack.yml

# Does the freshness check exist yet?
find scripts -iname "*freshness*"

# How many real pilot_status:deferred entries (anchored — the unanchored form also matches
# the schema-doc comment at line 14 and overcounts by 1)
grep -c '^\s*pilot_status: "deferred"' tests/atomic-tests.yaml

# CI status of the working branch (as of 2026-07-11: all three checks fail — see Provenance
# above; don't assume green without running this)
gh pr checks $(git branch --show-current) 2>/dev/null
```
