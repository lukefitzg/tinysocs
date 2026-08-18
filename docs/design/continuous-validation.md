# Continuous Validation Pipeline — Design

**Status**: Approved design, partially implemented, **publication half parked 2026-08-18** — the harness (`Test-AtomicDetection.ps1`, `tests/atomic-tests.yaml`) is real and stays; the weekly public-dashboard cadence was abandoned with the commercial strategy (`docs/design/strategy-zero-support.md`). Validation evidence now lives in-repo (`tests/atomic-results.json`, `docs/pilot-ruleset.md`) with no cadence promised.
**Author**: Luke FitzGerald + Claude session, 2026-05-26 (decisions locked), design written 2026-05-31.
**Related**: `docs/design/rule-format-v2.md` (v2 schema). This design is deliberately schema-invariant against v2 so they can ship in parallel.

---

## Why this exists

The continuous validation pipeline is the **proof-of-claim that anchors the content-as-a-service thesis**. Without it, the pitch is "trust us, our detection rules are good." With it, the pitch is "here's the public dashboard, every rule re-tested weekly against Atomic Red Team, see the green/amber/red for yourself."

No SMB SIEM competitor publishes this today. It is the single biggest credibility differentiator we can ship before first paying customer, and it is the artefact we can point a co-founder, an early customer, or a journalist at.

It is also the credibility floor: the day we charge for content is the day a stranger has to trust that the content is current and validated. The dashboard is the receipt.

## What this design covers

- Where the harness runs and how often.
- What artefacts it produces and where they live.
- The public dashboard shape and what it claims.
- Honest framing of pass / skip / miss / error.
- Schema-invariance against v2 (so v2 lands without breaking the pipeline).
- Coverage-gap honesty (not every rule has an Atomic test today).

## What this design does **not** cover

- Detection coverage *expansion* (adding new Atomic tests for uncovered rules). That's gap #4 (content cadence) — the pipeline just exposes the gap.
- The signed rules feed (gap #1) — separate work, separate consumer.
- TinyDocs surfacing alongside the dashboard. Future iteration once TinyDocs exists.

---

## Existing assets (already built; ~80% of the harness is done)

| Path | What it does | Re-usable as-is? |
|---|---|---|
| `tests/atomic-tests.yaml` | Maps 19 MITRE techniques → expected TinySocs rule IDs + ART test number + fallback command + skip-reason metadata | Yes |
| `tests/Test-AtomicDetection.ps1` | 910-line PowerShell harness: installs Invoke-AtomicRedTeam, runs each test, queries OpenSearch for `rule_id` in `tinysocs-alerts-*`, writes JSON | Yes |
| `tests/atomic-results.json` | Result schema: `generated_at`, `efficacy_pct`, `total_tests`, `results[]` with `technique_id`, `expected_rules`, `detected_rules`, `status`, `reason` | Yes (with one schema bump — see below) |
| `.github/workflows/pages.yml` | Deploys `site/` to GitHub Pages on push to main | Yes — extends naturally to validation dashboard |
| `site/index.html` | Existing landing page | Stays as-is; dashboard lives in a new subpath |
| `tests/atomic-tests.yaml` notes (e.g., "this VM") | Implicit reference to the existing Windows test VM | The VM is the execution venue |

So the build cost is:
- A scheduled Windows Task Scheduler entry that runs the harness weekly and commits results.
- A schema bump (versioning + a couple of new fields).
- A static HTML/JS dashboard in `site/validation/` that consumes the result history.
- A pages workflow tweak so the dashboard auto-refreshes when new results commit.

That is meaningfully smaller than "build a validation pipeline from scratch." 2–3 weekends total, not 6.

## Architecture

```
                          [ Existing Windows test VM ]
                           ├─ TinySocs agent + OpenSearch (running 24/7)
                           ├─ Sysmon (installed, configured)
                           └─ Task Scheduler entry: "weekly Sunday 02:00 local"
                                          │
                                          ▼
              ┌───────────────────────────────────────────────────────────┐
              │  Test-AtomicDetection.ps1 -OutputJson results/{YYYY-WW}.json │
              │   1. Pulls latest main (git pull)                          │
              │   2. Runs 19 Atomic technique tests in sequence            │
              │   3. Queries OpenSearch tinysocs-alerts-*                  │
              │   4. Writes per-run JSON to results/2026-W22.json          │
              │   5. Commits + pushes via PAT/deploy key                   │
              └───────────────────────────────────────────────────────────┘
                                          │
                                          ▼
                          [ GitHub: push to main ]
                                          │
                                          ▼
              ┌───────────────────────────────────────────────────────────┐
              │  pages.yml (already exists; trigger extended to results/*) │
              │   1. Build site/validation/ dashboard from results/*.json  │
              │   2. Deploy site/ to GitHub Pages                          │
              └───────────────────────────────────────────────────────────┘
                                          │
                                          ▼
                  https://lukefitzg.github.io/tinysocs/validation/
                  ← the public proof-of-claim URL we put in outreach
```

## File layout

```
results/
├── latest.json                      # symlink or copy of newest weekly file
├── 2026-W21.json                    # one file per ISO week
├── 2026-W22.json
├── ...
└── summary.json                     # rolled-up state for dashboard (built in CI)

site/
├── index.html                       # existing landing
└── validation/
    ├── index.html                   # dashboard SPA-lite (vanilla JS, fetches summary.json)
    ├── styles.css
    └── data/
        └── summary.json             # copy of results/summary.json, built by pages.yml
```

`results/` lives in the repo. ~5KB per file × 52 weeks = ~250KB/year. Negligible.

## Result file schema

Bump to v2 of the result file (the existing `atomic-results.json` is implicit v1):

```json
{
  "schema_version": 2,
  "run_id": "2026-W22-001",
  "generated_at": "2026-05-31T02:00:00Z",
  "iso_week": "2026-W22",
  "git_commit": "c76edb2",
  "platform": {
    "os": "Windows 11 Pro 22H2",
    "tinysocs_version": "0.9.0",
    "sysmon_version": "15.15",
    "opensearch_version": "3.3.2"
  },
  "summary": {
    "rules_in_pack": 39,
    "rules_with_atomic_test": 24,
    "atomic_tests_run": 19,
    "atomic_tests_detected": 15,
    "atomic_tests_skipped": 3,
    "atomic_tests_missed": 0,
    "atomic_tests_error": 1,
    "rule_pass_rate": 0.83,
    "technique_pass_rate": 0.79
  },
  "results": [
    {
      "technique_id": "T1110.001",
      "technique_name": "Brute Force - Password Guessing",
      "expected_rules": ["TS-001", "TS-002"],
      "detected_rules": ["TS-001"],
      "status": "DETECTED",
      "category": "PASS",
      "reason": "",
      "started_at": "2026-05-31T02:00:14Z",
      "duration_seconds": 47
    }
  ]
}
```

Schema changes from v1:

| Field | New | Why |
|---|---|---|
| `schema_version` | yes | trivial future-proofing |
| `run_id` / `iso_week` / `git_commit` | yes | every run is uniquely addressable; dashboard correlates against the commit that produced it |
| `platform.*` | yes | so the public claim is defensible ("on this OS, this version") |
| `summary.*` (expanded) | yes | rolls up what was previously implicit in `efficacy_pct` plus net-new metrics for honest coverage reporting |
| `category` (per-result) | yes | maps each detailed status to one of `PASS` / `SKIP_PLATFORM` / `SKIP_PREREQ` / `MISS` / `ERROR` for dashboard colouring |
| `started_at` / `duration_seconds` | yes | useful for harness debugging and visible run-time in the dashboard |

`status` retains the existing values (`DETECTED`, `SKIP`, `MISSED`, `ERROR`). `category` is a normalised colour bucket the dashboard renders against.

**Schema-invariance against v2 rules**: this file references rules by `id` only. v2 rule format does not change rule IDs (TS-001 stays TS-001). When v2 migration runs, no result-file changes are needed.

### Category mapping (status → dashboard colour)

| `status` | `category` | Dashboard colour | Meaning |
|---|---|---|---|
| `DETECTED` (any expected rule fired) | `PASS` | green | The pack caught what it should have |
| `SKIP` with `reason` matching `Requires Domain Controller`, `Requires TinySocs FIM module`, `Sysmon required` | `SKIP_PLATFORM` | amber-grey | Test cannot run on this venue; not a rule defect |
| `SKIP` with `reason` matching `Tamper Protection`, `requires admin` etc. | `SKIP_PREREQ` | amber-grey | Environmental constraint; expected behaviour |
| `MISSED` | `MISS` | red | Rule should have fired and didn't. This is the only alarming category. |
| `ERROR` | `ERROR` | grey | Harness issue (network, ART install, OpenSearch query). Investigate but not a rule failure. |

The dashboard explicitly distinguishes platform-skips from misses so we don't cry wolf. Today's snapshot has 3 SKIP and 0 MISS — the public dashboard must make that distinction obvious.

## Public dashboard

URL: `https://lukefitzg.github.io/tinysocs/validation/`

### Layout (in priority order — top of page first)

**Headline** — the number anyone screenshots:

```
TinySOCs detection validation · 2026-W22
39 rules in pack · 24 with Atomic Red Team coverage · 21 passing this week · 3 platform-skipped · 0 missed

Last run: Sunday 2026-05-31 02:00 UTC · commit c76edb2 · Windows 11 / TinySocs 0.9.0
[ See methodology ]    [ Download results JSON ]    [ View on GitHub ]
```

**Per-rule table** — sortable, the bulk of the page:

| Rule ID | Name | MITRE | Last 12 weeks | This week | Reason (if not pass) |
|---|---|---|---|---|---|
| TS-001 | brute_force_logon | T1110.001 | `🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢🟢` | PASS | — |
| TS-062 | ntds_dit_access | T1003.003 | `⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪⚪` | SKIP_PLATFORM | Requires Domain Controller |
| TS-130 | account_discovery | T1087.001 | `🟡🟡🔴⚪⚪⚪⚪⚪⚪⚪⚪⚪` | ERROR | ART fallback fails from UNC path |

**MITRE matrix** — heatmap by technique with coloured cells, links to the per-technique detail. Reuses the existing `mitre_coverage.py` data if useful.

**Coverage gap section** — honest:

> 15 of 39 rules do not yet have an Atomic Red Team test. We commit to adding one new test per week ([content cadence](../../docs/cadence.md)). Rules without a test are marked `untested` in the per-rule table.

This is the section that signals discipline. Hiding the gap is worse than naming it.

**Methodology page** (separate `/validation/methodology/`):

- What Atomic Red Team is, how the harness runs, what counts as a pass.
- Disclosure: "Skipped tests are skipped *because of the test environment* (e.g., requires Domain Controller). The rule itself is unchanged. A skipped test is not a failed rule."
- Link to the harness source on GitHub.
- Link to the raw JSON for any week.

## Dashboard implementation notes

- Vanilla HTML + a small JS file (no framework). Fetches `data/summary.json` on load. Total dashboard payload <50KB.
- Sparkline-style "last 12 weeks" rendered as a sequence of coloured Unicode dots in the table (no chart library needed). If we want a proper heatmap later, swap in observable-plot or similar.
- All static — no backend, no API calls at view time.
- The `summary.json` is generated by a small Python script in CI (`scripts/build_validation_summary.py`) that reads `results/*.json`, computes per-rule history, writes the consolidated summary.

## CI changes

### Extend `pages.yml`

```yaml
on:
  push:
    branches: [main]
    paths:
      - 'site/**'
      - 'results/**'           # NEW: rebuild when validation results land

jobs:
  deploy:
    steps:
      - uses: actions/checkout@v4
      - name: Build validation summary
        run: |
          python3 scripts/build_validation_summary.py \
            --results-dir results \
            --output site/validation/data/summary.json
      - name: Setup Pages
        uses: actions/configure-pages@v5
      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: site
      - name: Deploy to GitHub Pages
        uses: actions/deploy-pages@v4
```

Two changes: trigger on `results/**` and one extra step that builds the summary JSON before deploying.

### New: `scripts/build_validation_summary.py`

Reads all `results/*.json` files, produces `site/validation/data/summary.json` containing:

- Latest-run summary block (the headline numbers).
- Per-rule history: `{ "TS-001": [{"iso_week": "2026-W21", "category": "PASS"}, ...] }` — only the last 12 weeks.
- Per-technique history (same shape, keyed by technique_id).
- Coverage stats: which rule IDs have/don't have an Atomic test.

This is the only new code that consumes the rule pack format. It reads rule IDs from `packaging/detection/rules.yml` (v1 today). When v2 lands, this is the one file we update — that's the schema-invariance budget paid in full.

### On-VM cron-equivalent

Windows Task Scheduler entry, configured manually once:

- Trigger: weekly, Sunday 02:00 local.
- Action: PowerShell script that does:
  1. `cd C:\path\to\tinysocs-repo`
  2. `git pull --ff-only origin main`
  3. `pwsh tests/Test-AtomicDetection.ps1 -OutputJson "results/$(Get-Date -UFormat '%Y-W%V').json"`
  4. `git add results/*.json`
  5. `git commit -m "validation: $(Get-Date -UFormat '%Y-W%V') run"`
  6. `git push origin main`

Authentication: a deploy key with write access scoped to the repo, stored in the VM's user keychain. Not a PAT — keys are easier to rotate and don't carry account-level access.

A wrapper script (`scripts/run_weekly_validation.ps1`) wraps all six steps with logging and error handling so the Task Scheduler entry is one-liner clean.

## Honest framing — the parts that could embarrass us

Three places where the dashboard could undermine credibility if we're not careful:

1. **A run fails entirely (the VM was down, git push failed, OpenSearch crashed).** The dashboard should show "last successful run: 2026-W21" with a clear "current run incomplete" banner — not show stale data as if fresh. The headline timestamp must be the date of the *committed* run, not "today."
2. **A MISS appears for the first time.** This is the failure mode that matters. Process: same-day investigation, written postmortem committed to `results/postmortems/{run_id}-{rule_id}.md`, dashboard links to it inline. "Yes we missed; here's why; here's what we did." That posture beats hiding it by orders of magnitude.
3. **Coverage stays bad.** If 15/39 rules have no Atomic test in week 0 and 14/39 in week 4, the dashboard makes that visible. Discipline of "one new test per week" lives in the content-cadence doc (gap #4); the dashboard is the receipt.

## What v1 of this pipeline ships

**Must build:**
1. Schema-v2 update to result JSON (script: `scripts/migrate_atomic_results_to_v2.py` — one-shot, reads the existing `atomic-results.json` and writes `results/2026-W09.json` so the historical snapshot is preserved).
2. `Test-AtomicDetection.ps1` produces the new schema (add `run_id`, `iso_week`, `git_commit`, `platform.*`, `summary.*`, per-result `category`, timestamps).
3. `scripts/build_validation_summary.py` — reads `results/*.json`, writes `summary.json` for the dashboard.
4. `scripts/run_weekly_validation.ps1` — VM-side wrapper that pulls, runs, commits, pushes.
5. `site/validation/index.html` + `styles.css` + `validation.js` — the static dashboard.
6. `site/validation/methodology/index.html` — the disclosure page.
7. `.github/workflows/pages.yml` extension to build summary on push to `results/**`.
8. Task Scheduler entry on the VM (operator step, documented in `docs/operator/weekly-validation-setup.md`).
9. Deploy key setup on VM (operator step, documented in the same doc).

**Not v1:**
- New Atomic tests for uncovered rules. Lives in content cadence.
- Coverage migrations for v2 rule pack format. Updates `build_validation_summary.py` to read the v2 schema when v2 lands.
- Pretty charts beyond the dot grid. Iterate after first paying customer if there's a reason.
- Multi-platform validation (Windows Server, different OS versions). Single-VM Windows 11 is fine for v1.
- Premium-pack-specific validation runs. Once premium packs exist, the harness runs the same way; the dashboard splits the per-pack view.

## Order of operations (suggested build sequence)

1. **Schema migration** — bump result JSON to v2, write the migration script, port the existing `atomic-results.json` to `results/2026-W09.json` so the dashboard has historical data on day 1.
2. **Harness update** — modify `Test-AtomicDetection.ps1` to emit the v2 schema (add the new fields). Confirm against a manual run on the VM.
3. **Summary builder** — `build_validation_summary.py`. Test against the migrated historical results.
4. **Dashboard** — static HTML/JS. Iterate against the summary JSON until it looks shippable.
5. **CI extension** — update `pages.yml`, push to main, verify the dashboard deploys.
6. **VM automation** — wrapper script + Task Scheduler entry + deploy key. First real weekly run after this.
7. **Methodology page + outreach update** — write the disclosure page, add the URL to outreach templates in `docs/outreach-templates.md`.

Each step is a single commit / single afternoon. Steps 1–5 don't require touching the VM at all — pure local + CI work, fully testable.

## Open questions

1. **VM uptime SLA.** The Task Scheduler approach assumes the VM stays up. If you reboot the VM mid-week for unrelated reasons (e.g., dev work), does the Sunday cron fire after the VM comes back, or does the week silently skip? The wrapper script should detect "no run committed in 8+ days" and self-recover. Worth a `scripts/check_validation_freshness.py` that runs in CI and opens an issue if the latest result is more than 8 days old.
2. **Public-page hosting domain.** The implied URL is `lukefitzg.github.io/tinysocs/validation/`. If TinySOCs gets its own domain (e.g., `tinysocs.io`) the GitHub Pages CNAME is a one-line change. Worth registering the domain now so the URL we put in outreach materials doesn't have to change.
3. **Run-on-rule-change.** Today the harness only fires weekly. When v2 lands and we start shipping rules every week (content cadence), we might want a "validate on every rule push" trigger too. Out of scope for v1, but worth wiring in via a `workflow_dispatch` trigger so it's available for manual ad-hoc validation runs.
4. **Coverage of backend rules.** Once the Python KQL engine activates (v2.1), the harness needs to validate backend rules too. The current harness only checks `tinysocs-alerts-*` for `rule_id` — that index is engine-agnostic, so backend rules will write into it the same way. Probably zero changes needed when v2.1 ships, but worth confirming.
5. **What if Atomic Red Team itself breaks or changes a test?** The harness pins to `master` of the ART repo today. Probably fine for v1; v1.x should pin to a tag and update deliberately.
