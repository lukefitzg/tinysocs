---
name: tinysocs-change-control
description: The gate every other TinySocs skill routes through before a change lands. Load this whenever you're about to add, enable, disable, or tune a detection rule; touch schema, licensing, tier, pricing, or the signed-pack trust path; edit installer/config defaults; publish a rule count, efficacy percentage, or any other public-facing claim (GTM docs, README, dashboard copy); write PowerShell that ships to Windows; commit a planning/phase-summary document; or when you're unsure whether a task is "in scope" for the detection-content-as-a-service pivot at all. Contains: the pivot-alignment decision procedure, a change-class-to-gate table, the non-negotiables with their incident histories (BSL/MIT relicensing scare, dual-engine honesty, CI-green rule, ASCII-only PowerShell, plan-docs-not-committed, CLAUDE.md hard rules), the CLAUDE.md stale-facts protocol with the current list of known-stale lines, and a pre-merge checklist. Does not itself contain rule-writing mechanics, validation harness details, or positioning copy — it tells you which sibling skill owns those and when you're required to go there first.
---

# TinySocs change control

This is the front door. Every other skill in this library assumes you passed through here first for anything that changes detection behavior, public claims, schema/licensing/tiers, or the installer/trust path. If you arrived at another skill directly, and the task fits one of the change classes below, come back here before you act.

## 1. The pivot-alignment filter

TinySocs (as of 2026-07-11) is a solo, part-time founder project with **zero paying customers** and a **hard deadline: first paying customer by mid-Aug 2026**. CLAUDE.md's rule is explicit: *"Don't add features to the platform that don't move the content-as-a-service pivot forward."*

Before starting any non-trivial task, answer this in order:

1. **Does it serve one of the 7 roadmap gaps?** (v2 rule schema, continuous validation pipeline, signed feed, Stripe + licence gate, TinyDocs, content cadence, AI-assisted triage — per `docs/roadmap.md`, which is the current canonical gap list; see §4 for why this supersedes CLAUDE.md's "8 strategic gaps" language).
2. **Does it fix something actively blocking one of those gaps** (a CI break, a dead rule, a broken installer script, a stale doc that would mislead a customer or contributor)?
3. **Is it a hard rule / non-negotiable violation** (BSL relicensing risk, a secret about to be committed, CI red)? Fix on sight regardless of (1).

If the answer to all three is no — it's a distraction. Decline, or park it explicitly ("noted, out of scope for the pivot, revisit post-first-customer") rather than silently doing it. Concrete out-of-scope examples from the roadmap's own "explicitly off the roadmap" list: real-time FIM beyond the canary use case, response automation, macOS/Linux collectors, cloud relay, multi-tenant dashboard, ML correlation — these were deliberately cut from a pre-pivot "Phases 23-27" backlog and are not to creep back in.

Deferred-but-legitimate work (don't build now, but don't call it a distraction either — see tinysocs-research-frontier for the full list): FP telemetry channel, backend Python KQL engine activation (v2.1), premium-pack tiering enforcement beyond the entitlement gate, allowlist runtime, baseline runtime beyond FIM.

## 2. Change classes and their gates

| Change class | Examples | Gate | Owning skill |
|---|---|---|---|
| **Detection-behavior change** | Add/enable/disable a rule, change a `threshold`/`window_minutes`/`cooldown_minutes`, add/edit a `field_match` clause, touch `DetectionEngine.cs` or `RuleLoader.cs`/`PackLoader.cs` matching logic | Requires an Atomic Red Team test case (`tests/atomic-tests.yaml`) + an xUnit firing/silent pair in `tests/TinySocs.Agent.Tests/` + a harness run plan. No rule ships enabled without this. | tinysocs-validation-and-qa (what counts as evidence), tinysocs-detection-validation-toolkit (how to author the test pair) |
| **Public-claim change** | Rule counts ("N rules"), efficacy percentages, any number in `docs/one-pager.md`, `docs/faq.md`, `docs/competitive-positioning.md`, README, or dashboard/marketing copy | Requires the banned-numbers check — some historical figures (e.g. the March "100%" efficacy number, the stale W23 53.85%/61.5% dashboard figures) are permanently banned from quoting. State the honest rule triad (19 enabled / 39 defined / 89 total, as of 2026-07-11) rather than a single "N rules" figure. | tinysocs-external-positioning |
| **Schema / licensing / tier change** | Anything touching `docs/design/rule-format-v2.md`'s locked schema, `scripts/licence.py` entitlement logic, tier names or contents | Tier architecture is **locked**: `free` / `pro` / `msp`, names and pack-list contents fixed. **No prices** anywhere — not in schema, not in docs, not in code — until the first cohort of customer conversations happens. `scripts/licence.py` has zero price/currency literals as of 2026-07-11 (verified) — keep it that way. | tinysocs-architecture-contract (design), tinysocs-change-control (this file, for the lock itself) |
| **Installer / trust-path change** | `packaging/iss/Quickstart.iss`, `ContentPackConfig.Enabled` default, anything that would flip signed-pack verification on for new installs | The signed-pack trust path (`PackLoader`/`Ed25519Verifier`/`LicenceReader`) is **implemented but dormant**: `ContentPackConfig.Enabled` defaults to `false` (`src/TinySocs.Agent/Configuration/AgentConfig.cs:146`), and the installer ships only the legacy unsigned `rules.yml` with no public key baked in. Flipping this on for real installs is a founder-level decision (it changes what a customer's agent trusts) — flag it, don't just do it. | tinysocs-architecture-contract |
| **Rule-content migration** | Moving a rule from the 39-rule C# set or 50-rule Python catalogue into a v2 pack | Migration is **mechanical, not interpretive** — CLAUDE.md: "Treat the existing 39 rules + 50-rule catalogue as assets, not legacy... Don't rewrite detections during migration." Use `scripts/migrate_rules_to_v2.py`, don't hand-author. | tinysocs-architecture-contract, detection-engineering-reference |

If a task spans two rows (e.g. "enable TS-135 and update the one-pager to say 20 rules"), gate on **every** row it touches — don't let the easier gate excuse the harder one.

## 3. Non-negotiables, with their incident history

Each of these earned its rule the hard way. Know the incident, not just the rule — it's what tells you the rule isn't optional.

### BSL-1.1 licensing discipline
- **Rule**: Never relicense third-party MIT/Apache-sourced code as BSL. Fix a stale "MIT" claim about *this* repo's license on sight, wherever it surfaces.
- **Incident**: the README footer claimed "MIT" for ~11 weeks after the LICENSE file actually switched to BSL-1.1 in March 2026, and a further stale claim was found in `docs/competitive-positioning.md` a full 3 months after the LICENSE change — with some of those claims not just mislabeled but **factually inverted** ("no commercial restrictions" under a license that has commercial restrictions). Three separate fix passes, three months apart:
  - LICENSE → BSL-1.1: commit `7860f41`, 2026-03-07
  - README fixed: commit `9bea321`, 2026-05-26 (+11 weeks)
  - `docs/competitive-positioning.md` fixed: commit `e820e7a`, 2026-06-10 (+3 months from LICENSE)
- **Current state (verified 2026-07-11)**: `grep -rn '\bMIT\b' --include='*.md' .` finds no live stray license-claim hits — every remaining "MIT" mention is either CLAUDE.md's own instruction, the v2 design doc's historical note, or a legitimate third-party attribution (BouncyCastle.Cryptography, MIT-licensed, used for Ed25519 in the C# agent — `docs/design/signed-feed.md:50`). Keep it that way: re-run the grep before any doc-heavy PR.
- Third-party code (BouncyCastle, etc.) gets vendored/attributed, never silently re-licensed under BSL.

### Dual-engine honesty
- **Rule**: Never present a Python KQL rule (from `src/tinysocs/agent/detections/rules.yaml`, the 50-rule catalogue) as something that actually fires alerts in a **default single-node install**. `packaging/iss/Quickstart.iss` never references `Install-OperatorTasks.ps1`, `MasterHeartbeat`, or the orchestrator — a customer who just runs the installer gets no scheduled Python execution, and `DetectionEngine.cs` (C# engine) implements only `threshold_by_key`.
- **But this is narrower than CLAUDE.md's "no scheduled runner consumes that file" claim, and that claim is stale** (verified 2026-07-11, corrects the previous version of this skill, which repeated it uncritically). The opt-in federation/MSP path *does* wire up a scheduled runner: `scripts/Install-OperatorTasks.ps1:90-108` registers a Windows Scheduled Task `TinySocs-MasterHeartbeat` (every `$MasterEveryMinutes`, default 15 min) that runs `scripts/Run-Master.ps1`, which invokes `python -m tinysocs.orchestrator.master --rules ps_script_block,auth_failed_burst --window 15m` (rule IDs default via `TINYSOCS_CRON_RULES`). `master.py` fans out to each node's `/agg` endpoint; `src/tinysocs/api/node.py:473` (`_run_rule`) looks the rule up via `RULES.get(rule_id)`, where `RULES` (`src/tinysocs/agent/detections/registry.py:141`) is loaded straight from `rules.yaml` — the same 50-rule catalogue — and executes it against live OpenSearch, threshold-gated, before anchoring evidence. So: for any node where an operator has run `Install-OperatorTasks.ps1` (this is the MSP/federation path, not the Quickstart default), a real subset of the Python catalogue does fire on a schedule. Check whether that script has been run before asserting the catalogue is inert for a given deployment.
- Every v2 pack rule carries a `runs_on` field (`agent` | `backend`) precisely so nobody can quietly ship a backend-only rule as if it were live. If you're writing or reviewing a v2 rule, check `runs_on` before describing it as running.

### CI must be green before you trust any merge
- **Rule**: don't treat a merged PR's code as validated if CI wasn't actually passing when it landed. Check `.github/workflows/ci.yml` ran clean, not just that the PR merged.
- **Incident**: CI was silently red for **about a month** (2026-06-10 to 2026-07-11, per commit `37005ad`'s own message: "CI has been red since at least June 10 across every run on main and this branch"). Three independent breaks stacked, each masking the next: 868 pre-existing Ruff violations, a mypy invocation that "had never once worked" (`mypy tinysocs` treated as a file path — no `tinysocs` dir exists at repo root, package is under `src/tinysocs`), and a missing `cryptography` dependency in `pyproject.toml` (present only in `requirements.txt`, so `pip install -e ".[dev]"` — what CI actually runs — never installed it, failing Windows test collection before a single test ran). Fixed in `37005ad` (2026-07-11).
- **Concrete consequence**: every commit from `f7402bf` (2026-06-06, v2 pack signing) through `279e4d6` (2026-07-11, FIM fix) — i.e. the entire signed-feed/licence-gate/pilot-pack build-out — landed under **broken CI with no real signal**. Don't assume "it was in a merged commit" means "CI actually checked it" for anything in that window; re-verify by hand if it matters.
- **Current CI ground truth (verified 2026-07-11, `.github/workflows/ci.yml`)**: `ci.yml` runs `ruff check .`, `mypy -p tinysocs`, `pytest --cov=tinysocs` on Linux (Python 3.10/3.11 matrix), plus a `windows-test` job that runs `pytest` on Windows, `dotnet publish` (build only), and Pester (`tests/Test-InstallerModule.ps1`). **`dotnet test` does not appear anywhere in any workflow** — the C# xUnit suite (`tests/TinySocs.Agent.Tests/`, 52 test methods / 70 cases as of `37005ad` — per that commit's own message, "dotnet build + test (70/70 C# tests green)"; `DetectionEngineTests.cs` alone asserts the exact 19-rule enabled set) is **not run in CI**. If you're relying on "CI is green" as proof the detection engine works, it isn't proof of that specific thing — run `dotnet test` by hand (see tinysocs-build-and-env).

### ASCII-only in PowerShell shipped to Windows
- **Rule**: no em-dashes, curly quotes, or other non-ASCII characters in any `.ps1` file. Windows PowerShell 5.1 (not PS 7+) mangles them under the console's ANSI codepage, corrupting string terminators and silently swallowing the next statement.
- **Incident history — this has recurred at least five times**, most recently two days before this skill was authored:
  - `d4d0b84` "Fix PS 5.1 parse error: replace non-ASCII chars with ASCII"
  - `62b61b7` "Fix PS here-string parse error in YAML fallback"
  - `5746899` "Replace em-dash characters in Full-Rebuild.ps1 with ASCII dashes"
  - `d777cb9` "Fix Full-Rebuild.ps1: replace em dashes with ASCII hyphens to avoid PS encoding errors"
  - `e8a7e3c` "Fix em dash in watermark YAML comment causing OpenSearch keystore failure"
  - `94dae2b` (2026-07-10, most recent) "Demo-Ransomware.ps1: ASCII-only output (em-dashes broke Windows PowerShell 5.1)"
- **Action**: before committing any `.ps1` change, grep it for non-ASCII, **excluding the CR byte** (the repo's `.ps1` files are legitimately CRLF-terminated, and `\r` (0x0D) falls outside `[ -~]`, so a naive grep flags every line of every CRLF file — verified 2026-07-11: the plain `[^ -~]` pattern hits 99/99 lines of `scripts/Demo-Ransomware.ps1`, 200 lines of `modules/TinySocs.Uninstall.ps1`, 972 of `installer/Run-OpenSearch.ps1`, none of which have an actual non-ASCII problem): `LC_ALL=C tr -d '\r' < path/to/script.ps1 | grep -n '[^ -~]'`. Treat any real hit as a bug, not a style nit.

### Plan documents are working files, not commits
- **Rule**: phase-plan/summary-style documents belong in the founder's local planning archive, not in git.
- **Incident**: `docs/phase-21-plan.md` (511 lines) was added and removed **the same day** — `9ed2234` "Add Phase 21 plan and summary documents" then `93a31a8` "Remove phase-21-plan.md from repo (plan is working document, not committed)", both 2026-03-24. Reinforced again 2026-06-05 when `docs/phase-15-plan.md` (794 lines) and `docs/phase-18-plan.md` (602 lines) — the last two pre-pivot planning docs — were pruned (`a26939c`) in favor of `docs/roadmap.md`.
- **Action**: if you're asked to "write up a plan" for a task, write it as a scratch file or conversation output, not a repo commit. `docs/roadmap.md` and `docs/design/*.md` (status-headered, cross-referenced) are the only durable planning artifacts that belong in the repo. See also CLAUDE.md's rule: don't recreate `docs/phase-N-summary.md` style retrospectives unless asked.

### Hard rules from CLAUDE.md (restated verbatim — binding regardless of staleness elsewhere in that file)
- **Work network stays out.** Don't suggest leveraging the founder's day-job colleagues or management for TinySocs outreach. Hard rule, not a preference.
- **Validatr stays hermetically separate.** Don't read or reason about `~/life-os/work/validatr/` in a TinySocs session. The IP question between the two is unresolved; don't let context bleed either direction.
- **No prices anywhere yet.** Don't push prices into the schema, code, or any marketing doc. Tier architecture (`free`/`pro`/`msp`) is locked; prices land only after the first customer conversations.
- **Don't recreate phase-N-summary.md retrospectives** unless explicitly asked. The next weeks are about shipping the pivot, not documenting phases (see the plan-docs incident above for why this became a rule).
- **No credentials in this repo, ever.** `.env.example` is a template; real `.env` is gitignored. Signing keys (`keys/tinysocs-2026.{key,pub}`, `keys/licensing-2026.{key,pub}`) live on disk gitignored, never committed — private keys must never be committed under any circumstance.

## 4. The CLAUDE.md stale-facts protocol

**User decision, binding on every session**: CLAUDE.md's **rules** are binding even where its **facts** are stale. Don't silently contradict CLAUDE.md — state the code-verified reality and cite file:line, explicitly flagging the gap. Don't "helpfully" rewrite CLAUDE.md yourself as a side effect of an unrelated task; that's a founder-level edit (CLAUDE.md is explicit that it gets updated at specific trigger points — see its own "Update this file when" section).

**Known-stale CLAUDE.md lines as of 2026-07-11** (re-verify before citing further out):

| CLAUDE.md claim | Line | Reality | Truth lives at |
|---|---|---|---|
| "No rule signing, no rule feed, no licence checking, no Stripe integration. All greenfield." | CLAUDE.md:36 | **False since 2026-06-06.** All four exist and are wired: `src/TinySocs.Agent/Detection/{PackLoader,Ed25519Verifier,LicenceReader}.cs`, constructed in `OpenSearchBulkShipper.cs:57,128-129`; feed server `src/tinysocs/api/feed.py` (port 8095) with an SDK-free Stripe webhook; `scripts/{pack_sign.py,licence.py,stripe_pricing.py}`. But the trust path is **dormant** in production installs — see §2's installer/trust-path row. | `docs/design/rule-format-v2.md` (status: "implemented"), `docs/design/signed-feed.md` (status: "implemented... remaining work is operational, not protocol"), `docs/roadmap.md` gaps #3/#4 |
| "Rule format v2 (in progress — see `docs/design/rule-format-v2.md`)" | CLAUDE.md §"8 strategic gaps" item 1 | Schema is locked and **implemented**, not in-progress. Migration script (`scripts/migrate_rules_to_v2.py`) and C# loader (`PackLoader.cs`) both exist and are exercised by real packs (`packs/base/2026.27/`). | `docs/design/rule-format-v2.md` status header |
| "the 8 strategic gaps" | CLAUDE.md | The referenced "strategic brief" enumerating 8 is not checked into the repo. `docs/roadmap.md` (dated 2026-06-05, more current) tracks **7** gaps: v2 schema, validation pipeline, signed feed, Stripe/licence, TinyDocs, content cadence, plus a newer #7 (AI-assisted triage, added 2026-06-15, no design doc yet). `docs/roadmap.md:41` itself flags this count mismatch and says it can't be reconciled without the missing brief. | `docs/roadmap.md` |
| "A 2026-07-08 validation pass then found two more dead rules: TS-113... TS-120..." | CLAUDE.md | The TS-113 fix and TS-120 deferral are real and both present in code (`FileIntegrityInput.cs:575-582`, `docs/pilot-ruleset.md:21-22`) but they landed in commit `347c98e`/`ac9ef81` (authored 2026-07-04, merged 2026-07-10), not a separate 2026-07-08 commit — no commit dated 2026-07-08 exists in `git log`. Read "2026-07-08" as "when the validation analysis happened" (a VM run), not a commit date, if you need to cite it. | `git log -S'TS-113'`, `docs/pilot-ruleset.md:21-22` |
| "19 rules enabled... rest disabled for per-environment tuning" | CLAUDE.md | **Accurate and verified** (2026-07-11: `grep -c "enabled: true" packaging/detection/rules.yml` → 19; `grep -c "^  - id:" packaging/detection/rules.yml` → 39). Don't second-guess this one — it checks out. | `packaging/detection/rules.yml` |
| "No allowlist primitives in either engine today. Not even a `not_if` clause." | CLAUDE.md | **Accurate and verified** (2026-07-11: `grep -ri allowlist src/` → zero hits in the C# agent tree). Schema fields for `allowlist_scopes` exist in the v2 pack schema design, but the engine never reads them. | `docs/design/rule-format-v2.md` "Must build" list (still unbuilt), tinysocs-research-frontier |
| "no scheduled runner consumes [rules.yaml] — it's read only by `reporting/mitre_coverage.py` and the AI assistant's `search_kql` corpus" | CLAUDE.md §"The Python rule catalogue" | **False for the opt-in federation/MSP path** (found 2026-07-11, this skill's own §3 previously repeated it uncritically). `scripts/Install-OperatorTasks.ps1` → `TinySocs-MasterHeartbeat` scheduled task (every 15 min default) → `Run-Master.ps1` → `tinysocs.orchestrator.master` → node `/agg` → `registry.py`'s `RULES` (loaded from `rules.yaml`) does execute a rule subset (`ps_script_block`, `auth_failed_burst` by default) against live OpenSearch on a schedule. True for the Quickstart-only default install (`Quickstart.iss` never wires this up) — false once an operator runs `Install-OperatorTasks.ps1`. | §3 "Dual-engine honesty" above, `scripts/Install-OperatorTasks.ps1`, `src/tinysocs/orchestrator/master.py`, `src/tinysocs/api/node.py:473` |

**Protocol when you find a new stale CLAUDE.md fact mid-task**: state it in your output with the file:line of both the stale claim and the code-verified truth; don't silently work around it; don't edit CLAUDE.md yourself unless the user's task is specifically "update CLAUDE.md." If the staleness is dangerous (e.g. it would cause someone to "greenfield" something that already exists), say so explicitly, the way this file does.

## 5. Pre-merge checklist

Run through this before calling any change "done," in addition to whatever the specific change-class gate in §2 required:

1. **Pivot-alignment**: can you name which of the 7 roadmap gaps (or which non-negotiable) this change serves? If not, stop and ask.
2. **CI actually green**: `ruff check .`, `mypy -p tinysocs`, `pytest` all pass locally — don't assume a prior green CI run means the current diff is clean, and remember `dotnet test` isn't in CI at all, so run it by hand for any C# change (see tinysocs-build-and-env).
3. **ASCII check on any `.ps1` touched**: `LC_ALL=C tr -d '\r' < <file>.ps1 | grep -n '[^ -~]'` returns nothing. (Don't drop the `tr -d '\r'` — the repo's `.ps1` files are CRLF-terminated, and grepping `[^ -~]` directly flags every line as a false positive.)
4. **No secrets**: `git diff --cached` contains no `keys/*.key`, no real `.env` values, no OpenSearch/HMAC credentials.
5. **No prices, no work-network mentions, no Validatr references** slipped into docs or commit messages.
6. **Rule-count / efficacy claims** (if touched) pass the banned-numbers check — see tinysocs-external-positioning.
7. **Detection-behavior changes** have an Atomic test + xUnit pair — see tinysocs-validation-and-qa.
8. **No plan/phase-summary doc** is being committed unless explicitly asked for.
9. **CLAUDE.md staleness**: if your change touches an area CLAUDE.md describes, check it against §4's table (and re-verify — that table is a snapshot, not a subscription) before trusting CLAUDE.md's prose at face value.
10. **Commit message**: imperative present tense, references rule IDs (`TS-NNN`) and pack IDs (`base`, `demo`, etc.) where relevant, per CLAUDE.md's commit conventions.

## When NOT to use this skill

- You already know the change class and just need the mechanics — go straight to the owning skill from §2's table (tinysocs-validation-and-qa, tinysocs-external-positioning, tinysocs-architecture-contract, tinysocs-detection-validation-toolkit).
- You need the domain theory behind a detection rule (event IDs, MITRE mapping, threshold semantics) — detection-engineering-reference.
- You need to debug a live symptom (silent engine, shipper failure, HMAC mismatch) — tinysocs-debugging-playbook.
- You need historical context on *why* something is the way it is beyond the incidents cited here — tinysocs-failure-archaeology has the full chronicle.
- You need the exact config knobs/flags/ports for a change — tinysocs-config-and-flags.
- You're deciding whether a candidate rule has enough evidence to graduate from idea to shipped — tinysocs-research-methodology.
- You're evaluating a genuinely unbuilt/deferred subsystem (allowlists, FP telemetry, KQL runner, live Stripe) — tinysocs-research-frontier.

## Provenance and maintenance

Authored: 2026-07-11, against branch `fix/ci-green`, HEAD `37005ad` (one dirty file: `tests/test_feed_server.py`). Fixer pass: 2026-07-11 (corrected the dual-engine, ASCII-check, and C# test-count claims below after re-verification against the repo).

Primary sources:
- `/Users/lukefitzgerald/tinysocs/CLAUDE.md` (the file this skill gates deviations from)
- `docs/roadmap.md` (canonical current gap list, supersedes CLAUDE.md's "8 gaps" framing)
- `docs/design/rule-format-v2.md`, `docs/design/signed-feed.md` (status headers, "Must build" lists)
- `git log --oneline --all` and targeted `git log -S`/`--grep` searches (incident dating)
- `.github/workflows/ci.yml` (direct read, 2026-07-11)
- `packaging/detection/rules.yml`, `src/TinySocs.Agent/Configuration/AgentConfig.cs:146`, `scripts/licence.py` (direct grep, 2026-07-11)
- `scripts/Install-OperatorTasks.ps1`, `scripts/Run-Master.ps1`, `src/tinysocs/orchestrator/master.py`, `src/tinysocs/api/node.py`, `src/tinysocs/agent/detections/registry.py`, `packaging/iss/Quickstart.iss` (direct read, 2026-07-11 — the opt-in scheduled-runner path in §3 "Dual-engine honesty")
- `tests/TinySocs.Agent.Tests/*.cs` at HEAD `37005ad` and at `347c98e` via `git show` (direct count, 2026-07-11 — the C# test-suite figures in §3 "CI must be green")
- Prior discovery-pass digests (session-local scratch files — not re-derivable, ignore if absent; captured 2026-07-11, same-day as this authoring — no staleness gap)

Re-verification commands (run before trusting any volatile fact in this file):

```bash
# Enabled / total rule counts (§4 table, last row)
grep -c "enabled: true" packaging/detection/rules.yml
grep -c "^  - id:" packaging/detection/rules.yml

# Allowlist absence (§4 table, last row)
grep -ri allowlist src/TinySocs.Agent/ | wc -l   # expect 0

# Trust-path dormancy (§2 installer row)
grep -n "Enabled" src/TinySocs.Agent/Configuration/AgentConfig.cs | grep -i pack
grep -n "pack" packaging/iss/Quickstart.iss       # expect no hits enabling it

# CI actually runs (§3 CI-green section)
grep -n "dotnet test\|ruff check\|mypy -p tinysocs\|pytest" .github/workflows/ci.yml

# C# xUnit suite size at HEAD (§3 CI-green section) -- expect 52 methods / 70 cases
grep -c '\[Fact\]\|\[Theory\]' tests/TinySocs.Agent.Tests/*.cs
grep -c '\[InlineData' tests/TinySocs.Agent.Tests/*.cs

# ASCII check false-positive guard (§3 ASCII section) -- must exclude CR, repo .ps1 files are CRLF
LC_ALL=C tr -d '\r' < scripts/Demo-Ransomware.ps1 | grep -n '[^ -~]'   # expect nothing

# Scheduled Python-catalogue runner, opt-in path only (§3 Dual-engine honesty)
grep -n "MasterHeartbeat" scripts/Install-OperatorTasks.ps1
grep -n "operatortasks\|masterheartbeat\|orchestrator" packaging/iss/Quickstart.iss   # expect no hits (Quickstart doesn't wire it up)

# No live stray MIT license claims (§3 BSL section)
grep -rln '\bMIT\b' --include='*.md' . | grep -v '.git/'

# No prices in licensing code (§2 schema/licensing row)
grep -riE '\$[0-9]|price|usd' scripts/licence.py

# CLAUDE.md's greenfield claim vs reality (§4 table, row 1)
grep -n "greenfield\|No rule signing" CLAUDE.md
ls src/TinySocs.Agent/Detection/{PackLoader,Ed25519Verifier,LicenceReader}.cs

# Working-tree cleanliness / branch position
git status --porcelain
git log --oneline main..HEAD
```
