---
name: tinysocs-docs-and-writing
description: Documentation discipline for TinySocs — how docs/design/ status headers work, which doc to trust FIRST when design-doc headers and CLAUDE.md disagree (docs/roadmap.md), the full doc-drift ledger (stale rule counts, stale versions, two-different TinyDocs artifacts out of sync with each other), and the writing rules (date-stamp volatile numbers, no prices, plan docs stay uncommitted, ASCII-only near PowerShell). Load this when asked to write or update any doc under docs/ or docs/design/, when reconciling a status-header contradiction, when a rule-count or version number needs correcting across docs, when authoring or syncing tinydocs/*.md or packaging/detection/rule_docs.yml, or when told "CLAUDE.md says X but is that still true." Not for external-facing claims content (ICP, competitive positioning, banned efficacy figures) — see tinysocs-external-positioning.
---

# TinySocs docs and writing discipline

Scope: how documentation is structured, which source wins when docs disagree, and the concrete list of drift currently in the tree (as of 2026-07-11, branch `fix/ci-green`, HEAD `37005ad`). This skill is about **doc hygiene and routing**, not about what to say to a buyer (that's `tinysocs-external-positioning`) and not about which facts are true in the engine (that's `tinysocs-architecture-contract` / the CLAUDE.md ground truth).

## 1. The routing rule — check this FIRST, before CLAUDE.md or any design-doc header

When you need "what's the current status of gap N / feature X," the priority order is:

1. **`docs/roadmap.md`** — read this first. It is a single-canvas status tracker (124 lines, status `draft`, authored 2026-06-05, actively appended since) that cross-references CLAUDE.md and every `docs/design/*.md` file **without restating them**, and it is demonstrably fresher than both. It self-flags the exact place it disagrees with CLAUDE.md: `docs/roadmap.md:41` — *"`CLAUDE.md` calls these 'the 8 strategic gaps' but enumerates 6 active + 3 deferred. The referenced 'strategic brief' is not checked into the repo, so the canonical list of 8 can't be reconciled here. Treat this table as authoritative until the brief surfaces."*
2. **`docs/design/<topic>.md`** status header — second-most current, but can lag `roadmap.md` by weeks. Example: `continuous-validation.md`'s header says "Approved design, not yet implemented," but `docs/roadmap.md:32,80-90` gives the sharper truth — the pipeline is largely built (harness, dashboard HTML/CSS/JS, result-file schema all exist on disk) and is blocked on a measurement bug and three noisy rules, not on missing code. Reading the header alone would make you say "doesn't exist" when the honest answer is "built, not yet trustworthy."
3. **`CLAUDE.md`** gap list — treat as the most likely to be stale of the three. It is hand-maintained prose and drifts. See §4 for the specific stale lines as of this date.

`docs/roadmap.md` lives outside `docs/design/` (it is *not* a design doc — it's the connective tissue across all of them) but is the closest thing this repo has to ground truth for "where are we." Don't skip it because it isn't in the `docs/design/` folder.

## 2. `docs/design/` conventions

Every file in `docs/design/` opens with:

```
# <Title> — Design

**Status**: <value>
**Author**: <name(s)>, <date>
**Depends on** / **Related** / **Covers strategic gap(s)**: <cross-refs>
```

CLAUDE.md's stated status vocabulary is `draft`, `approved`, `implemented`, `superseded` — in practice authors append qualifying clauses rather than using a bare enum. Current inventory (verified against file headers, 2026-07-11):

| File | Status (verbatim) | Covers gap # |
|---|---|---|
| `docs/design/rule-format-v2.md` | *"Approved, schema locked, **implemented**. Migration script and C# engine changes both done — `PackLoader`/`Ed25519Verifier`/`LicenceReader` are wired through `OpenSearchBulkShipper` and enforce signed-pack loading (2026-06-06; see `signed-feed.md`)."* | #1 |
| `docs/design/signed-feed.md` | *"implemented (protocol + trust core + agent enforcement + feed server + Stripe webhook). Remaining work is operational, not protocol — see 'Build sequencing'."* | #3, #4 |
| `docs/design/continuous-validation.md` | *"Approved design, not yet implemented."* — **stale header, see below** | #2 |
| `docs/design/content-cadence.md` | *"draft"* | #6 |

No `superseded` doc exists yet. `rule-format-v2.md` explicitly supersedes the implicit "v1" (the two raw rule files) without marking itself superseded.

**The `rule-format-v2.md` / `signed-feed.md` "implemented" status is the mirror-image problem to `continuous-validation.md` below — code-complete is being read as live.** Both headers say "implemented," and the code backing them (`PackLoader`, `Ed25519Verifier`, `LicenceReader`, wiring into `OpenSearchBulkShipper.cs:126`) genuinely exists and is unit-tested. But `ContentPackConfig.Enabled` defaults to `false` (`src/TinySocs.Agent/Configuration/AgentConfig.cs:146`, with the comment at lines 133-135 confirming it's deliberate: *"Opt-in so existing installs are unaffected until the feed is rolled out"*), and `OpenSearchBulkShipper.cs:126` gates the whole `PackLoader` construction behind that same flag — `if (_config.Detection.Pack.Enabled)`. The Inno Setup installer (`packaging/iss/Quickstart.iss`) ships only the legacy `rules.yml` and `rule_docs.yml`; grepping it for pack/`.sig`/key provisioning turns up nothing — no signed pack, no trust-anchor keys are shipped to any install. So **no current customer install exercises the signed-pack trust path.** Read "implemented" here as "built, dormant, not yet rolled out to any customer" — not "live." (Whether it should be flipped on is a `tinysocs-change-control` question, not a docs one.)

**`continuous-validation.md`'s header is stale.** It says "not yet implemented," but every one of its own "existing assets" — `tests/atomic-tests.yaml`, `tests/Test-AtomicDetection.ps1`, `results/*.json`, `site/validation/{index.html,styles.css,validation.js,methodology/,data/}` — is present on disk and functioning. The accurate status (per `docs/roadmap.md:32,80-90`) is: pipeline built, publication blocked on a harness attribution bug and three over-firing rules (TS-061/TS-130/TS-131), not on missing code. Treat "not yet implemented" here as **"built but not yet shippable,"** not "doesn't exist." Full remediation of this gap (fix the harness, republish the dashboard, restart weekly cadence) is the job of `tinysocs-validation-publication-campaign` — this skill's job is just to flag that the header is wrong and point you there.

## 3. Cross-reference, don't restate

CLAUDE.md's own rule ("Design docs... Cross-reference rather than re-state. If a decision is in another doc, link.") is followed reasonably well in practice — use it as the template for anything you add:

- `docs/design/content-cadence.md` does not re-explain the pack schema or signing protocol; it says *"Depends on: `rule-format-v2.md` (pack schema, `pack_version`), `signed-feed.md` (sign + publish + channels), `continuous-validation.md` (the weekly Atomic Red Team run)."* and gets on with the process content unique to itself.
- `docs/design/signed-feed.md` does not restate the pack envelope; it says *"Depends on: `docs/design/rule-format-v2.md` (pack envelope, `metadata.signature`, `metadata.tier`, `pack_id`+`pack_version`). This doc does not restate the pack schema."*
- `docs/roadmap.md` itself models this at the top: *"`CLAUDE.md` holds the condensed version as agent instructions, and the per-gap design docs hold the detail. This doc cross-references both rather than restating them."*

When you write or edit a doc here: if a fact already has a home (a design doc, CLAUDE.md, a skill), link to it by name/path instead of copying the number or the claim. Duplicated facts are exactly how the drift in §4 happened — a rule count gets corrected in one place and not propagated.

## 4. Doc-drift ledger (as of 2026-07-11) — what's wrong, where, and who owns the fix

This is a living list. When you fix one of these, delete its row (don't leave "FIXED" markers to rot). When you find a new one, add it here with a fix-owner.

| # | Drift | Where | Fix owner |
|---|---|---|---|
| 1 | **`CLAUDE.md:36`** — *"No rule signing, no rule feed, no licence checking, no Stripe integration. All greenfield."* False since 2026-06-06: `Ed25519Verifier.cs`, `PackLoader.cs`, `LicenceReader.cs`, `src/tinysocs/api/feed.py`, and a real signed pack (`packs/base/2026.27/pack.yml.sig`) all exist and are wired through `OpenSearchBulkShipper.cs:126-130`. See `docs/design/signed-feed.md` status header. **But don't over-correct the other way**: "wired through" means the code path exists and compiles, not that it's live — `ContentPackConfig.Enabled` defaults `false` (`AgentConfig.cs:146`) and the installer ships no pack/key files (`packaging/iss/Quickstart.iss`), so the path is dormant on every current install. See §2. | Founder edits CLAUDE.md directly (see §6) |
| 2 | **`CLAUDE.md:44`** — *"1. Rule format v2 (in progress — see `docs/design/rule-format-v2.md`)."* The doc it points to says **implemented**, not in-progress. | Founder edits CLAUDE.md directly |
| 3 | `docs/competitive-positioning.md:18` says **"20 curated & validated"** in its comparison table; `docs/competitive-positioning.md:44,84` (prose, same file), `docs/one-pager.md`, `docs/faq.md`, and CLAUDE.md's corrected rule-count paragraph all say **19 enabled**. TS-120 was deferred 2026-07-08, dropping the count from 20→19; the table cell wasn't updated in the same pass. Single-cell fix. | `tinysocs-external-positioning` (this is a customer-facing claim) |
| 4 | `docs/detection-coverage.md` — header says *"Auto-generated by `mitre_coverage`,"* last regenerated 2026-02-23, predates the pilot cut. Shows **32 techniques**; the current corrected claim (one-pager.md, faq.md) is **16 techniques / 8 tactics** for the 19-enabled set. Needs a re-run of `reporting/mitre_coverage.py` against the current pack, not a hand-edit. | `tinysocs-diagnostics-and-tooling` (owns `mitre_coverage.py`) then `tinysocs-external-positioning` for republishing the number |
| 5 | `docs/demo-script.md:1` — H1 says **"TinySocs Demo Script (v0.9.0)"**; product is at **v0.10.0**. Touched incidentally in the 2026-07-11 Ruff/mypy CI-fix commit (`37005ad`) but that was a 1-line unrelated change, not a content review. | Whoever next runs the demo script — gate the fix through `tinysocs-change-control` if the script's steps also need updating, otherwise a trivial version-string fix |
| 6 | `docs/pilot-guide.md`, `docs/mssp-guide.md`, `docs/outreach-templates.md` — **not touched** in the 2026-07-10 pivot-messaging pass (commit `347c98e`) that rewrote `one-pager.md`/`faq.md`/`roadmap.md`/`getting-started.md`/`competitive-positioning.md` with the corrected 19/39/50 rule framing and the new ICP-driven headline. Last touched 2026-02-21 / 2026-06-03 respectively — predate both the ICP work (`icp.md`, 2026-06-10) and the rule-count correction. Likely still say old counts / old positioning. | `tinysocs-external-positioning` |
| 7 | `tinydocs/README.md`'s "Priority 20" table math doesn't reconcile: it says *"the remaining **17** base rules... 20 + 17 = **37** base rules,"* but CLAUDE.md's current breakdown is 39 defined / 19 enabled / 18 held-back-for-tuning / 2 lab-only. 37 ≠ 39, and the doc never spells out that 37 = 39 − 2 lab-only. A reader of `tinydocs/README.md` alone cannot derive CLAUDE.md's breakdown unaided. | Whoever next edits `tinydocs/README.md` — cosmetic arithmetic fix, no gate needed |
| 8 | **`tinydocs/*.md` includes TS-060 and TS-100** in its published "Priority 20" table — both are **disabled** per `docs/pilot-ruleset.md`, and TS-060 is flagged there as **dead-as-shipped** (the shipped `sysmon-config.xml` has an empty ProcessAccess include list, so Sysmon Event 10 never fires and TS-060 structurally cannot trigger). Meanwhile `packaging/detection/rule_docs.yml` (the runtime-consumed artifact, same commit `347c98e`) correctly excludes TS-060/TS-100 and includes the real enabled set instead (adds TS-080-sys, TS-110, TS-131 that `tinydocs/` lacks; also carries TS-120, itself deferred — see row 9). A customer following a TS-060 alert link would land on an explainer for a rule that can never fire. | `tinysocs-change-control` — this is a customer-visible correctness bug in shipped docs, gate any rewrite of the Priority 20 table |
| 9 | `packaging/detection/rule_docs.yml` carries an entry for **TS-120**, which `docs/pilot-ruleset.md` explicitly marks deferred (no event source — heartbeats bypass the engine). Likely written before the final TS-120 deferral decision (2026-07-08) and not pruned. Harmless (unused entries are simply never looked up) but should be removed to keep the file matching the enabled set exactly. | Next rule-docs sync pass — see §5 |
| 10 | **`docs/RUNBOOK.MD`** references scheduled task names `TinySOCS_Master_Daily` and `TinySOCS_Ledger_Health` (uppercase `TinySOCS`, underscore style). The actual registered task names, per `scripts/Install-OperatorTasks.ps1:56,76,97`, are `TinySocs-RotateQueues`, `TinySocs-NightlyVerifyLedger`, `TinySocs-MasterHeartbeat` (mixed-case `TinySocs`, hyphen style). Anyone following the runbook to check "is the daily job running" via Task Scheduler will search for a task name that doesn't exist. | Whoever next touches ledger ops docs — `tinysocs-run-and-operate` owns the actual task inventory |
| 11 | `docs/RUNBOOK.MD` and `docs/PHASE4_LEDGER.MD` use uppercase `.MD` extensions — the only two files in the tree that do (both from the oldest layer, 2025-10-28, predating the lowercase `.md` convention every other doc uses). Cosmetic, but breaks case-sensitive `*.md` globs. | Low priority; rename on next touch |
| 12 | `docs/roadmap.md:37,73` references **`docs/design/ai-triage.md`** for workstream #7 (AI-assisted triage) — this file does **not exist** (`ls docs/design/` returns only `content-cadence.md`, `continuous-validation.md`, `rule-format-v2.md`, `signed-feed.md`). **This is not a bug** — roadmap.md is honest about it in the same breath: *"concept — design-first; no design doc yet."* Listed here only so a doc-hygiene pass doesn't "fix" it by inventing a stub design doc; the honest move is to leave it as a forward reference until #7 is actually picked up. | N/A — working as intended, don't "fix" |

Two things worth restating from CLAUDE.md itself, since they're doc-drift adjacent: the README footer used to wrongly claim "MIT" (fixed 2026-05-26 to BSL-1.1) — **if you see another stale MIT claim surface anywhere** (CHANGELOG, package metadata, marketing site), fix it on sight, per CLAUDE.md's own standing instruction.

## 5. TinyDocs — two distinct artifacts, keep both in sync with the enabled set

Do not conflate these. They serve different consumers and currently disagree with each other (see drift rows 7-9 above).

| | `tinydocs/*.md` | `packaging/detection/rule_docs.yml` |
|---|---|---|
| **What** | 20 long-form knowledge-base pages, one per rule ID | 20 short alert-companion YAML entries |
| **Consumer** | Human reader (customer clicks through from an alert), pack build copies referenced `docs:` paths into the signed pack | `src/TinySocs.Agent/Detection/RuleDocs.cs` → `RuleDocsLoader`, wired into `AlertWriter.cs` (`_ruleDocs` field, `BuildEmailBody(alert, RuleDoc? doc)`), and the dashboard `/api/rule-docs` route |
| **Content** | What it detects, why it matters, what a true positive looks like, common false positives **and how to allowlist them**, tuning knobs, references | `title`, `what_happened`, `do_first` (2-4 steps), `false_alarm_if` — deliberately excludes event IDs/MITRE IDs/index names ("never promise the product does something it doesn't") |
| **Loader failure mode** | N/A (static markdown, pack-build-time copy) | Non-fatal: `RuleDocsLoader` wraps the whole load in try/catch, returns an empty dict on any exception, falls back to the rule's technical name/description if an entry is missing (`RuleDocs.cs:76-82`) |
| **Current rule-ID set (2026-07-11)** | TS-001, 002, 010, 020, **060**, 061, 062, 070, 071, 080, 081, 082, 090, **100**, 113, 114, 130, 132, 133, 135 | TS-001, 002, 010, 020, 061, 062, 070, 071, 080, 080-sys, 081, 082, 090, 110, 113, 114, **120**, 130, 131, 132 |

Both should track the **19-enabled set** (TS-001,002,010,020,061,062,070,071,080,080-sys,081,082,090,110,113,114,130,131,132 — per `docs/pilot-ruleset.md`). `rule_docs.yml` is the closer match (only stray entry: TS-120, deferred). `tinydocs/` is the more divergent one (missing TS-080-sys/110/131 that are enabled; carrying TS-060/100 that are disabled, one of them dead-as-shipped).

**Rule for future rule changes**: whenever a rule is enabled, disabled, or its ID changes in `packaging/detection/rules.yml` / the v2 pack, update both TinyDocs artifacts in the same change — don't let one lag the other again. Gate any customer-visible rewrite through `tinysocs-change-control`.

## 6. CLAUDE.md's own update triggers — restated, plus the one currently unmet

CLAUDE.md states its own "update this file when" list:

- The dual-engine reality changes (Python runner activates, or schemas converge).
- A new top-level subsystem lands (Stripe integration, feed server, TinyDocs).
- The strategic phase shifts (post-first-customer, post-team-hire, post-Apache conversion).
- A hard rule changes (work-network policy, validatr separation, etc.).
- Anything in here turns out to be wrong.

**Currently unmet**: the second trigger fired on 2026-06-06 (feed server + Stripe + TinyDocs all landed) and the fifth trigger is live right now (drift rows 1-2 above — CLAUDE.md is factually wrong about signing/feed/licence/Stripe being greenfield). CLAUDE.md was in fact edited in the commit that made these true (`347c98e`, 2026-07-10) — the rule-count paragraph was corrected — but the adjacent "All greenfield" and "in progress" lines were missed in the same edit.

**Skills do not edit CLAUDE.md.** This skill's job — and every sibling skill's job — is to *flag* staleness with file:line evidence and let the founder make the edit (or explicitly ask an agent session to do it as a scoped task). State code-verified reality, and where CLAUDE.md is stale, say so explicitly with the file:line of the truth, per the founder's own stated protocol for handling this file. CLAUDE.md's **rules** (work-network exclusion, Validatr separation, no-prices-in-schema, BSL discipline, dual-engine honesty, "don't add non-pivot features") remain binding regardless of which facts in the file are stale — staleness is about facts, not about the rules being wrong.

## 7. Writing rules for anything in `docs/` or `.claude/skills/`

- **Date-stamp volatile numbers.** Rule counts, percentages, "as of" statuses — write `19 rules enabled (as of 2026-07-11)`, not a bare `19 rules enabled`. Every number in this file's own §4 table is a snapshot; expect it to drift and expect the next reader to re-verify before trusting it blind.
- **No prices.** Tier architecture (free/pro/msp) is locked; prices are not set until after the first cohort of customer conversations (CLAUDE.md, "Don't do for me"). Don't let a number leak into a doc, a skill, or a schema example.
- **Plan docs stay uncommitted.** Don't commit scratch planning documents (`docs/phase-N-summary.md`-style retrospectives) unless explicitly asked — CLAUDE.md: "Don't recreate `docs/phase-N-summary.md` style retrospectives unless asked. The next 12 weeks are about shipping the pivot, not documenting phases."
- **ASCII-only in anything PowerShell-adjacent.** Any doc containing PowerShell snippets, or describing steps a customer will paste into PowerShell 5.1, must stay ASCII — em-dashes and smart quotes have broken Windows PowerShell 5.1 before (see `git log` commit `94dae2b`, "Demo-Ransomware.ps1: ASCII-only output (em-dashes broke Windows PowerShell 5.1)"). This applies to `docs/getting-started.md`, `docs/troubleshooting.md`, `docs/operator-runbook.md`, and any skill content a small model might paste verbatim into a customer's terminal.
- **Cross-reference, don't restate** (§3) — the single biggest cause of the drift in §4 is the same fact living in two places and only one getting fixed.
- **Status headers on design docs are load-bearing, not decorative.** If you implement something a design doc describes, update its header in the same change — don't leave a header saying "not yet implemented" once the code ships (see the `continuous-validation.md` case in §2).

## When NOT to use this skill

- Writing or checking **customer-facing claims** (rule counts in marketing copy, competitive comparisons, banned efficacy figures, ICP messaging) — see `tinysocs-external-positioning`. This skill tells you *where* the doc-drift is; that skill tells you what's safe to say to a buyer.
- Deciding whether a documentation or code change is even in scope for the pivot, or needs a design doc before code — see `tinysocs-change-control`.
- Rewriting `docs/design/continuous-validation.md`'s status header for real by fixing the underlying harness/publication problem — that's the executable campaign in `tinysocs-validation-publication-campaign`, not a docs-only fix.
- Looking up what counts as validation evidence, the atomic-test structure, or banned numbers — see `tinysocs-validation-and-qa`.
- Day-to-day ops runbook content (ports, NSSM services, ProgramData layout) — see `tinysocs-run-and-operate`; this skill only flags that `docs/RUNBOOK.MD`'s task names are stale, it doesn't own the correct task inventory.

## Provenance and maintenance

Authored 2026-07-11, session branch `fix/ci-green` @ HEAD `37005ad`.

Primary sources (all re-read directly, not taken from digests on faith):
- `/Users/lukefitzgerald/tinysocs/CLAUDE.md` (lines 36, 44, "Design docs" section, "Update this file when", "Don't do for me")
- `/Users/lukefitzgerald/tinysocs/docs/roadmap.md` (lines 1-5, 17, 41, 118)
- `/Users/lukefitzgerald/tinysocs/docs/design/{rule-format-v2,signed-feed,continuous-validation,content-cadence}.md` (status headers, lines 1-6 each)
- `/Users/lukefitzgerald/tinysocs/src/TinySocs.Agent/Configuration/AgentConfig.cs` (lines 128, 133-135, 146 — `ContentPackConfig.Enabled` defaults `false`, opt-in comment)
- `/Users/lukefitzgerald/tinysocs/src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs` (line 126 — `PackLoader` construction gated on `_config.Detection.Pack.Enabled`)
- `/Users/lukefitzgerald/tinysocs/packaging/iss/Quickstart.iss` (grepped for pack/`.sig`/key — confirms installer ships no signed pack or trust-anchor keys)
- `/Users/lukefitzgerald/tinysocs/docs/competitive-positioning.md` (lines 18, 44, 84)
- `/Users/lukefitzgerald/tinysocs/docs/demo-script.md` (line 1)
- `/Users/lukefitzgerald/tinysocs/tinydocs/README.md` (full file) and `ls tinydocs/`
- `/Users/lukefitzgerald/tinysocs/packaging/detection/rule_docs.yml` (rule-ID grep)
- `/Users/lukefitzgerald/tinysocs/docs/RUNBOOK.MD`, `docs/PHASE4_LEDGER.MD` (full files)
- `/Users/lukefitzgerald/tinysocs/scripts/Install-OperatorTasks.ps1` (lines 56, 76, 97 — actual task names)
- `/Users/lukefitzgerald/tinysocs/docs/pilot-ruleset.md` (referenced for the 19-enabled ground truth and TS-060/TS-120 status)
- Discovery digests `docs-inventory.md` and `design-docs.md` (used for breadth, every load-bearing claim independently re-verified against the files above)

Re-verification commands (run these before trusting any volatile fact above — the repo always wins over this file):

```bash
# Doc-drift row 1-2: is CLAUDE.md still stale on signing/feed?
grep -n "greenfield\|in progress — see" CLAUDE.md

# Is the signed-pack trust path still dormant (feature-flagged off, not shipped)?
grep -n "Enabled" src/TinySocs.Agent/Configuration/AgentConfig.cs | sed -n '1,2p'
grep -n "_config.Detection.Pack.Enabled" src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs
grep -in "pack\|\.sig" packaging/iss/Quickstart.iss

# Doc-drift row 3: rule-count residual inconsistency
grep -n "20 curated\|19 high-fidelity" docs/competitive-positioning.md

# Doc-drift row 5: demo script version tag
head -1 docs/demo-script.md

# Doc-drift row 7-9: TinyDocs rule-ID set divergence
grep -oE '^\| TS-[0-9]+' tinydocs/README.md | sort -u
grep -n '^  TS-' packaging/detection/rule_docs.yml | sort -u

# Doc-drift row 10: scheduled task name mismatch
grep -n "TaskName" scripts/Install-OperatorTasks.ps1
grep -n "TinySOCS_" docs/RUNBOOK.MD

# Design-doc status headers (all four, one shot)
for f in docs/design/*.md; do echo "== $f =="; sed -n '1,4p' "$f"; done

# Is docs/design/ai-triage.md still (rightly) absent?
ls docs/design/

# Freshest cross-cutting status source, re-read in full
sed -n '1,50p' docs/roadmap.md

# git state (uncommitted files, most recent commits)
git status --porcelain=v1
git log --oneline -5
```
