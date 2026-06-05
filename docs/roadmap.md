# TinySOCs Roadmap — Pivot to Detection-Content-as-a-Service

**Status**: draft
**Author**: Luke FitzGerald + Claude session, 2026-06-05.
**Purpose**: Single canvas for the work between now and first paying customer. This is the *forward* plan; `CLAUDE.md` holds the condensed version as agent instructions, and the per-gap design docs hold the detail. This doc cross-references both rather than restating them.

---

## The thesis (one paragraph)

The product as shipped is implicitly a DIY SIEM: the customer installs, tunes rules, and maintains. SMB IT generalists can't do that and will churn. The pivot: the **platform stays free or near-free** (including a stale weekly snapshot of base rules), and recurring revenue comes from a **paid subscription to a continuously-validated detection content feed** — signed, version-pinned, delivered automatically. The customer never edits a rule file; tuning happens via allowlists, AI-assisted triage, and FP feedback. Tiers are locked (`free` / `pro` / `msp`); prices are not set until the first cohort of customer conversations. Full context: `CLAUDE.md` → "Strategic phase".

**Lineage.** This pivot is not a new idea — it's an old one sharpened. The first product roadmap (Oct 2025, archived in the founder's planning notes) already named "rule updates" and "commercial licence for rule packs" as the *Pro* tier, and flagged Atomic Red Team validation as the way to prove detection efficacy to buyers. The content-as-a-service strategy is those two threads — paid validated content, and public proof it works — promoted from "Pro feature" to the whole business model.

## The constraint

- **First paying customer: mid-Aug 2026** (8-12 weeks from the strategic brief, ~10 weeks from this doc).
- **Part-time founder budget** — evenings and weekends.
- Zero paying customers, zero pilots, zero outreach sent today. GTM materials exist under `docs/` but are unused.

This budget is why sequencing is ruthless: ship increments a customer can *see*, and don't build platform features that don't move the pivot.

---

## The gaps, sequenced

Sequencing is locked. State as of 2026-06-05.

| # | Gap | State | Detail / design | Dependency |
|---|-----|-------|-----------------|------------|
| 1 | **Rule format v2** — unified, `runs_on`-aware schema | design-approved, not implemented | `docs/design/rule-format-v2.md` | Keystone — feed (#3) depends on the schema being stable |
| 2 | **Continuous validation pipeline** — public weekly Atomic Red Team results | largely built; **blocked on a clean run + honest number** | `docs/design/continuous-validation.md`; harness `tests/Test-AtomicDetection.ps1`; dashboard `site/validation/`; CI `.github/workflows/pages.yml` | Runs in parallel with #1; schema-invariant by design |
| 3 | **Signed rules feed** — signed, version-pinned, auto-delivered content | not started | *(no design doc yet)* | Needs #1 schema stable |
| 4 | **Stripe + licence-key gate** — paywall the feed | not started | *(no design doc yet)* | Pairs with #3 |
| 5 | **TinyDocs** — per-rule knowledge base, top ~20 most-visible rules | not started | *(no design doc yet)* | Independent; can start anytime |
| 6 | **Documented content cadence** — 1 new rule + 1 tuning patch / week | not started (process doc, not code) | *(no doc yet)* | Independent; needs the feed (#3) to deliver against |

**Count note:** `CLAUDE.md` calls these "the 8 strategic gaps" but enumerates 6 active + 3 deferred. The referenced "strategic brief" is not checked into the repo, so the canonical list of 8 can't be reconciled here. Treat this table as authoritative until the brief surfaces; reconcile then.

### Critical path

```
#1 v2 schema ──────────► #3 signed feed ──────► #4 Stripe/licence gate
       │                                              (paywall)
       └─ (parallel) ─► #2 validation pipeline ──► public dashboard
                            (biggest credibility lever; nearly done)

#5 TinyDocs ─── independent, slots in anytime
#6 content cadence ─── process; activates once #3 can deliver
```

The two load-bearing, design-first items are **#1 (schema)** and **#3 + #4 (feed + licensing)** — per `CLAUDE.md`, get these right on paper before writing C# or migrations.

---

## Nearest milestone: ship the validation dashboard honestly

Gap #2 is the most advanced and the highest-credibility. It is **not done** — it's blocked on publishing a *trustworthy* number, not a convenient one. Standing rule: **do not publish a number until one clean run on a fully-warm OpenSearch self-reports it.** Real engine efficacy is ~73-83% (index ground truth), not the harness's buggy 25%.

Open issues before publish (tracked in the validation work, branch `validation-pipeline`):

1. Triage noisy rules **TS-061 / TS-130 / TS-131** in `packaging/detection/rules.yml` (over-fire → production FP + validation pollution).
2. Fix harness **noise-blind attribution** — a test passes if *any* co-listed rule fires; it must validate the technique-specific rule (`tests/atomic-tests.yaml` `expected_rules`).
3. Honest postmortems for two real gaps: PowerShell (TS-030 / TS-082) and ingress (TS-132).
4. **OpenSearch-green readiness gate** before the weekly unattended run queries.
5. Then: one clean run → `scripts/normalize_validation_run.py` → merge `results/` to `main` → Pages publishes.

---

## Deferred to post-first-customer

Explicitly *not* now, with the reason:

- **FP telemetry channel** — needs the FP UI button to land first; the consent ask is easier with paying customers.
- **Backend Python KQL engine activation (v2.1)** — only the C# engine runs in v2.0; activating the 50-rule catalogue is post-first-customer.
- **Premium pack tiering enforcement** — tier architecture is locked, enforcement waits.

### Explicitly off the roadmap (the road not taken)

The pre-pivot planning notes (Oct–Dec 2025) carried a feature-expansion roadmap — "Phases 23–27": real FIM (not demo), response automation / auto-block, macOS + Linux collectors, cloud relay for NAT traversal, multi-tenant dashboard, and ML behavioural correlation. That was a *keep-building-the-platform-toward-an-acquisition* path. The pivot supersedes it: per `CLAUDE.md`, we do not add platform features that don't move the content-as-a-service strategy. These items are recorded here only so they don't quietly creep back in as "obvious next features." They are not the backlog.

---

## Out of scope / hard rules

- No prices in schema or marketing docs until after first customer conversations.
- Maintain dual-engine honesty: 39 rules actually fire (C#); 50 are a documented catalogue (Python, no runner). Every v2 rule carries `runs_on`.
- Work-network outreach is off-limits (see `CLAUDE.md`).

---

## Open questions

- **Where does the canonical "strategic brief" live, and does it define 8 gaps or 6?** Until it's in the repo, this doc is the de facto plan and the count is unreconciled.
- **Do gaps #3-#6 need their own design docs before work starts?** #1 and #2 each got one; the feed and licensing layer are at least as load-bearing and currently have none. Strong case for a `docs/design/signed-feed.md` before any C#/protocol code.
- **What's the minimum publishable validation result?** Is a single warm-run honest number enough to go public, or do we want N consecutive stable weeks first?
- **TinyDocs (#5) is independent — does it jump the queue?** It's customer-visible, low-risk, and unblocks nothing else, which makes it a good "spare-evening" task while #1/#3 designs settle.
- **How do the historical phase notes (Google Drive) map onto these 6 gaps?** Pending import — may surface gaps or decisions not captured here.
