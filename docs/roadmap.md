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

Sequencing is locked. State as of **2026-06-06**.

| # | Gap | State | Detail / design | Dependency |
|---|-----|-------|-----------------|------------|
| 1 | **Rule format v2** — unified, `runs_on`-aware schema | **schema locked; migration + C# loader built** | `docs/design/rule-format-v2.md`; `scripts/migrate_rules_to_v2.py`; C# `PackLoader` | Keystone — feed (#3) depends on the schema being stable |
| 2 | **Continuous validation pipeline** — public weekly Atomic Red Team results | largely built; **blocked on a clean run + honest number** | `docs/design/continuous-validation.md`; harness `tests/Test-AtomicDetection.ps1`; dashboard `site/validation/`; CI `.github/workflows/pages.yml` | Runs in parallel with #1; schema-invariant by design |
| 3 | **Signed rules feed** — signed, version-pinned, auto-delivered content | **trust core + agent enforcement + feed HTTP server built** | `docs/design/signed-feed.md`; `scripts/pack_sign.py`; C# `Ed25519Verifier`/`PackLoader`; `src/tinysocs/api/feed.py` | Needs #1 schema stable |
| 4 | **Stripe + licence-key gate** — paywall the feed | **licence mint/verify + entitlement + Stripe webhook built; agent reads tier offline** | `docs/design/signed-feed.md` Parts 4–6; `scripts/licence.py`; `scripts/stripe_pricing.py`; `src/tinysocs/api/feed.py`; C# `LicenceReader` | Pairs with #3 |
| 5 | **TinyDocs** — per-rule knowledge base, top ~20 most-visible rules | **top-20 published; scaffolder built** | `tinydocs/`; `scripts/scaffold_tinydocs.py` | Independent; can start anytime |
| 6 | **Documented content cadence** — 1 new rule + 1 tuning patch / week | **drafted** (process doc) | `docs/design/content-cadence.md`; wires `mitre_coverage.py` → `migrate_rules_to_v2.py` → `pack_sign.py` → feed | Independent; needs the feed (#3) to deliver against |
| 7 | **AI-assisted triage & schema-grounded querying** — ground the AI assistant on live field schema + the v2 catalogue so a generalist can investigate in natural language without editing rules | **concept — design-first; no design doc yet** | extends `src/tinysocs/api/bot.py` + the `search_kql` corpus; design doc TBD (`docs/design/ai-triage.md`) | Needs #1 schema stable; pairs with deferred FP telemetry |

**Progress since 2026-06-05 (this branch).** The keystone schema is locked and the feed/licensing layer is built and proven end-to-end on the CLI, **inside the C# agent**, and now **vendor-side**. Agent: ed25519-verifies a signed pack, pins the signing `key_id`, gates by licence entitlement, refuses tampered/untrusted content (`src/TinySocs.Agent/Detection/{Ed25519Verifier,PackLoader,LicenceReader}.cs`, wired through `OpenSearchBulkShipper`). Vendor: `src/tinysocs/api/feed.py` is a small FastAPI app — an entitlement-gated mint endpoint that 302s to short-TTL signed URLs (Part 4.5) and a Stripe webhook that mints + revokes licence keys with no Stripe SDK (Part 6), both reusing the same `licence.py` decision the agent uses; covered by `tests/test_feed_server.py`. The full revenue loop (Stripe sub → key → live channel + premium → cancel revokes → agent verifies offline) runs locally with no cloud account. What remains for #3/#4 is **operational, not protocol**: the real object store (S3/R2 URL-signing in place of the blob stand-in) and the Stripe dashboard prices. Deferred still-deferred: content cadence (#6), premium-pack tiering enforcement beyond the gate, backend KQL engine (v2.1).

**Count note:** `CLAUDE.md` calls these "the 8 strategic gaps" but enumerates 6 active + 3 deferred. The referenced "strategic brief" is not checked into the repo, so the canonical list of 8 can't be reconciled here. Treat this table as authoritative until the brief surfaces; reconcile then.

### Critical path

```
#1 v2 schema ──────────► #3 signed feed ──────► #4 Stripe/licence gate
       │                                              (paywall)
       └─ (parallel) ─► #2 validation pipeline ──► public dashboard
                            (biggest credibility lever; nearly done)

#5 TinyDocs ─── independent, slots in anytime
#6 content cadence ─── process; activates once #3 can deliver
#7 AI-triage (schema-grounded) ─ independent; parallel once #1 stable; NOT on first-customer path
```

The two load-bearing, design-first items are **#1 (schema)** and **#3 + #4 (feed + licensing)** — per `CLAUDE.md`, get these right on paper before writing C# or migrations.

---

## Workstream #7 — AI-assisted triage & schema-grounded querying (added 2026-06-15)

An addition to the original 6 (not a reconciliation of the brief's "8"). It makes real a clause the thesis already promises: tuning "via allowlists, **AI-assisted triage**, and FP feedback." Today the only piece that exists is a thin assistant (`src/tinysocs/api/bot.py`) reading the 50-rule KQL catalogue as a `search_kql` corpus. This workstream is what lets an SMB generalist operate the SIEM without ever editing a rule — i.e. the operating model the whole pivot is sold on.

The technique, three parts — all generic engineering, none novel:

1. **Schema grounding.** Profile the live OpenSearch field schema and the v2 rule catalogue into a corpus the assistant reads *before* writing a query, so it queries real field names instead of guessing. Kills the "field not found → try again" loop that makes a generalist give up.
2. **Known-good-query + gotchas corpus.** Vetted queries, detection context, and query gotchas the assistant retrieves from, so triage starts from proven patterns rather than a blank prompt.
3. **Lessons / feedback loop.** Findings and corrections from a session are logged for vendor review and fold back into the corpus and into content cadence (#6) — the same flywheel that turns FP feedback into tuning patches.

Placement, honestly:

- **Not on the first-customer critical path.** The first sale closes on feed (#3) + validation proof (#2) + paywall (#4). This is a `pro`/`msp` *differentiator*, not the thing that gets the first signature — do not let it stall the 8-week items.
- **Design-first** (per `CLAUDE.md`): it touches the AI layer and reads the rule catalogue, so it wants `docs/design/ai-triage.md` before code. Not written yet.
- **Depends on #1** (v2 schema) for catalogue grounding; **pairs with the deferred FP telemetry channel** — the lessons loop is the consent-friendly front end for that channel.
- Good **spare-evening / parallel** work once #1 is stable and the revenue loop (#3/#4) is operational — same slot as TinyDocs (#5).
- **Maintains dual-engine honesty:** the assistant grounds on each rule's `runs_on`, so it never implies a backend (Python) rule is firing when only the C# engine runs.

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
- ~~**Do gaps #3-#6 need their own design docs before work starts?**~~ **Resolved (2026-06-06):** `docs/design/signed-feed.md` now covers #3 + #4 (what's signed, distribution/versioning, client verify, licence + entitlement, feed-server auth, Stripe→issuance, key rotation). #6 is a process doc, still to write.
- **What's the minimum publishable validation result?** Is a single warm-run honest number enough to go public, or do we want N consecutive stable weeks first?
- **TinyDocs (#5) is independent — does it jump the queue?** It's customer-visible, low-risk, and unblocks nothing else, which makes it a good "spare-evening" task while #1/#3 designs settle.
- **How do the historical phase notes (Google Drive) map onto these 6 gaps?** Pending import — may surface gaps or decisions not captured here.
- **Does #7 (AI-triage) earn a design doc now, or wait until #3/#4 are operational?** It's design-first and customer-visible, but explicitly off the first-customer path; the risk is it becomes the shiny thing that stalls the revenue loop.
