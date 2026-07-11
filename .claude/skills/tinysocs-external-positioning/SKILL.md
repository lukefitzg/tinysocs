---
name: tinysocs-external-positioning
description: What TinySocs may say publicly, and why — ICP and beachhead definition, the honest rule-count triad (19/39/89) and where it still drifts, which validation numbers are banned/quotable/internal-only, the stale public validation dashboard (linked from live outreach and the landing page — highest-priority external discrepancy), competitor matrix, locked free/pro/msp tiers with no prices, and the reproducibility bar a public claim must clear before it ships. Load this before writing or reviewing anything customer-facing — one-pager, FAQ, landing page copy, outreach email, pitch deck, competitive comparison, investor/pilot conversation talking points, or any place a rule count, an efficacy percentage, or a price is about to be typed. Also load it when auditing existing GTM docs for staleness or overclaiming (see the icp-platform-gaps.md worked example in §7).
---

# TinySocs external positioning

Everything here governs what leaves the repo and reaches a prospect, investor, or the public internet. If you are writing or reviewing customer-facing copy — the one-pager, FAQ, landing page, an outreach email, a pitch deck slide, a competitive comparison — check every number and every claim against this file before it ships. **Any change to a public claim gates through tinysocs-change-control** (it counts as a pivot-relevant decision even when no code changes).

Session ground truth date: 2026-07-11, branch `fix/ci-green`, HEAD `37005ad`. Re-verify anything volatile before quoting it externally — see Provenance section for the exact commands.

## 1. ICP — who we sell to, and why now

Canonical source: `docs/icp.md` (status: draft, as of this writing). Companions: `docs/competitive-positioning.md`, `docs/mssp-guide.md`, `docs/pilot-guide.md`.

**Two buyer profiles** (`docs/icp.md:10-14`):

| Profile | Who | Note |
|---|---|---|
| A — SMB end-customer | Runs TinySocs on their own estate | 20–150 staff, 10–100 endpoints, Windows/M365-centric, zero dedicated security staff, some IT ownership |
| B — MSP / IT shop | Deploys across many client estates as managed service | 5–50 SMB clients; wants service margin, not box-resale; explicitly framed as "the leverage play for a part-time founder" |

**The forcing-function thesis** — this is the single most important thing to get right in any pitch. TinySocs is sold against a **dated, external reason to act now**, not general "you should have security monitoring" hygiene. Security monitoring is a should-do until something external makes it urgent. Rank the trigger, don't sell the hygiene:

1. **A blocked deal** — a bigger customer's security questionnaire / vendor-risk review demands proof of log monitoring and the prospect can't say yes. Revenue on hold. Fastest-closing trigger (`icp.md:22`).
2. **Cyber-insurance renewal** — insurer now requires monitoring/EDR-class controls; hard deadline, named cost (`icp.md:23`).
3. **Compliance/audit obligation** — HIPAA, PCI DSS, NIST CSF, ISO 27001 prep, NIS2/Cyber Essentials for Ireland/EU (`icp.md:24`).
4. **Recent incident or near-miss** — emotional + budget unlock, but unpredictable timing (`icp.md:25`).

Lead generation should hunt for the trigger, not the company profile. "Just raised a Series A and now selling to enterprise" (→ questionnaires incoming) is a better search than "SMBs in Ireland."

**Recommended beachhead** (`docs/icp.md:69-79`): Irish/UK B2B SaaS and tech companies, ~20–120 staff, Microsoft/Windows shops, that have just hit the enterprise security-questionnaire / SOC 2 / ISO 27001 wall. Founder-reachable via NDRC/Enterprise Ireland/PorterShed/Dogpatch alumni network — **this is the founder's own startup-accelerator ecosystem, not the day-job network.** The doc itself makes the distinction (`icp.md:46`): "Founder-reachable... Not the day-job network." This is consistent with, and does not override, the CLAUDE.md hard rule below.

Secondary beachhead: regulated SMBs (dental/clinics, accountancy, legal) reached *through* an MSP (`icp.md:79`).

**Anti-ICP** (`icp.md:83-90`): Mac/Linux-heavy estates, >150 staff/>100 endpoints single-site, no IT ownership at all, no trigger present ("tyre-kickers"), enterprises wanting SLAs/24-7 support/SOAR, fully cloud-native shops with no Windows host.

**Messaging hooks** (`icp.md:94-103`):
- Headline: "Always-on security monitoring for companies without a security team." The doc self-corrects inline: *"(Note: always-on / 24-7 automated, not 'staffed SOC' — keep it honest.)"* (`icp.md:98`) — don't imply human eyes-on-glass.
- Trust line (the content-feed differentiator): "Every detection is tested against real attacks and signed before it reaches you." **Caveat, don't use unqualified**: the signing/PackLoader code path exists (`PackLoader.cs`, `Ed25519Verifier.cs`) but is dormant — `ContentPackConfig.Enabled` defaults to `false` (`src/TinySocs.Agent/Configuration/AgentConfig.cs:146`), `OpenSearchBulkShipper.cs:126` only constructs the verifying `PackLoader` when that flag is on, and the installer (`packaging/iss/Quickstart.iss`) ships no `packs/` content or trusted keys. A shipped install today loads the unsigned legacy `rules.yml` via `RuleLoader`, not a signed pack. Either reword to describe the vendor-side signing process (true today) rather than agent-side verified delivery (not true today), or hold the line until the trust path is wired into a real install. `site/index.html:213-214` already makes this exact overclaim live ("Every detection is tested against real-world attacks before it reaches you, and signed so you know it's genuine.") — flag it for correction, don't treat it as precedent that the claim is cleared.
- CTA for this phase is **email capture, not "buy now."**

**Pilot-fit checklist** (`icp.md:114-121`): a 6-item qualify-in-one-call list — Windows/M365 10-100 endpoints; no dedicated security staff but a named IT owner; a live trigger with a rough date; a named human who can say yes; live-environment pilot only; reachable warm or one-hop.

**Open questions the doc leaves unresolved** (`icp.md:127-130`): whether the beachhead is SaaS-only or split with MSP-channel, Ireland-only vs Ireland+UK geography, and a real compliance-fit gap — the shipped compliance frameworks (NIST CSF, HIPAA, PCI DSS) don't match what the beachhead's actual SOC 2/ISO 27001 questionnaire buyers ask for (see §7 gap S2). Don't paper over this gap in a pitch; it's a named unresolved item, not solved.

## 2. The honest rule-count triad — say it exactly this way

**Canonical framing (matches CLAUDE.md, matches `docs/pilot-ruleset.md`):**

> 19 enabled in the pilot base pack (2026.27) / 39 defined in the C# engine / 89 including the roadmap catalogue (39 + the 50-rule Python catalogue)

MITRE coverage for the 19-rule pack: **16 techniques across 8 tactics** (consistent across `one-pager.md:37`, `faq.md:38`, `competitive-positioning.md:44,84`, `demo-script.md:62`). Do not conflate the three numbers or use one to imply another — the 89 figure includes 50 rules that have no scheduled runner (see CLAUDE.md's dual-engine section and `detection-engineering-reference` for the mechanics). Never say "TinySocs has 89 rules" to a prospect without immediately qualifying that only 19 are running detections in a shipping install.

**Known-good phrasing, verified live in the repo this session:**
- `docs/one-pager.md:37`, `docs/faq.md:38`, `docs/demo-script.md:62`, `docs/competitive-positioning.md:44,84` all state the 19/39/50(+89) framing correctly and consistently.

**Known drift — fix on sight, same discipline as a stale "MIT" claim:**
- `docs/competitive-positioning.md:18` — the comparison-matrix table row still reads **"20 curated & validated (39 in engine; 50 more roadmapped)"** while the prose two sections later in the *same file* (`:44`, `:84`) correctly says 19. This is a partial find-and-replace miss from the `347c98e` pilot-pack-ship commit (2026-07-10) that rewrote the prose but not the table cell. Treat this exactly like the README "MIT" claim CLAUDE.md calls out: if you see it, fix it to "19" — don't leave two numbers live in one doc.
- Why the count is 19, not 20: `docs/pilot-ruleset.md:31-33` — TS-120 (agent version drift) was found to have no event source during the 2026-07-08 validation pass and was deferred (`enabled: false`), dropping the enabled count from a planned 20 to a proven 19. TS-113 was separately near-dead (grouped by a field FIM events never carried) but was *fixed*, not deferred — see CLAUDE.md's corrected-ground-truth block and `FileIntegrityInput.cs:575-582`.
- Older stale figure to recognize and reject if it surfaces: "17 MITRE ATT&CK techniques across 9 tactics" — flagged in the `icp-platform-gaps.md` 2026-07-06 audit as jargon/staleness, and confirmed no longer present in the currently-live one-pager or FAQ.

## 3. Banned / quotable / internal-only validation numbers

This table is the single most load-bearing thing in this skill. Get it wrong and you ship a number that embarrasses the company or, worse, that a prospect can disprove by clicking a link.

| Number | Source | Status | Why |
|---|---|---|---|
| **March 2026-03-01 "100% efficacy"** | `tests/atomic-results.json` (old, dated artifact) | **BANNED — never quote** | Predates the June test-fidelity overhaul in `tests/atomic-tests.yaml`. Explicit kill-quote at `docs/pilot-ruleset.md:208`: "must not be quoted — it predates the current rule definitions." Several March "DETECTED" credits were earned by rule definitions that no longer exist (e.g. TS-061 matched *any* process creation before `field_match` existed). The raw artifact file with this number baked in is still in the repo — it's a grep landmine for anyone who reads `atomic-results.json` without first reading `pilot-ruleset.md`'s warning. |
| **Raw 57.1%** (all techniques including deferred/env-skipped, unfiltered) | `docs/pilot-ruleset.md:65` — "The raw 57.1% from the first run counted the 6 deliberately-deferred (disabled) rules as misses and must not be quoted; the harness now skips them." | **Not quotable in any form** | Not a curated figure; conflates deferred and environment-blocked rules with genuine misses. |
| **88.9% (8/9 executed, 2026-07-08 run)** | `docs/detection-efficacy.md:9,75` | **Internal-only — not yet cleared for external use** | The source doc names its own preconditions before this "goes on the one-pager" (`detection-efficacy.md:80-83`): (1) one more clean single-run pass for a cleaner artifact — optional, coverage is already proven across two runs; (2) four environment-limited rules (TS-082, TS-081, TS-062, TS-110 — Defender RTP off, Tamper Protection off, a lab DC, a FIM-enabled install) need targeted runs before they can be individually claimed as attack-validated. As of this session no customer-facing doc quotes 88.9% — checked `one-pager.md`, `faq.md`, `competitive-positioning.md`, `outreach-templates.md`. This is the correct posture; don't jump the gun. **Also gate on the public dashboard being rebuilt** — see next row — a number this good sitting next to a dashboard showing 53.85% is worse than not publishing it at all. Full rebuild plan: `tinysocs-validation-publication-campaign`. |
| **53.85% (2026-W23, June run)** | `site/validation/data/summary.json`, live at `/validation/` | **Currently live and worse than reality** | See §4 — this is the highest-priority discrepancy in the whole positioning surface. |

**Safe, currently-used, general claims** (no specific percentage, verified consistent across `one-pager.md`, `faq.md`, `competitive-positioning.md`, `outreach-templates.md` this session):
- "Every shipped rule is validated against real (Atomic Red Team) attacks before release." **Not currently accurate — needs the same staleness caveat as the next bullet, not a pass.** Every enabled rule has an Atomic test *defined*, but per `tinysocs-validation-and-qa` §4, only 9 of the 19 enabled rules have been proven to fire in a live attack→pipeline→alert run as of the 2026-07-08 harness (the rest are xUnit-proven on synthetic events, or environment-gated SKIPs — TS-081, TS-062, TS-110, TS-080-sys, TS-120 have never been attack-validated at all). Confirmed in `tests/atomic-results.json`: 8 DETECTED, 1 MISSED, 10 SKIP. Reword to something defensible, e.g. "Every shipped rule has an Atomic Red Team test defined; as of 2026-07-11, 9 of 19 enabled rules have been proven to fire against a live attack, the rest are xUnit-proven or environment-blocked" — or drop the claim until more of the SKIPs clear.
- "Results are published weekly, including misses — no cherry-picking." (True in principle; the *current instance* of the practice is stale, see §4 — the claim about the *practice* remains honest even though today's published instance is behind.)
- "19 high-fidelity rules enabled in the free base pack, covering 16 MITRE ATT&CK techniques across 8 tactics."

## 4. The stale public validation dashboard — highest-priority live discrepancy

`site/validation/data/summary.json` feeds `site/validation/validation.js`, rendered at `/validation/` and linked from the landing page ("See this week's test results", `site/index.html:216`) and from **both** outreach templates (`docs/outreach-templates.md:35` and the MSSP template `:63`) as the credibility proof point.

Verified current content, this session (`site/validation/data/summary.json:1-25`):

```json
"run_id": "2026-W23-001", "iso_week": "2026-W23", "generated_at": "2026-06-03T21:03:48Z",
"git_commit": "0184cbb",
"summary": { "rules_in_pack": 39, "atomic_tests_total": 19, "atomic_tests_detected": 7,
             "technique_pass_rate": 0.5385, "rule_pass_rate": 0.3462 }
```

This is week 2026-W23 (early June) — it predates the pilot base pack 2026.27 (shipped 2026-07-10, commit `347c98e`) and predates the July 2026-07-08 88.9% re-run entirely. `site/validation/data/summary.json` is gitignored (CI-built, never committed — `.gitignore:198`), so `git log` has no history for it at all; the `0184cbb`/`2026-06-03T21:03:48Z` values above are the JSON's own self-reported `git_commit`/`generated_at` fields, not something git can corroborate. Taking those fields at face value, weekly cadence has been dead roughly five weeks as of 2026-07-11.

**Why this matters more than a stale number in a doc**: it is a live, linked, external URL. Anyone who clicks through from the landing page or an outreach email lands on a **53.85% technique pass rate against an old ruleset** — worse than the current internal 88.9% truth, and with no distinction between "enabled in the pilot pack" (19) vs "defined in the engine" (39) — the dashboard just shows all 39 rules undifferentiated, so a visitor cannot tell which rules are actually live in the product they'd be buying.

There is also a methodology bug baked into the current public description: `site/validation/methodology/index.html:59-61` describes "pass" as "at least one of its expected rules fires within the timeout" — this is the noise-blind attribution bug `docs/roadmap.md:87` calls out ("a test passes if any co-listed rule fires; it must validate the technique-specific rule"). The page is accurately describing current (flawed) behavior, so it isn't stale relative to the code — but it's describing a known-bad measurement standard as if it were final. If the attribution fix ships, this page needs a rewrite too.

**Do not link a prospect to `/validation/` right now without disclosing it's stale**, and do not fix the underlying data as a side effect of a positioning task — that's a dedicated body of work. **Fixing this dashboard is the job of `tinysocs-validation-publication-campaign`.** This skill's job is to flag the discrepancy and stop it from being amplified in new copy, not to run the rebuild.

## 5. Reproducibility standard — the bar a public validation claim must clear

Synthesized from `docs/roadmap.md:82`, `docs/detection-efficacy.md`, and `site/validation/methodology/index.html`. A number does not ship unless all of the following are true:

1. **One clean run on a fully-warm OpenSearch self-reports it** (`roadmap.md:82`) — don't publish from a cold-start or partial run.
2. **The run is against rule definitions equivalent to what's currently shipping.** A pass under an old rule definition (e.g. pre-`field_match` TS-061) does not count, even if the artifact says "DETECTED."
3. **The raw run artifact, git commit, and timestamp are recorded** — `summary.json`'s `run_id`/`git_commit`/`generated_at` fields exist precisely so any published number traces to a specific commit. A number with no traceable artifact doesn't ship.
4. **State which pack version** the number applies to (e.g. "2026.27") — rule counts and pass rates are pack-specific, not eternal facts about the product.
5. **Misses get a written postmortem, not silence** (`methodology/index.html:77-78`).
6. **Skips are categorized by why** (platform/prereq vs genuine gap) rather than folded into misses — outreach copy explicitly promises "passes, skips, and misses" are all public (`site/validation/index.html` meta description).
7. **The public dashboard reflects the same run being quoted internally.** A number correct in a design doc but not reflected at the linked public URL is not yet a shippable public claim — see §4.

If you can't point to a specific `results/` artifact, harness commit, and updated methodology page for a number, it doesn't go in a one-pager, an email, or a slide.

## 6. Competitors

Comparison matrix (`docs/competitive-positioning.md:9-22`) names: **Blumira, Todyl, Perch / ConnectWise, Elastic SIEM, MS Sentinel.** Dimensions compared: deployment model, pricing model, setup time, AI assistance, compliance reporting, on-prem option, MSSP/multi-tenant, detection rule count, threat intelligence, operator skill level, open source, data residency.

**Huntress is not in the public comparison matrix.** It appears only once, internally, in `docs/design/rule-format-v2.md:401`, inside a non-binding tier-pricing note: "Priced below Blumira/Todyl/Huntress on per-endpoint-equivalent basis." Do not add Huntress to customer-facing comparisons without a deliberate decision — its current appearance is internal pricing context, not an external claim.

**Honest weaknesses section** (`competitive-positioning.md:38-50`, self-critical, keep it that way in any external doc that reuses this material):
- Windows-only, no Linux/macOS agent.
- Single-developer project — no SLA, no 24-7 support, no community scale.
- Smaller detection library — reframed as a deliberate signal-to-noise trade, not denied.
- No cloud-native/SaaS delivery option.
- No SOAR/automated response — response is manual.
- Single-box architecture caps at ~100 endpoints/node.

**Positioning axis**: validated-content-as-a-service + time-to-value, priced below per-endpoint incumbents on a per-endpoint-equivalent basis — **with no actual numbers**, see §7. The pricing-model row in the matrix (`competitive-positioning.md:12`) cites competitor public list prices (e.g. Blumira "$144+/user/yr") but gives no TinySocs price — correct, none exists yet.

## 7. Tier architecture — locked, no prices, anywhere

**Locked tiers**: free / pro / msp. Canonical shape in `docs/design/rule-format-v2.md:395-401`:
- **free**: `base` pack only, stale weekly snapshot (no continuous updates), C# engine + allowlists (schema exists, runtime does not — see `tinysocs-research-frontier`) + local Ollama assistant only.
- **pro**: live `base` pack feed + premium packs (persistence-premium, m365-pack, etc.) + cloud-LLM assistant. Per-site flat, endpoint band TBD.
- **msp**: pro + federation hub + multi-tenant management. Per-site flat designed to enable MSP margin.
- Closing line, verbatim: **"Pricing is locked after first cohort of customer conversations, not now."**

**Hard rule, restated from CLAUDE.md and independently stated in three places in the repo** (`icp.md:5`, `roadmap.md:110`, `rule-format-v2.md:401`): no price numbers anywhere — not in the schema, not in any doc, not on the landing page — until after the first cohort of customer conversations. Verified this session: no `$`/`€`/`/mo`/`/yr` TinySocs price appears in `one-pager.md`, `faq.md`, `competitive-positioning.md`, `icp.md`, `outreach-templates.md`, `pilot-guide.md`, `mssp-guide.md`, or `site/index.html` — the only currency figures present are competitors' own public list prices in the comparison table, which is fine to cite as-is (it's their public number, not ours).

Do not let a task "just add an example price for illustration" onto any of those surfaces. Gate any tier/pricing copy change through `tinysocs-change-control`.

## 8. Worked example: `docs/icp-platform-gaps.md` — how to audit for overclaiming

This doc is the template for how positioning audits should run. Status: "audit complete (2026-07-06); all six MUST items implemented same day. SHOULD/COULD items remain open." Scope is explicitly UX/messaging, not a code review — evidence base was `dashboard.py`, `AlertWriter.cs`, `llm_*.py`, `reporting/`, plus the one-pager/FAQ/getting-started docs themselves.

**The yardstick, reusable for any future audit of a customer-facing surface**: does it answer the ICP's three questions — *"Are we being attacked? Are we compliant? Can I explain this to my boss?"* Grade every surface against that, not against what a security analyst would want. Priority tiers: **MUST** (fix before first pilot install — a pilot that stumbles here fails in week 1), **SHOULD**, **COULD**.

**What it found and what happened to it:**
- A direct contradiction: the FAQ used to say "Can I write custom detection rules? Yes — use the Rule Builder," directly contradicting the pivot thesis "customer never edits a rule file" — selling rule-authoring to this ICP recreates the churn problem the subscription exists to solve. **Verified current text** (`docs/faq.md:42`, this session): *"Advanced users can create custom rules via the Rule Builder, but no customer needs to."* Softened, but the Rule Builder is still surfaced as an available feature.
- A jargon inventory flagged marketing collateral against itself: `"Lightweight AI-Powered SIEM"` as an H1 and comparisons to Splunk/Elastic/Sentinel were called buyer-mismatched — "the buyer doesn't know what a SIEM is and isn't comparing against Splunk — they're comparing against doing nothing or an MSP quote."
- Fix item M6 (rewrite one-pager H1 to `icp.md` language, demote the Splunk comparison, reframe the rule-editing FAQ answer around allowlists/tuning-as-a-service) is confirmed landed: current `docs/one-pager.md:1` H1 reads "TinySocs — Always-On Security Monitoring for Companies Without a Security Team," matching the `icp.md` recommended headline.
- Gap S2, still open: no questionnaire/insurer evidence artifact — the beachhead's actual ask. The shipped compliance reports cover NIST CSF/HIPAA/PCI DSS, but the beachhead (SaaS companies facing SOC 2/ISO 27001 questionnaires) needs a different evidence artifact entirely. This is a real, named, unresolved gap — don't imply it's covered.
- **The unresolved tension this doc deferred honestly, and that this skill should keep deferred rather than silently resolve**: item C1 — "Rule Builder's existence contradicts the managed-content story long-term — decide its fate alongside tiering, not now." Every UI affordance that invites rule-editing recruits the customer back into the job the subscription is supposed to remove. The audit fixed the copy (M6) but explicitly left the product decision (hide/gate the builder) for the tiering work. Do not resolve this tension in a positioning task — it belongs with the tier/Stripe work, gate through `tinysocs-change-control`.
- Also explicitly flagged and preserved as a design choice: "honest all-clear vs simple all-clear" — a qualified degraded-state UI ("1 of 12 machines not reporting") is called "the trust moat — resist simplifying it away for the demo." Don't let a sales-demo request talk you into a fake all-green state.

Use this doc's method — fixed yardstick, MUST/SHOULD/COULD triage, name contradictions between marketing copy and the stated pivot thesis explicitly — as the pattern for any future positioning audit.

## 9. GTM doc set inventory — what exists, what's fresh, what's stale

| Doc | Purpose | Freshness (as of 2026-07-11) |
|---|---|---|
| `docs/one-pager.md` | External pitch sheet | Fresh — touched in `347c98e` (2026-07-10) |
| `docs/faq.md` | Public FAQ | Fresh — `347c98e` |
| `docs/competitive-positioning.md` | Comparison matrix + pitches | Fresh but has the table/prose rule-count split, §2 |
| `docs/icp.md` | ICP/beachhead definition | Draft status, `4a62cb7` (2026-06) |
| `docs/icp-platform-gaps.md` | Overclaiming audit | `347c98e`; MUSTs fixed same-day, SHOULD/COULD open |
| `docs/demo-script.md` | Sales demo walkthrough | Touched `37005ad` (1 line, unrelated CI fix) and `347c98e` |
| `docs/pilot-ruleset.md` | Rule-by-rule validation ledger, the ground truth GTM must not outrun | Fresh — `347c98e` major rewrite |
| `docs/detection-efficacy.md` | Headline efficacy report | Fresh — `347c98e` rewrite |
| **`docs/pilot-guide.md`** | Pilot deployment walkthrough | **STALE — last touched `1038563`, 2026-02-21. Missed the `347c98e` sweep entirely.** |
| **`docs/mssp-guide.md`** | MSP/MSSP deployment guide | **STALE — same commit `1038563`, 2026-02-21. Missed the sweep.** |
| **`docs/outreach-templates.md`** | Cold email / Reddit templates | **STALE — last touched `0184cbb`, 2026-06-03. Missed the sweep**, and it's the doc actively linking to the stale `/validation/` dashboard (§4). |
| `site/index.html` | Landing page | `e0bae04` (2026-06-23) — no rule counts or percentages on it, defers all numeric proof to the linked (stale) `/validation/` dashboard |
| `site/validation/*` | Public dashboard | **STALE data**, see §4 |

**Before using pilot-guide.md, mssp-guide.md, or outreach-templates.md in an actual pilot or outreach send**, re-check them against the current 19/39/89 framing and the current pack version (2026.27) — they predate the `347c98e` correction pass and have not been re-swept. Don't assume "recently in the repo" means "recently correct" — check the commit date, not the file's presence.

## 10. Hard rules, restated

These are binding regardless of what a task seems to ask for. They come from CLAUDE.md and are repeated here because positioning work is exactly where they get violated by accident.

- **Work network stays out of outreach.** Never suggest leveraging day-job colleagues or management for TinySocs outreach — this is a hard rule, not a preference. The founder-reachable network for the beachhead (§1) is the startup-accelerator ecosystem (NDRC/Enterprise Ireland/PorterShed/Dogpatch), explicitly *not* the day job.
- **No prices, anywhere, until after first customer conversations.** See §7.
- **Every public number gates through this skill and through `tinysocs-change-control`.** A number that hasn't been checked against §3's banned/quotable/internal-only table, or a tier/pricing change that hasn't gone through change control, does not ship — regardless of how confident the request sounds.
- **BSL-1.1 discipline**: license language must say BSL-1.1 with the Apache-2.0-in-4-years conversion and the Additional Use Grant, never "MIT" or "open source" unqualified. A stale MIT claim was already found and fixed once in `competitive-positioning.md` (commit `e820e7a`) — fix any recurrence on sight, same as the rule-count table drift in §2.
- **Dual-engine honesty in any external framing**: never imply the 50-rule Python catalogue is running detections in a customer's environment. It is a roadmap library — see CLAUDE.md and `detection-engineering-reference` for the mechanics.

## When NOT to use this skill

- Actually rebuilding the public validation dashboard, normalizing the 2026-07-08 run, or restarting weekly cadence — that is `tinysocs-validation-publication-campaign`. This skill only tells you the dashboard is stale and why that matters for copy.
- Deciding what counts as evidence for a *new* rule, or the xUnit/Atomic harness mechanics themselves — that's `tinysocs-validation-and-qa` and `tinysocs-detection-validation-toolkit`.
- Classifying whether a change is in-scope for the pivot, or the CI-green/BSL/plan-docs process rules — that's `tinysocs-change-control`.
- Rule engine mechanics, threshold semantics, MITRE technique detail — that's `detection-engineering-reference` and `tinysocs-architecture-contract`.
- Open engineering gaps (allowlist runtime, signed-pack activation, FP telemetry, Python KQL runner, baselines) as technical problems to solve — that's `tinysocs-research-frontier`. This skill only tells you not to claim those things are live.
- Doc-formatting conventions (status headers, cross-reference discipline) for design docs generally — that's `tinysocs-docs-and-writing`.

## Provenance and maintenance

Authored: 2026-07-11, from a live re-read of every cited file plus a prior discovery-pass digest (a session-local scratch file — not re-derivable, ignore if absent).

Primary sources (all re-verified this session, file:line as cited inline above): `docs/icp.md`, `docs/icp-platform-gaps.md`, `docs/competitive-positioning.md`, `docs/one-pager.md`, `docs/faq.md`, `docs/pilot-ruleset.md`, `docs/detection-efficacy.md`, `docs/roadmap.md`, `docs/design/rule-format-v2.md`, `docs/outreach-templates.md`, `docs/pilot-guide.md`, `docs/mssp-guide.md`, `site/index.html`, `site/validation/data/summary.json`, `site/validation/methodology/index.html`, `tests/atomic-results.json`, `tests/atomic-tests.yaml`.

Re-verification commands for volatile facts in this skill:

```bash
# Rule-count triad consistency across GTM docs (should all say 19/39/50-or-89)
grep -n "19 high\|19 enabled\|20 curated\|20 high" docs/one-pager.md docs/faq.md docs/competitive-positioning.md docs/demo-script.md docs/pilot-ruleset.md

# Is the competitive-positioning.md table/prose split still there?
grep -n "curated & validated" docs/competitive-positioning.md   # table row, watch for "20" vs "19"

# Is the public validation dashboard still stale?
# NOTE: summary.json is gitignored (built in CI, never committed) — `git log` on it returns nothing.
# Staleness is established from the JSON's own self-reported fields, not git history.
grep -n "run_id\|iso_week\|generated_at\|git_commit\|technique_pass_rate" site/validation/data/summary.json

# Has the pack version moved past 2026.27? (changes what 88.9% and the 19-count apply to)
# NOTE: packaging/detection/rules.yml is the legacy v1 format and has no pack_id/pack_version fields —
# check the actual pack manifest instead.
grep -n "pack_id\|pack_version" packs/base/2026.27/pack.yml
cat docs/pilot-ruleset.md | grep -n "^# \|2026\."

# Does any customer-facing doc quote a banned/premature number?
grep -rn "100%\|88\.9%\|57\.1%" docs/one-pager.md docs/faq.md docs/competitive-positioning.md docs/outreach-templates.md site/index.html

# Has a price crept into any GTM surface?
grep -rEn '\$[0-9]|€[0-9]|/mo\b|/month\b|/yr\b' docs/one-pager.md docs/faq.md docs/icp.md docs/outreach-templates.md docs/pilot-guide.md docs/mssp-guide.md site/index.html

# Have the stale docs (pilot-guide, mssp-guide, outreach-templates) been touched since the 347c98e sweep?
git log -1 --format="%h %ci" -- docs/pilot-guide.md docs/mssp-guide.md docs/outreach-templates.md

# Has Huntress moved from internal pricing notes into the public comparison matrix?
grep -n "Huntress" docs/competitive-positioning.md docs/design/rule-format-v2.md

# Signing/feed/licence code exists (this alone does NOT mean the trust line is safe to ship —
# it only proves the classes exist; also check whether the path is actually wired into a shipping install).
grep -n "Ed25519Verifier\|LicenceReader\|PackLoader" src/TinySocs.Agent/Detection/*.cs 2>/dev/null | head -5

# Is the signed-pack trust path actually live in a shipping install, or still dormant? (gates trust-line copy:
# "signed before it reaches you" — see §1 caveat)
grep -n "public bool Enabled" src/TinySocs.Agent/Configuration/AgentConfig.cs
grep -n "packs" packaging/iss/Quickstart.iss
```
