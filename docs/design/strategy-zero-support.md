# Strategy v3 — Free, zero-support release

**Status**: approved
**Author**: Luke FitzGerald + Claude session, 2026-08-18.
**Supersedes**: `docs/roadmap.md` (detection-content-as-a-service pivot) and the tier/feed/Stripe commercialisation plan in `docs/design/rule-format-v2.md` §tiers and `docs/design/signed-feed.md`.
**Purpose**: Record the strategic decision and its consequences so no future session (human or agent) resurrects the dead plan by accident.

---

## The decision

TinySOCs is released as a **free, zero-support, source-available** security monitoring tool for homelabbers, tinkerers, students, and small IT shops that want to see what's happening on their Windows machines without a week of setup.

There is no paid tier, no subscription feed, no founder-led sales motion, and no support relationship. Distribution is broadcast (blog post, Show HN, r/selfhosted, r/homelab), not outbound.

## Why (one paragraph, honest)

The content-as-a-service pivot (`docs/roadmap.md`, 2026-06-05) required founder-led B2B sales — cold outreach, pilot calls, ongoing customer support. The mid-Aug 2026 first-customer deadline passed with zero outreach sent, while every piece of avoidant-compatible work (pilot ruleset, validation harness, signing pipeline, GTM docs) got built. That is conclusive evidence about the founder's fit with that motion, not a scheduling problem. The product is real; the sales model wasn't. This strategy keeps the product, the reputation upside, and the founder's evenings.

## What changes

| Area | Old plan | Now |
|---|---|---|
| Revenue | Paid feed subscription (free/pro/msp tiers) | None. Optional GitHub Sponsors link only. |
| Feed / licence / Stripe / signing | Gaps #3–#4 of the roadmap; code built, dormant | **Parked in place**, marked dormant. Not deleted — git keeps it either way, and the code is the reopening option (see below). Tests keep passing. |
| Tiers | Locked free/pro/msp architecture | Moot. Tier language removed from all user-facing surfaces. The "no prices anywhere" rule survives trivially. |
| Rule editing | "Customer never edits a rule file" — Rule Builder was a contradiction to hide | Inverted: for a tinkerer audience, editable rules are a **feature**. Rule Builder and `rules.yml` editing are documented, not gated. |
| Support | Pilot onboarding, tuning-as-a-service | `SUPPORT.md`: provided as-is, best-effort; issue templates require diagnostic output (`Test-TinySocsHealth`). |
| GTM docs | one-pager, outreach templates, pilot/MSSP guides, ICP, competitive positioning | Archived or deleted (per the 2026-08-18 audit). No outreach will be sent. |
| Public validation dashboard | Weekly cadence, credibility lever | Stale (W23) instance taken down or replaced with an honest static summary. Weekly cadence is not promised. See `docs/pilot-ruleset.md` for the ground truth ledger. |
| Federation / orchestrator | MSP-tier feature | Kept, explicitly marked **experimental** in docs. |
| Licence | BSL-1.1 | **Unchanged.** Free to use under the Additional Use Grant; converts to Apache 2.0 per-version after 4 years. README states plainly that this is source-available, not OSI open source. Preserves commercial optionality at zero cost. |

## What does not change

- **Honesty rules.** The rule-count triad (19 enabled / 39 defined / 89 incl. the Python catalogue), the banned validation numbers (March 100%, raw 57.1%, W23 53.85%/61.5%), dual-engine honesty (the Python catalogue does not run in a default install). A free product earns its reputation the same way a paid one would.
- **Engineering discipline.** CI green, ASCII-only PowerShell, no secrets in repo, Atomic + xUnit evidence for any detection change.
- **BSL third-party discipline.** Vendored MIT/Apache code stays attributed, never re-licensed.

## Reopening condition

The commercial door reopens on **inbound signal only**: if real users ask to pay for maintained detection content, the dormant feed/licence/signing path (`src/tinysocs/api/feed.py`, `scripts/licence.py`, `PackLoader.cs`) is the product — self-serve checkout, no sales calls. Nothing else reopens it. No outbound motion will be planned again.

## Launch plan (broadcast only)

1. Repo truth-pass and zero-support scaffolding complete (this branch).
2. Launch blog post in the founder's voice: "I built a tiny SIEM for small Windows networks."
3. Show HN, r/selfhosted, r/homelab — one post each, written once, no follow-up obligation.
4. Then: watch. Respond to what's fun to respond to. Nothing is owed.

## Open questions

- Does the stale validation dashboard get rebuilt honestly (the `tinysocs-validation-publication-campaign` work) before launch, or taken down and replaced with a static pointer to `tests/atomic-results.json`? Taking it down is the zero-obligation default; rebuilding it is optional polish.
- Does the demo pack (`packs/demo`) ship in the free release or stay a dev artifact?
- Is a weekly "1 rule" cadence continued for fun, or explicitly not promised? (Current answer: not promised; do it if enjoyable.)
