# Content Cadence — Design

**Status**: draft
**Author**: Luke FitzGerald + Claude session, 2026-06-13.
**Covers strategic gap**: #6 (documented content cadence — 1 new rule + 1 tuning patch per week).
**Depends on**: `rule-format-v2.md` (pack schema, `pack_version`), `signed-feed.md` (sign + publish + channels), `continuous-validation.md` (the weekly Atomic Red Team run). This doc is **process, not code** — it stitches the already-built pieces into a repeatable weekly ritual and states honestly what is and isn't sustainable part-time.

---

## Why this exists

The revenue thesis is *"the platform is free; you pay for continuously-validated detection content delivered automatically."* "Continuously" is a promise. A founder pitch that makes it gets one question back: **"You're part-time. What's the actual pipeline, and can you keep it up?"** Gaps #1–#5 built the machinery — schema, signing, feed, paywall, docs. This doc is the operating procedure that turns the machinery into a *cadence* a buyer can believe and a public dashboard can prove.

The deliverable is deliberately small and regular: **one new rule + one tuning patch, packed-signed-published once per ISO week.** Regularity beats volume — a dated, signed, validated version every week is the credibility artifact, not the raw rule count.

## The weekly unit

A week produces exactly one immutable feed coordinate: `(base, <year.weeknum>)` — e.g. `base/2026.24`. Inside it:

| Half | What | Source (pre-customer) | Source (post-customer) |
|---|---|---|---|
| **1 new rule** | a `TS-NNN` entry added to the live agent rule set | a MITRE coverage gap (`reporting/mitre_coverage.py`) or an Atomic Red Team technique not yet detected | same, biased by what customer environments actually face |
| **1 tuning patch** | a threshold change, a new `field_match` value, or a widened `allowlist_scopes` on an existing rule | founder's own lab/validation observations | FP-feedback channel (deferred gap #8) once installs generate signal |

Both halves ship **inside the signed pack**. The customer never edits a rule file — tuning reaches them as new signed content, consistent with the pivot thesis (`rule-format-v2.md` → "Why v2 exists").

> **Honest caveat (read before pitching a feedback loop):** pre-customer, the "tuning patch" half is founder-sourced from your own validation runs and lab. There is no telemetry-driven FP loop yet — that's gap #8, deferred until there are paying installs to ask for consent. Pitch the cadence you have (validated, signed, weekly), not a closed-loop FP system you don't. The loop closes after the first customers, not before.

## The weekly pipeline

Every step below is an existing script. The cadence is the sequence, not new tooling.

```
1. SOURCE   pick the new rule + the tuning patch
            new rule:   reporting/mitre_coverage.py  (where's the heatmap cold?)
            patch:      last week's results/<iso-week>.json + lab observation

2. AUTHOR   edit packaging/detection/rules.yml      (the 39 live C# agent rules)
            add an Atomic test -> tests/atomic-tests.yaml   (expected_rules: [TS-NNN])
            -- a rule with no Atomic test does not ship. This is the gate.

3. VALIDATE pwsh scripts/run_weekly_validation.ps1   (harness -> results/ -> push)
            the new rule must be DETECTED (no MISS). A miss is published honestly
            (continuous-validation.md) and blocks promotion of that rule, not the run.

4. PACK     python scripts/migrate_rules_to_v2.py --version <year.weeknum>
            regenerates packs/base/<year.weeknum>/pack.yml from the v1 source

5. SIGN     python scripts/pack_sign.py sign packs/base/<year.weeknum>/pack.yml \
                   --key-id tinysocs-2026
            emits pack.yml.sig + pack.yml.canonical (the agent's trust path)

6. PUBLISH  upload packs/base/<year.weeknum>/ to the feed object store, then
            bump index.json: latest -> <year.weeknum>; snapshot auto-lags to the
            prior version (free tier is always one version behind — by design)

7. DOCS     if the new rule is customer-visible, scaffold its TinyDoc:
            python scripts/scaffold_tinydocs.py TS-NNN   (then write the body)
```

The validation step (3) is already automated as a Windows Task Scheduler job (`run_weekly_validation.ps1` → `docs/operator/weekly-validation-setup.md`), so the recurring human work is concentrated in steps 1–2 (author + faithful Atomic test) and 6 (publish). Steps 4–5 are one command each.

## Cadence invariants

These are the rules that keep the cadence honest under part-time pressure:

1. **One version per ISO week, never an in-place edit.** A fix to a shipped pack is a *new* `pack_version`, never a mutation of an existing coordinate — this is what makes client caching and rollback safe (`signed-feed.md` → "Version identity").
2. **No rule ships without a passing Atomic test.** The public validation dashboard is the credibility lever; shipping a rule the harness can't fire would poison it. The Atomic test is part of the rule, not an afterthought.
3. **A missed week degrades freshness, never function.** Skip a week and there's simply no new `latest`; free tier was already lagging and is unaffected, pro just gets no new content that week. Never backfill a fake version to "keep the streak" — the dashboard's dates are the proof, and faking them is the one thing that breaks the whole pitch. (Mirrors the `signed-feed.md` principle: billing/availability state degrades *freshness and breadth*, never the agent's function.)
4. **Tuning patches are content, not config.** A threshold tweak reaches customers as a new signed pack, not as an instruction to edit a file. If a change can't be expressed as pack content (schema-level), it's not a tuning patch — it's a release.

## Time budget (the part that has to be true)

Honest per-week estimate on an evenings/weekends budget:

| Step | Effort | Notes |
|---|---|---|
| Source rule + patch | ~30–45 min | mitre_coverage heatmap makes this fast; the judgement is "what's worth detecting," not "what's missing" |
| Author rule | ~30 min | mechanical given the v2 schema; `threshold_by_key` + optional `field_match` |
| **Author faithful Atomic test** | **~60–90 min** | **the real bottleneck.** Test fidelity is hard — see the TS-001 note in `tests/atomic-tests.yaml` (6-distinct-usernames vs one-account was a fidelity bug that hid as weak detection). Budget for this honestly. |
| Validate | ~0 min hands-on | automated job; you read the result |
| Pack + sign + publish | ~15 min | three commands + an upload |
| TinyDoc (when visible) | ~30 min | not every rule; the top-visible ones |

**~3–4 hours/week** when the Atomic test is non-trivial, ~2 when it's a variant of an existing technique. That fits a part-time budget — *but the Atomic test, not the rule, is the load-bearing cost.* If a week is tight, the rule is the cuttable half before the test quality is.

## Sustainability risks (sparring, not cheerleading)

- **Single point of failure.** One part-time founder *is* the cadence. Vacation, illness, or a hard week at the day job = a missed version. Invariant #3 makes that survivable, not invisible. Pre-hire, accept and document the gap; don't promise an SLA the headcount can't back.
- **The tuning-patch half is thin until there are customers.** Said above; worth repeating because it's the most over-claimable part of the pitch. A defensible framing: *"new validated detections weekly today; FP-driven tuning as the install base grows."*
- **Volume is not the story; provable regularity is.** ~50 rules/year on top of 39 is real growth, but the buyer-facing value is the *dated, signed, publicly-validated weekly drop* — the thing a DIY-rules competitor and a heavyweight like Huntress both fail to show transparently. Lead with the dashboard, not the count.

## Demo hook

The whole loop — *Stripe sub → signed key → live channel + premium → tamper-rejected → cancel revokes → agent verifies offline* — runs on a laptop with no cloud and no Stripe account:

```bash
scripts/demo_feed.sh
```

Pair it with the public validation dashboard (`site/validation/`, latest `docs/validation/2026-W23.md`) and you have both halves of the pitch in two artifacts: *"here's the content machine, and here's the public proof it works every week."*

## Non-goals

- The feed protocol, signing, and paywall — owned by `signed-feed.md`.
- The validation harness internals and the public dashboard — owned by `continuous-validation.md`.
- The FP-feedback telemetry channel — deferred gap #8; this doc assumes founder-sourced tuning until it lands.
- Premium-pack cadence — `m365-pack` and other backend (`runs_on: backend`) rules are disabled until the v2.1 KQL runner activates; cadence is `base`-only until then.
- Prices and SLAs.

## Open questions

1. **Intra-week hotfix versioning.** `pack_version` is `year.weeknum` — one slot per week. If a bad rule needs pulling mid-week, is the fix `2026.24` re-cut (violates immutability) or a sub-version `2026.24.1`? Lean sub-version; not yet in the schema. Decide before the first time it's needed, not during.
2. **Patch bundling.** Is "one tuning patch" literally one change, or "the tuning delta for the week" (possibly several small threshold tweaks)? The latter is more honest about how tuning actually accumulates. Probably bundle, and describe the week's patch in the pack changelog.
3. **Premium-pack cadence onset.** When the v2.1 backend runner activates, does `m365-pack` get its own weekly slot or ride `base`'s version stamp? Affects whether `pro` perceives premium as "also weekly."
4. **Cadence continuity at scale.** The first hire's first job is arguably *owning the cadence* so it survives the founder. Note it now; it's a post-first-customer decision.
</content>
</invoke>
