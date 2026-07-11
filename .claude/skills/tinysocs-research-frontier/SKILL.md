---
name: tinysocs-research-frontier
description: Catalogue of TinySocs's deferred/unbuilt subsystems as open problems, ordered by leverage toward first paying customer (mid-Aug 2026) — allowlist runtime, signed-pack activation in real installs, FP telemetry channel, Python KQL backend runner (v2.1), rule-level baseline engine, premium-tier pack enforcement, AI-assisted triage. Load this when asked "what's left to build," "what should I work on next," "is X built yet," when scoping a new design doc for one of these gaps, or before claiming any of these features exist externally. Each entry states why it's deferred (with source), the concrete repo assets already in place, first three actionable steps with real file paths, and a falsifiable milestone. Everything here is unbuilt or dormant — do not describe any of it as shipped.
---

# TinySocs research frontier

Seven gaps between "code compiles" and "the pivot's promises are real." Ordered by leverage toward the first paying customer (target: mid-Aug 2026, per `CLAUDE.md` → "Strategic phase"). This is a **planning reference**, not a runbook — it tells you what's missing and where to start, not how to operate what already runs (see `tinysocs-run-and-operate`) or how the current system behaves (see `tinysocs-architecture-contract`).

**Binding constraint on all seven**: nothing here may be described externally as existing (`tinysocs-external-positioning` owns the honest-claims list). Any change that touches detection behavior, public claims, or the locked free/pro/msp tier architecture gates through `tinysocs-change-control` — this skill scopes the work, it does not authorize starting it.

Ground truth verified 2026-07-11 at branch `fix/ci-green`, HEAD `37005ad`. Two brief-era "gaps" mentioned in older strategy docs are **already built** and are intentionally NOT listed here as open problems: rule signing (`Ed25519Verifier.cs`, `PackLoader.cs`), the feed server + Stripe webhook (`src/tinysocs/api/feed.py`), and TinyDocs (`tinydocs/*.md`, `RuleDocs.cs`). See `tinysocs-architecture-contract` for how those work today — problem #2 below is about why the signed-pack path is *dormant in real installs* despite being built, which is a different gap.

---

## 1. Allowlist runtime — the v2.0 "must build" that never landed

**Leverage: highest.** This is the mechanism the entire pivot's tuning story depends on ("customer never edits a rule file... tuning happens via allowlists" — `CLAUDE.md` → "Strategic phase"). Without it, "tuning via allowlists" is vapor and support load falls back to editing YAML by hand, which is exactly what SMB generalists can't do.

**Why deferred**: it was never actually started, not formally deferred. `docs/design/rule-format-v2.md:30` states plainly: *"No allowlist primitives exist in either engine... There is no 'exclude this user/host/process from this rule' mechanism anywhere."* That line is still true — `grep -rn -i "allowlist" src/TinySocs.Agent/` returns zero hits (verified 2026-07-11).

**Asset already in this repo** (bigger than usual — the schema and the design are both done, only the runtime is missing):
- Every rule in every signed pack already carries `allowlist_scopes` — e.g. `packs/base/2026.27/pack.yml:32` (TS-001: `[user, user_pattern, host]`), `pack.yml:70` (TS-002: `[source_ip, source_ip_cidr]`). The C# schema field exists; nothing reads it.
- Full merge semantics are designed, not just sketched, in `docs/design/rule-format-v2.md:237-296`:
  - File: `C:\ProgramData\TinySocs\Collector\allowlists.yml` (customer-local, unsigned, never in the signed pack, never sent to the vendor — `rule-format-v2.md:239,61`).
  - Scope vocabulary and per-rule declaration: engine attaches an allowlist entry to a rule only if the entry's scope is in that rule's `allowlist_scopes`; an entry citing an undeclared scope is a **loud skip** — log + skip, never silently ignored (`rule-format-v2.md:275`).
  - Pipeline: parse `allowlists.yml` → key entries by `rule_id` → attach matching scopes → at detection time, condition match → evaluate attached allowlist → suppress on match, else alert (`rule-format-v2.md:281-283`).
  - Hot reload: file watcher on `allowlists.yml`, atomic reload, no agent restart (`rule-format-v2.md:285`).
  - Two open questions the design doc leaves for the implementer (`rule-format-v2.md:389-391`): where entries originate in the UI (probably the alert-details view — "mark as FP → allowlist [user] from this rule," which couples this to problem #3 below), and how to surface a stale entry referencing a since-removed `rule_id`.

**First three steps in this repo**:
1. Read `docs/design/rule-format-v2.md:237-296` end to end — the merge semantics are the spec, don't re-derive them.
2. Add an `AllowlistLoader` beside `src/TinySocs.Agent/Detection/RuleLoader.cs` (same directory, same `YamlDotNet` + `UnderscoredNamingConvention` pattern already used there) that parses `allowlists.yml` and indexes entries by `rule_id` + scope. Wire a `FileSystemWatcher` for hot reload — `RuleLoader`'s sibling, `TryReloadRules()` in `OpenSearchBulkShipper.cs:1369-1386`, is a poll-based *analogue* to imitate for reload semantics, but the design doc calls for a watcher, not a timer — don't silently downgrade to polling.
3. Thread allowlist suppression into `DetectionEngine.EvaluateEvent` (`src/TinySocs.Agent/Detection/DetectionEngine.cs`) after a `threshold_by_key` condition matches and before an alert is emitted — check the matched key's fields against any attached allowlist entry for that rule's declared `allowlist_scopes`, suppress on hit.

**You have a result when**: an xUnit test in `tests/TinySocs.Agent.Tests` (sibling to `DetectionEngineTests.cs`) proves that a synthetic event which would fire TS-001 (brute-force logon) is suppressed when the triggering `TargetUserName` is present in a `user` or `user_pattern` scope entry in a test `allowlists.yml`, and fires normally when the entry is absent or scoped to something TS-001 doesn't declare (loud-skip path exercised, not just the happy path).

---

## 2. Signed-pack activation gap — built but dormant in every real install

**Leverage: very high, low effort.** The engine and vendor-side trust path (problem list intro, above) are done and tested. What's missing is turning it on for anyone who isn't a developer running the CLI by hand. Until this closes, "signed, version-pinned, delivered automatically" (`CLAUDE.md` strategic-phase description) is true of the code and false of every shipping install.

**Why deferred**: opt-in by design during the build-out so existing installs weren't disrupted — see the comment at `src/TinySocs.Agent/Configuration/AgentConfig.cs:133-135` ("Opt-in so existing installs are unaffected until the feed is rolled out"). That rollout step never happened.

**Verified current state**:
- `ContentPackConfig.Enabled` defaults to `false` — `AgentConfig.cs:146`.
- The example config template that ships to customers, `config/agent-config.example.yml:95-99`, has a `detection:` block pointing at `rules_file: ...\rules.yml` and **no `pack:` sub-block at all** — an operator following the template has no path to the signed pack even if they wanted one.
- The Inno Setup installer, `packaging/iss/Quickstart.iss`, stages `packaging/detection/rules.yml` and `rule_docs.yml` (lines 84, 90) into `Collector\rules\` — it stages **no `packs/` directory and no public key**. Grep for `.pub`/pack staging in the installer returns nothing.
- Net effect: every install today runs the legacy unsigned `RuleLoader` path against `rules.yml`, 60-second poll reload (`AgentConfig.cs:130`/`133`, default `ReloadIntervalSeconds`). The `PackLoader`/`Ed25519Verifier`/`LicenceReader` trio never executes outside manual CLI testing.

**First three steps in this repo**:
1. Add a `pack:` block to `config/agent-config.example.yml` under the existing `detection:` key, mirroring `ContentPackConfig`'s fields (`AgentConfig.cs:144-160`: `enabled`, `pack_file`, `signature_file`, `public_key`, `signing_key_id`) so the documented default install path includes it.
2. Extend `packaging/iss/Quickstart.iss` to stage a `packs/base/<version>/pack.yml.canonical` + matching `.sig` + the embedded public key (`keys/tinysocs-2026.pub` content, baked in at build time — never the private key) into `Collector\packs\`, alongside the existing `rules.yml` staging block (`Quickstart.iss:82-90`).
3. Flip `ContentPackConfig.Enabled` default to `true` **for new installs only** (gate this through `tinysocs-change-control` — it changes detection-loading behavior) once (1) and (2) are staged and a VM install has been smoke-tested per `tinysocs-run-and-operate`.

**You have a result when**: a fresh Quickstart install on a clean Windows VM produces an agent log line showing `PackLoader` verified and loaded `2026.27` (or later) — not `RuleLoader` reading `rules.yml` — with no manual config edits after setup completes.

---

## 3. FP telemetry channel — blocked on the FP UI, then on a separate repo

**Leverage: high but sequenced behind #1.** This is the feedback loop that lets vendor-curated content actually improve from real customer environments ("FP feedback that flows back to vendor" — `CLAUDE.md`). Not on the first-customer critical path, but it's the thing that makes the subscription defensible in month 2+.

**Why deferred** (two independent reasons, both current):
- Needs the FP UI button to land first — `CLAUDE.md:52`, `docs/roadmap.md:98`: *"needs the FP UI button to land first; the consent ask is easier with paying customers."*
- `docs/design/rule-format-v2.md:389` (design open question #1) ties allowlist-entry creation to the alert-details "mark as FP → allowlist [user]" flow — meaning the UI surface for problem #1 and the UI surface for FP telemetry are the same click, which means this can't really start independently of #1.
- The vendor-side telemetry store is explicitly **out of this repo's scope** per `CLAUDE.md` → "What does NOT belong": *"Telemetry received from installs (if/when FP feedback channel lands, the vendor-side store is a separate repo)."* This is a hard rule, not a design choice — don't build a telemetry ingestion service inside `tinysocs`.

**Asset in this repo**: `src/tinysocs/api/dashboard.py` already has a generic "dismiss recommendation — false positive or not applicable" action (`dashboard.py:4275`, confirm dialog at `dashboard.py:8602`) for a *different* feature (recommendations), which is the closest existing UI pattern to imitate for an alert-level FP button — it is not itself the FP telemetry channel and doesn't write anywhere durable today.

**First three steps in this repo** (once #1's allowlist UI groundwork exists — don't start this cold):
1. Design the alert-details "mark as FP" surface as an extension of the allowlist-entry-creation flow from problem #1, not a separate control — resolve `rule-format-v2.md:389`'s open question explicitly in a design doc.
2. Scope exactly what leaves the customer's box: rule_id + scope + anonymized match context, nothing that looks like customer data (`CLAUDE.md` → "What does NOT belong" — no real or synthetic-from-real customer data in this repo, and telemetry receipt is a separate repo by rule).
3. Write the consent copy and the opt-in default (off, per the roadmap's "consent ask is easier with paying customers" reasoning) before writing any code — this is a design-first item per `CLAUDE.md` working preferences (touches the AI/tuning layer).

**You have a result when**: there's a written design doc (`docs/design/fp-telemetry.md`, doesn't exist yet) with status `draft`, cross-referencing `rule-format-v2.md`'s open question #1 — code follows only after that's `approved`. Do not build the local half of this ahead of the design doc; the coupling to problem #1's UI makes premature code likely to need a rewrite.

---

## 4. Python KQL backend runner activation (v2.1, explicitly post-first-customer)

**Leverage: deliberately low right now.** This is Strategy B's parking lot: `docs/design/rule-format-v2.md`'s "Strategy decision: v2.0 ships C#-only" section scoped the backend engine out of v2.0 on purpose so the keystone schema could ship without waiting on a second running engine. `CLAUDE.md` confirms: *"The Python KQL engine activation is queued as v2.1 work (post-first-customer)."*

**Asset in this repo**:
- 50 KQL-based rules already exist in `src/tinysocs/agent/detections/rules.yaml`, loaded into a `RULES` dict by `src/tinysocs/agent/detections/registry.py:141` (`_load_rules_from_yaml()`), and already **executable on demand** — `src/tinysocs/api/node.py:565` (`GET /agg`) and `node.py:594` (`POST /agg`) run any subset of `RULES` against OpenSearch for an arbitrary window right now. What's missing is only the *scheduler*, not the query engine.
- **Correction to a common assumption**: these 50 rules are **not yet migrated into v2 schema form**. `scripts/migrate_rules_to_v2.py:18-20` says so explicitly: *"This migrates only the C# agent rules... The 50-rule Python catalogue (`src/tinysocs/agent/detections/rules.yaml`, `runs_on: backend`) is a separate mechanical pass, deferred until the backend runner activates (v2.1)."* `runs_on: backend` is documented *intent* in that comment, not a field present in any file on disk today — `rules.yaml` is still v1 shape (verify: `grep -c "runs_on" src/tinysocs/agent/detections/rules.yaml` returns 0 as of 2026-07-11). Don't claim these 50 rules are "in v2 form" — they aren't yet.

**First three steps in this repo** (when v2.1 is actually scheduled — not before first customer):
1. Run the *backend* analogue of `scripts/migrate_rules_to_v2.py` — doesn't exist yet, needs authoring — to lift `src/tinysocs/agent/detections/rules.yaml` into v2 pack shape with `runs_on: backend`, per the deferred-pass note above.
2. Add a scheduler (APScheduler or a simple cron-style loop; `grep -rn "import.*schedul\|BackgroundScheduler\|croniter\|apscheduler" src/tinysocs/agent/ src/tinysocs/api/` returns nothing — there is no scheduling *library* wired into this codebase to reuse; the plain-text hits for "schedule"/"cron" in `tools.py`, `actions.yaml`, and `rules.yaml`'s `scheduled_task_creation` rule are an unrelated agent-tool schema and a detection rule name, not a scheduling primitive) that periodically calls the same code path `node.py`'s `/agg` already uses, writing hits into `tinysocs-alerts-*` instead of returning them synchronously.
3. Preserve `runs_on` honesty end-to-end: the migrated backend rules must never appear in a C# `PackLoader`-consumed pack, and the C# `RuleLoader`/`PackLoader` must keep ignoring `runs_on: backend` entries if packs ever mix engines in one file (`tinysocs-architecture-contract` owns this invariant — read it before touching either loader).

**You have a result when**: a scheduled run (not a manual `/agg` call) writes a backend-engine alert document into `tinysocs-alerts-*` tagged `runs_on: backend`, and `reporting/mitre_coverage.py`'s heatmap (which already reads both rule files, `mitre_coverage.py:29-30`) can be checked to confirm it isn't double-counting a rule that now fires from two engines.

---

## 5. Baseline engine (rule-level learning-period baselines) — schema inert by design

**Leverage: low, not urgent.** Baselines ("rules auto-quiet down per environment," `rule-format-v2.md:17`) are a maturity feature for month 3+ tuning, not a blocker for a first pilot running curated, human-tuned thresholds.

**Why deferred**: explicit design decision, not an oversight. `docs/design/rule-format-v2.md:298`: *"Baseline is not built in v2.0. The field is in the schema; the engine treats `baseline.enabled: true` as a runtime warning ('baseline not yet implemented') until v2.0.x adds it. No rule in v2.0 sets `enabled: true`."* Verify the last clause: `grep -c "enabled: true" packaging/detection/rules.yml | grep -B2 baseline` — every shipped rule's `baseline.enabled` is `false` (see e.g. `packs/base/2026.27/pack.yml.canonical`, TS-001's baseline block: `"enabled":false`).

**Do not confuse with**: FIM's own file-hash baseline (`src/TinySocs.Agent/Configuration/FimConfig.cs:56`, `BaselinePath` → `fim-baseline.json`, populated by `FileIntegrityInput.cs:156-221`). That's a real, running, per-file-hash baseline used to detect *drift from a known file state* — a completely different mechanism from the rule-level statistical baseline (`baseline.keyed_by` + `learning_days` + `action_below_baseline`) described in the schema. FIM baselining works today; rule-level baselining does not exist anywhere.

**First three steps in this repo** (treat as a v2.0.x point release per the design doc, not urgent):
1. Re-read `rule-format-v2.md:287-296` for exact semantics: sliding `learning_days` window of counts grouped by `baseline.keyed_by`, three post-learning actions (`suppress`, `downgrade_severity`, `tag`).
2. Decide storage: the design doc says baseline data lives "alongside `allowlists.yml`: customer-local, not shipped to vendor" (`rule-format-v2.md:296`) — this makes it a natural extension of whatever `AllowlistLoader` gets built for problem #1; don't build a separate storage mechanism.
3. Add the runtime warning first (cheap, and closes a silent-trust gap): if any pack ships a rule with `baseline.enabled: true` before the engine supports it, `RuleLoader`/`PackLoader` should log a loud warning rather than silently ignoring the field — the design doc calls for this and it doesn't exist yet either (`grep -rn "baseline" src/TinySocs.Agent/Detection/` to confirm before/after).

**You have a result when**: a rule with `baseline.enabled: true` and `action_below_baseline: suppress` demonstrably suppresses an alert that would otherwise fire once its `learning_days` window has data, proven by an xUnit test — until then, treat any pack setting `baseline.enabled: true` as a bug, not a feature, per the design doc's own instruction.

---

## 6. Premium-tier pack enforcement — protocol done, content and pricing missing

**Leverage: medium, but genuinely blocked on business inputs, not engineering.** The entitlement *mechanism* is finished; what's missing is (a) packs worth paying for and (b) real prices, and (b) is explicitly locked.

**Why deferred**: `docs/roadmap.md:100`: *"Premium pack tiering enforcement — tier architecture is locked, enforcement waits."* `CLAUDE.md:54` lists it alongside FP telemetry as deferred to post-first-customer. Separately, `CLAUDE.md` → "Don't do for me": *"Don't push prices into the schema or the marketing docs yet... prices land after first customer conversations."* That's a hard rule, not a task to route around.

**Verified current state**:
- The entitlement gate is real and tested: `LicenceReader.cs` (`EntitlementFor("pro")`, `EntitlementFor("msp")` — `LicenceReader.cs:39,45`) and `feed.py`'s `can_access(tier, pack_id, channel)` check (`feed.py:153-156`) both enforce tier → pack/channel access.
- Stripe wiring is protocol-complete without a live account: `scripts/stripe_pricing.py` maps opaque `price_id` env vars (`TINYSOCS_PRICE_PRO`, `TINYSOCS_PRICE_MSP`) to tiers with no Stripe SDK dependency (`stripe_pricing.py:21-23,45`), and `feed.py:244-256` resolves a webhook payload's `price_id` through it to mint/revoke licence keys. `docs/roadmap.md:39` confirms this loop "runs locally with no cloud account" and is covered by `tests/test_feed_server.py`.
- What's actually missing: real per-tier pack **content**. `find packs -maxdepth 2 -type d` shows only `packs/base/*` (free tier) and `packs/demo/*` (lab/demo, never shipped) — there is no `pro` or `msp` pack directory anywhere. There's nothing yet to gate.

**First three steps in this repo** (mostly business-sequenced, not code-sequenced):
1. Do not touch pricing. Wait for the first cohort of customer conversations per `CLAUDE.md`.
2. When ready to scope pro/msp *content* (not price): identify which of the 12 Python-catalogue-only rules noted in `rule-format-v2.md:28` (M365 cloud-identity, cross-source geo-anomaly, network/firewall rules — "the natural home for... the obvious shape of 'premium packs'") make sense as a `pro`-tier pack once problem #4's backend runner exists — premium content without a running engine to fire it is just marketing.
3. When content exists, extend `scripts/migrate_rules_to_v2.py` (or its problem-#4 backend sibling) with a `--tier pro` flag to emit `packs/pro/<version>/pack.yml`, then sign with `scripts/pack_sign.py` and set real `TINYSOCS_PRICE_PRO`/`TINYSOCS_PRICE_MSP` env vars only once Stripe prices exist.

**You have a result when**: a `packs/pro/<version>/` (or `msp`) directory exists with rules genuinely distinct from `base`, `feed.py`'s `can_access` denies a `free`-tier key that pack, and a `pro`-tier key succeeds — all provable without needing real prices set (test with a fake `TINYSOCS_PRICE_PRO` env value, exactly as `tests/test_feed_server.py` already does).

---

## 7. AI-assisted triage — concept only, no design doc yet

**Leverage: lowest of the seven for the first-customer deadline** — explicitly flagged as off that path. Real longer-term value (it's the mechanism that makes "tuning via... AI-assisted triage" in `CLAUDE.md`'s strategic phase true), but starting code here now risks becoming, in the roadmap's own words, "the shiny thing that stalls the revenue loop" (`docs/roadmap.md:123`).

**Why deferred**: `docs/roadmap.md:37` (workstream table, item 7) status is literally **"concept — design-first; no design doc yet."** It was added later than the original six-gap brief: `docs/roadmap.md:60`, "Workstream #7 — AI-assisted triage & schema-grounded querying (added 2026-06-15)." Confirmed: `find docs -iname "*triage*"` returns nothing — `docs/design/ai-triage.md` genuinely does not exist as of 2026-07-11, despite being named as the target path in the roadmap.

**Asset in this repo**: a thin assistant already exists — `src/tinysocs/api/bot.py`, reading the 50-rule KQL catalogue via a `search_kql` tool corpus (`docs/roadmap.md:62`; corpus wiring in `src/tinysocs/agent/tools.py` and `src/tinysocs/agent/detections/registry.py`). This is described in the roadmap as "the only piece that exists" toward this workstream — a retrieval corpus, not triage logic.

**Dependencies noted in the roadmap** (don't start out of order): needs #1 (v2 schema — already stable, satisfied) for catalogue grounding; pairs with the deferred FP telemetry channel (problem #3 above) as "the consent-friendly front end for that channel" (`docs/roadmap.md:74`).

**First three steps in this repo**:
1. Write `docs/design/ai-triage.md` — this is the actual first step, not optional preamble. Follow `tinysocs-docs-and-writing` conventions: status header (`draft`), cross-reference `rule-format-v2.md` and `bot.py` rather than restating them, open-questions section at the bottom.
2. Scope the "known-good-query + gotchas corpus" the roadmap calls for (`docs/roadmap.md:67`): vetted queries, detection context, and query gotchas the assistant retrieves from — decide whether this extends the existing `search_kql` corpus in `registry.py`/`tools.py` or is a new retrieval source.
3. Explicitly resolve, in the design doc, how this triage surface relates to the FP-mark / allowlist-creation UI from problems #1 and #3 — the roadmap ties them together ("the lessons loop is the consent-friendly front end for that [FP telemetry] channel") and building triage UI without that resolved risks the same coupling mistake flagged in problem #3.

**You have a result when**: `docs/design/ai-triage.md` exists with status `approved` (not before — this is design-first per `CLAUDE.md` working preferences, "anything touching... the licensing layer" and, by the same logic the roadmap applies, the AI layer). Do not write triage code against a `draft` doc.

---

## When NOT to use this skill

- To find out what already runs in production today → `tinysocs-architecture-contract` (dual-engine split, signed-pack trust path as-built, known weak points) or `tinysocs-config-and-flags` (which flags are production-safe vs experimental).
- To decide whether a change is worth doing at all, or how to gate it → `tinysocs-change-control` (pivot-alignment filter, CI-green rule, plan-docs-not-committed rule). This skill scopes *what* the gaps are; change-control decides *whether and how* to start closing one.
- To write the actual validation/proof harness for a rule or a fix → `tinysocs-detection-validation-toolkit` and `tinysocs-validation-and-qa`.
- To find precedent for a previously-abandoned approach before restarting one of these gaps → `tinysocs-failure-archaeology` (dead ends, reverts, root causes).
- To phrase any of these gaps for a prospect or in GTM material → `tinysocs-external-positioning` (banned efficacy figures, honest rule-count triad, what may/may not be claimed as built). Never let this skill's "asset already in place" language leak into an external claim that a gap is closed.
- To evaluate whether a *candidate rule* (not a subsystem) has enough evidence to ship → `tinysocs-research-methodology`.

---

## Provenance and maintenance

Authored 2026-07-11, branch `fix/ci-green`, HEAD `37005ad`. Every claim in this file was checked directly against the repository on that date (not sourced from digests alone) — see the grep/find commands cited inline. Primary sources:

- `/Users/lukefitzgerald/tinysocs/CLAUDE.md` (strategic phase, 8 gaps list, "don't do for me" hard rules)
- `/Users/lukefitzgerald/tinysocs/docs/roadmap.md` (workstream table, workstream #7 section, "still-deferred" lines 39/98/100)
- `/Users/lukefitzgerald/tinysocs/docs/design/rule-format-v2.md` (allowlist design §237-296, baseline design §287-298, audit findings §1-7, status header)
- `/Users/lukefitzgerald/tinysocs/src/TinySocs.Agent/Configuration/AgentConfig.cs` (`ContentPackConfig.Enabled` default, line 146)
- `/Users/lukefitzgerald/tinysocs/config/agent-config.example.yml` (no `pack:` block, confirmed line 95-99)
- `/Users/lukefitzgerald/tinysocs/packaging/iss/Quickstart.iss` (rules.yml/rule_docs.yml staging, lines 82-90; no pack/key staging)
- `/Users/lukefitzgerald/tinysocs/src/TinySocs.Agent/Detection/LicenceReader.cs`, `/Users/lukefitzgerald/tinysocs/src/tinysocs/api/feed.py`, `/Users/lukefitzgerald/tinysocs/scripts/stripe_pricing.py` (entitlement/Stripe protocol)
- `/Users/lukefitzgerald/tinysocs/scripts/migrate_rules_to_v2.py` (lines 18-20: backend catalogue migration explicitly deferred to v2.1)
- `/Users/lukefitzgerald/tinysocs/src/tinysocs/api/node.py` (`/agg` endpoint, lines 565, 594), `/Users/lukefitzgerald/tinysocs/src/tinysocs/agent/detections/registry.py` (`RULES` dict, line 141)
- `/Users/lukefitzgerald/tinysocs/src/TinySocs.Agent/Configuration/FimConfig.cs` + `FileIntegrityInput.cs` (FIM's distinct file-hash baseline)
- `/Users/lukefitzgerald/tinysocs/packs/` directory listing (only `base` and `demo` tiers exist)

Re-verification commands, one per volatile fact class:

```bash
# 1. Allowlist runtime still unbuilt
grep -rn -i "allowlist" src/TinySocs.Agent/ | wc -l   # expect 0

# 2. Signed-pack activation still opt-in / off by default
grep -n "public bool Enabled" src/TinySocs.Agent/Configuration/AgentConfig.cs   # expect "= false;" on the ContentPackConfig one (second match)
grep -n "^pack:" config/agent-config.example.yml       # expect no match
grep -n "packs\\\\" packaging/iss/Quickstart.iss       # expect no match (no packs/ staged)

# 3. FP UI / telemetry channel status
grep -n -i "FP UI\|FP telemetry" CLAUDE.md docs/roadmap.md

# 4. Backend rules not yet in v2 form
grep -c "runs_on" src/tinysocs/agent/detections/rules.yaml   # expect 0
grep -n "deferred until the backend runner activates" scripts/migrate_rules_to_v2.py

# 5. Baseline still schema-inert
grep -n "baseline.enabled: true" packaging/detection/rules.yml packs/base/*/pack.yml   # expect no live "true"

# 6. Premium tier packs still absent
find packs -maxdepth 1 -type d   # expect only base, demo — no pro, no msp

# 7. AI-triage design doc still unwritten
find docs -iname "*triage*"   # expect no results; when it appears, this problem is no longer "no design doc"
```

Update this file when any of the seven closes (move it out, don't just relabel it), when a new gap opens (e.g. if the FP UI button lands, re-check whether problem #3 becomes actionable), or when the strategic phase shifts per `CLAUDE.md`'s own "Update this file when" list.
