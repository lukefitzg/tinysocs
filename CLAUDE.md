# CLAUDE.md

## What this repo is

TinySOCs — a self-hosted SIEM for SMBs and small MSPs. Windows agent (C# .NET 8) ships events to a bundled OpenSearch backend, FastAPI services for dashboard/AI assistant/federation, Inno Setup installer for one-shot Windows deployment. ~28k LOC, ~330 commits, v0.10.0, BSL-1.1 licence (converts to Apache 2029).

## Strategic phase (mid-2026)

The product as currently shipped is implicitly a DIY platform: customer installs, customer tunes detection rules, customer maintains. SMB IT generalists cannot do this and will churn. The repo is pivoting to **detection-content-as-a-service**:

- Platform stays free or near-free, including a stale weekly snapshot of base rules.
- Recurring revenue is a paid subscription to a continuously-validated detection content feed: signed, version-pinned, delivered automatically.
- Tiers: free / pro / msp. Prices unset until first cohort of customer conversations; tier architecture is locked.
- Customer never edits a rule file. Tuning happens via allowlists, AI-assisted triage, and FP feedback that flows back to vendor.

**Hard timeline**: first paying customer in 8–12 weeks (mid-Aug 2026). Part-time founder budget (evenings/weekends).

Zero paying customers today. Zero pilots. GTM materials exist under `docs/` (one-pager, outreach templates, pilot guide, MSSP guide, competitive doc) but no outreach has happened.

## Repo realities you must know before changing anything

### The dual-engine "two rule files" is misleading

There are two YAML rule files but only **one running detection engine**:

1. **C# agent engine** (`src/TinySocs.Agent/Detection/`, rules in `packaging/detection/rules.yml`, shipped via the signed `base` pack under `packs/`) — a single rule type (`threshold_by_key`) against raw Windows events in-process. 39 rules are defined; **20 are enabled in the pilot base pack (2026.27)**, the rest disabled for per-environment tuning. **This is the only engine that actually fires alerts in production.**
2. **Python rule "catalogue"** (`src/tinysocs/agent/detections/rules.yaml`) — 50 KQL-based rules, but **no scheduled runner consumes them**. The file is read only by `reporting/mitre_coverage.py` (MITRE heatmap) and by the AI assistant as a `search_kql` corpus. Treat it as a documented roadmap library, not a running detection set.

When someone asks "how many rules does TinySOCs have," the honest answer is "20 enabled in the pilot base pack (2026.27), 39 defined in the C# engine, 89 including the roadmap catalogue." Don't conflate. (As of 2026-07-04 the pilot cut disabled 17 noisy/dead/duplicate rules and gave 4 mislabeled rules real `field_match` filters — see `docs/pilot-ruleset.md`. The disabled 17 stay in `rules.yml` as `enabled: false` for v2 redesign.)

The Python KQL engine activation is queued as v2.1 work (post-first-customer). For v2.0, only the C# engine runs.

### Other things that look like they might exist but don't

- **No allowlist primitives** in either engine today. Not even a `not_if` clause.
- **No rule signing, no rule feed, no licence checking, no Stripe integration.** All greenfield.
- **FIM is its own subsystem** (`FimConfig.cs`) that emits synthetic events into the C# engine. Don't treat FIM rules as "regular" rules — their event source is internal.
- The README footer used to claim "MIT" — fixed 2026-05-26 to BSL-1.1. If you see another stale "MIT" claim surface anywhere (CHANGELOG, package metadata, marketing site), fix it on sight.

### The 8 strategic gaps (from the strategic brief)

These define the work between now and first paying customer. Sequencing locked:

1. **Rule format v2** (in progress — see `docs/design/rule-format-v2.md`). Keystone for everything else.
2. **Continuous validation pipeline** (public weekly Atomic Red Team results) — runs in parallel with v2, biggest credibility lever.
3. **Signed rules feed** — depends on v2 schema being stable.
4. **Stripe + licence key gate** — pairs with the feed.
5. **TinyDocs** (per-rule knowledge base) for the top ~20 most-visible rules.
6. **Documented content cadence** (1 new rule + 1 tuning patch per week) — process doc, not code.

Deferred to post-first-customer:
- FP telemetry channel (needs the FP UI button to land first; consent ask is easier with paying customers).
- Backend Python KQL engine activation (v2.1).
- Premium pack tiering enforcement.

### Files you'll reach for often

| Path | What it is |
|---|---|
| `src/TinySocs.Agent/Detection/DetectionEngine.cs` | The actual detection runtime (C#) |
| `src/TinySocs.Agent/Detection/RuleLoader.cs` | v1 YAML → C# rule object |
| `packaging/detection/rules.yml` | The 39 rules that actually run |
| `src/tinysocs/agent/detections/rules.yaml` | 50-rule catalogue (not running) |
| `src/tinysocs/api/{bot,node,dashboard}.py` | FastAPI services |
| `src/tinysocs/reporting/frameworks/*.yaml` | Compliance mappings (NIST CSF, HIPAA, PCI DSS) |
| `tests/atomic-tests.yaml` + `tests/atomic-results.json` | Atomic Red Team validation harness |
| `docs/design/rule-format-v2.md` | Active design (this session) |
| `ledger/`, `src/tinysocs/orchestrator/`, `src/tinysocs/federation_certs.py` | Federation + HMAC evidence ledger |

## How I work

Carried mostly from `~/life-os/CLAUDE.md`:

- I think in systems. Don't oversimplify — give me the real tradeoffs.
- Be a sparring partner, not a yes-man. Push back when something is wrong or suboptimal.
- Dry, witty, direct. No preamble. No sycophancy.
- Default to simple and composable over clever.
- Production code by default — error handling, logging, the things I'd add anyway.
- Prefer CLI over GUI. Give me commands, not console instructions.
- If something will take more than 5 minutes to maintain, flag it.

TinySOCs-specific working preferences:

- **Design first, code second** for anything touching the rule engine, the feed protocol, or the licensing layer. These are the load-bearing decisions of the next 12 weeks — get them right on paper before writing C# or schema migrations.
- **Don't add features to the platform that don't move the content-as-a-service pivot forward.** If a task doesn't serve v2 schema, allowlists, validation pipeline, feed, Stripe, TinyDocs, or content cadence — it's probably a distraction.
- **Strong preference for shipping increments customers can see.** A pack with one new signed rule a week shipping to a feed is more valuable than three months of refactoring with nothing to show.
- **Treat the existing 39 rules + 50-rule catalogue as assets, not legacy.** Migration to v2 is mechanical, not interpretive. Don't rewrite detections during migration.
- **Maintain the dual-engine schema honesty.** Every v2 rule has a `runs_on` field. Don't quietly let backend rules ship as if they run.

## Don't do for me

- Don't suggest leveraging my Nielsen colleagues or management for TinySOCs outreach. Work network stays out. This is a hard rule, not a preference.
- Don't read or reason about `~/life-os/work/validatr/`. Validatr is a separate product on employer infrastructure; the IP question is unresolved and I'm keeping the two repos hermetically separated in conversation.
- Don't push prices into the schema or the marketing docs yet. Tier architecture is locked (free/pro/msp); prices land after first customer conversations.
- Don't recreate `docs/phase-N-summary.md` style retrospectives unless asked. The next 12 weeks are about shipping the pivot, not documenting phases.

## Working preferences for this repo specifically

### Code

- Python is the iteration language. C# is for runtime-critical agent paths. Prefer adding logic to the Python services when both would work and the latency cost is acceptable.
- The C# agent uses YamlDotNet with `UnderscoredNamingConvention`. v2 rule schema YAML must round-trip cleanly through it.
- The Python services target FastAPI; new endpoints follow the patterns in `src/tinysocs/api/`.
- Tests under `tests/`. Atomic Red Team integration is the validation gold standard — any new rule needs an Atomic test case (`tests/atomic-tests.yaml`).

### Design docs

- Live in `docs/design/`. Markdown only. Status header at the top (`draft`, `approved`, `implemented`, `superseded`).
- Cross-reference rather than re-state. If a decision is in another doc, link.
- Open questions section at the bottom — these are the things that keep the design honest.

### Commits

- Imperative present tense. Reference rule IDs (`TS-001`, etc.) and pack IDs (`base`, `m365-pack`, etc.) when relevant.
- Don't commit the contents of `data/`, `logs/`, `dist/`, `build/`, `.venv*/`, or anything in `vendor/` that we didn't author.
- The repo has a worktree at `.claude/worktrees/` — that's a prior session's worktree, not active. Ignore unless asked.

## Sensitive data + secrets

- No credentials in this repo. Ever.
- `.env.example` is the template; real `.env` is gitignored.
- HMAC keys, signing keys, OpenSearch passwords live outside the repo (real values in the user's password manager; placeholders in code/docs).
- BSL-1.1 licence — commercial rights reserved; each released version converts to Apache 2.0 four years after its first public release. Be careful what gets included from third-party MIT/Apache sources; vendor those, don't re-license.

## What belongs in this repo

- Product code (agent, services, dashboard, installer).
- Rule packs, TinyDocs (once authored), schemas, signed artifacts (the .sig files, not the keys).
- Design docs, GTM docs, compliance mappings.
- Atomic Red Team test cases and the validation harness output.
- The runbook + operator guides.

## What does NOT belong

- Customer data (real or synthetic-from-real).
- Telemetry received from installs (if/when FP feedback channel lands, the vendor-side store is a separate repo).
- Private signing keys.
- Anything that conflates this repo with Nielsen work product.

## Update this file when

- The dual-engine reality changes (Python runner activates, or schemas converge).
- A new top-level subsystem lands (Stripe integration, feed server, TinyDocs).
- The strategic phase shifts (post-first-customer, post-team-hire, post-Apache conversion).
- A hard rule changes (work network policy, validatr separation, etc.).
- Anything in here turns out to be wrong.
