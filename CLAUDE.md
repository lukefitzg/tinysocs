# CLAUDE.md

## What this repo is

TinySOCs — a self-hosted SIEM for small Windows networks: homelabs, tinkerers, students, small IT shops. Windows agent (C# .NET 8) ships events to a bundled OpenSearch backend, FastAPI services for dashboard/AI assistant/federation, Inno Setup installer for one-shot Windows deployment. ~28k LOC, v0.10.0, BSL-1.1 licence (source-available; each version converts to Apache 2.0 after 4 years).

## Strategic phase (2026-08-18: free zero-support release)

Canonical decision record: `docs/design/strategy-zero-support.md`. The short version:

- TinySOCs is a **free, zero-support, source-available** tool. No paid tiers, no subscription feed, no founder-led sales, no support relationship. Distribution is broadcast (blog post, Show HN, r/selfhosted, r/homelab) — write once, no follow-up obligation.
- The previous detection-content-as-a-service pivot (`docs/roadmap.md`, now superseded) was abandoned 2026-08-18: its mid-Aug first-customer deadline passed with zero outreach ever sent. The commercial machinery it produced (feed server, licence gate, pack signing, Stripe scaffolding) is **parked in place, dormant** — the reopening option if inbound demand ever appears. Inbound only; no outbound motion gets planned again.
- Rule editing flipped from liability to feature: the audience is tinkerers, so the Rule Builder and direct `rules.yml` editing are documented, not hidden. The old "customer never edits a rule file" constraint is dead.
- Support posture: `SUPPORT.md` (as-is, best-effort), issue templates that require `Test-TinySocsHealth` output. Nothing is owed to anyone.

## Repo realities you must know before changing anything

### The dual-engine "two rule files" is misleading

There are two YAML rule files but only **one running detection engine**:

1. **C# agent engine** (`src/TinySocs.Agent/Detection/`, rules in `packaging/detection/rules.yml`, shipped via the signed `base` pack under `packs/`) — a single rule type (`threshold_by_key`) against raw Windows events in-process. 39 rules are defined; **19 are enabled in the pilot base pack (2026.27)**, the rest disabled for per-environment tuning. **This is the only engine that actually fires alerts in production.**
2. **Python rule "catalogue"** (`src/tinysocs/agent/detections/rules.yaml`) — 50 KQL-based rules with **no scheduled runner in a default install**. Read by `reporting/mitre_coverage.py` (MITRE heatmap) and the AI assistant's `search_kql` corpus. One exception: the opt-in federation path (`scripts/Install-OperatorTasks.ps1` → `TinySocs-MasterHeartbeat` task → orchestrator → node `/agg`) does execute a small subset (`ps_script_block`, `auth_failed_burst` by default) on a schedule — but `Quickstart.iss` never wires that up, so a stock install runs none of it. Treat the catalogue as a documented rule library, not a running detection set.

When someone asks "how many rules does TinySOCs have," the honest answer is "19 enabled in the pilot base pack (2026.27), 39 defined in the C# engine, 89 including the roadmap catalogue." Don't conflate. (As of 2026-07-04 the pilot cut disabled 17 noisy/dead/duplicate rules and gave 4 mislabeled rules real `field_match` filters — see `docs/pilot-ruleset.md`. A 2026-07-08 validation pass then found two more dead rules: TS-113 grouped by a field FIM events never carried — fixed in `FileIntegrityInput` — and TS-120 was unwired with no event source, so it was deferred too. That makes 18 non-lab rules held back as `enabled: false` for v2, 19 enabled. All 19 are proven to fire by `DetectionEngineTests.cs`.)

There is no plan to activate the Python KQL engine. It stays a library unless someone wires it up for fun.

### Dormant subsystems (exist, built, deliberately not live)

- **Signed-pack trust path**: `PackLoader.cs`, `Ed25519Verifier.cs`, `LicenceReader.cs` exist and work, but `ContentPackConfig.Enabled` defaults `false` and the installer ships the legacy unsigned `rules.yml` via `RuleLoader.cs`. Parked per the strategy doc.
- **Feed server + licensing**: `src/tinysocs/api/feed.py`, `feed_store.py`, `scripts/{pack_sign,licence,stripe_pricing}.py`. Built during the abandoned pivot; dormant; tests still run. Don't extend, don't delete.
- **No allowlist primitives** in either engine. Not even a `not_if` clause. (Schema fields exist in the v2 design; no runtime.)
- **FIM is its own subsystem** (`FimConfig.cs`) that emits synthetic events into the C# engine. Don't treat FIM rules as "regular" rules — their event source is internal.
- The README footer used to claim "MIT" — fixed 2026-05-26 to BSL-1.1. If you see another stale "MIT" claim surface anywhere (CHANGELOG, package metadata, marketing site), fix it on sight.

### The work between now and public launch

See `docs/design/strategy-zero-support.md` §Launch plan. In one line: truth-pass on every public claim, zero-support scaffolding (SUPPORT.md, issue templates, health-check surfacing), bulletproof install/uninstall, then broadcast launch. No feature work is on the critical path.

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
| `docs/design/strategy-zero-support.md` | Current strategy (canonical decision record) |
| `docs/design/rule-format-v2.md` | v2 pack schema (implemented; feed usage dormant) |
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

- **Design first, code second** for anything touching the rule engine or the installer's trust path. Get load-bearing decisions right on paper before writing C# or schema migrations.
- **Don't add work that doesn't serve the free launch.** If a task doesn't serve the truth pass, zero-support scaffolding, install/uninstall reliability, or launch materials — it's probably a distraction. Feature work resumes only if the project turns out to be fun post-launch.
- **Minimise standing obligations.** Anything that implies a promise to strangers (a weekly cadence, a support channel, a live dashboard) either gets automated to zero-touch or doesn't ship.
- **Treat the existing 39 rules + 50-rule catalogue as assets, not legacy.** Don't rewrite detections during mechanical migrations.
- **Maintain the dual-engine schema honesty.** Every v2 rule has a `runs_on` field. Don't quietly let backend rules ship as if they run.

## Don't do for me

- Don't suggest leveraging my Nielsen colleagues or management for TinySOCs outreach. Work network stays out. This is a hard rule, not a preference.
- Don't read or reason about `~/life-os/work/validatr/`. Validatr is a separate product on employer infrastructure; the IP question is unresolved and I'm keeping the two repos hermetically separated in conversation.
- Don't add pricing, tier, or subscription language anywhere — code, docs, or site. The commercial path is parked (see `docs/design/strategy-zero-support.md`); the old free/pro/msp tier design survives only inside the dormant code and its design docs.
- Don't recreate `docs/phase-N-summary.md` style retrospectives unless asked.
- Don't propose outbound GTM work (outreach, pilots, sales collateral). That chapter is closed; the strategy doc's reopening condition is inbound demand only.

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
