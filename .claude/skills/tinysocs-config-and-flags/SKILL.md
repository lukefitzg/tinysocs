---
name: tinysocs-config-and-flags
description: Configuration atlas for TinySocs — every config file, env var, and default across the C# agent and the Python services (dashboard, bot, node/federation, feed/licensing). Load this when you need to know what a setting actually defaults to, which env var wins when two exist, why an agent won't ship telemetry (Detection.Pack.Enabled defaults false, TLS verify defaults off), why federation refuses to start (MASTER_SHARED_SECRET fatal), which LLM_MODE default is live at a given call site, or why .env.example doesn't match what a service actually reads. Also load when auditing "is this safe to run in prod" for TLS verify flags, credential fallback chains, or SMTP env families. Not for the detection rule schema itself (see detection-engineering-reference) or for installer/service mechanics (see tinysocs-run-and-operate).
---

# TinySocs config and flags atlas

Ground truth verified directly in the repo on 2026-07-11 against branch `fix/ci-green` @ `37005ad`. Every path/line below was re-checked; do not trust a prior digest's line numbers without re-grepping — this file included, if it ages.

## 1. C# agent config (`src/TinySocs.Agent/`)

### Resolution order

`ConfigLoader.cs` (`src/TinySocs.Agent/Configuration/ConfigLoader.cs:11-48`):

1. `TINYSOCS_AGENT_CONFIG` env var, if set → used verbatim as the file path.
2. Else `./config/agent-config.yml` **relative to the process's current working directory** (not the exe's directory — a classic NSSM footgun if `AppDirectory` isn't set correctly; see `tinysocs-run-and-operate`).
3. If the resolved file doesn't exist: silently returns `new AgentConfig()` (all defaults) — the agent starts but is effectively idle (no inputs configured). No error, no log line at this layer.

YAML is parsed with YamlDotNet, `UnderscoredNamingConvention`, `IgnoreUnmatchedProperties()` — so a v2 pack field the C# model doesn't know about is silently dropped, not an error (round-trip discipline lives in `tinysocs-build-and-env`).

### `AgentConfig` — key sections and defaults

Source: `src/TinySocs.Agent/Configuration/AgentConfig.cs` (all line numbers below refer to this file).

| Section | Field | Default | Line | Note |
|---|---|---|---|---|
| `Agent` | `LogFile` | `C:\ProgramData\TinySocs\Collector\logs\agent.log` | 24-25 | |
| `Agent` | `DebugFakeInput` | `false` | 28 | Dev-only guard — must be explicitly `true` in YAML to let the synthetic `FakeInput` run. |
| `Output` | `Url` | `https://localhost:9201` | 81 | **9201, not 9200** — see §6 "the Python-default-port gap". |
| `Output` | `SslVerify` | `false` | 82 | **Production-unsafe default.** Ships accepting any cert. |
| `Output` | `User` / `Pass` | `""` / `""` | 86-87 | Falls through to env-var chain and CredMan if unset — see §2. |
| `Queue` | `RetentionPolicy.MinSuccessfulShipCount` | `1` | 75 | |
| `Detection` | `Enabled` | `true` | 128 | |
| `Detection` | `RulesFile` | `C:\ProgramData\TinySocs\Collector\rules\rules.yml` | 129 | This is the legacy v1 file — the one that actually runs today. |
| `Detection` | `ReloadIntervalSeconds` | `60` | 130 | Hot-reload poll interval for `RulesFile`. |
| `Detection.Notification` | `WebhookUrl` | `null` | 172 | |
| `Detection.Notification.Retry` | `MaxAttempts`/`BackoffSeconds`/`MaxAgeSeconds` | `3`/`30`/`3600` | 179-181 | |
| `Detection.Notification.Email` | `SmtpPort` | `587` | 187 | C#-side notification email — a **third** SMTP family, distinct from the two Python ones in §3.6. Configured only via YAML, no env var. |

### `ContentPackConfig` (`Detection.Pack.*`) — the signed v2 pack trust path

`AgentConfig.cs:144-166`. This is real, implemented code (Ed25519 verification lives in `Ed25519Verifier.cs`/`PackLoader.cs`) — but **dormant** in every real install: nothing sets `Enabled: true` in any shipped config template, and the Inno Setup installer never writes a `pack:` block. Production installs run the legacy `RulesFile` path only. (Architecture and trust-chain detail: `tinysocs-architecture-contract`.)

| Field | Default | Line | Meaning |
|---|---|---|---|
| `Enabled` | `false` | 146 | **The kill switch.** Until this is `true` in the deployed YAML, the pack path never runs, no matter what else is set. |
| `PackFile` | `C:\ProgramData\TinySocs\Collector\packs\pack.yml.canonical` | 150-151 | The signed bytes actually verified + loaded. The human-readable `pack.yml` sitting next to it is **not** on the trust path — don't hand-edit it and expect it to matter. |
| `SignatureFile` | `""` | 154 | Empty ⇒ derived as `PackFile` with `.canonical`→`.sig`. |
| `PublicKey` | `""` | 157 | base64 of the raw 32-byte Ed25519 **pack-signing** public key — the embedded trust anchor. Empty = no key configured = pack load fails closed. |
| `SigningKeyId` | `tinysocs-2026` | 160 | Must match the pack's declared key id, or the pack is rejected (key-confusion defence). |
| `LicenceKey` | `""` | 163 | Empty ⇒ free tier. |
| `LicencePublicKey` | `""` | 166 | base64 raw Ed25519 public key for the **separate** licensing keypair (`licensing-2026` by convention — different blast radius from pack signing). Empty ⇒ tier is read from the licence payload without cryptographic verification. |

Gate any change that flips `Enabled` to `true` in a shipped template through `tinysocs-change-control` — that's the pivot's most load-bearing config toggle.

### appsettings*.json are decoys

`src/TinySocs.Agent/appsettings.json` and `appsettings.Development.json` contain **only** a `Logging.LogLevel` block (verified: both files, 6 lines each, no other keys). They configure .NET's built-in logging framework, nothing about detection, output, or packs. If you're hunting for a setting and it's not in `agent-config.yml`, it is not in `appsettings*.json` either — it's simply not read anywhere, or it's an env var (§2).

## 2. The credential fallback chain — duplicated in two files

Both `EventLogInput.cs` and `OpenSearchBulkShipper.cs` implement the **same three-variable env fallback**, independently, almost verbatim:

```
TINYSOCS_SIEM_USER  ??  SIEM_USER  ??  OPENSEARCH_USERNAME
TINYSOCS_SIEM_PASS  ??  SIEM_PASS  ??  OPENSEARCH_PASSWORD
```

- `OpenSearchBulkShipper.cs:974-975` — `GetEnvFirst("TINYSOCS_SIEM_USER", "SIEM_USER", "OPENSEARCH_USERNAME")`, used by the main bulk shipper's `TryGetUserPass` (`OpenSearchBulkShipper.cs:965-999`), itself only consulted *after* `_config.Output.User`/`Pass` (config wins over env).
- `EventLogInput.cs:650-655` — the identical chain, inlined, used only by the **TS-080 direct-alert fast path** (`EnsureAlertHttpClient`, `EventLogInput.cs:614-...`) which opens its own separate `HttpClient` rather than reusing the shipper's. Priority there: config → env → Windows Credential Manager (`SiemCredentials.Target`, default `TinySocs/SIEM/Creds`).

**Consequence for anyone debugging auth**: fixing credentials in one code path (e.g. patching the shipper) does not fix the other. If TS-080 direct alerts are failing auth but bulk shipping works (or vice versa), check both call sites — this is the classic two-copies-of-the-same-logic trap. See `tinysocs-debugging-playbook` for the symptom-side triage; this skill only owns "what the variable resolves to."

## 3. Python env-var families, by service

All verified via `grep -n "os.getenv\|os.environ" src/tinysocs/api/*.py` etc. on 2026-07-11.

### 3.1 Dashboard + bot (`src/tinysocs/api/dashboard.py`, `bot.py`)

| Var | Default | Where | Note |
|---|---|---|---|
| `SIEM_URL` | `https://localhost:9201` | dashboard.py (10+ call sites, e.g. 355, 1797, 1952) | |
| `SIEM_USER` | `admin` | dashboard.py:356 etc. | |
| `SIEM_PASS` | `""` | dashboard.py:357 etc. | `.env.example` ships `SIEM_PASS=ChangeMe123!` — see §4. |
| `LLM_MODE` | **inconsistent** | see below | |
| `ANTHROPIC_MODEL` | `""` (no default) | dashboard.py:4908 | Empty ⇒ explicit error: `"No Anthropic model configured. Set ANTHROPIC_MODEL in Settings..."` |
| `OPENAI_MODEL` | `""` (no default) | dashboard.py:5000 | Same pattern: `"No OpenAI model configured..."` |
| `OFFLINE_LLM_MODEL` | `qwen2.5:0.5b-instruct` | dashboard.py:5119, `llm_ollama.py:11` | |
| `BOT_PORT` | `8090` | bot.py:674 | |
| `BOT_ID` | `bot-{BOT_PORT}` | bot.py:630 | |
| `TINYSOCS_BOT_WORKERS` | `1` | bot.py:675 | **Replay-cache caveat**: `auth.py:16-18` — the HMAC replay cache is an in-process TTL dict (`_replay_cache`, `auth.py:32`); "in multi-worker deployments a replay could succeed across workers." Do not raise this above `1` without also fixing replay-cache sharing. |
| `BOT_ENABLE_DIAG` | `0` (falsy) | bot.py:584 | |
| `BOT_SHARED_SECRET` | **none — fatal if unset** | bot.py:97,157-160 | HMAC secret for inbound bot calls. Fails closed at module-load time (`FATAL: BOT_SHARED_SECRET must be set.`, `sys.exit(1)`), plus a second startup guard at bot.py:671-673 (`SystemExit`, skipped only in `--demo` mode). bot.py also fatal-exits at 99-108 if `NODE_SECRET`/`MASTER_SHARED_SECRET` is unset (secret used for outbound calls to node's `/evidence/append`). Same fail-closed posture as node.py's `MASTER_SHARED_SECRET` (§3.2), not a contrast. |
| `TINYSOCS_SKEW_SECS` | `300` | bot.py:120 (`ALLOWED_SKEW_SECONDS`) | Also read by node.py (§3.2) — shared name, independently defaulted in each file. |
| `DASHBOARD_TLS_CERT` / `TINYSOCS_TLS_CERT` | `""` | bot.py:679-680 | First non-empty wins. |
| `DASHBOARD_TLS_KEY` / `TINYSOCS_TLS_KEY` | `""` | bot.py:681-682 | |
| `DASHBOARD_BIND` | `127.0.0.1` (demo mode) / `0.0.0.0` otherwise | bot.py:683 | |
| `UVICORN_LOG_LEVEL` | `info` | bot.py:676, node.py:1657 | |
| `TINYSOCS_QUEUE_PATH` / `ACTIONS_QUEUE_PATH` | `./data/actions_queue.jsonl` | see §4 (contradiction) | |
| `WEBHOOK_URL` / `WEBHOOK_ENABLED` | settings-page only | dashboard.py:9777-9838 | |

**`LLM_MODE` default is genuinely inconsistent across call sites** — verified by grep, not a guess:

| Call site | Default |
|---|---|
| `dashboard.py:2955`, `2991`, `4792`, `5531` | `"openai"` |
| `dashboard.py:4764` (`_llm_client` or similar internal helper) | `"offline"` |
| `agent/llm_select.py:64` | `"openai"` |
| `orchestrator/master.py:549` | `"openai"` |

Net effect: most of the app treats "unset" as "try OpenAI" (which then fails cleanly with a "no key" message), but one dashboard.py code path treats "unset" as "offline" mode. If you're chasing "why did the assistant behave differently depending on which endpoint was hit," this is why — check which of the above line ranges the failing endpoint routes through before assuming it's a bug in your own change.

### 3.2 Node / federation (`src/tinysocs/api/node.py`)

| Var | Default | Line | Note |
|---|---|---|---|
| `MASTER_SHARED_SECRET` | **none — fatal if unset** | `node.py:104-129` (`_load_secret`) | Prints `FATAL: MASTER_SHARED_SECRET must be set. Refusing to start with no shared secret.` to stderr and calls `sys.exit(1)`. This is the one credential in the whole stack that hard-fails closed. Contrast: `orchestrator/check_ledger.py:108` defaults the *same-named* var to `"dev-secret-change-me"` instead of failing — an inconsistency between the node server and one of its own diagnostic clients. |
| `TINYSOCS_SKEW_SECS` | `300` | node.py:136 | |
| `TINYSOCS_NODE_ID` / `COMPUTERNAME` | `"local"` | node.py:137 | |
| `TINYSOCS_LEDGER_DIR` | `ledger` (relative to CWD) | node.py:99 | Under NSSM with `AppDirectory=%ProgramData%\TinySocs`, resolves to `C:\ProgramData\TinySocs\ledger`. |
| `TINYSOCS_NODES` | `""` (comma-separated list) | dashboard.py:2104, master-side | Master's fan-out target list. |
| `TINYSOCS_HUB_URL` | `""` | node.py:1394 | |
| `TINYSOCS_REGISTER_INTERVAL` | `60` | node.py:1395 | |
| `PORT` / `NODE_PORT` | `8081` | node.py:1419, 1654 | `PORT` checked first. |
| `TINYSOCS_INSECURE_SKIP_VERIFY` | **inconsistent default** | node.py, bot.py, master.py, check_ledger.py | See §5 — safety-relevant, not just cosmetic. |

### 3.3 Feed / licensing (`src/tinysocs/api/feed.py`, `scripts/licence.py`, `scripts/stripe_pricing.py`)

| Var | Default | Line | Note |
|---|---|---|---|
| `FEED_PORT` | `8095` | feed.py:296 | |
| `TINYSOCS_KEY_DIR` | `<repo_root>/keys` | feed.py:61 | Where Ed25519 pack-signing + licensing keypairs live on disk (gitignored — never commit private keys, per CLAUDE.md). |
| `TINYSOCS_PACKS_DIR` | `<repo_root>/packs` | feed.py:62 | |
| `TINYSOCS_LICENSING_KEY_ID` | `licensing-2026` | feed.py:63 | |
| `TINYSOCS_FEED_URL_TTL` | `120` (seconds) | feed.py:64 | |
| `TINYSOCS_GRACE_DAYS` | `14` | feed.py:65 | |
| `TINYSOCS_FEED_URL_SECRET` | `""` | feed.py:76 | |
| `TINYSOCS_STRIPE_WEBHOOK_SECRET` | `""` | feed.py:219 | Feeds the SDK-free Stripe webhook verifier. |
| `TINYSOCS_PRICE_PRO` / `TINYSOCS_PRICE_MSP` | none (opaque Stripe *price id*, e.g. `price_xxx`) | `scripts/stripe_pricing.py:21-22,52,96,104` | **These are Stripe price IDs, not dollar figures** — no price values belong in code or docs per CLAUDE.md's locked-tier rule. `scripts/demo_feed.sh:28` demonstrates with `price_demo_pro`. |

`scripts/licence.py` reads no env vars directly — it's a pure-local CLI (`issue`/`inspect`/`entitlement` subcommands) built on `scripts/pack_sign.py`'s key I/O, which is also env-var-free (key dir passed via `--key-dir`, not `TINYSOCS_KEY_DIR`, for that specific tool — don't assume the feed server's env var applies to the CLI).

### 3.4 Retention / queue vars

| Var | Default | Where | Note |
|---|---|---|---|
| `WINLOG_RETENTION_DAYS` | `30` | dashboard.py:1865, node.py:1223 (falls back to `RETENTION_DAYS` too) | node.py's fallback chain (`WINLOG_RETENTION_DAYS` → `RETENTION_DAYS` → `"30"`) is one level deeper than dashboard.py's (`WINLOG_RETENTION_DAYS` → `"30"` directly) — same variable name, different fallback depth in the two files. |
| `ALERT_RETENTION_DAYS` | `90` | dashboard.py:1843,1866; node.py:1225 | |
| `CUSTOM_RETENTION_DAYS` | `30` | dashboard.py:1867; node.py:1227 (same `RETENTION_DAYS` fallback) | |
| `ANCHORS_RETENTION_DAYS` | `30` | `.env.example` | Ledger anchor retention, separate axis from alert/winlog retention. |
| `TINYSOCS_LEDGER_RETENTION_DAYS` | `30` | `.env.example` | |
| `TINYSOCS_QUEUE_PATH` / `ACTIONS_QUEUE_PATH` | `./data/actions_queue.jsonl` | multiple files | See the precedence contradiction in §4. |

### 3.5 Node/federation HMAC + anchors tuning (`.env.example`, `orchestrator/master.py`)

`TINYSOCS_HMAC_STYLE` (`pipe`/`dot`/`ts`), `TINYSOCS_SIG_PREFIX`, `REQUEST_TIMEOUT_SEC`, `MASTER_DEADLINE_SEC`, `MASTER_RETRIES`, `MASTER_RETRY_MIN_MS`/`MAX_MS`, `FANOUT_WAIT_ALL`, `HIDE_ZERO_RULES`, `ENSURE_ANCHORS`, `TINYSOCS_ANCHORS_ALIAS` — all confirmed live (referenced in `orchestrator/master.py` and/or `orchestrator/check_ledger.py`), not stale leftovers. Full HMAC-style/skew semantics belong to `tinysocs-architecture-contract` (the ledger/federation chain) — this skill only certifies that the env vars are real and states their `.env.example` defaults. (`RETENTION_ASYNC`/`RETENTION_SLICES` previously listed here do not exist anywhere in the repo — removed 2026-07-11; don't reintroduce without a grep hit to back them.)

### 3.6 Two SMTP families — do not conflate

| Family | Vars | Default port | Used by |
|---|---|---|---|
| A | `TINYSOCS_SMTP_HOST`, `TINYSOCS_SMTP_PORT`, `TINYSOCS_SMTP_USER`, `TINYSOCS_SMTP_PASS` | `587` | `src/tinysocs/reporting/daily_summary.py:341-368` (report emailing) |
| B | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` | `25` | `src/tinysocs/orchestrator/master.py:796-802` (alert notification emailing) |

Setting one family does **not** configure the other. If daily-summary emails work but alert-notification emails don't (or vice versa), you're looking at the wrong family. (There's also a **third**, unrelated, C#-side email config — `Detection.Notification.Email` in §1 — configured only via YAML, no env var at all.)

## 4. `.env.example` staleness warnings

`.env.example` (103 lines, verified 2026-07-11) predates the feed server, the licence gate, and Stripe integration entirely — it has **zero** `FEED_PORT`/`STRIPE`/`PRICE`/`TINYSOCS_KEY_DIR` entries. Don't treat it as a superset of what the running system reads; it's a snapshot from the federation/ledger phase (its own header calls it "Phase 4/5 foundation + PR #1").

Specific traps:

- **`TINYSOCS_RULES=tinysocs/agent/detections/rules.yaml`** — points at the 50-rule Python KQL catalogue. Setting this env var does **not** make any rule "run" in production; it only changes what `agent/detections/engine.py` (an on-demand, non-scheduled module) reads when explicitly invoked. No warning comment in the file says this. Don't let an engineer conclude that pointing this at a custom file activates detection — the dual-engine reality is authoritative in CLAUDE.md and `tinysocs-architecture-contract`.
- **`SIEM_PASS=ChangeMe123!`** — a real, guessable placeholder shipped in the example file. If a customer or dev copies `.env.example` to `.env` verbatim, they ship this password. Flag on sight if you ever see it outside `.env.example` itself (e.g. committed to a real `.env`, which shouldn't be tracked at all — see CLAUDE.md's "no credentials in this repo, ever").
- **Queue-path precedence contradiction**: `.env.example`'s comment says *"Preferred key used by bot.py; legacy `ACTIONS_QUEUE_PATH` remains supported"* and *"PR #1 makes `ACTIONS_QUEUE_PATH` the single source for queue path defaults"* — those two claims already disagree with each other, and neither matches the actual code:
  - `bot.py:146` states the real precedence in a docstring: `actions_queue.QUEUE_PATH > TINYSOCS_QUEUE_PATH/ACTIONS_QUEUE_PATH > fallback file next to this module`.
  - `agent/actions_queue.py:20` builds `QUEUE_PATH` from `ACTIONS_QUEUE_PATH` only (via `agent/config.py:90`'s `actions_queue_path`) — it **never reads `TINYSOCS_QUEUE_PATH`**.
  - Net effect: if the `tinysocs.agent.actions_queue` module is importable (the normal case), `TINYSOCS_QUEUE_PATH` is silently ignored regardless of what `.env.example` implies is "preferred." Only when that import fails does bot.py fall back to checking `TINYSOCS_QUEUE_PATH` first. If you're debugging "I set `TINYSOCS_QUEUE_PATH` and it didn't take," this is why — set `ACTIONS_QUEUE_PATH` instead, or verify which import path bot.py actually took.

## 5. Production-safe vs dev-only: TLS/SSL verification flags

Two independent flags control TLS verification, and **both default to insecure** in at least one place:

- **C# agent**: `Output.SslVerify` defaults to `false` (`AgentConfig.cs:81`). Ships accepting any server certificate for the OpenSearch output by default. Also gates a `DangerousAcceptAnyServerCertificateValidator` for TS-080's direct-alert `HttpClient` (`EventLogInput.cs:625-629`).
- **Python — inconsistent across files, verified by grep**:

  | File | Default when `TINYSOCS_INSECURE_SKIP_VERIFY` unset |
  |---|---|
  | `api/bot.py:114` | verify **ON** (default `"0"`) |
  | `orchestrator/master.py:152` | verify **ON** (default `False`) |
  | `orchestrator/check_ledger.py:100,108` | verify **OFF** (default `True` — comment literally says `# default skip verify (local lab)`) |

  So the exact same env var name flips the exact opposite way depending on which script reads it. `check_ledger.py` is a diagnostic tool (see `tinysocs-diagnostics-and-tooling`) so its insecure-by-default posture is lower-stakes than the servers', but don't assume setting `TINYSOCS_INSECURE_SKIP_VERIFY=0` universally forces verification everywhere — check the specific file.
  - `dashboard.py` additionally hardcodes `verify=False` at several internal httpx call sites unconditionally (lines 2111, 3257, 3312, 3864, 3895) — these are **not** gated by any env var at all; they're always insecure for those specific internal calls (mostly localhost-to-localhost node/meta probes).

**The trap for careless prod deployment**: `SslVerify: false` (C#) and `TINYSOCS_INSECURE_SKIP_VERIFY=1` (Python, where it defaults to secure) are meant as local/self-signed-cert conveniences for a bundled, same-host OpenSearch. Nothing stops either from silently riding along into a customer install where OpenSearch briefly listens on a network interface, or where a signed cert should be enforced. Any config-hardening pass belongs behind `tinysocs-change-control` since it touches customer-facing default behavior.

## 6. Ports table

| Port | Service | Protocol | Source |
|---|---|---|---|
| 9201 | OpenSearch REST API (production install) | HTTPS | `packaging/iss/scripts/OpenSearch.Persistence.ps1:8` (`-HttpPort 9201` default), `Quickstart.iss` (11 occurrences, e.g. line 1557) |
| 9200 | OpenSearch REST API — **dev-bundle / code-default only** | HTTP | `OpenSearch/config/opensearch.yml:5` (`http.port: 9200`, this repo's local dev config); also the fallback default baked into several Python modules (`tinybox/opensearch_bootstrap.py:29`, `orchestrator/anchors.py:53`, `orchestrator/master.py:163` all default `SIEM_URL` to `http://127.0.0.1:9200`) |
| 5602 | OpenSearch Dashboards | HTTPS | `Quickstart.iss:3029` (`-DashboardsUrl 'https://localhost:5602'`) |
| 8090 | Bot + operator dashboard (dashboard mounted at `/dashboard`) | HTTP/HTTPS | `bot.py:674` default, `bot.py:403` (`app.mount("/dashboard", dashboard_app)`) |
| 8081 | Node / federation API | HTTP/HTTPS | `node.py:1419,1654` default (`PORT` or `NODE_PORT`) |
| 8095 | Feed server (signed packs, licensing, Stripe webhook) | HTTP/HTTPS | `feed.py:296` default |
| 9300 | OpenSearch transport (cluster-internal) | TCP | standard OpenSearch transport port, not separately overridden in this repo's config |

**"The Python-default-port gap"** (distinct from "the 9200 trap" owned by `tinysocs-debugging-playbook`/`tinysocs-run-and-operate` — that's the installer/PowerShell layer *actively rewriting* loopback `9200`/`http` URLs to `9201`/`https`; this is a *different, unrewritten* failure mode): production installs run OpenSearch on **9201**, but several Python modules' *code-level* defaults still say `9200` (they assume `SIEM_URL` is always set externally, e.g. via the installer's env file — confirmed the installer does write `SIEM_URL=https://localhost:9201` into the deployed env, `Quickstart.iss:2743,2777`). If you run any of those Python modules standalone (a script, a one-off diagnostic, a dev shell) **without** the installer's env file sourced, there is no rewrite helper in the Python path — they'll silently try port 9200 against a production box that's actually listening on 9201 and get connection-refused — not an auth error, not a clear "wrong port" message. Always confirm `SIEM_URL` is set in your shell before running orchestrator/reporting scripts ad hoc.

## 7. Pack tuning knobs — mechanism real, currently inert

`PackLoader.cs:252-283` implements a real feature: a v2 rule's `tuning.threshold.envvar` field names an environment variable a customer can set to override that rule's threshold without editing the signed pack; the override is clamped to the rule's declared `[min, max]` via `Math.Clamp` (line 279) so it can't be tuned outside the vendor-approved range, and every override is logged (`PackLoader.cs:280-283`).

**But it's inert today**: the shipped `packs/base/2026.27/pack.yml` has exactly 13 `envvar:` fields, and **all 13 are `null`** (verified: `grep -c "envvar:"` = 13, `grep -c "envvar: null"` = 13). No rule in the currently-signed pilot pack exposes a tunable env var. Combined with `Detection.Pack.Enabled` defaulting `false` (§1), this whole mechanism is doubly dormant — designed, coded, tested presumably, but not yet turned on for any customer. Treat as a **candidate** capability, not a shipped one, in any customer-facing claim (gate through `tinysocs-external-positioning` for wording).

## When NOT to use this skill

- Rule schema fields (`threshold_by_key`, `field_match`, `window_minutes`, MITRE tags) — see `detection-engineering-reference`.
- Installer flow, NSSM service definitions, `ProgramData` directory layout, scheduled tasks — see `tinysocs-run-and-operate`.
- Whether a given flag/toggle is safe to flip in a released pack or template — the decision process is `tinysocs-change-control`; this skill only tells you what the flag does and what it defaults to.
- Why the signed-pack trust path is dormant architecturally (not just the config default) — see `tinysocs-architecture-contract`.
- Debugging a live symptom (auth failures, silent detection engine, dashboard 401s) — start at `tinysocs-debugging-playbook`, which will point back here for the specific variable once the symptom is triaged.
- Rebuilding the dev environment from scratch (venv, csproj, Inno Setup) — see `tinysocs-build-and-env`.

## Provenance and maintenance

Authored 2026-07-11 against branch `fix/ci-green` @ `37005ad`. Primary sources (all read directly, not taken from prior digests):

- `src/TinySocs.Agent/Configuration/AgentConfig.cs`
- `src/TinySocs.Agent/Configuration/ConfigLoader.cs`
- `src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs` (lines ~900-1000)
- `src/TinySocs.Agent/Inputs/EventLogInput.cs` (lines ~600-670)
- `src/TinySocs.Agent/Detection/PackLoader.cs` (lines ~190-283)
- `src/TinySocs.Agent/appsettings.json`, `appsettings.Development.json`
- `.env.example` (full file, 103 lines)
- `src/tinysocs/api/dashboard.py`, `bot.py`, `node.py`, `feed.py`, `auth.py`
- `src/tinysocs/orchestrator/master.py`, `check_ledger.py`, `anchors.py`
- `src/tinysocs/agent/config.py`, `actions_queue.py`, `detections/engine.py`, `llm_select.py`, `llm_ollama.py`
- `src/tinysocs/reporting/daily_summary.py`
- `src/tinysocs/tinybox/opensearch_bootstrap.py`
- `scripts/licence.py`, `scripts/pack_sign.py`, `scripts/stripe_pricing.py`, `scripts/demo_feed.sh`
- `packaging/iss/Quickstart.iss`, `packaging/iss/scripts/OpenSearch.Persistence.ps1`
- `packs/base/2026.27/pack.yml`
- `OpenSearch/config/opensearch.yml`

### Re-verification commands (one per volatile fact class)

```bash
# AgentConfig defaults haven't moved/changed
grep -n "SslVerify\|RulesFile\|ReloadIntervalSeconds" src/TinySocs.Agent/Configuration/AgentConfig.cs

# ContentPackConfig.Enabled is still false by default
grep -n "public bool Enabled" src/TinySocs.Agent/Configuration/AgentConfig.cs

# Credential fallback chain still duplicated in both files
grep -n "TINYSOCS_SIEM_USER" src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs src/TinySocs.Agent/Inputs/EventLogInput.cs

# appsettings*.json are still logging-only (should print exactly one top-level key: Logging)
python3 -c "import json; print(list(json.load(open('src/TinySocs.Agent/appsettings.json')).keys()))"

# LLM_MODE default inconsistency still present
grep -n 'getenv("LLM_MODE"' src/tinysocs/api/dashboard.py src/tinysocs/agent/llm_select.py src/tinysocs/orchestrator/master.py

# ANTHROPIC_MODEL / OPENAI_MODEL still have no default
grep -n 'getenv("ANTHROPIC_MODEL"\|getenv("OPENAI_MODEL"' src/tinysocs/api/dashboard.py

# MASTER_SHARED_SECRET still fatal-if-unset in node.py
grep -n "FATAL: MASTER_SHARED_SECRET" src/tinysocs/api/node.py

# BOT_SHARED_SECRET (and NODE_SECRET/MASTER_SHARED_SECRET) still fatal-if-unset in bot.py
grep -n "FATAL: BOT_SHARED_SECRET\|FATAL: NODE_SECRET or MASTER_SHARED_SECRET\|BOT_SHARED_SECRET must be set" src/tinysocs/api/bot.py

# TINYSOCS_INSECURE_SKIP_VERIFY default still inconsistent across files
grep -n "TINYSOCS_INSECURE_SKIP_VERIFY" src/tinysocs/api/bot.py src/tinysocs/orchestrator/master.py src/tinysocs/orchestrator/check_ledger.py

# Pack tuning envvars still all null in the shipped pilot pack
grep -c "envvar:" packs/base/2026.27/pack.yml; grep -c "envvar: null" packs/base/2026.27/pack.yml

# .env.example still predates the feed/Stripe/licensing surface
grep -c "FEED_PORT\|STRIPE\|TINYSOCS_PRICE" .env.example   # expect 0

# Ports still match: installer writes 9201, OpenSearch dashboards 5602
grep -n "HttpPort 9201\|DashboardsUrl" packaging/iss/Quickstart.iss packaging/iss/scripts/OpenSearch.Persistence.ps1

# Two SMTP families still separate
grep -n "TINYSOCS_SMTP_\|SMTP_HOST" src/tinysocs/reporting/daily_summary.py src/tinysocs/orchestrator/master.py

# Queue-path precedence still contradicts .env.example's comment
grep -n "QUEUE_PATH" src/tinysocs/api/bot.py src/tinysocs/agent/actions_queue.py
```
