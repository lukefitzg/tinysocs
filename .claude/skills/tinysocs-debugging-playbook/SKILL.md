---
name: tinysocs-debugging-playbook
description: Symptom-to-triage runbook for TinySocs' real, previously-hit failure modes — load this when a detection rule doesn't fire, alerts don't show up in the dashboard, the agent's OpenSearch shipper is failing, HMAC calls between bot/node/dashboard return 401, the Windows dashboard shows stale "Loading..." widgets or unexpectedly logs the user out, a PowerShell 5.1 script throws a garbled error or hangs, an agent swap doesn't take effect because NSSM respawned the old binary, or federation/ledger verification looks broken. Each failure family is a symptom-to-check-to-cause-to-fix table plus the war story that produced it. Use this for "why isn't X happening" triage; use tinysocs-failure-archaeology if you want the full chronicle of an investigation instead of the fast checklist, and detection-engineering-reference for the theory behind thresholds/windows/field_match rather than debugging them.
---

# TinySocs debugging playbook

Zero-context triage. Each table's first column is a symptom; the second column is the
**one command to run first** — it discriminates between causes fast, before you go
reading code. Run it on the machine noted. Then map the result to a cause and a fix
pointer.

Jargon used below, defined once: **threshold_by_key** — the only C# rule type; counts
events sharing a `group_by` key within `window_minutes` and fires at `threshold`.
**Cooldown** — a per-`{rule_id}|{group_key}` suppression window after a rule fires, so
repeat matches don't re-alert. **HMAC** — keyed-hash request signing used between the
bot/node/dashboard services instead of API keys. **NSSM** — Non-Sucking Service
Manager, wraps `TinySocs.Agent.exe` as a Windows service and restarts it on exit.
**TOFU** — trust-on-first-use certificate pinning (accept + remember the first cert
seen, flag any change after).

## 1. Detection engine silent (rule should have fired, nothing in `tinysocs-alerts-*`)

| Symptom | First check (run on) | Likely cause | Fix pointer |
|---|---|---|---|
| No alert at all for a technique you just ran | `grep -n "id: \"TS-NNN\"" -A3 packaging/detection/rules.yml \| grep enabled` (macOS dev or Windows install dir) | Rule is `enabled: false` — 20 of the 39 defined rules are disabled in the pilot pack (as of 2026-07-11; commit 347c98e) | Check `enabled:` before assuming an engine bug. Enabling requires gating through **tinysocs-change-control** (rule-behavior change). |
| Rule is enabled but still nothing | Count real event volume vs `threshold`/`window_minutes` in the rule block | Test generated fewer events than the threshold, or spread them past `window_minutes` | Confirmed historical instance: `docs/getting-started.md` and `Invoke-TinySocsSmokeTest` (`modules/TinySocs.Installer.psm1:15285`) generated only `1..6` / `1..5` failed logons against TS-001's threshold of 15 — could never fire. Fixed in commit `347c98e` (now generates 20). If you hit this again, the fix is always "raise the trigger volume above threshold," not "lower the threshold" (that's a rule-content change, gate it). |
| Rule enabled, volume looks right, source event type is Sysmon Event 10 (ProcessAccess) | `grep -n "ProcessAccess" -A3 integrations/sysmon/sysmon-config.xml` | TS-060 (`lsass_access`) is `enabled: false` specifically because the shipped `sysmonconfig` ships `<ProcessAccess onmatch="include"></ProcessAccess>` with **no rules inside** — Sysmon's own semantics mean an empty include list means nothing is logged, so Event 10 never fires even with Sysmon running. See `packaging/detection/rules.yml:178-197` for the disabled-reason comment. | Don't "fix" this by re-enabling TS-060 — the underlying event source is dead until the Sysmon config is rewritten. TS-061 (`credential_dumping_tools`, enabled, event_id 4688) covers named-tool cred dumping instead. |
| Rule's channel is `heartbeat` | `grep -n "TS-120" -A18 packaging/detection/rules.yml` | TS-120 (`agent_version_drift`) is `enabled: false` because heartbeats are handled by a separate code path that never reaches the detection engine's event pipeline — there is no event source wiring it up. Deferred 2026-07-08. | Don't debug this as "engine not matching" — it's an unwired rule, not a broken match. Any fix is v2/backlog work; see **tinysocs-research-frontier**. |
| FIM rule (`TinySocs-FIM` channel) never groups/fires despite file changes happening | `grep -n "winlog" src/TinySocs.Agent/Inputs/FileIntegrityInput.cs` | Historical bug (fixed): TS-113 (`fim_mass_modification`, `group_by: "winlog.computer_name"`, `packaging/detection/rules.yml:687-705`) grouped by a field FIM events never populated. Fixed by adding a `winlog.computer_name` block to every FIM event in `FileIntegrityInput.cs:575-583` (`EmitEvent`). | If a *different* FIM/threshold rule looks silent, check that its `group_by` field is actually present in the emitted event body — this exact bug class (group key not populated by the input source) is the highest-value first check for any silent `threshold_by_key` rule, not just TS-113. |
| Rule fired once, then goes quiet for repeat attacks | `grep -n "CooldownMinutes\|cooldown_minutes" src/TinySocs.Agent/Detection/DetectionRule.cs packaging/detection/rules.yml` | Working as designed: cooldown key is `{rule.Id}|{groupKey}` (`DetectionEngine.cs:255`); if `cooldown_minutes` isn't set in the rule, the engine falls back to `window_minutes` as the effective cooldown (`DetectionRule.cs:44-46`). A rule with a 5-minute window and no explicit cooldown suppresses re-fires for 5 more minutes after the first alert. | Not a bug to fix reflexively — confirm with the operator whether they want a shorter cooldown before touching it (rule-behavior change, gate through **tinysocs-change-control**). |

**The scar**: the getting-started smoke test is the canonical example of "the rule engine
was never broken, the reproduction was." `docs/getting-started.md` told a new operator to
run 6 fake failed logons against a rule that fires at 15 in 5 minutes — a doc that could
never demonstrate the product it was demoing, shipped for months before commit `347c98e`
(2026-07-08, "Ship pilot base pack 2026.27") raised the trigger to 20. TS-113 is the
sibling scar on the engine side: the rule's *logic* was correct, but the event source
never populated the field the logic grouped by, so it silently produced zero groups
forever. Both bugs share a lesson: when a rule "doesn't fire," check the data reaching
the engine before you touch the rule's `threshold`/`window_minutes`/`condition`.

## 2. OpenSearch / shipper failures

| Symptom | First check (run on) | Likely cause | Fix pointer |
|---|---|---|---|
| Script/curl call to OpenSearch times out or connects to the wrong thing on `9200` | `curl.exe -sk https://127.0.0.1:9201/_cluster/health` (Windows) | **The 9200 trap**: OpenSearch's plain HTTP listener is not the supported surface. Canonical REST is HTTPS on **9201**. The installer auto-rewrites loopback `9200`/`http` URLs to `9201`/`https` — see `modules/TinySocs.Installer.psm1:3254` (`# 1.1) Normalize SIEM_URL for loopback installs (avoid the 9200 trap)`) and the same rewrite at lines 754-771. (This is the installer-layer *rewrite*; a related but distinct failure — Python code-level defaults that are never rewritten when run standalone — is "the Python-default-port gap" in `tinysocs-config-and-flags` §6. Don't conflate the two.) | Always address OpenSearch at `https://127.0.0.1:9201` (or `:9200` only if you know you want the rewritten alias). Never hand-roll a port; call the existing normalization helpers if scripting new installer flows. |
| Fresh install: postinstall aborts even though OpenSearch looks fine afterward | Check install log timestamp of the abort vs when `.opendistro_security` finished initializing | Cold first-boot can take up to ~2 minutes for `.opendistro_security` to initialize before the HTTPS port opens; the old 180s wait lost that race. Fixed in commit `81c97d2` (raised to 300s in `packaging/iss/scripts/OpenSearch.Persistence.ps1`). | If you see this again on a slower VM, the wait is already 300s — look for a *new* slow step, don't just re-raise the timeout again. |
| OpenSearch crash-loops on fresh install with a YAML parse error mentioning "special characters not allowed" | `xxd OpenSearch/config/opensearch.yml \| head -1` (macOS/dev, check for `ef bb bf`) | UTF-8 BOM at byte 0 of the vendor `opensearch.yml`. Java's YAML parser rejects it. Fixed in commit `1a11d6e` — BOM stripped from the source file, plus belt-and-suspenders strips at TB-10e (disk watermark injection) and TB-11c (post-Persistence, both config copies). | If a BOM reappears (e.g. someone edits `OpenSearch/config/opensearch.yml` with an editor that re-adds it), re-strip with `Get-Content -Raw \| Set-Content -NoNewline -Encoding UTF8` (no BOM) rather than reverting the belt-and-suspenders strips. |
| Agent events aren't reaching OpenSearch at all, but the agent process is alive | Check `C:\ProgramData\TinySocs\Collector\agent\queue` for a growing backlog (Windows) — path defined in `src/TinySocs.Agent/Configuration/AgentConfig.cs:64` | Bulk indexing is failing (auth, TLS, cluster full/red, index template mismatch) and the shipper is falling back to on-disk queueing rather than dropping events. | Diagnose the actual bulk failure (check agent log around the shipper component) before assuming data loss — the queue existing is by design, a *permanently growing* queue is the bug signal, not the queue itself. |

**The scar**: three separate OpenSearch outages taught three separate lessons that all
look like "OpenSearch is broken" from the outside: wrong port (9200 vs 9201), too-short
patience (180s vs actual cold-boot time), and an invisible byte-order-mark that no diff
tool shows by default. None of them were OpenSearch bugs — they were installer/config
bugs pointed at OpenSearch. Reach for `curl.exe -sk https://127.0.0.1:9201/_cluster/health`
before assuming the cluster itself is unhealthy.

## 3. HMAC auth mismatches (401s between bot/node/dashboard)

Signing lives in `src/tinysocs/api/auth.py`. Headers: `X-TinySOCS-Timestamp`,
`X-TinySOCS-Signature`, `X-TinySOCS-Nonce` (optional). Three accepted message styles —
the verifier tries all three so either side can use any style: `"{ts}"` (`ts`),
`"{ts}|{nonce}"` (`pipe`, the default for outbound signing), `"{ts}.{nonce}"` (`dot`).

| Symptom | First check (run on) | Likely cause | Fix pointer |
|---|---|---|---|
| 401 "Timestamp out of range" | Compare wall-clock time on caller vs callee machine | Clock skew beyond the allowed window (default 300s, overridable via `TINYSOCS_SKEW_SECS`; see `src/tinysocs/api/bot.py:120`, `src/tinysocs/api/node.py:136`) | Sync clocks (NTP) rather than widening skew — widening the window is a security-relevant change, gate through **tinysocs-change-control**. |
| 401 "Bad signature" | Confirm which secret each surface expects: bot inbound calls use `BOT_SHARED_SECRET`; node calls (from bot to node's `/evidence/append`) use `NODE_SECRET`, falling back to `MASTER_SHARED_SECRET` if unset (`bot.py:19-20,97-109`); node's own inbound HMAC uses `MASTER_SHARED_SECRET` only, no fallback (`node.py:105-129`) | Secret mismatch between caller/callee, or a caller signing with the wrong env var for the surface it's calling | Match secret-to-surface from the table above; don't assume one shared secret covers everything. Node **FATAL-exits at startup** (`sys.exit(1)`) if `MASTER_SHARED_SECRET` is unset — check node's stderr/log first if it isn't running at all. |
| 401 "Replay detected" only under load / with multiple workers | Check whether the service is running with `workers > 1` (uvicorn/gunicorn) | The replay cache (`_replay_cache` dict, `auth.py:32`) is **per-process, in-memory**. With multiple worker processes, a legitimate retry can land on a different worker than the original and get accepted twice — or, less intuitively, the same nonce can be rejected on one worker while never having been seen there. | This is a known architectural limitation, not a bug to patch reflexively — don't add a shared cache without checking whether it belongs in this pivot's scope (**tinysocs-change-control**). Workaround: run affected services single-worker, or ensure caller always retries with a fresh nonce. |
| Missing headers entirely (401 "Missing HMAC headers") | `grep -n "sign_request_headers\|X-TinySOCS" <calling module>` | Caller built the request without going through `sign_request_headers()` in `auth.py`, or stripped headers via a proxy/gateway in between | Route all outbound signed calls through `auth.sign_request_headers()` rather than hand-building headers. |

**The scar**: this design tries hard to be forgiving (three message styles, secret
fallback chains) precisely because early integration between bot/node/dashboard kept
breaking on style/secret mismatches. The flexibility masks a real gap: the replay cache
doesn't survive a process restart or a multi-worker deployment, so "replay protection"
is best-effort, not a guarantee — don't market it as one (relevant to
**tinysocs-external-positioning** if this ever comes up in a security claim).

## 4. Dashboard (widgets stuck, unexpected logout, silent failures)

Session model: `POST /api/auth/login` checks the password against `SIEM_PASS`
(`src/tinysocs/api/dashboard.py:151-168`) and returns an opaque bearer token backed by
an in-memory `_active_sessions` dict — no JWT, no persistence across a service restart.
`GET /api/auth/check` validates it. As of 2026-07-11, only **15 of 73** `@dashboard_app`
routes call `_verify_dashboard_session(request)` — most dashboard endpoints are
**unauthenticated at the server level** and rely on the frontend not exposing links to
them without a valid token. Don't assume an endpoint is protected because the UI gates
access to it.

| Symptom | First check (run on) | Likely cause | Fix pointer |
|---|---|---|---|
| A dashboard action (e.g. "Purge old logs") appears to silently do nothing, user has to click twice | Check whether the frontend call used `authFetch()` vs plain `fetch()` for that action | `authFetch()` clears the session token and reopens the login prompt on any 401 *and throws*, so the calling code's own error handling never runs — the failure is invisible. Fixed for the purge action in commit `931d724`; the same class of bug can recur in any new `authFetch()` call site. | For actions where a stale-session failure needs to be visibly reported (not just silently re-login), use plain `fetch()` with explicit 401 handling, per `931d724`. |
| Widgets stuck on "Loading..." after a dashboard frontend change | Check whether the change split dashboard JS into multiple `<script>` blocks | Historical bug: a two-script split (separate login script + main dashboard script) had a coordination issue between blocks that couldn't be resolved remotely. Reverted in commit `dd95fbd` back to a single `<script>` block containing login, unlock, and all widget-init functions. | Keep dashboard JS in one script block unless you have a concrete plan for cross-script coordination — this isn't a stylistic preference, it's a scar. Any dashboard architecture change is a UI change; sanity-check scope against **tinysocs-change-control** if it's large. |
| Login appears to hang / do nothing | Check what hostname the frontend is calling (not `localhost`?) | Root cause noted alongside `dd95fbd`: "unresponsive login" traced to a non-localhost hostname URL in a fetch call. | Dashboard API calls should target `localhost`/`127.0.0.1` consistent with the rest of the loopback-first design (see the 9200-trap pattern in family 2). |

**The scar**: `dd95fbd`'s commit message is unusually candid — "the separate script blocks
had a coordination issue that couldn't be resolved remotely." That's an admission the
team debugged this live against a remote VM and gave up trying to fix the split rather
than reverting it. If you're tempted to re-split dashboard JS for maintainability, know
that the last attempt cost enough pain to revert outright.

## 5. PowerShell 5.1 traps (installer, Windows agent scripts)

TinySocs installer/ops scripts target **Windows PowerShell 5.1** (not PowerShell 7) —
this is a distinct, older engine with distinct traps.

| Symptom | First check (run on) | Likely cause | Fix pointer |
|---|---|---|---|
| A script prints garbled text and swallows the statement after a colored `Write-Host` line | Search the script for em-dash (`—`) or other non-ASCII characters | PS 5.1's console under the default ANSI codepage mangles em-dashes, corrupting the apparent string terminator so `-ForegroundColor` leaks as literal text and the next statement gets swallowed. Hit in `scripts/Demo-Ransomware.ps1`, fixed in commit `94dae2b` — replaced with ASCII hyphens. | Keep all PowerShell 5.1-targeted script *output strings* ASCII-only. This is a standing rule — see **tinysocs-change-control**'s ASCII-only-PowerShell non-negotiable. |
| TLS handshake to `https://127.0.0.1:9201` fails or hangs from PowerShell, but `curl.exe` to the same URL works | Try `curl.exe -sk <url>` directly instead of `Invoke-RestMethod`/`Invoke-WebRequest` | Self-signed local TLS + PS 5.1's Schannel-backed HTTP stack does brittle, non-replicable revocation checks and can hang on negotiation. Documented at `modules/TinySocs.Installer.psm1:5216`, `:12569`, `:12603`. | Prefer `curl.exe -sk` (or `-k -s`) for self-signed-TLS calls in PS 5.1 scripts, as the rest of the codebase already does (`modules/TinySocs.Installer.psm1:13450`, `scripts/Full-Rebuild.ps1`, `scripts/Ledger_Health.ps1`). Don't fight Schannel. |
| `ConvertFrom-Json` call on an OpenSearch response takes forever or the script appears to freeze | Check the size of the response body / whether `_source` was requested unfiltered | Large unfiltered `_source` payloads (full documents) are slow to parse under PS 5.1's JSON deserializer. | Project only needed fields via an OpenSearch `_source` filter (or `_source: false` + explicit fields) in the query before parsing, rather than pulling and parsing full documents client-side. |
| A script that takes `-SourceDir` (or similar path param) crashes immediately with a `Join-Path` error when called with a relative path like `.` | Check whether the param is resolved to an absolute path before use | `Split-Path '.' -Parent` returns an **empty string**, not `.` or the cwd — any `Join-Path` built on that result throws. Hit in `Deploy-AgentUpdate.ps1`, fixed in commit `2125f87` (resolve to absolute path up front, drop the dead line that relied on the empty result). | Any new script parameter that accepts a directory path should call `Resolve-Path`/`[System.IO.Path]::GetFullPath()` on it immediately, before any `Split-Path`/`Join-Path` chain. |

**The scar**: every one of these is "PowerShell 5.1 is not PowerShell 7 and not bash,"
re-learned four separate times on four separate scripts. There is no PS7 upgrade planned
(Windows Server default matters more than developer convenience here) — treat 5.1's
quirks as permanent constraints, not bugs to eventually outgrow.

## 6. NSSM respawn trap (agent binary swap doesn't take effect)

The agent runs as an NSSM-wrapped Windows service (`TinySocsAgent`) that respawns
`TinySocs.Agent.exe` on exit. Full stop-order mechanics — why the deploy script also
stops the `TinySocs-Quickstart` process first, and why that process is *not* itself
an agent respawn path — live in **tinysocs-run-and-operate §2/§9**; don't re-derive
them here.

| Symptom | First check (run on) | Likely cause | Fix pointer |
|---|---|---|---|
| Deployed a new agent binary but the running process still behaves like the old one (old rule count, old log format, etc.) | Check whether the deploy script stopped the `TinySocsAgent` NSSM service before replacing the exe (Windows) | `taskkill`-then-replace races NSSM's respawn: NSSM detects the exit and relaunches the (about-to-be-replaced) binary fast enough to re-lock the file, or the new file gets written but the already-running old process was never actually the one killed. | Stop the watchdog process, then the service, in that order — see **tinysocs-run-and-operate §2/§9** for the full procedure and why. Fixed for `Deploy-AgentUpdate.ps1` in commit `70cf7f8`; verify success by reading NSSM's own stdout log (`TinySocsAgent.out.log`), not just process presence. |
| Need to confirm a deploy actually took effect | Read `TinySocsAgent.out.log` (NSSM's captured stdout) for the agent's own startup line (rule count loaded, version) | — | Same commit (`70cf7f8`) established this as the verification method: it confirmed "20 rules from rules.yml, 9/9 audit subcategories set, no errors" this way on the Win11 VM. |

**The scar**: NSSM's entire purpose — never let the agent silently stay dead — is exactly
what makes naive redeploys silently no-op. Any script that stops/replaces/starts the
agent binary must be NSSM-aware, not process-aware.

## 7. Federation / ledger

| Symptom | First check (run on) | Likely cause | Fix pointer |
|---|---|---|---|
| Suspect ledger tampering or a broken hash chain | `python src/tinysocs/orchestrator/check_ledger.py --verify` (macOS dev or wherever `ledger/` is mounted) | Chain break, or you're reading the wrong schema for the file you're looking at | See next row — confirm schema first, `--verify` output can be misleading if you hand-parse the wrong field names. |
| Ledger JSONL fields don't match what you expected | `head -1 ledger/<file>.jsonl` | `ledger/` holds **two coexisting JSONL schemas**: an older "rule/evidence" schema (`sequence`, `rule`, `stable_hash`, `prev_hash`, `node_id`, `head_sha256` — e.g. `ledger/2025-11-07.jsonl`) and a newer "node head" schema (`node_id`, `sequence`, `ts_utc`, `head_prev`, `payload_sha256`, `head_sha256` — e.g. `ledger/node-1.jsonl`, `node-8081.jsonl`). Field names overlap (`sequence`, `node_id`, `head_sha256`) but mean slightly different things (`prev_hash` vs `head_prev`). | Identify which schema a file uses before writing any script against it — don't assume `ledger/*.jsonl` is homogeneous. |
| Federation Site registration fails cert validation, or a legitimate cert rotation gets flagged as tampering | `cat "$env:ProgramData\TinySocs\Assistant\pinned_certs.json"` (Windows) or check `src/tinysocs/federation_certs.py:135-230` | TOFU (trust-on-first-use) pinning: the **first** cert seen for a Site's URL is pinned; any later mismatch is treated as a potential MITM and rejected, including a legitimate cert renewal. | A legitimate cert rotation requires deliberately re-pinning (`pin_site_cert`), not silently accepting the new cert — that's a security control working as designed. Don't "fix" a rotation failure by making mismatches permissive; that defeats the pin. Gate any change to this behavior through **tinysocs-change-control**. |

**The scar**: the two ledger schemas are not a migration in progress that finished badly
— both are read by different tooling for different purposes (see
**tinysocs-architecture-contract** for which is which). Treat schema divergence as a
fact about this subsystem, not a bug to unify away without checking who reads which file.

## When NOT to use this skill

- Want the full narrative of an investigation (what was tried, what didn't work, why) rather than the fast triage table — see **tinysocs-failure-archaeology**.
- Need the theory behind thresholds, windows, `field_match`, MITRE mapping, or Windows/Sysmon event semantics rather than a debugging step — see **detection-engineering-reference**.
- Need to decide whether a fix is in-scope for the pivot, or whether a rule/config/public-claim change needs sign-off before you make it — see **tinysocs-change-control** (this skill routes several fixes through it deliberately).
- Need config flag reference (env vars, ports, `AgentConfig`/`ContentPackConfig` fields) rather than a symptom — see **tinysocs-config-and-flags**.
- Need to rebuild the dev environment from scratch (not debug a running one) — see **tinysocs-build-and-env**.
- Need installer/service/ports/retention operational reference rather than a failure symptom — see **tinysocs-run-and-operate**.
- Need to measure something (health check, smoke test, MITRE coverage, ledger diagnostics) rather than debug a failure — see **tinysocs-diagnostics-and-tooling**.
- Need to prove a rule fires (Atomic test authorship, xUnit pairs) rather than debug why it didn't — see **tinysocs-detection-validation-toolkit**.

## Provenance and maintenance

Authored 2026-07-11 against branch `fix/ci-green`, HEAD `37005ad`. Every command,
line number, and commit SHA above was re-run/re-verified directly in the repo during
authoring (not taken on trust from discovery digests). Primary sources:

- `packaging/detection/rules.yml` (rule enabled/disabled state, TS-060/TS-113/TS-120 comments)
- `docs/getting-started.md`, `modules/TinySocs.Installer.psm1` (smoke test, 9200 trap, TLS/Schannel comments, NSSM)
- `src/TinySocs.Agent/Inputs/FileIntegrityInput.cs` (TS-113 fix)
- `src/TinySocs.Agent/Detection/DetectionEngine.cs`, `DetectionRule.cs` (cooldown semantics)
- `src/TinySocs.Agent/Configuration/AgentConfig.cs` (queue path)
- `src/tinysocs/api/auth.py`, `bot.py`, `node.py`, `dashboard.py` (HMAC, session model, endpoint auth count)
- `src/tinysocs/orchestrator/check_ledger.py`, `src/tinysocs/federation_certs.py`, `ledger/*.jsonl` (federation/ledger)
- Commits: `347c98e`, `81c97d2`, `1a11d6e`, `931d724`, `dd95fbd`, `94dae2b`, `2125f87`, `70cf7f8`

Re-verification commands for the volatile facts in this skill:

```bash
# Rule enabled/disabled state and reasons (family 1)
grep -n "enabled: false\|enabled: true" packaging/detection/rules.yml | wc -l
grep -n "TS-060\|TS-113\|TS-120" -A20 packaging/detection/rules.yml

# Smoke test trigger volume still above threshold (family 1)
grep -n "1\.\.20\|threshold is 15" modules/TinySocs.Installer.psm1 docs/getting-started.md

# TS-113 group-by field fix still present (family 1)
grep -n "winlog" -A3 src/TinySocs.Agent/Inputs/FileIntegrityInput.cs

# 9200-trap rewrite still present (family 2)
grep -n "9200 trap" modules/TinySocs.Installer.psm1

# HMAC headers/skew/secret wiring unchanged (family 3)
sed -n '1,20p' src/tinysocs/api/auth.py
grep -n "TINYSOCS_SKEW_SECS" src/tinysocs/api/*.py

# Dashboard auth coverage ratio (family 4) — re-run both, compare
grep -c "^@dashboard_app\." src/tinysocs/api/dashboard.py
grep -c "_verify_dashboard_session(request)" src/tinysocs/api/dashboard.py

# Ledger schema divergence still present (family 7)
head -1 ledger/2025-11-07.jsonl; head -1 ledger/node-1.jsonl
```
