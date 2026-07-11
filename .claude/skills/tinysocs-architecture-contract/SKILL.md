---
name: tinysocs-architecture-contract
description: Load-bearing design decisions and invariants for TinySocs — the dual-engine split (C# agent engine is the only thing that fires alerts; the Python rules.yaml catalogue never runs on a schedule), rule-loading paths (legacy unsigned RuleLoader vs signed-but-dormant PackLoader), FIM as a synthetic-event subsystem, the TS-080 direct-alert fast path, the federation/evidence-ledger hash chain, the end-to-end alert flow, and the named known-weak-points (no allowlist runtime, schema-only baseline, mostly-unauthenticated dashboard, custom-KQL CRUD UI that contradicts the pivot's "customer never edits a rule file" promise). Load this before touching DetectionEngine.cs, RuleLoader.cs, PackLoader.cs, FileIntegrityInput.cs, EventLogInput.cs, node.py, feed.py, or check_ledger.py, or before asserting how any of these subsystems behave — this is the "how does TinySocs actually work" reference, not the "how do I run it" or "what do I do when it breaks" reference.
---

# TinySocs architecture contract

This is the map of how the system actually behaves, verified against code, not aspiration. Every claim below was checked against the repo on 2026-07-11 at branch `fix/ci-green`, HEAD `37005ad`. Re-verify anything volatile before quoting it externally — see Provenance at the bottom.

## 1. The central invariant: dual-engine split, one engine fires

There are two YAML rule surfaces in this repo. Only one of them ever produces an alert.

| | C# agent engine | Python KQL catalogue |
|---|---|---|
| Rule file | `packaging/detection/rules.yml` (legacy) or a signed pack under `packs/` | `src/tinysocs/agent/detections/rules.yaml` |
| Rule count | 39 defined, 19 enabled (as of 2026-07-11) | 50 rules |
| Rule type | one: `threshold_by_key` | KQL query + threshold |
| Runs | **inline, in-process, on every shipped batch** | **on demand only — no scheduler** |
| Consumers | `DetectionEngine.EvaluateEvent` | `reporting/mitre_coverage.py` (MITRE heatmap); AI assistant's `search_kql` tool (`src/tinysocs/agent/tools.py`, `src/tinysocs/agent/detections/registry.py`); `node.py` `/agg` endpoint (imports `RULES` from the registry, evaluated per-request, not scheduled) |
| Fires alerts in production? | **Yes — this is the only engine that does.** | **No.** |

**Why the split exists** (binding working preference from `/Users/lukefitzgerald/tinysocs/CLAUDE.md`): C# is for the runtime-critical agent path; Python is the iteration language, used where latency cost is acceptable. Don't try to collapse this by moving detection logic into Python without going through the v2 schema and `runs_on` discriminator (below) — that's how you'd silently stop rules from firing.

**Where the C# engine actually runs**: `OpenSearchBulkShipper.cs:246-263`, inline in the ship loop, evaluating every event in a batch **before** the batch is POSTed to OpenSearch (`_httpClient.PostAsync(_bulkUri, ...)` at line 287):

```csharp
// **DETECTION PIPELINE**: Evaluate events before shipping
if (_detectionEngine != null && _alertWriter != null)
{
    var allAlerts = new List<AlertDocument>();
    foreach (var evt in batch)
    {
        var alerts = _detectionEngine.EvaluateEvent(evt);
        if (alerts.Count > 0) allAlerts.AddRange(alerts);
    }
    if (allAlerts.Count > 0)
        await _alertWriter.WriteAlertsAsync(allAlerts, stoppingToken).ConfigureAwait(false);
}
```

Implication: detection is coupled to the shipper's batch cadence (`output.Bulk.FlushIntervalMs`, `BatchSizeEvents`), not a separate consumer of the OpenSearch index. If the shipper stalls (queue backlog, network outage), detection stalls with it — there is no independent tailing process re-reading events out of OpenSearch to detect on.

**Single rule type, despite the schema comment**: `DetectionRule.cs:15` documents `Type` as `"threshold_by_key, match_single, cardinality"`, but `DetectionEngine.cs:75` only ever checks `if (rule.Type == "threshold_by_key")`. `match_single` and `cardinality` are dead vocabulary — don't assume they're implemented because the field comment lists them.

**`runs_on` is an authoring convention, not an enforced guardrail — do not trust it as a runtime safety mechanism.** Every v2 rule in a pack carries `runs_on: agent | backend` (`docs/design/rule-format-v2.md:19,60,99`; confirmed present at `packs/base/2026.27/pack.yml:22,60,97,130,163…`), and the design doc claims "C# `RuleLoader` understands `runs_on` and silently skips non-agent rules" (`rule-format-v2.md:371`). That claim is aspirational, not implemented: `grep -rni "runs_on\|RunsOn" src/TinySocs.Agent/Detection/*.cs` returns zero hits. `DetectionRule.cs` has no `RunsOn` property at all (legacy `RuleLoader`'s `IgnoreUnmatchedProperties()` silently drops the field), and `PackLoader.MapRule()` (`PackLoader.cs:168-250`) maps `id`/`name`/`severity`/`enabled`/`detection`/`mitre` with no `runs_on` check — it will load and enable a `runs_on: backend` rule exactly like a `runs_on: agent` one, gated only by `enabled` and non-empty `id`/`type`. Today's apparent safety is incidental: a `runs_on: backend` rule typically uses `detection.type: kql_threshold`, which just never matches `DetectionEngine`'s `rule.Type == "threshold_by_key"` check (`DetectionEngine.cs:75`) — not because anything checked `runs_on`. Mixing a `runs_on: backend` rule with `detection.type: threshold_by_key` into a pack would silently ship and fire as if it were an agent rule, which is exactly the outcome CLAUDE.md's "don't quietly let backend rules ship as if they run" rule is meant to prevent. Treat adding real `runs_on` enforcement to both loaders as open work, not a completed guardrail.

**"How many rules does TinySocs have?"** — don't conflate the tiers. 19 enabled / 39 defined (C# engine) / 89 including the Python roadmap catalogue. Full quotable framing and where the number is allowed to appear: `tinysocs-external-positioning`.

## 2. Rule-loading paths: legacy unsigned vs signed-and-dormant

Two independent loaders feed the C# `DetectionEngine`, selected by config, never both:

### RuleLoader (legacy, active in every real install today)

- `src/TinySocs.Agent/Detection/RuleLoader.cs`
- Reads `packaging/detection/rules.yml` (or wherever `Detection.RulesFile` points) as plain YAML via `YamlDotNet` with `UnderscoredNamingConvention`.
- No signature, no licence check. Filters `Where(r => r.Enabled)`.
- Re-read on a timer: `TryReloadRules()` in `OpenSearchBulkShipper.cs:1369-1386` reloads every `Detection.ReloadIntervalSeconds` (`AgentConfig.cs:130`, **default 60**), not a filesystem watcher.
- On any read/parse failure it logs and returns an **empty rule list** ("Detection disabled"), it does not keep stale rules — a truncated or invalid `rules.yml` silently zeroes out detection.

### PackLoader (signed v2, implemented but dormant in production)

- `src/TinySocs.Agent/Detection/PackLoader.cs`, `Ed25519Verifier.cs`, `LicenceReader.cs`.
- Selected when `Detection.Pack.Enabled == true` — **default is `false`** (`AgentConfig.cs:146`), and production config templates and the Inno Setup installer do not set it or ship a public key. **This path does not run in any real install today.** State this plainly whenever discussing signed content — it's built, tested, not switched on.
- Trust chain, in order:
  1. Read `PackFile` (default `C:\ProgramData\TinySocs\Collector\packs\pack.yml.canonical`) — **the exact signed bytes**, compact sorted-key canonical JSON, produced by `scripts/pack_sign.py`. The human-readable `pack.yml` is explicitly *not* on the trust path (comment at `AgentConfig.cs:148-149`: "The agent verifies + loads THIS file; the human-readable pack.yml is not on the trust path"). Confirmed on disk: `packs/base/2026.27/pack.yml.canonical` sits alongside `pack.yml` and `pack.yml.sig`.
  2. Verify the Ed25519 signature over those canonical bytes against the embedded/config'd public key (`PackLoader.cs` uses `System.Text.Json`, **not YamlDotNet**, to parse — this is a different parser from the legacy path, deliberately, since it must parse exactly the bytes that were signed).
  3. Pin `key_id`: even a mathematically valid signature is refused if `metadata.signature.key_id` doesn't match the configured `SigningKeyId` (default `"tinysocs-2026"`) — defence against key-confusion if multiple signing keys ever exist.
  4. Licence-gate: `LicenceReader.Resolve(...)` + `LicenceReader.CanAccess(tier, packId, channel)` — a validly-signed pack the licence doesn't entitle is still refused.
  5. Map rules, keep only `Enabled` ones.
- **Refuse-and-freeze, no fallback to unsigned**: `LoadRules()` in `OpenSearchBulkShipper.cs:1326-1364` — if `_packLoader != null` and `Load()` fails for any reason (bad signature, wrong key_id, licence not entitled, missing file), it logs an error and returns; **it does not fall back to `RuleLoader`/`rules.yml`, and it does not clear the engine's currently-loaded rules** — the last-good rule set (or an empty one, on first load) stays in effect. A pack that fails verification never silently degrades to unsigned rules.

`ContentPackConfig` fields worth knowing when configuring this path: `PackFile`, `SignatureFile` (empty → derived by swapping `.canonical`→`.sig`), `PublicKey` (base64 raw Ed25519 pubkey, the pack-signing trust anchor), `SigningKeyId`, `LicenceKey` (empty = free tier), `LicencePublicKey` (empty = "read tier without verifying" per the field comment — a soft-fail mode worth knowing about if you ever reason about licence security).

Both loaders write into the same `DetectionEngine.UpdateRules(...)` — the engine itself doesn't know or care which loader produced its rule list.

Turning this path on for a real install, or changing anything about the trust chain, is a pivot-relevant, security-relevant change: **gate through tinysocs-change-control**.

## 3. FIM: a synthetic-event subsystem, not a regular event-log source

`FileIntegrityInput.cs` doesn't read a Windows event log — it watches the filesystem directly and **manufactures** its own event stream on channel `TinySocs-FIM` with event IDs 1001 (created), 1002 (modified — content hash changed), 1003 (deleted), 1004 (renamed). These synthetic events are pushed through the same queue as real Windows events, so the detection engine treats them identically to Sysmon/Security events — but nothing upstream of `FileIntegrityInput` produced them; they're internal.

Two things about FIM that trip people up:

- **It carries its own baseline** — `_baseline: ConcurrentDictionary<filePath, sha256Hash>`, persisted to `_fimConfig.BaselinePath`, loaded/created in `InitializeBaseline()`. This is genuinely implemented (unlike the schema-only `baseline:` block below). It's a file-hash baseline scoped to FIM only — do not generalize "TinySocs has baselining" from this; nothing else in the engine baselines anything.
- **`winlog.computer_name` is synthesized, not inherited** — added at `FileIntegrityInput.cs:575-582` (`Environment.MachineName`) specifically because TS-113 (ransomware mass-modification, `group_by: winlog.computer_name`) had no host key to group on without it. `git blame`/`git show -s --format=%ad` pin this to commit `347c98e`, dated 2026-07-10 (not 2026-07-08 — CLAUDE.md's date for this fix is off by a day; trust the commit date here). Before this fix, TS-113 could never form a group and never fired. If you touch `FileIntegrityInput`'s event body construction, keep this field — removing it silently kills TS-113 and any other FIM rule that groups by host.

## 4. TS-080's direct-alert fast path — a wart, don't replicate it

`EventLogInput.cs:245-254,532-610`: when a Security-channel event 1102 (event log cleared) is seen, `TryWriteDirectAlert1102()` fires a **hard-coded TS-080 alert directly**, writing straight to OpenSearch/alerts.log — bypassing the queue, the shipper's batch loop, and `DetectionEngine` entirely. The code comment explains why: without this, a test harness where 1102 needs to fire immediately (not wait for the next batch flush) couldn't observe it in time.

But `packaging/detection/rules.yml:348-367` **also** defines a regular engine rule `TS-080` (`event_id: 1102, channel: Security, threshold: 1, window_minutes: 5, cooldown_minutes: 60`) that fires through the normal engine path. That means event 1102 can produce **two alert documents with different metadata shapes for the same real-world event** — the direct-alert path and the engine path aren't reconciled. There's a dedup guard (`_writtenDirectAlertIds`, capped at 1000 entries, per-process, cleared on overflow) but it only prevents the direct path from double-firing on itself within one window; it does nothing about the direct-path/engine-path duplication.

`TS-080-sys` (event 104, channel `System`) is a separate, non-duplicated engine-only rule — the fast path is scoped to 1102/Security only.

**Do not add another direct-alert bypass for a new rule.** If a rule needs faster-than-batch-interval firing, that's a shipper flush-interval or architecture conversation, not a per-rule hard-coded exception — gate any such change through tinysocs-change-control.

## 5. Federation / evidence-ledger hash chain

Two roles, `node.py` (site) and `master.py` (hub side of the orchestrator), talk over HMAC-authenticated HTTP.

- **Ledger anchor** (jargon, defined here): a append-only, hash-chained JSONL record of evidence entries. Each entry's `prev_hash` is the previous entry's `head_sha256` (`node.py:726,731`); the chain lives in `ledger/<node-id>.jsonl` with the current head cached in `ledger/<node-id>.head`. "Anchoring" means periodically writing the current chain head into OpenSearch (alias `tinysocs_anchors`, `src/tinysocs/orchestrator/anchors.py`) so a third party (or a later audit) can detect if the local JSONL was rewritten after the fact — the OpenSearch copy is the tamper-evidence witness, not the source of truth.
- `POST /evidence/append` (`node.py:710`) — HMAC-required, appends one entry and advances the head.
- `python -m tinysocs.orchestrator.check_ledger --verify` (`check_ledger.py`) — validates local chain integrity, then compares each node's current head against the latest anchor found in OpenSearch. This is the only automated check that the ledger hasn't been tampered with since its last anchor.
- **HMAC skew** (jargon, defined here): the request-signing scheme (`node.py:296-299`, centralized in `tinysocs.api.auth.make_verify_hmac`) accepts a signed timestamp within a tolerance window — `SKEW_SECS` (`node.py:136`, default 300s, env `TINYSOCS_SKEW_SECS`) — to absorb clock drift between node and hub without rejecting legitimate requests. A "skew" failure in practice usually means the two machines' clocks have drifted past 5 minutes, not that credentials are wrong — see tinysocs-debugging-playbook for the triage.
- **TOFU cert pinning** (jargon, defined here): Trust-On-First-Use — on first successful connection to a hub, the node pins the hub's TLS cert fingerprint to `pinned_certs.json` (`src/tinysocs/federation_certs.py`, `load_pinned_certs`/`save_pinned_certs`, called from `node.py:1484-1498` during auto-registration). Subsequent connections are checked against the pin; a mismatch is treated as a potential MITM, not silently accepted. There is no CA-based alternative in this repo — TOFU is the whole model.
- Most node read endpoints (`/agg`, `/sample`, `/alerts/*`, `/fleet/*`, `/events/recent`, `/host/timeline`, `/storage/stats`) only enforce HMAC if `TINYSOCS_NODE_AUTH_READS=1` is set (`_verify_hmac_if_enabled`) — off by default for backward compatibility. `/evidence/append` always requires HMAC (`Depends(_verify_hmac)`, node.py:710). `/storage/purge` (node.py:1242) — despite being destructive (deletes OpenSearch indices per `body.older_than_days`) — uses the same conditional `_verify_hmac_if_enabled` gate as read endpoints, **not** the unconditional one: it is unauthenticated in the default configuration. This is significant enough to also be a §7 weak point, not just a footnote here.

## 6. Alert flow, end to end

```
raw/synthetic event → agent queue → OpenSearchBulkShipper batch loop
        → DetectionEngine.EvaluateEvent (threshold_by_key, in-memory sliding windows)
        → AlertWriter.WriteAlertsAsync, fan-out to:
              1. tinysocs-alerts-{yyyy.MM.dd} index (AlertWriter.cs:142)
              2. alerts.log (local file)
              3. webhook (Slack-compatible JSON POST, fire-and-forget)
              4. SMTP email — rate-limited to 1 email per rule per 5 minutes
                 (ConcurrentDictionary<ruleId, DateTime> _lastEmailPerRule)
```

Cooldown/dedup state (`DetectionEngine._windows`, `_lastAlertTime`) is an **in-memory `Dictionary` guarded by a single lock, per agent process** — it does not persist across a service restart (NSSM respawn, upgrade, reboot). A rule that just fired and is inside its `cooldown_minutes` window will be eligible to fire again immediately after a restart, because the cooldown clock reset with the process. Same caveat applies to `EventLogInput._writtenDirectAlertIds` (TS-080 fast-path dedup, capped at 1000 entries).

**Heartbeats bypass all of this.** `OpenSearchBulkShipper.cs:1213-1308` writes a heartbeat document directly to the `tinysocs-heartbeat` index every 60 seconds via upsert (fixed doc ID per agent) — it never goes through the queue or the detection engine. This is *why* TS-120 (`agent_version_drift`, `packaging/detection/rules.yml:954-972`, `enabled: false`) is dead: it's written as an engine rule with `channel: heartbeat`, but heartbeats never reach the engine to be matched against any rule. Deferred to v2 per the rule's own comment block (lines 951-953) pending a real version-drift emitter.

## 7. Known weak points — state these plainly, don't paper over them

| Weak point | Evidence | Status |
|---|---|---|
| No allowlist runtime | `grep -rn allowlist src/TinySocs.Agent` → 0 hits (checked 2026-07-11); schema fields exist in v2 packs but nothing reads them in C# | Open — see tinysocs-research-frontier |
| Baseline is schema-only outside FIM | `pack.yml` has `baseline:` / `action_below_baseline: suppress` blocks (e.g. `packs/base/2026.27/pack.yml:40-45`); zero references to either key in `PackLoader.cs`, `DetectionRule.cs`, `DetectionEngine.cs` | Schema-only; only FIM's file-hash baseline (§3) actually runs |
| Dashboard endpoints mostly unauthenticated server-side | `src/tinysocs/api/dashboard.py` — no `Depends(...)` auth, no auth middleware found on e.g. `/api/rules` GET/POST/PUT/DELETE (checked 2026-07-11) | Open |
| Custom-KQL CRUD UI contradicts "customer never edits a rule file" | `dashboard.py:2584-2852` — `/api/rules` lets a user create/update/delete custom KQL-based rules stored in `custom_rules.json`, independent of the signed-pack model | Unresolved tension between the dashboard's existing feature and the strategic pivot's "tuning happens via allowlists/AI-triage/FP feedback, never rule edits" promise (CLAUDE.md). Don't extend this UI without raising the conflict — gate through tinysocs-change-control. |
| Signed-pack trust path is implemented but dormant | §2 above | `ContentPackConfig.Enabled` defaults `false`; no shipping install turns it on |
| `/storage/purge` unauthenticated by default | `node.py:1242` — `dependencies=[Depends(_verify_hmac_if_enabled)])`, gated only by `TINYSOCS_NODE_AUTH_READS` (default `False`, node.py:303) — unlike `/evidence/append` which always requires HMAC | Open — a data-destroying endpoint (purges OpenSearch indices) ships with no auth requirement out of the box |
| Feed blob route is a CDN stand-in | `feed.py:12-13,169-187` docstring: "Stand-in for the CDN/object store: serve pack bytes behind a signed URL" | Fine for now; do not describe the feed as CDN-backed in customer-facing material |
| Licence store is flat JSON, not a database | `src/tinysocs/api/feed_store.py:25-58` — `LicenceStore` reads/writes `data/feed/licence_store.json` (atomic tmp-file swap, no concurrency control beyond that) | Fine at current scale (zero paying customers, 2026-07-11); revisit before real load |
| Per-process replay/cooldown cache | §6 above | By design for now; means "restart the agent" is a legitimate (if crude) way to reset a stuck cooldown — see tinysocs-debugging-playbook |
| Python KQL catalogue has no scheduled runner | §1 above | Deferred to v2.1 post-first-customer (CLAUDE.md); see tinysocs-research-frontier |

## When NOT to use this skill

- Thresholds, windows, MITRE mapping semantics, SMB false-positive theory → detection-engineering-reference.
- How to build/run/deploy any of the above (ports, NSSM, installer flow) → tinysocs-build-and-env, tinysocs-run-and-operate.
- Symptom-first triage ("engine seems silent", "HMAC mismatch", "dashboard won't auth") → tinysocs-debugging-playbook.
- Deciding whether a change is allowed at all (pivot-alignment filter, CI-green rule, BSL discipline) → tinysocs-change-control.
- Rule counts for external claims, banned efficacy figures, ICP framing → tinysocs-external-positioning.
- What counts as validated ("harness-validated" definition, atomic test structure) → tinysocs-validation-and-qa.
- The open research questions this section only flags (allowlists, FP telemetry, KQL runner activation, premium tiering) → tinysocs-research-frontier.
- Historical dead ends and reverted approaches → tinysocs-failure-archaeology.

## Provenance and maintenance

Authored 2026-07-11 against branch `fix/ci-green`, HEAD `37005ad`. Primary sources read directly:

- `src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs` (detection call site, heartbeat, rule reload, LoadRules refuse-and-freeze logic)
- `src/TinySocs.Agent/Detection/DetectionEngine.cs`, `DetectionRule.cs`, `RuleLoader.cs`, `PackLoader.cs`, `AlertWriter.cs`
- `src/TinySocs.Agent/Configuration/AgentConfig.cs` (`ContentPackConfig`, `ReloadIntervalSeconds`)
- `src/TinySocs.Agent/Inputs/FileIntegrityInput.cs`, `EventLogInput.cs`
- `src/tinysocs/api/node.py`, `feed.py`, `feed_store.py`, `dashboard.py`
- `src/tinysocs/orchestrator/anchors.py`, `check_ledger.py`
- `src/tinysocs/federation_certs.py`
- `docs/design/rule-format-v2.md`
- `packaging/detection/rules.yml`, `packs/base/2026.27/pack.yml{,.canonical,.sig}`

Re-verification commands for the volatile facts above:

```bash
# Detection call site still inline pre-POST in the shipper
grep -n "DETECTION PIPELINE" -A20 src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs

# Single rule type actually evaluated (vs the aspirational Type comment)
grep -n 'rule.Type ==' src/TinySocs.Agent/Detection/DetectionEngine.cs

# Pack path still defaults off
grep -n "public bool Enabled" src/TinySocs.Agent/Configuration/AgentConfig.cs

# Legacy reload interval default
grep -n "ReloadIntervalSeconds" src/TinySocs.Agent/Configuration/AgentConfig.cs

# TS-080 duplication still present (fast path + engine rule)
grep -n "1102" src/TinySocs.Agent/Inputs/EventLogInput.cs | head -5
grep -n -A5 'id: "TS-080"' packaging/detection/rules.yml

# TS-113 host-key fix still in FIM event body, and confirm its commit date
grep -n "computer_name" src/TinySocs.Agent/Inputs/FileIntegrityInput.cs
git blame -L 575,583 src/TinySocs.Agent/Inputs/FileIntegrityInput.cs

# runs_on still unenforced by either C# loader (should return 0 hits)
grep -rni "runs_on\|RunsOn" src/TinySocs.Agent/Detection/*.cs | wc -l

# /storage/purge still on the conditional (not unconditional) HMAC gate
grep -n 'storage/purge"' -A1 src/tinysocs/api/node.py
grep -n '_NODE_AUTH_READS = ' src/tinysocs/api/node.py

# TS-120 still disabled, heartbeat still bypasses the engine
grep -n -A3 'id: "TS-120"' packaging/detection/rules.yml
grep -n "tinysocs-heartbeat" src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs

# Allowlist runtime still absent
grep -rn "allowlist" src/TinySocs.Agent | wc -l

# Baseline still schema-only outside FIM
grep -n "baseline" src/TinySocs.Agent/Detection/PackLoader.cs src/TinySocs.Agent/Detection/DetectionEngine.cs

# Dashboard rule CRUD still present, still no visible auth dependency
grep -n '@dashboard_app\.\(get\|post\|put\|delete\)("/api/rules' src/tinysocs/api/dashboard.py

# Licence store still flat JSON
grep -n "_DEFAULT_STORE" src/tinysocs/api/feed_store.py

# HMAC skew default unchanged
grep -n "SKEW_SECS =" src/tinysocs/api/node.py

# Python KQL catalogue still has no scheduler (no cron/APScheduler/Timer wired to rules.yaml)
grep -rln "rules.yaml" src/tinysocs
```
