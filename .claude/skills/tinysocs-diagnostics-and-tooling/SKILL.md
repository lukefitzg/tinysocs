---
name: tinysocs-diagnostics-and-tooling
description: Measure, don't eyeball, whether a TinySocs install is actually working. Covers Test-TinySocsHealth (16 checks) and Invoke-TinySocsSmokeTest (the TS-001 brute-force trigger) in modules/TinySocs.Installer.psm1 — what each check proves, which ones are structurally INFO/WARN on a minimal install, and the "committed smoke test could never fire" scar that already burned this project once. Also covers reading the live alert pipeline with curl.exe against tinysocs-alerts-* day indices, mitre_coverage.py (regenerates docs/detection-coverage.md, currently stale), check_ledger.py --verify (federation ledger head-vs-anchor verification), and storage/purge diagnostics (ISM policy checks, purge-logs endpoint, disk queue size). Load this when asked "is TinySocs actually working," "prove the pipeline end to end," "why does health check show WARN," "how do I confirm an alert fired," "check the MITRE coverage doc," "verify the ledger," or "check retention/purge is actually deleting things." Ends with a 10-minute prove-the-pipeline runbook. Does not interpret rule efficacy or Atomic Red Team results (tinysocs-validation-and-qa) and does not fix what these tools find (tinysocs-debugging-playbook).
---

# TinySocs diagnostics and tooling

Ground truth verified directly against `modules/TinySocs.Installer.psm1`, `tests/Test-AtomicDetection.ps1`,
`src/tinysocs/reporting/mitre_coverage.py`, `src/tinysocs/orchestrator/check_ledger.py`, and
`src/tinysocs/api/dashboard.py` on branch `fix/ci-green` (2026-07-11). Line numbers cited below can drift —
re-verify with the grep commands in Provenance before trusting them in a review or a doc.

This skill is about **measuring** state, not fixing it. Every tool here answers "is X actually true right
now," never "make X true." If a check fails, the fix belongs in tinysocs-debugging-playbook.

---

## 1. `Test-TinySocsHealth` — the 16-check health probe

Defined `modules/TinySocs.Installer.psm1:14794` (verify: `grep -n 'function Test-TinySocsHealth' modules/TinySocs.Installer.psm1`).

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Test-TinySocsHealth
# or with explicit creds instead of CredMan lookup:
Test-TinySocsHealth -SiemUrl "https://localhost:9201" -User "admin" -Pass "secret"
```

Returns `$true`/`$false` and prints a `[STATUS ] Check Name  Detail` line per check. Run on the machine
being diagnosed (Windows host or VM with TinySocs installed) — it reads local services, local files, and
calls the local OpenSearch/Assistant over loopback.

### What each check actually proves

| # | Check | Severity on fail | What it proves |
|---|---|---|---|
| 1 | OpenSearch Service | **FAIL** | `TinySocsOpenSearch` NSSM service is `Running` |
| 2 | Heartbeat Fresh | **FAIL** (WARN if missing) | A doc exists in `tinysocs-heartbeat` and is < 2 min old — the agent's heartbeat writer is alive. Run *before* check 3 deliberately, to "prime" PS 5.1's TLS callback for the plain HTTP-root check that follows |
| 3 | OpenSearch HTTP | **FAIL** | `GET /` on `$SiemUrl` (default `:9201`) returns a response |
| 4 | Index Template | **FAIL** | `tinysocs-winlog` index template exists (`GET /_index_template/tinysocs-winlog`) |
| 5 | Recent Ingestion | WARN | A doc exists in `tinysocs-winlog-*` with `@timestamp >= now-5m` — events are actively flowing, not just that the template exists |
| 6 | @timestamp Mapping | WARN (FAIL if wrong type found) | `@timestamp` field maps to type `date`. Uses the **field-specific** mapping API (`/tinysocs-winlog-*/_mapping/field/%40timestamp`), not the full mapping — the full mapping response contains duplicate JSON keys that break PS 5.1's `ConvertFrom-Json` |
| 7 | Agent Service | WARN | `TinySocsAgent` NSSM service is `Running` |
| 8 | Alert Template | WARN | `tinysocs-alerts` index template exists |
| 9 | Rules File | WARN | `C:\ProgramData\TinySocs\Collector\rules\rules.yml` exists and contains the literal string `rules:` — a syntax smoke test, not a validity check |
| 10 | Assistant Service | WARN | `TinySocsAssistant` NSSM service is `Running` |
| 11 | Assistant API | WARN | `GET /meta` on port 8081 responds — tries `curl.exe -ks` first (HTTPS then HTTP), and falls back to `Invoke-RestMethod` whenever curl.exe doesn't yield a response, whether because curl.exe is missing or because both curl attempts failed to connect (the more common real-world case — a stopped/unreachable Assistant, not a missing binary). PS 5.1's TLS stack is unreliable for this specific probe even with the cert-bypass callback set, so curl.exe is the primary path here, not a fallback |
| 12 | Webhook | INFO | Whether a `webhook_url` is configured in `agent-config.yml` — presence only, no delivery test |
| 13 | Webhook Delivery | WARN (INFO if not configured) | **Live POST** of `{"text":"[TinySocs] Health check — webhook delivery test"}` to the configured URL, checks for a 2xx. This actually sends a message to Slack/Teams/whatever is configured |
| 14 | Email SMTP | WARN (INFO if not configured) | Raw TCP connect + `EHLO` handshake to the configured SMTP host:port (default 587), checks for a `250` response. Does not send an actual email |
| 15 | Sysmon Service | INFO | Checks `Sysmon64` then `Sysmon64a` (ARM64), prefers whichever is `Running`. Absence is not a failure — Sysmon is optional |
| 16 | Dashboard TLS | **FAIL** (only if network mode) | If `assistant.env`'s `DASHBOARD_BIND` is not `127.0.0.1`, requires `DASHBOARD_TLS_CERT` to point at an existing file. Localhost-only installs auto-PASS this check (TLS not required) |

`$allPassed` (the return value) is set to `$false` by FAIL-severity checks (1, 3, 4, 6-if-wrong-type,
16-if-network-without-cert) **and** by check 2's stale/missing-heartbeat paths — both the FAIL "stale" branch
and the WARN "no heartbeat document found" branch flip it (only the WARN catch-block for an HTTP/connection
exception on check 2 leaves `$allPassed` untouched). So it is not true that WARN rows never flip the overall
result — one of them does. Don't rely on "absence of a `FAIL` line" as a shortcut for health; always read the
literal `$allPassed` / `Overall Status` line.

### The "16/16 PASS" claim is optimistic

`docs/getting-started.md:37` and the operator runbook both say "you should see 16/16 PASS." That's true only
on an install with notifications configured, Sysmon installed, and network-mode TLS set up. **A fresh minimal
install (no webhook, no SMTP, no Sysmon, localhost dashboard) will structurally show INFO rows for checks
12-15** — those checks report INFO by design when the feature isn't configured, not PASS. Read the literal
`$allPassed` return value / `Overall Status` line, not the PASS count, to decide if the install is actually
healthy — **do not** substitute "no `FAIL` line printed" as a proxy for that; check 2's missing-heartbeat
path is WARN-severity but still flips `$allPassed` to `$false` (see above), so an install with zero `FAIL`
lines can still report unhealthy.

---

## 2. `Invoke-TinySocsSmokeTest` — trigger-and-verify

Defined `modules/TinySocs.Installer.psm1:15285` (verify: `grep -n 'function Invoke-TinySocsSmokeTest' modules/TinySocs.Installer.psm1`).

```powershell
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Invoke-TinySocsSmokeTest
```

### Mechanism (current, as committed in 347c98e)

1. Runs `Test-TinySocsHealth` first (informational — doesn't gate step 2).
2. Counts `tinysocs-alerts-*/_count` (baseline).
3. Generates **20 failed logon attempts** for a **nonexistent user `tinysocs_smoketest`**, via
   `Start-Process cmd.exe -Credential $fakeCred` in a loop — each failed logon writes a Windows Security
   Event ID 4625. This is designed to trip **TS-001** (`brute_force_logon`), the pilot pack's enabled rule
   with `threshold: 15, window_minutes: 5, group_by: winlog.event_data.TargetUserName`
   (`packaging/detection/rules.yml:21-40`, confirmed enabled and threshold=15 by direct read).
4. Sleeps 30s for ingestion + detection cycle.
5. Re-counts `tinysocs-alerts-*/_count`. PASS if the delta is `> 0`.

### The canonical stale-doc scar — why this matters and why you must re-verify

**This exact mechanism was broken for months and is the reason this project distrusts "the doc says it
works."** The originally committed version had two independent bugs that made the smoke test structurally
unable to pass on a customer install:

- `Invoke-TinySocsSmokeTest` fired 5 PowerShell ScriptBlock events targeting `script_block_volume` /
  `ps_script_block_lab` — **lab-only rules that ship `enabled: false`** on customer installs. The trigger
  could never land on a rule that was actually running.
- `docs/getting-started.md`'s manual fallback instructions told the operator to generate **6** failed
  logons against a rule whose threshold was **15**. Mathematically could not fire.

Both were fixed in commit `347c98e` ("Ship pilot base pack 2026.27: 20 high-fidelity rules (#9)") — the
smoke test now uses the real enabled TS-001 rule at 20 attempts (5 above its 15 threshold, and validated at
18 attempts in the Atomic harness per the code comment), and `docs/getting-started.md:76-89` matches. **Both
are confirmed committed and correct as of this writing** — but the whole point of this scar is: don't take
that on faith. Before trusting either file, re-run:

```bash
grep -n -A20 'id: "TS-001"' packaging/detection/rules.yml | grep threshold
grep -n '16/16\|run at least\|15 failed logons' docs/getting-started.md
```

and confirm the numbers agree with each other and with the live `rules.yml` on disk. A wrong runbook that
mathematically cannot fire is worse than no runbook — it produces a false "the pipeline is broken" panic
(or worse, false confidence that it works, when what actually happened is nothing).

---

## 3. Reading the alert pipeline directly

When you don't trust (or don't have) the smoke test, query OpenSearch yourself. Two things make this
reliable on Windows:

### Why `curl.exe`, not `Invoke-RestMethod`

PowerShell 5.1's Schannel TLS stack fails the handshake against the bundled OpenSearch's self-signed cert
in ways `Invoke-RestMethod` **silently swallows into an empty result** — a real alert in the index can read
back as zero hits, producing a false "nothing fired." `curl.exe -sk` (skip cert verify) negotiates the same
endpoint reliably. This isn't a style preference; it's the difference between a real MISS and a tooling
artifact (verified in `tests/Test-AtomicDetection.ps1:204-213`, and it's why the harness itself uses
curl.exe for every OpenSearch call).

```powershell
# From a Windows host with TinySocs installed, admin creds from CredMan or explicit:
curl.exe -sk -u admin:<password> "https://localhost:9201/tinysocs-alerts-*/_count"
```

### Query day indices, not the `tinysocs-alerts-*` wildcard, under load

Alerts are indexed one per UTC day: `tinysocs-alerts-{yyyy.MM.dd}` (confirmed
`src/TinySocs.Agent/Detection/AlertWriter.cs:142`). A wildcard against `tinysocs-alerts-*` matches every
historical daily index — on a long-lived install this can be 40+ indices / 80+ shards, and on the bundled
1GB-heap single-node OpenSearch under concurrent ingest, that query's latency can exceed a client timeout,
producing a **false MISS** even though the alert is sitting in the index. Scope to just today (+ yesterday,
for runs spanning UTC midnight):

```bash
TODAY=$(date -u +%Y.%m.%d)
YDAY=$(date -u -v-1d +%Y.%m.%d 2>/dev/null || date -u -d yesterday +%Y.%m.%d)
curl.exe -sk -u admin:<password> \
  "https://localhost:9201/tinysocs-alerts-$TODAY,tinysocs-alerts-$YDAY/_search?ignore_unavailable=true" \
  -H 'Content-Type: application/json' \
  --data-binary '{"size":50,"_source":["alert.rule_id","timestamp"],"query":{"bool":{"must":[{"range":{"timestamp":{"gte":"2026-07-11T00:00:00.000Z"}}}]}}}'
```

### The `-Since` floor pattern

The live index accumulates alerts across the install's entire lifetime (15k+ docs across months on a
long-running pilot host is normal). If you're asking "did *this* action just fire an alert," you must apply
a lower time bound (`gte` on `timestamp`) set to when you started your test — otherwise a rule that fired
last week reads as "detected" for a test you ran five minutes ago. This is the exact bug class the Atomic
harness calls its "detection floor" (`tests/Test-AtomicDetection.ps1:420-434`). When checking your own
smoke-test results by hand, always record `Get-Date` immediately before triggering and filter on it.

### `_source` projection — avoid the `ConvertFrom-Json` hang

Alert documents carry a `matched_events` array (the raw events that tripped the rule), which can make
individual docs multi-KB to multi-MB. Fetching full `_source` and parsing it with PS 5.1's
`ConvertFrom-Json` on such payloads is pathologically slow — observed 30-45 minute hangs in the harness's
history, long enough to blow past any reasonable timeout and register as a MISS on an alert that actually
fired. Always project `_source` down to what you need:

```json
"_source": ["alert.rule_id", "timestamp"]
```

If you need the full matched-events payload for a specific alert, fetch that one document by ID separately
— never bulk-fetch full `_source` across a search result set on PS 5.1.

---

## 4. `mitre_coverage.py` — MITRE ATT&CK coverage report

`src/tinysocs/reporting/mitre_coverage.py`. Run from the macOS/Linux dev checkout or on a Windows install
with the Python environment active.

```bash
python -m tinysocs.reporting.mitre_coverage                              # stdout summary
python -m tinysocs.reporting.mitre_coverage --output navigator-layer.json  # ATT&CK Navigator layer
python -m tinysocs.reporting.mitre_coverage --output-md docs/detection-coverage.md  # regenerate the doc
python -m tinysocs.reporting.mitre_coverage --atomic-results tests/atomic-results.json --output navigator-layer.json
```

### What it reads — the engine-honesty caveat

`load_all_rules()` (`mitre_coverage.py:104-136`) reads **both** rule files and concatenates them:
`packaging/detection/rules.yml` (C# engine, tagged `_source: csharp`) **and**
`src/tinysocs/agent/detections/rules.yaml` (the 50-rule Python KQL catalogue, tagged `_source: python`,
**not a running detection set** — no scheduled runner consumes it; see CLAUDE.md's dual-engine section).

**This means the coverage numbers this tool prints conflate a running detection engine with a documented
roadmap library.** A technique showing "covered" in the Navigator layer or `docs/detection-coverage.md`
may be covered only by a Python-catalogue rule that never fires in production. When quoting coverage
numbers externally, always disambiguate C#-engine-covered vs catalogue-covered — gate any such external
claim through tinysocs-change-control and tinysocs-external-positioning.

It does **not** distinguish enabled vs disabled C# rules either — a technique whose only C# rule is one of
the 18 disabled-for-pilot rules still counts as "covered."

### What it regenerates, and its current staleness

`--output-md docs/detection-coverage.md` overwrites that file with a fresh tactic/technique table.
**As of this writing `docs/detection-coverage.md` claims 32 techniques covered across 11/14 tactics** —
re-run the tool to check whether that's still current; it was last regenerated against an unknown prior
rule-count snapshot and nothing in CI enforces it staying in sync with `rules.yml`/`rules.yaml` edits. Treat
this file as advisory, not authoritative, until it's wired into CI or a pre-commit check.

---

## 5. `check_ledger.py --verify` — federation ledger integrity

`src/tinysocs/orchestrator/check_ledger.py`. Requires env `TINYSOCS_NODES` (comma-separated node API URLs,
e.g. `http://localhost:8081`) and `MASTER_SHARED_SECRET` (the HMAC key nodes and master share). A **ledger**
here is an append-only HMAC-chained JSONL evidence log per federation node; an **anchor** is a periodic
snapshot of a node's ledger head written into OpenSearch, used to detect tampering between anchor points.

```bash
export TINYSOCS_NODES="http://localhost:8081"
export MASTER_SHARED_SECRET="<shared-secret>"
python -m tinysocs.orchestrator.check_ledger              # health probe: current heads only
python -m tinysocs.orchestrator.check_ledger --verify      # full verify: local chain + anchor comparison
```

`--verify` does two things per node, in order, short-circuiting if the first fails:

1. **Local chain verification** (`_ledger.verify_chain(node_id)`) — walks the on-disk `.jsonl` ledger and
   confirms every entry's `prev` hash link is intact and the sequence has no gaps. Failure reasons surface
   directly: `prev_link_mismatch`, `head_mismatch`, `sequence_gap`.
2. **Anchor comparison** — only runs if step 1 passed. Fetches the node's current head via
   `GET {node}/evidence/head`, then searches the `tinysocs_anchors` OpenSearch alias
   (`TINYSOCS_ANCHORS_ALIAS` env, default `tinysocs_anchors`) for the most recent anchor doc for that node
   (matched by node_url — with localhost/127.0.0.1 alias handling — or node_id), and compares
   `current_head == anchored_head`. Mismatch → `anchor_mismatch`; no anchor doc found at all →
   `no_anchor` (expected on a fresh node before the first anchor cycle runs).

Output is a JSON array, one row per node, each with `ok: true/false` and (on failure) a `reason` string.
An HTTP 501 from `/evidence/head` means that node build doesn't expose ledger evidence at all — not a real
failure, a capability gap — but the two modes report it with a different shape. The plain health-probe path
(no `--verify`) emits `{ok: null, capability: "no-ledger", ...}` straight from `_get_head`. `--verify`
normalizes the same 501 into `{ok: false, reason: "no_ledger_capability", node_id: ...}` — no `capability`
key in that row, and `ok` is literally `False`, not `null`. Don't treat `ok: false` from `--verify` as proof
of a real ledger problem without checking `reason` first — `no_ledger_capability` is benign.

---

## 6. Storage / purge diagnostics

### ISM policy verification

The three OpenSearch ISM (Index State Management) policies that auto-delete old indices — what they contain
and where they're bound is owned by tinysocs-run-and-operate (`packaging/opensearch/policies/*.json`). To
**verify** a policy is actually attached to a live index (not just that the JSON file exists on disk):

```bash
curl.exe -sk -u admin:<password> "https://localhost:9201/_plugins/_ism/explain/tinysocs-alerts-*" | python3 -m json.tool
```

This returns, per matching index, the `index.plugins.index_state_management.policy_id` it's actually
running under and its current ISM state — the ground truth of whether the policy is *bound*, as opposed to
merely present in `packaging/opensearch/policies/`. A policy file existing in the repo proves nothing about
a given live index until this comes back non-null for it.

### The purge endpoints and their silent-401 history

`src/tinysocs/api/dashboard.py`:
- `POST /api/settings/purge-logs` (:1932) — the real implementation. Deletes whole `tinysocs-*` indices
  either by age (`older_than_days`, defaults from `WINLOG_RETENTION_DAYS`/`ALERT_RETENTION_DAYS` env) or
  everything (`older_than_days: 0`). Requires `SIEM_PASS` to be configured — returns a clear error string
  if not, rather than silently no-op-ing.
- `POST /api/storage/purge` (:2028) — a thin alias for the above, used by the dashboard's Storage widget.
- `POST /api/alerts/purge` (:1779) — separate code path, purges the alerts index plus local alert-state
  and chat-session files.

**History worth knowing before you debug "purge button does nothing":** commit `931d724` ("Fix Settings
purge: use fetch instead of authFetch to avoid silent 401 redirect") — the dashboard's purge button
previously called the API via a helper that, on session expiry, silently redirected to the login page on a
401 instead of surfacing an error, so an operator clicking "Purge" with a stale session saw nothing happen
and no error. If purge appears to silently no-op today, check the browser network tab for a 401 first,
not the backend logic — that failure mode has recurred (`git log --oneline -- src/tinysocs/api/dashboard.py`
shows at least 4 separate purge-button fix commits: `1ee6ed4`, `1091043`, `931d724`, `f121dc5`).

### Agent disk queue size check

The C# agent's disk queue (segment-based ship buffer) caps at 100 segments × 10MB ≈ 1GB
(`AgentConfig.cs:64-67` — full mechanics owned by tinysocs-run-and-operate). To check current queue
pressure on a host:

```powershell
$q = "C:\ProgramData\TinySocs\Collector\agent\queue"
$files = Get-ChildItem $q -Filter "segment-*.jsonl" -ErrorAction SilentlyContinue
"{0} segments, {1:N1} MB" -f $files.Count, (($files | Measure-Object Length -Sum).Sum / 1MB)
```

A queue near 100 segments / ~1GB means the shipper is falling behind ingestion (OpenSearch down, network
partition, or shipper crash-looping) — that's a debugging-playbook problem once you've confirmed it here.

---

## 7. Prove the pipeline end-to-end in 10 minutes

Run this on a fresh (or freshly suspicious) install, in order. Each step's pass condition is stated so you
don't have to eyeball colored PowerShell output.

```powershell
# 1. (Windows host, admin PowerShell) Load the module.
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"

# 2. Health check — expect no FAIL lines. WARN/INFO on webhook/SMTP/Sysmon/dashboard-TLS
#    are normal on a minimal install; do not expect literal "16/16 PASS" (see §1).
Test-TinySocsHealth

# 3. Record the current time before triggering anything — you'll need this as your
#    detection floor if you query manually later.
$testStart = Get-Date

# 4. Run the smoke test — this both triggers AND verifies (§2). Expect
#    "Alert Ingested: PASS" with a nonzero new-alert count.
Invoke-TinySocsSmokeTest

# 5. If step 4 reports no new alerts, don't guess — check the pipeline stages directly:

#    5a. Is the agent even seeing 4625 events? (confirms Windows audit policy is on)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$testStart} -ErrorAction SilentlyContinue | Measure-Object

#    5b. Is the agent shipping? Check the disk queue isn't backed up (§6).
Get-ChildItem "C:\ProgramData\TinySocs\Collector\agent\queue" -Filter "segment-*.jsonl" | Measure-Object

#    5c. Is OpenSearch actually receiving winlog docs for this window? (curl.exe, §3)
curl.exe -sk -u admin:<password> "https://localhost:9201/tinysocs-winlog-*/_count"

#    5d. Query the alerts index directly with the day-scoped, _source-projected,
#        detection-floor pattern from §3, filtering on rule_id "TS-001" and your
#        $testStart timestamp.
```

Interpreting the outcome:
- Step 2 has a FAIL → stop here, that's the root cause; hand off to tinysocs-debugging-playbook with the
  specific check name.
- Step 4 PASS → pipeline is proven end-to-end (Windows audit → agent → OpenSearch → detection → alert doc).
  Nothing further needed.
- Step 4 fails but 5a-5c all look healthy → the detection engine itself isn't firing on real TS-001
  conditions even though data is flowing; that's a rule-logic question, not a diagnostics question — see
  tinysocs-debugging-playbook's "silent detection engine" entry, or tinysocs-detection-validation-toolkit
  if you're trying to formally prove/disprove a specific rule.
- Step 5a comes back empty → Windows audit policy isn't capturing 4625 (`auditpol /get /subcategory:"Logon"`
  should show failure auditing enabled) — an environment/config problem, not a TinySocs bug.

---

## When NOT to use this skill

- **Interpreting rule efficacy, Atomic Red Team pass/fail meaning, or what "harness-validated" means** →
  **tinysocs-validation-and-qa**. This skill tells you how to run the plumbing checks and read raw alert
  data; it does not define what counts as proof a rule works.
- **Fixing what these tools find** (agent silent, shipper failing, HMAC mismatch, dashboard auth failure,
  OpenSearch won't start) → **tinysocs-debugging-playbook**.
- **Installer flow, service registration, ProgramData layout, retention policy *design*, scheduled tasks** →
  **tinysocs-run-and-operate**. This skill only covers *verifying* those things are working, not what they
  are or how they're configured.
- **Formally authoring/running an Atomic Red Team validation for a specific rule, or closing a named
  validation gap** → **tinysocs-detection-validation-toolkit**.
- **Deciding whether a coverage number, efficacy percentage, or rule count is safe to say to a customer** →
  **tinysocs-external-positioning** (and gate through tinysocs-change-control regardless).

---

## Provenance and maintenance

Authored 2026-07-11 against branch `fix/ci-green`, HEAD `37005ad`. Primary sources read directly:
- `modules/TinySocs.Installer.psm1` (`Test-TinySocsHealth` at line 14794, `Invoke-TinySocsSmokeTest` at
  line 15285 — both read in full)
- `docs/getting-started.md` (lines 25-93, confirming the smoke-test fix is committed)
- `packaging/detection/rules.yml` (TS-001 definition, lines 21-40)
- `tests/Test-AtomicDetection.ps1` (curl.exe rationale lines 204-242, detection-floor/day-index/source-
  projection logic lines 420-476)
- `src/TinySocs.Agent/Detection/AlertWriter.cs` (alert index naming, line 142)
- `src/tinysocs/reporting/mitre_coverage.py` (full read)
- `src/tinysocs/orchestrator/check_ledger.py` (full read)
- `src/tinysocs/api/dashboard.py` (purge endpoints, lines 1779-2033)
- `docs/detection-coverage.md` (current staleness snapshot: 32 techniques / 11 tactics)
- `packaging/opensearch/policies/*.json` (ISM policy bodies)
- `git log --oneline` for `347c98e` (smoke-test fix) and the purge-endpoint fix history

Re-verification commands for the volatile facts in this file:
```bash
# Health check line number / check count
grep -n 'function Test-TinySocsHealth' modules/TinySocs.Installer.psm1
grep -c 'Check = "' modules/TinySocs.Installer.psm1 | head -1   # rough upper bound, includes both functions

# Smoke test line number and mechanism
grep -n 'function Invoke-TinySocsSmokeTest' modules/TinySocs.Installer.psm1
sed -n '21,40p' packaging/detection/rules.yml | grep threshold   # confirm TS-001 threshold still 15

# getting-started.md still matches the fixed smoke test
grep -n '16/16\|run at least\|15 failed logons' docs/getting-started.md

# Alert index naming pattern
grep -n 'tinysocs-alerts-{' src/TinySocs.Agent/Detection/AlertWriter.cs

# mitre_coverage.py still reads both rule files
grep -n '_CSHARP_RULES\|_PYTHON_RULES' src/tinysocs/reporting/mitre_coverage.py

# detection-coverage.md staleness
head -5 docs/detection-coverage.md
python -m tinysocs.reporting.mitre_coverage   # compare live count against the doc

# check_ledger.py env vars and verify logic unchanged
grep -n 'TINYSOCS_NODES\|MASTER_SHARED_SECRET\|def main' src/tinysocs/orchestrator/check_ledger.py

# Purge endpoint fix history still accurate
git log --oneline -- src/tinysocs/api/dashboard.py | grep -i purge

# ISM policies still 30/90/30 day retention
grep -n 'min_index_age' packaging/opensearch/policies/*.json

# xUnit still absent from CI (context for why these PowerShell tools matter more)
grep -n 'dotnet test' .github/workflows/*.yml   # expect no output
```
