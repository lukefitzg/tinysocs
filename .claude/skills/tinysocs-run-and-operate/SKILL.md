---
name: tinysocs-run-and-operate
description: How to install, run, and operate TinySocs on a real Windows host — pilot, customer, or VM. Covers the Inno Setup installer flow (Quickstart.iss), the ~610KB TinySocs.Installer.psm1 PowerShell "brain", the NSSM-wrapped services (TinySocsOpenSearch/Agent/Node/Assistant), the C:\ProgramData\TinySocs directory layout, scheduled tasks, retention/ISM policies, rule hot-reload, upgrade/uninstall behavior, and the VM deploy-bundle path for pushing an updated agent+rules. Load this when asked to install TinySocs, stand up a pilot host, explain what runs where, find a log file, change a service, adjust retention, deploy an updated agent/rules build to a VM, or debug "why didn't my install do X." Does NOT cover health-check/smoke-test interpretation (tinysocs-diagnostics-and-tooling) or building the artifacts the installer ships (tinysocs-build-and-env).
---

# TinySocs: run and operate

Ground truth verified directly against the repo on 2026-07-11, branch `fix/ci-green`,
HEAD `37005ad`. Source digest: `operations.md` (captured 2026-07-06 on branch
`pilot-ruleset-2026.27` with uncommitted mods) — **all facts below were re-verified
in the current tree**; line numbers shifted slightly from the digest but every
function name, config default, path, and behavior described here matches the current
HEAD. The digest's "uncommitted" smoke-test/getting-started fix is now **committed**
(clean working tree except `tests/test_feed_server.py`, unrelated to this skill).

This skill is about the *shipped, wired* operational path: the unsigned `rules.yml`
running through the C# agent. It is not a design doc — for why the pack-signing path
exists but is dormant, see tinysocs-architecture-contract.

## 1. Installer flow (Windows, `TinySocs-Setup.exe`)

Source: `packaging/iss/Quickstart.iss` (Inno Setup, ~3400 lines).

- `[Setup]` (Quickstart.iss:39-55): `AppVersion=0.10.0`, installs to
  `C:\Program Files\TinySocs` (`DefaultDirName={commonpf}\TinySocs`),
  `PrivilegesRequired=admin`, `ArchitecturesAllowed=x64compatible` (hard 64-bit
  requirement), output `TinySocs-Setup.exe`.
- `[Files]` (Quickstart.iss:58-126) stages: `TinySocsNode.exe`, `TinySocsMaster.exe`,
  `TinySocsAnchors.exe`, the published agent (`TinySocs.Agent.exe`) into `{app}\bin`;
  `packaging\detection\rules.yml` → `{commonappdata}\TinySocs\Collector\rules\rules.yml`
  with `onlyifdoesntexist` (operator edits survive an upgrade); `packaging\detection\rule_docs.yml`
  → same dir, `ignoreversion` **without** `onlyifdoesntexist` (vendor TinyDocs content,
  always overwritten — deliberate asymmetry, matches `RuleDocs.cs`); `thirdparty\nssm.exe`
  → `{app}\bin`; the Assistant PyInstaller bundle → `{app}\Assistant`; `modules\TinySocs.Installer.psm1`
  and friends → `{app}\modules`.
- `[Dirs]` (Quickstart.iss:269-301) pre-creates the whole ProgramData tree — see §4.
- Wizard collects: role (TinyBox hub vs Site node), shared secret, SIEM + dashboard
  password (auto-generated if blank), notification config (with a live "Test Webhook"
  button), optional LLM key, dashboard bind mode (localhost HTTP vs network HTTPS),
  and a **Sysmon checkbox (checked by default)**.
- **Post-install runs in `[Code] CurStepChanged(ssPostInstall)`** (Quickstart.iss:1812+),
  not in `[Run]` — `[Run]` only contains the finish-page "Launch Dashboard" checkbox.
  The ssPostInstall chain: verify config backups → TinyBox role installs/inits the
  local OpenSearch chain, Site role writes node config only → registers the Assistant
  service → imports dashboards → writes notification config → conditionally registers
  the daily summary task (Phase 12, Quickstart.iss ~3086-3098): the installer itself
  calls `Register-TinySocsDailySummaryTask -To <EmailTo>` inside
  `CurStepChanged(ssPostInstall)` whenever the wizard collected `EmailEnabled=true`
  and a non-empty `EmailTo` — no separate operator action is required for that case.
  See §6 for how this relates to `Register-TinySocsTasks`.
- Uninstall: `[UninstallRun]` (Quickstart.iss:311-325) runs
  `TinySocs.Uninstall.ps1 -FromInnoUninstall`. See §8.

**The brain is `modules/TinySocs.Installer.psm1`** — one file, ~623KB, 16,242 lines,
**210 functions** (`grep -c '^function ' modules/TinySocs.Installer.psm1`). Key entry
points and their current line numbers:

| Function | Line | Purpose |
|---|---|---|
| `Register-TinySocsOpenSearchService` | 11993 | NSSM-registers OpenSearch |
| `Install-TinySocsAgentService` | 13114 | NSSM-registers the agent |
| `Register-TinySocsNodeService` | 13186 | NSSM-registers the federation node |
| `Ensure-TinySocsAssistantService` | 13331 | NSSM-registers the dashboard/bot |
| `Register-TinySocsTasks` | 13521 | Heartbeat/Anchors/RotateQueue scheduled tasks |
| `Pair-TinySocs` | 13905 | Site-node pairing to a TinyBox |
| `Uninstall-TinySocs` | 14273 | Programmatic uninstall |
| `Test-TinySocsHealth` | 14794 | 16-check health probe — see tinysocs-diagnostics-and-tooling |
| `Invoke-TinySocsSmokeTest` | 15285 | health + fire TS-001 + verify alert count delta |
| `Register-TinySocsDailySummaryTask` | 15793 | daily 07:00 email task |
| `Install-TinySocsSysmon` | 15862 | Sysmon deployment |

Note: two OpenSearch service-registration code paths coexist in this module
(`Ensure-TinySocsOpenSearchServiceDeterministic` and
`Register-TinySocsOpenSearchService`/`Ensure-TinySocsOpenSearchService`), and both
`Register-TinySocsServices` (direct NSSM install of `TinySocsNode.exe`) and
`Register-TinySocsNodeService` (PowerShell-runner wrapper) exist. Overlapping
generations in one module — if a change needs touching service registration,
grep for all candidates first, don't assume there's one function.

## 2. Services — all NSSM-wrapped

**NSSM** (Non-Sucking Service Manager) wraps an arbitrary exe/script as a real Windows
service with auto-restart. Lives at `C:\Program Files\TinySocs\bin\nssm.exe`.

| Service | Runs | Key config | Depends on |
|---|---|---|---|
| `TinySocsOpenSearch` | `Run-OpenSearch.ps1` → `opensearch.bat` | `OPENSEARCH_PATH_CONF` env pinned to `C:\ProgramData\TinySocs\OpenSearch\config` | — |
| `TinySocsAgent` | `TinySocs.Agent.exe` (display "TinySocs Collector Agent") | machine env `TINYSOCS_AGENT_CONFIG=C:\ProgramData\TinySocs\Collector\agent-config.yml` | — |
| `TinySocsNode` | federation node FastAPI, port 8081 | env `PORT`/`SIEM_URL`/`SIEM_SSL_VERIFY`/`PRIVACY_MODE`/`SIEM_USER`/`SIEM_PASS` via `AppEnvironmentExtra`; delayed-auto start | `sc.exe config TinySocsNode depend= TinySocsOpenSearch` (only wired when a TinyBox is present — mind the space after `depend=`) |
| `TinySocsAssistant` | `{app}\Assistant\TinySocs-Quickstart.exe` (PyInstaller bundle: bot+dashboard on 8090, node API on 8081) | env loaded from `assistant.env`; startup probe `GET http(s)://127.0.0.1:8090/dashboard/api/auth/check` | — |
| `Sysmon64` / `Sysmon64a` (ARM64) | Sysinternals Sysmon | config `C:\ProgramData\TinySocs\Sysmon\sysmon-config.xml` | — |
| `TinySocsMaster`, `TinySocsAnchors` | present in the uninstall kill-list | — | Normally run as **scheduled tasks**, not services (see §6) |

Recovery: `sc.exe failure` reset=60s / restart action set for `TinySocsNode` and
`TinySocsAssistant`; NSSM `AppExit Default Restart` with 2-3s restart delay.

**Management (run as admin on the host):**
```powershell
Get-Service TinySocs* | Format-Table Name, Status, StartType
Restart-Service TinySocsAgent       # after agent-config.yml edits — NOT needed for rules.yml, see §7
Restart-Service TinySocsAssistant   # after assistant.env edits
C:\Program` Files\TinySocs\bin\nssm.exe status TinySocsAgent
C:\Program` Files\TinySocs\bin\nssm.exe stop TinySocsAgent
C:\Program` Files\TinySocs\bin\nssm.exe edit TinySocsAgent   # opens NSSM's GUI editor
```

**No agent watchdog in `TinySocs-Quickstart.exe`** (corrected 2026-07-11 — a prior
version of this skill claimed otherwise): `TinySocs-Quickstart.exe` is built solely
from `src/tinysocs/launcher/quickstart.py` (`packaging/tinysocs-quickstart.spec`).
Read end to end, that file starts the Node and Bot FastAPI apps as in-process uvicorn
threads, runs `orchestrator.master` once, and runs `anchors ensure` — it contains no
`subprocess`/`Popen` call, no reference to `TinySocs.Agent.exe`, and no
process-monitoring loop of any kind. It does not start, watch, or relaunch the agent.
The actual respawn mechanism for `TinySocs.Agent.exe` is **NSSM** on the
`TinySocsAgent` service (`AppExit Default Restart`, confirmed above) — kill the agent
process directly without stopping the service and NSSM relaunches it, not the
Quickstart exe. `scripts/Deploy-AgentUpdate.ps1` still stops the `TinySocs-Quickstart`
process as its step 1, before the service stop, and its own header calls this "the
watchdog" — keep doing that because the script's own logic expects it, but don't
repeat "the watchdog respawns the agent" as an established architectural fact; it
isn't backed by the source. See §9 and §11.

## 3. Ports

| Port | What | Notes |
|---|---|---|
| **9201** | OpenSearch REST, HTTPS — **the canonical port** | "The 9200 trap": if code/scripts build a loopback URL on 9200/http, `Get-TinySocsSiemUrl`-style helpers auto-rewrite it to `https://…:9201`. `Pair-TinySocs` explicitly rewrites `:9200`→`:9201` unless `TINYSOCS_ALLOW_9200=true`. (This installer-layer *rewrite* is distinct from "the Python-default-port gap" in `tinysocs-config-and-flags` §6, where standalone Python modules have a stale `9200` code default and nothing rewrites it — don't conflate the two.) |
| 9200 | Legacy/undoctored OpenSearch default, probed as a fallback candidate | Don't target this directly for a TinyBox install |
| 9300 | OpenSearch transport | |
| 5602 | OpenSearch Dashboards UI, HTTPS | 5601 appears only inside the container/legacy note |
| 8081 | Federation node API (`TinySocsNode` / assistant node API) | localhost bind by default; health probes hit `/meta` |
| 8090 | Bot/dashboard FastAPI, mounted at `/dashboard` | localhost HTTP by default; `DASHBOARD_BIND=0.0.0.0` + TLS certs for network mode (confirmed `src/tinysocs/api/bot.py`, `dashboard.py`) |
| 587 | Default SMTP port used by the email-alert health check | |
| 8095 | Signed-content feed server (`src/tinysocs/api/feed.py`) | **Not part of any installed system** — dormant, see tinysocs-architecture-contract |
| 9201 (nginx) | `nginx/opensearch.conf` — a **lab/Docker** TLS terminator (`ts-opensearch:9200` upstream, `server_name siem.lan`) | Different topology entirely, not the Windows TinyBox install path — don't confuse it when mapping ports |

## 4. `C:\ProgramData\TinySocs\` layout

Created by both `[Dirs]` in Quickstart.iss and `New-ProgramDataLayout` in the psm1.
Root resolver: `Get-TinySocsDataRoot` = `$env:ProgramData\TinySocs`.

```
C:\ProgramData\TinySocs\
  logs\                        # installer/postinstall logs; BUILTIN\Users has modify ACL
  queue\                       # actions_queue.jsonl — hourly-rotated
  ledger\                      # federation HMAC evidence ledger (node-*.jsonl + .head)
  config\                      # assistant-knowledge.md
  anchors\state\
  audit\actions_audit.jsonl    # action-engine audit trail (src/tinysocs/actions/executor.py:30)
  Sysmon\sysmon-config.xml
  version-manifest.json        # agent version drift source
  remove_on_uninstall.flag     # opt-in: presence triggers full data wipe on uninstall
  Collector\                   # the C# agent's world
    agent-config.yml           # canonical config; NSSM sets TINYSOCS_AGENT_CONFIG to this path
    agent\queue\                # disk queue: segment-*.jsonl, 10MB segments, max 100 (~1GB cap)
    agent\bookmarks\            # event-log read bookmarks, persisted every 10s
    agent\config.yml            # legacy config location (back-compat)
    rules\rules.yml              # THE RUNNING RULES — default DetectionConfig.RulesFile
    rules\rule_docs.yml          # TinyDocs alert-companion content (always overwritten)
    packs\pack.yml.canonical     # signed-pack default path — dormant, ContentPackConfig.Enabled=false by default
    logs\TinySocsAgent.{out,err}.log, alerts.log
    notification_queue.jsonl     # webhook/email retry queue
  Assistant\
    assistant.env               # env for TinySocsAssistant (LLM keys, DASHBOARD_BIND/TLS, SIEM creds)
    certs\dashboard-{cert,key}.pem
    threat_cache.db             # threat-intel SQLite cache
    logs\, TinySocsAssistant.{out,err}.log
  OpenSearch\
    bin\Run-OpenSearch.ps1      # NSSM runner
    config\ (+certs, opensearch-security)   # OPENSEARCH_PATH_CONF pinned here
    certs\root-ca.pem, etc.
    data\  logs\  security\  scripts\
```

Confirmed against `src/TinySocs.Agent/Configuration/AgentConfig.cs`:
- `RulesFile` default = `C:\ProgramData\TinySocs\Collector\rules\rules.yml` (AgentConfig.cs:129)
- `ReloadIntervalSeconds` default = 60 (AgentConfig.cs:130) — see §7
- `ContentPackConfig.Enabled` default = **false** (AgentConfig.cs:146) — the signed
  pack path is opt-in and off by default on every real install
- `QueueConfig.SegmentMaxBytes` = 10MB, `MaxSegments` = 100 (~1GB cap) (AgentConfig.cs:67-71)
- `BookmarksConfig.PersistIntervalSeconds` = 10 (AgentConfig.cs:59)

ACLs: SIDs (locale-proof) — SYSTEM + BUILTIN\Administrators full control,
BUILTIN\Users modify on logs/queue dirs. Secrets: DPAPI LocalMachine files +
Windows Credential Manager (`TinySocs/OpenSearch/tinysocs` target).

## 5. Log locations

| Log | Path |
|---|---|
| Agent stdout/err | `C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.{out,err}.log` (NSSM-named — **not** `agent.log`; `agent.log` is only a fallback for dev/non-service installs) |
| Alert log | `C:\ProgramData\TinySocs\Collector\logs\alerts.log` |
| Assistant | `C:\ProgramData\TinySocs\Assistant\TinySocsAssistant.{out,err}.log` (+ `Assistant\logs\`) |
| OpenSearch | `C:\ProgramData\TinySocs\OpenSearch\logs\` (`opensearch.{out,err}.log` + per-service NSSM stdout/stderr logs) |
| Installer post-install | `C:\ProgramData\TinySocs\logs\postinstall-powershell*.log` |
| Uninstall | `%TEMP%\tinysocs-uninstall.log` |
| Action audit | `C:\ProgramData\TinySocs\audit\actions_audit.jsonl` |
| Node/federation | `C:\ProgramData\TinySocs\logs\TinySocsNode.{out,err}.log` |

## 6. Scheduled tasks

Registered by `Register-TinySocsTasks` (Installer.psm1:13521), task folder `\TinySocs\`,
principal `SYSTEM`/Highest, idempotent (unregisters+re-registers on each run):

| Task | Schedule | Action | Env override |
|---|---|---|---|
| `TinySocsHeartbeat` | every 15 min | master runner, `-window 15m -deadline 30 -rules 'auth_failed_burst,ps_script_block'` | `HEARTBEAT_MINUTES` |
| `TinySocsAnchorsEnsure` | daily 03:10 | `TinySocsAnchors.exe --ensure` | — |
| `TinySocsAnchorsPrune` | daily 03:15 | `TinySocsAnchors.exe --prune --retention-days 45` | `ANCHORS_RETENTION_DAYS` (default **45**, product side) |
| `TinySocsRotateQueue` | hourly | `modules\TinySocs.RotateQueue.ps1` | — |
| `TinySocs\DailySummary` | daily 07:00 | `python -m tinysocs.reporting.daily_summary --to <addr>` (registered via `Register-TinySocsDailySummaryTask` — a separate function, **not** called from `Register-TinySocsTasks`. It *is* auto-invoked by the installer itself, in Quickstart.iss Phase 12/`ssPostInstall`, whenever the wizard's notification config has `EmailEnabled=true` and a non-empty `EmailTo` — see §1. An operator only needs to call it manually to (re)register the task outside that install-time path, e.g. after changing notification config post-install.) | — |

**Retention default disagreement (confirmed, not a bug you should "fix" reflexively):**
the product task defaults `ANCHORS_RETENTION_DAYS` to **45 days**
(`Register-TinySocsTasks`, Installer.psm1:13521-13531), while the dev-only
`scripts/Run-AnchorsRetention.ps1` defaults to **30 days**. Both read the same env
var, so setting it overrides either path consistently — but if you're diagnosing why
anchor retention doesn't match a doc, check which script actually ran.

Two other places name *different* task names than the ones actually registered —
don't trust them: `docs/RUNBOOK.MD` (an 18-line relic) names
`TinySOCS_Master_Daily`/`TinySOCS_Ledger_Health`, which do not match
`TinySocsHeartbeat`/`TinySocsAnchorsEnsure`/`TinySocsAnchorsPrune`/`TinySocsRotateQueue`
registered above. Trust `docs/operator-runbook.md` and the code, not `RUNBOOK.MD`.

Dev-host-only wrappers exist under `jobs/` (`jobs/master_daily.ps1`,
`jobs/ledger_health.ps1`) — **both dot-source `$root\model_toggles.ps1`, which does
not exist anywhere in the repo** (verified: `ls jobs/model_toggles.ps1` → not found).
These scripts will fail immediately if scheduled from a fresh clone; treat as broken
until someone reconstructs or removes the dependency. Not part of the customer
install path.

## 7. Rule hot-reload — no restart needed

`DetectionConfig.ReloadIntervalSeconds` = **60** by default
(`src/TinySocs.Agent/Configuration/AgentConfig.cs:130`). Editing
`C:\ProgramData\TinySocs\Collector\rules\rules.yml` takes effect within 60 seconds
with **no service restart**. Confirm the reload happened via
`Get-Content "C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.out.log" -Tail 50`
— look for a `Detection engine updated with (\d+) rule` line.

This is a live production behavior, not a debugging trick — but any actual edit to
`rules.yml` content (adding/enabling/disabling a rule, changing a threshold) is a
detection-behavior change and **must gate through tinysocs-change-control** regardless
of how mechanically easy the hot-reload makes it.

## 8. Upgrade / uninstall

- **Upgrade**: `ssPostInstall` backs up `agent-config.yml`, `agent\config.yml`
  (legacy path), and `rules\rules.yml` to `<file>.pre-upgrade.bak` before writing new
  versions (Quickstart.iss ~3320-3355); `assistant.env` gets the same treatment. If a
  file would be clobbered, the backup lets you diff/restore.
- **Uninstall**: `[UninstallRun]` runs `TinySocs.Uninstall.ps1 -FromInnoUninstall`.
  That script detects an upgrade-in-progress via the command line matching
  `/UPGRADE|/UPDATE` (regex, case-insensitive) and **keeps ProgramData** in that case.
  On a genuine uninstall, full data removal happens **only if**
  `C:\ProgramData\TinySocs\remove_on_uninstall.flag` exists — otherwise ProgramData
  (config, logs, ledger, queue) survives the uninstall. The script stops/deletes
  services `TinySocsOpenSearch, TinySocsAgent, TinySocsNode, TinySocsMaster,
  TinySocsAnchors, TinySocsAssistant` and uninstalls Sysmon only on a full uninstall.
  Uninstall log: `%TEMP%\tinysocs-uninstall.log`.

## 9. Deploy-to-VM path (agent/rules hot-swap for validation)

Two-script pipeline for pushing a freshly-built agent + `rules.yml` to a validation VM
without running the full installer:

1. **`scripts/stage-deploy-bundle.sh`** (run on the build host, macOS/Linux):
   `dotnet publish` the win-x64 self-contained agent → `dist/agent-win-x64/`, then
   assembles `dist/deploy-bundle/` containing the agent exe,
   `packaging/detection/rules.yml`, `scripts/Deploy-AgentUpdate.ps1`, the atomic test
   harness (`tests/*.ps1`, `tests/atomic-tests.yaml`), and a generated `RUN-ON-VM.md`.
   **This validates the `rules.yml` fallback path only** — it explicitly does not
   exercise the signed-pack delivery path (that would need
   `Pack.Enabled=true` + a `.canonical`/`.sig` pair staged separately; see
   tinysocs-architecture-contract).
2. **`scripts/Deploy-AgentUpdate.ps1`** (run as Administrator on the VM), 9 steps:
   1. Stop the `TinySocs-Quickstart` process (`Deploy-AgentUpdate.ps1` calls it "the
      watchdog" in its own header, but `src/tinysocs/launcher/quickstart.py` has no
      code that starts, monitors, or relaunches `TinySocs.Agent.exe` — see §2; do
      this step because the script's flow expects it, not because it's a proven
      agent respawn path).
   2. Stop the `TinySocsAgent` **service** via NSSM (killing only the process re-locks
      the binary because NSSM immediately relaunches it).
   3. Back up and replace `C:\Program Files\TinySocs\bin\TinySocs.Agent.exe`.
   4. Deploy the new `rules.yml`.
   5. Clear stuck queue segments (`Collector\agent\queue\segment-*.jsonl`).
   6. Enable the 9 Windows audit subcategories the rules depend on via `auditpol`
      (Logon/failure, Logoff, Process Creation, Other Object Access, User Account
      Mgmt, Audit Policy Change, Security State Change, File System, Special Logon)
      plus registry `ProcessCreationIncludeCmdLine_Enabled=1` (needed for 4688
      command-line capture).
   7. Start the service (falls back to relaunching the watchdog if no service is
      registered — dev-install path).
   8. Wait ~15s, grep `TinySocsAgent.out.log` for `Detection engine updated with (\d+)
      rule` to confirm the reload; also checks for lingering MITRE-parsing errors.
   9. Verify `auditpol` settings actually stuck.

   `-SourceDir` is normalized via `Resolve-Path`, so `-SourceDir .` works from the
   bundle directory.

```bash
# On the build host (macOS/Linux):
scripts/stage-deploy-bundle.sh
# copy dist/deploy-bundle/ to the VM, then on the VM (as Administrator):
.\Deploy-AgentUpdate.ps1 -SourceDir .
```

## 10. Retention / storage

- **OpenSearch ISM policies** (`packaging/opensearch/policies/`, verified):
  - `tinysocs-winlog-retention.json`: delete indices with `min_index_age: 30d`
  - `tinysocs-alerts-retention.json`: delete indices with `min_index_age: 90d`
  - `tinysocs-custom-retention.json`: delete indices with `min_index_age: 30d`

  An **ISM policy** (Index State Management) is an OpenSearch construct that
  automatically transitions/deletes indices on a schedule — here, a single "delete"
  state triggered once an index crosses its age threshold. Bound to index templates
  via `plugins.index_state_management.policy_id`
  (`packaging/opensearch/templates/tinysocs-{winlog,alerts,custom}*.json`). Adjust
  policies in OpenSearch Dashboards → Index Management → Policies.
- **Agent disk queue**: 10MB segments, max 100 (~1GB cap), 200ms flush interval,
  fsync on flush; segments deleted after `MinSuccessfulShipCount=1` successful ship.
- **Actions queue rotation**: `modules/TinySocs.RotateQueue.ps1` prunes
  `%ProgramData%\TinySocs\queue` files older than 14 days, keeps max 7 files, rotates
  `actions_queue.jsonl` at 5MB. Runs hourly via `TinySocsRotateQueue` task.
- **Anchors prune**: 45-day default on the product task (§6 disagreement noted above).
- **Notification retry queue**: `Collector\notification_queue.jsonl`, 3 attempts,
  ~30s exponential backoff base, entries older than 1h discarded.
- **Threat-intel cache**: SQLite `Assistant\threat_cache.db`, TTL 24h for IPs, 7d for
  domain hashes.

## 11. Known operational traps

- **OpenSearch cold start can take up to 300 seconds** on first boot after install —
  don't treat an unresponsive `:9201` in the first few minutes as a failure.
- **PowerShell 5.1 TLS workarounds are load-bearing, not incidental.** The installer
  module deliberately **never restores** `ServerCertificateValidationCallback` after
  setting it — this is intentional (PS 5.1 caching quirk means restoring it breaks
  subsequent calls in the same session), not a leftover debug hack. Do not "clean
  this up" without understanding why it's there.
- **Prefer `curl.exe` over `Invoke-RestMethod` for probing `:8081`** — PS 5.1's TLS
  stack is unreliable for that specific probe; the health check code falls back
  curl.exe-first for exactly this reason.
- **`jobs/*.ps1` dot-source a `model_toggles.ps1` that does not exist in the repo**
  (confirmed above) — these dev-host wrapper scripts are broken from a fresh clone.
  Don't schedule them without first sourcing/removing that dependency.
- **Stop the `TinySocsAgent` service, not just the process, before any binary swap**
  — NSSM relaunches `TinySocs.Agent.exe` the instant it exits, re-locking the file
  (see §9 step 2). `Deploy-AgentUpdate.ps1` also stops `TinySocs-Quickstart` first
  (§9 step 1), but that exe has no code that monitors or relaunches the agent — see
  §2; treat that step as following the script's own flow, not as defusing a proven
  agent watchdog.
- **`docs/RUNBOOK.MD` vs `docs/operator-runbook.md`**: two runbooks exist. `RUNBOOK.MD`
  is a stale 18-line relic with task names that don't match reality (§6). Prefer
  `docs/operator-runbook.md`.
- **A literal `C:\ProgramData/TinySocs/Assistant` directory** may appear at the repo
  root on macOS dev machines — an artifact of a Windows-style path being treated as a
  relative directory name by some script run on macOS. Empty, safe to delete, not a
  real part of the product.
- **Old signed packs are unsigned**: `packs/base/2026.22` and `2026.23` contain only
  `pack.yml` (no `.canonical`/`.sig`), yet `packs/base/index.json` still advertises
  `snapshot: 2026.23`. Irrelevant today only because the signed-pack path is dormant
  (`ContentPackConfig.Enabled=false`) — becomes a real problem the day it's activated.
  Flag any activation work against this before shipping — gate through
  tinysocs-change-control.

## When NOT to use this skill

- Interpreting `Test-TinySocsHealth` / `Invoke-TinySocsSmokeTest` output, measuring
  whether the install is actually healthy, or other diagnostics → **tinysocs-diagnostics-and-tooling**.
- Building the agent/installer/pack artifacts this installer ships (`dotnet publish`,
  Inno Setup compile, signing keys, CI) → **tinysocs-build-and-env**.
- Deciding whether an operational change (rule edit, retention change, service
  reconfiguration) is allowed to ship → **tinysocs-change-control**.
- Understanding *why* the signed-pack trust path is dormant, or the federation/ledger
  design → **tinysocs-architecture-contract**.
- Debugging a specific symptom (agent silent, shipper failing, HMAC mismatch,
  dashboard auth failure) → **tinysocs-debugging-playbook**.
- Config file schema, env-var families, and which settings are production-safe vs
  experimental → **tinysocs-config-and-flags**.

## Provenance and maintenance

Authored 2026-07-11 against branch `fix/ci-green`, HEAD `37005ad`. Every fact in this
skill was re-verified by direct grep/read against the current tree (not just the
2026-07-06 digest) — see inline `(file:line)` citations. Primary sources:

- `packaging/iss/Quickstart.iss`
- `modules/TinySocs.Installer.psm1`
- `modules/TinySocs.Uninstall.ps1`
- `src/TinySocs.Agent/Configuration/AgentConfig.cs`
- `scripts/stage-deploy-bundle.sh`, `scripts/Deploy-AgentUpdate.ps1`
- `packaging/opensearch/policies/*.json`, `packaging/opensearch/templates/*.json`
- `docs/operator-runbook.md`
- `src/tinysocs/actions/executor.py`, `src/tinysocs/api/{bot,node,dashboard}.py`
- `src/tinysocs/launcher/quickstart.py`, `packaging/tinysocs-quickstart.spec`
- `jobs/*.ps1`, `nginx/opensearch.conf`

Re-verification commands for the volatile facts above:

```bash
# Function count / module size (drifts as the installer grows)
grep -c '^function ' modules/TinySocs.Installer.psm1
wc -l modules/TinySocs.Installer.psm1

# Rule reload interval + pack-enabled default (config contract)
# ("Enabled = false" alone silently matches nothing — the source is
# "Enabled { get; set; } = false", not a bare assignment)
grep -n "ReloadIntervalSeconds\|Enabled { get; set; } = false" src/TinySocs.Agent/Configuration/AgentConfig.cs

# Service kill-list still matches what's actually registered
grep -n "TinySocsOpenSearch\",$\|TinySocsAgent\",$" modules/TinySocs.Uninstall.ps1

# TinySocs-Quickstart.exe still has no agent-process monitoring code (re-check
# before ever re-asserting a "watchdog respawns the agent" claim)
grep -n "subprocess\|Popen\|TinySocs.Agent" src/tinysocs/launcher/quickstart.py

# Daily-summary task still auto-registered by the installer itself (Phase 12)
grep -n "Register-TinySocsDailySummaryTask\|EmailEnabled" packaging/iss/Quickstart.iss

# Scheduled task set + anchors retention default
grep -n "_RegisterIdempotent -TaskName\|retention = 45" modules/TinySocs.Installer.psm1

# ISM policy retention windows haven't drifted
grep -n min_index_age packaging/opensearch/policies/*.json

# jobs/*.ps1 dependency still broken (or fixed — re-check before repeating the claim)
ls jobs/model_toggles.ps1 2>&1

# Ports still match (9201 canonical, 8090 dashboard, 8081 node, 8095 feed)
grep -n '"9201"\|BOT_PORT\|NODE_PORT' modules/TinySocs.Installer.psm1 src/tinysocs/api/bot.py src/tinysocs/api/node.py

# Working-tree state (whether prior "uncommitted" fixes have landed)
git status --short
git log --oneline -5
```
