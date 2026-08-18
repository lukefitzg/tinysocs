# Known limitations

The honest list. Read this before exposing anything to a network, and before filing
an issue about something below — it's known. Last reviewed 2026-08-18.

## Security posture

- **Dashboard API auth**: fixed as of 2026-08-18 — a deny-by-default middleware now
  requires a valid session on every route except a small public allowlist (login,
  auth-check, password-status, the SPA shell, and the HMAC-authenticated node
  enrolment endpoint). First-boot password setup additionally requires a one-time
  **setup token printed to the dashboard service console/log**, closing the race
  where whoever reached the dashboard first could claim the admin password. The
  localhost-only default bind remains the recommended posture; network mode still
  means a self-signed cert and "trusted lab network only".
- **TLS verification is off by default on internal hops.** The agent→OpenSearch
  shipper, several dashboard→service calls, and federation fetches accept any
  certificate (self-signed topology). `TINYSOCS_INSECURE_SKIP_VERIFY` defaults vary
  by component. Fine for a homelab; know it's there.
- **`.env.example` ships placeholder secrets** (`ChangeMe123!`,
  `dev-secret-change-me`) for the *dev* setup, and nothing enforces that you changed
  them. The Windows installer is better: it auto-generates real secrets.

## Product scope

- **Windows-only agent.** No Linux/macOS collection.
- **~100 endpoints per node** is the practical ceiling of the single-box architecture.
- **19 of 39 detection rules ship enabled** (16 MITRE ATT&CK techniques / 8 tactics).
  The 50-rule Python KQL catalogue in the source tree does **not** run in a default
  install. Full split: [docs/detection-coverage.md](docs/detection-coverage.md).
- **Validation coverage is partial**: 8 of the 19 enabled rules are proven end-to-end
  against live Atomic Red Team attacks (last run 2026-07-08); the rest are proven on
  synthetic events or blocked on environment prerequisites. Evidence, including
  misses: [docs/pilot-ruleset.md](docs/pilot-ruleset.md).
- **No allowlist/exception primitives.** If a rule is noisy on your network, tuning
  means editing its YAML (threshold, window) or disabling it — there is no
  "exclude this host/user from this rule" mechanism.
- **Federation (Hub/Site, evidence ledger, orchestrator) is experimental.** It
  assumes one operator owns all nodes. `Install-OperatorTasks.ps1` registers
  scheduled tasks with highest run level and no confirmation.
- **Response actions** (`block_ip`, `disable_user`, `isolate_host`) are
  operator-approved and best-effort; this is not a SOAR.

## Rough edges

- **Uninstall keeps your data by default** (`C:\ProgramData\TinySocs` survives). To
  remove data too, create `C:\ProgramData\TinySocs\remove_on_uninstall.flag` before
  uninstalling. There is no wizard checkbox for this yet.
- **Uninstall and scheduled tasks**: fixed as of 2026-08-18 — uninstall now removes
  the experimental operator tasks (`TinySocs-RotateQueues`,
  `TinySocs-NightlyVerifyLedger`, `TinySocs-MasterHeartbeat`) along with everything
  else. If you uninstalled an *older* build after using the operator tasks, check for
  leftovers: `Get-ScheduledTask -TaskName TinySocs-* | Unregister-ScheduledTask -Confirm:$false`.
- **An empty dashboard looks like a broken one.** Before events arrive, widgets show
  "Loading..." — a not-reporting agent and a still-fetching dashboard look identical.
  Run `Invoke-TinySocsSmokeTest` to tell them apart.
- **Health check INFO/WARN results are often structural** on a minimal install — see
  [SUPPORT.md](SUPPORT.md).
- **The AI assistant costs money on your API key** if you configure a cloud LLM.
  Use Ollama for free/offline operation.
