# Known limitations

The honest list. Read this before exposing anything to a network, and before filing
an issue about something below — it's known. Last reviewed 2026-08-18.

## Security posture

- **The dashboard's API is largely unauthenticated.** The login screen protects the
  UI, but most API routes (including rule create/edit/toggle, alert purge, storage
  purge, action approval, and the LLM chat endpoint) don't verify a session. The
  mitigation is the **localhost-only default bind** — the launcher refuses non-loopback
  binds without TLS and falls back to localhost. If you choose "Network accessible"
  mode, every one of those routes is reachable by anything on your LAN behind a
  self-signed cert. Treat network mode as "trusted lab network only".
- **First-boot password race**: until the admin password is set, the setup-password
  endpoint is claimable by whoever reaches the dashboard first. On localhost that's
  you; in network mode, set the password immediately.
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
- **Uninstall can leave scheduled tasks behind** if you used the experimental
  operator tasks — `TinySocs-MasterHeartbeat` in particular survives uninstall and
  keeps firing every 15 minutes against a removed install. Remove manually:
  `Unregister-ScheduledTask -TaskName TinySocs-MasterHeartbeat,TinySocs-RotateQueues,TinySocs-NightlyVerifyLedger`.
- **An empty dashboard looks like a broken one.** Before events arrive, widgets show
  "Loading..." — a not-reporting agent and a still-fetching dashboard look identical.
  Run `Invoke-TinySocsSmokeTest` to tell them apart.
- **Health check INFO/WARN results are often structural** on a minimal install — see
  [SUPPORT.md](SUPPORT.md).
- **The AI assistant costs money on your API key** if you configure a cloud LLM.
  Use Ollama for free/offline operation.
