# TinySocs Phase 9 — Summary

## Goal
Turn TinySocs from a working local OpenSearch appliance into a working local SIEM by making Windows event log ingestion deterministic, persistent, and automatic on a clean install.

## What Was Delivered

### Commits (branch: `affectionate-chatterjee`)
1. **`baf725a`** — Fix agent not starting or shipping events after fresh install
2. **`e9d8ee6`** — Add `indices:monitor/*` to `tinysocs_role`
3. **`5ec9cc9`** — M4: Fix `@timestamp` mapping, document structure, and index template
4. **`8b752d2`** — Fix installer hang: always use curl `-k` for loopback readiness checks

### Changes by File

**`src/TinySocs.Agent/Configuration/AgentConfig.cs`**
- Added `User` and `Pass` properties to `OutputConfig` so YamlDotNet can deserialize credentials from `config.yml`
- Changed `SiemCredentialsConfig.Target` default from `TinySocs/SIEM/Creds` to `TinySocs/OpenSearch/tinysocs`

**`src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs`**
- Changed `BuildBulkPayload` to serialize `evt.Body` (not the full `AgentEvent` envelope) as the OpenSearch document, placing `@timestamp`, `message`, `winlog`, `event`, and `tinysocs` fields at document root

**`config/agent-config.yml`**
- Changed `siem_credentials.target` from `TinySocs/SIEM/Creds` to `TinySocs/OpenSearch/tinysocs`

**`packaging/opensearch/templates/tinysocs-winlog.json`** (new file)
- Index template for `tinysocs-winlog-*` indices (priority 100)
- Maps `@timestamp` as `date`, winlog/event fields as `keyword`/`long`
- Single-node settings: 1 shard, 0 replicas, `auto_expand_replicas: 0-1`

**`modules/TinySocs.Installer.psm1`**
- **New function: `Set-TinySocsAgentConfigCredentials`** — Injects `user:`/`pass:` into the `output:` section of agent `config.yml` (UTF-8 no BOM, re-applies ACLs)
- **Wired into `Install-TinySocsLocalSiem`:**
  - Template staging + bootstrap (`Ensure-TinySocsOpenSearchTemplatesStaged` + `Invoke-TinySocsOpenSearchTemplatesBootstrap`)
  - Credential injection via `Set-TinySocsAgentConfigCredentials`
  - Agent service registration via `Install-TinySocsAgentService`
- **Sterile NSSM environment in `Ensure-TinySocsAgentService`** — Blanks all credential env vars (`TINYSOCS_SIEM_USER`, `SIEM_USER`, `OPENSEARCH_USERNAME`, etc.) and sets `TINYSOCS_ALLOW_ENV_CREDS=0` so the agent reads credentials from `config.yml` instead of inheriting stale SYSTEM env vars
- **Broadened `tinysocs_role` permissions** in both `Ensure-TinySocsOpenSearchSecurityBootstrap` and `Initialize-TinySocsOpenSearchSecurity`:
  - Cluster: `cluster_composite_ops`, `cluster:monitor/*`, `cluster:admin/ingest/pipeline/*`, `indices:admin/index_template/*`
  - Index: `crud`, `create_index`, `indices:admin/*`, `indices:data/write/*`, `indices:data/read/*`, `indices:monitor/*`
- **Fixed `Wait-TinySocsLocalSiemReady`** — Always uses curl `-k` for loopback addresses to prevent TLS negotiation hangs on self-signed certs

### Root Causes Found and Fixed

| Problem | Root Cause | Fix |
|---------|-----------|-----|
| Agent service not registered after install | `Install-TinySocsLocalSiem` never called `Install-TinySocsAgentService` | Wired agent install into `Install-TinySocsLocalSiem` |
| Agent can't read CredMan creds | Runs as SYSTEM, can't access installing user's credential vault | Inject creds directly into `config.yml` via `Set-TinySocsAgentConfigCredentials` |
| Config file creds silently dropped | `OutputConfig` C# class had no `User`/`Pass` properties; YamlDotNet ignores unmatched properties | Added `User`/`Pass` to `OutputConfig` |
| Agent uses env creds instead of config | NSSM inherits SYSTEM environment; agent's `TryGetUserPass()` checks env vars first | Set sterile NSSM `AppEnvironmentExtra` blanking all cred vars |
| `siem_credentials.target` wrong | Pointed at `TinySocs/SIEM/Creds` (admin) instead of `TinySocs/OpenSearch/tinysocs` (service account) | Fixed default in both C# and YAML |
| `@timestamp` not sortable | Agent serialized full envelope (body nested); no index template mapped `@timestamp` as date | Serialize `Body` as document root; ship index template |
| `_cat/indices` returns 403 | `tinysocs_role` missing `indices:monitor/*` | Added to both role definition paths |
| Template/mapping GET returns 403 | `indices:admin/index_template/get` is a cluster-scoped action | Added `indices:admin/index_template/*` to cluster_permissions |
| Installer hangs for hours | `Wait-TinySocsLocalSiemReady` curl without `-k` on self-signed loopback | Always use `-k` for loopback readiness checks |

### Key Lessons Learned
- **Worktree vs main repo**: The Windows VM at `C:\Mac\Home\tinysocs` maps to `/Users/lukefitzgerald/tinysocs` (main repo), not the worktree. Built artifacts must be copied to main repo.
- **NSSM sterile environment is critical**: The agent inherits SYSTEM env vars. Without blanking cred vars in `AppEnvironmentExtra`, the agent picks up stale env creds (`source=env`) instead of config file creds (`source=output`).
- **Windows PowerShell 5.1 limitations**: No `-SkipCertificateCheck` on `Invoke-RestMethod`. Use `Add-Type` with `ServerCertificateValidationCallback` delegate. Single-quoted JSON in `curl.exe` args gets mangled — use `Invoke-RestMethod` or temp files.
- **YamlDotNet with `UnderscoredNamingConvention`**: Properties must exist on the C# class or they are silently ignored. `user:`/`pass:` parse correctly at any position within a YAML block.
- **OpenSearch Security action naming**: `indices:admin/index_template/*` is a cluster-level permission despite the `indices:` prefix. Must be in `cluster_permissions`, not `index_permissions`.

---

## Current Architecture

### Component Overview

```
+------------------------------------------------------------------+
|                     Windows Host                                  |
|                                                                   |
|  +-------------------+     +----------------------------------+   |
|  |  TinySocsAgent    |     |  TinySocsOpenSearch              |   |
|  |  (NSSM service)   |---->|  (NSSM service)                  |   |
|  |                   |     |  OpenSearch 3.3.2                 |   |
|  |  Reads: Windows   | TCP |  Port 9201 (localhost only)       |   |
|  |  Event Logs       | TLS |  TLS + Security Plugin            |   |
|  |  Ships: NDJSON    |     |  Index: tinysocs-winlog-YYYY.MM.DD|   |
|  |  bulk API         |     |                                   |   |
|  +-------------------+     +----------------------------------+   |
|                                                                   |
|  Config: C:\ProgramData\TinySocs\Collector\agent\config.yml       |
|  Logs:   C:\ProgramData\TinySocs\Collector\logs\                  |
|  Data:   C:\ProgramData\TinySocs\OpenSearch\data\                 |
+------------------------------------------------------------------+
```

### Services

| Service | Manager | Binary | Start Type | Identity |
|---------|---------|--------|------------|----------|
| `TinySocsOpenSearch` | NSSM | OpenSearch 3.3.2 JVM | Automatic | SYSTEM |
| `TinySocsAgent` | NSSM | `TinySocs.Agent.exe` (.NET 8, win-x64, self-contained) | Automatic | SYSTEM (sterile env) |

### Agent Architecture

```
EventLogInput (Windows Event Log API)
  Channels: Application, Security, System, PowerShell/Operational
  |
  v
AgentEvent { Ts, Input, Channel, EventId, Body }
  Body = { @timestamp, message, event{}, winlog{}, tinysocs{} }
  |
  v
FileQueueWriter (disk-backed JSONL queue)
  Location: C:\ProgramData\TinySocs\Collector\queue\
  |
  v
OpenSearchBulkShipper
  Serializes: evt.Body (document root, not envelope)
  Auth: Basic (user/pass from config.yml output section)
  Endpoint: https://localhost:9201/_bulk
  Index pattern: tinysocs-winlog-{yyyy.MM.dd}
  Deterministic ID: {computer}|{channel}|{record_id}
```

### Credential Resolution (OpenSearchBulkShipper.TryGetUserPass)

Priority order (first match wins):
1. Environment variables (`TINYSOCS_SIEM_USER`/`PASS`, etc.) — **blocked by sterile env**
2. Config `output.user` / `output.pass` — **active path**
3. Nested auth object in config
4. Windows CredMan (`siem_credentials.target`)

### OpenSearch Security

| Entity | Details |
|--------|---------|
| Admin user | `admin` / password in CredMan `TinySocs/SIEM/Creds` |
| Service user | `tinysocs` / random 32-char password in CredMan `TinySocs/OpenSearch/tinysocs` |
| Role | `tinysocs_role` — cluster monitor, index CRUD, admin, data read/write on `tinysocs-*`, `winlogbeat-*`, `logs-*`, etc. |
| TLS | Self-signed CA, localhost-only binding on port 9201 |

### Index Template (`tinysocs-winlog`)

- Pattern: `tinysocs-winlog-*`
- Priority: 100
- Key mappings: `@timestamp` (date), `winlog.channel` (keyword), `event.id` (long), `message` (text)
- Settings: 1 shard, 0 replicas, `auto_expand_replicas: 0-1`

### Document Structure (in OpenSearch)

```json
{
  "@timestamp": "2026-02-10T07:40:06.326Z",
  "message": "PowerShell console is ready for user input",
  "event": {
    "id": 40962,
    "code": 40962,
    "level": "Information",
    "provider": "Microsoft-Windows-PowerShell",
    "record_id": 2808914
  },
  "winlog": {
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "computer_name": "LUKEFITZGERC164",
    "provider_name": "Microsoft-Windows-PowerShell",
    "record_id": 2808914
  },
  "tinysocs": {
    "input_name": "win-events"
  }
}
```

### Installer Flow (Inno Setup + PowerShell)

```
Inno Wizard (Quickstart.iss)
  User selects TinyBox role
  |
  v
File copy phase (exe, config, modules, OpenSearch, templates)
  |
  v
Post-install PowerShell (inline in Quickstart.iss):
  TB-10: Service setup, OPENSEARCH_PATH_CONF, keystore repair
  TB-11: OpenSearch.Persistence.ps1 (restart + wait for port)
  TB-12: Readiness gate (curl health check, security init if 503)
  CRED PRESET: Probe authinfo, store working admin creds
  TB-3: Install-TinySocsLocalSiem
    |
    v
  Install-TinySocsLocalSiem:
    1. OpenSearch service config + start
    2. Wait for HTTP ready (curl -k for loopback)
    3. Security init (Initialize-TinySocsOpenSearchSecurity)
       - Creates tinysocs_role, tinysocs user, role mapping
    4. Template staging + bootstrap
       - Copies tinysocs-winlog.json to ProgramData
       - PUTs to /_index_template/tinysocs-winlog
    5. Credential injection
       - Reads tinysocs password from CredMan
       - Writes user:/pass: into agent config.yml
    6. Agent service registration
       - NSSM install + sterile env + start
```

### File Locations

| Purpose | Path |
|---------|------|
| Agent binary | `C:\Program Files\TinySocs\bin\TinySocs.Agent.exe` |
| Agent config | `C:\ProgramData\TinySocs\Collector\agent\config.yml` |
| Agent logs | `C:\ProgramData\TinySocs\Collector\logs\TinySocsAgent.out.log` |
| Agent queue | `C:\ProgramData\TinySocs\Collector\queue\` |
| OpenSearch home | `C:\Program Files\TinySocs\OpenSearch\` |
| OpenSearch config | `C:\ProgramData\TinySocs\OpenSearch\config\` |
| OpenSearch data | `C:\ProgramData\TinySocs\OpenSearch\data\` |
| OpenSearch logs | `C:\ProgramData\TinySocs\OpenSearch\logs\` |
| Index templates | `C:\ProgramData\TinySocs\OpenSearch\templates\` |
| TLS certs | `C:\ProgramData\TinySocs\OpenSearch\config\certs\` |
| Installer module | `C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1` |
| NSSM | `C:\Program Files\TinySocs\bin\nssm.exe` |

### Source Code Layout

| Purpose | Path |
|---------|------|
| Agent C# project | `src/TinySocs.Agent/` |
| Agent config model | `src/TinySocs.Agent/Configuration/AgentConfig.cs` |
| Config loader (YamlDotNet) | `src/TinySocs.Agent/Configuration/ConfigLoader.cs` |
| Bulk shipper | `src/TinySocs.Agent/Shipper/OpenSearchBulkShipper.cs` |
| Event log input | `src/TinySocs.Agent/Inputs/EventLogInput.cs` |
| Agent event model | `src/TinySocs.Agent/Models/AgentEvent.cs` |
| Config template | `config/agent-config.yml` |
| Index template | `packaging/opensearch/templates/tinysocs-winlog.json` |
| Installer module | `modules/TinySocs.Installer.psm1` |
| Inno Setup script | `packaging/iss/Quickstart.iss` |
| OpenSearch persistence | `packaging/iss/scripts/OpenSearch.Persistence.ps1` |

### Phase 9 Acceptance Criteria (All Met)

- [x] `TinySocsOpenSearch` service running
- [x] `TinySocsAgent` service running (Automatic start)
- [x] Documents in `tinysocs-winlog-*` within 60 seconds of startup
- [x] `@timestamp` sort works (mapped as `date`)
- [x] Ingestion survives reboot (NSSM Automatic)
- [x] Logs under `ProgramData` (deterministic, actionable)
- [x] Writes use `tinysocs` service user (not admin)
- [x] Clean install produces working SIEM with zero manual steps
- [x] Installer completes without hanging

### What Phase 9 Did NOT Cover (Future Work)

- **M5 Observability**: No health endpoint, heartbeat doc, or marker file. Logs exist but no single "is it healthy?" signal.
- **Multi-node pairing**: Single-box only. No master/node architecture yet.
- **Alerting/detection**: Events are collected and stored but not analysed.
- **Dashboards**: OpenSearch Dashboards port (5602) is configured but not wired into the install flow.
- **Log rotation**: Agent and OpenSearch logs grow unbounded.
- **Index lifecycle**: No ISM policy for rollover, retention, or deletion of old indices.
