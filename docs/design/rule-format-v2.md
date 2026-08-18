# Rule Format v2 — Design

**Status**: Approved, schema locked, **implemented**. Migration script (`scripts/migrate_rules_to_v2.py`) and C# engine changes both done — `PackLoader`/`Ed25519Verifier`/`LicenceReader` are wired through `OpenSearchBulkShipper` and enforce signed-pack loading (2026-06-06; see `signed-feed.md`). **2026-08-18**: the feed/tier machinery that consumed this schema is parked dormant (`docs/design/strategy-zero-support.md`); the schema itself remains the live pack format. `metadata.tier` is retained as an inert field.
**Author**: Luke FitzGerald + Claude session, 2026-05-26 (schema); 2026-06-06 (`field_match` carried into schema, signing/feed dependency).
**Supersedes**: implicit v1 across `packaging/detection/rules.yml` (C# agent) and `src/tinysocs/agent/detections/rules.yaml` (Python catalogue).

---

## Why v2 exists

TinySOCs is pivoting from a DIY self-hosted SIEM to a **detection-content-as-a-service** business: the platform is free, the recurring revenue is a paid subscription to a continuously-validated detection content feed. SMB/MSP customers cannot tune detection rules. The product must absorb that responsibility.

v2 is the rule format that makes this business possible. It introduces:

- A single schema authored once and consumed by both engines (agent + future backend).
- Allowlist primitives, so customers tune via UI without touching rule files.
- Learning-period baselines, so rules auto-quiet down per environment.
- A pack-and-sign envelope, so rule updates can be distributed and verified.
- An explicit `runs_on` discriminator so the schema is honest about which engine actually runs each rule.

## Audit findings that shaped this design

Before designing, an audit of the current state turned up the following (worth re-reading before changing anything):

1. **There is only one running detection engine.** The C# agent engine (`src/TinySocs.Agent/Detection/`) runs 39 rules of a single type (`threshold_by_key`) against raw Windows events in-process. It is the only engine that fires alerts in production today.
2. **The Python "rule file" is a catalogue, not an engine.** `src/tinysocs/agent/detections/rules.yaml` defines 50 KQL-based rules but is referenced only by `reporting/mitre_coverage.py` (for the MITRE heatmap) and by the AI assistant's `search_kql` tool corpus. No periodic detection runner consumes it. It is, in effect, a v2-ready rule library that hasn't been activated.
3. **~24 rules are duplicated** between the two files by intent (lsass_access, psexec_usage, event_log_cleared, all FIM rules, etc). In v2 these collapse to single entries with `runs_on: agent`.
4. **~12 rules exist only in Python and cannot run agent-side** (M365 cloud-identity, cross-source geo-anomaly, network/firewall, regex/cmdline-based process rules). These are the natural home for the future backend engine and the obvious shape of "premium packs."
5. **6 lab/demo rules pollute both files.** They should be in a separate `demo` pack and never ship to a real customer's running rule set.
6. **No allowlist primitives exist in either engine.** The Python file has primitive threshold-override via `tuning_envvars`. There is no "exclude this user/host/process from this rule" mechanism anywhere.
7. **License inconsistency** (historical, fixed 2026-05-26): the README footer used to contradict the BSL-1.1 `LICENSE` file. Noted here only because it was found during this design pass.

## Strategy decision: v2.0 ships C#-only

Two implementation strategies were considered:

- **Strategy A**: Activate the Python KQL engine in v2.0. Two running engines. ~3–4 extra weekends.
- **Strategy B** (chosen): v2.0 ships the unified schema, but only the C# engine actually runs rules. Python rules are re-saved in v2 format as a roadmap catalogue. Backend runner activates in v2.1, post-first-customer.

Reasoning: 8–12 week timeline to first paying customer is tight with just one engine to refit. Standing up a second runner is a yak shave. Customers convert on "rules that don't drown me in noise" + "fresh signed content" + "public weekly validation proof" — none of which require M365 detections at day 1.

## Goals

- One YAML schema describes every rule, regardless of target engine.
- Customer never edits a rule file. Allowlists live in a separate customer-local file.
- Pack-level signing (ed25519) and atomic version pinning.
- Mechanical migration from both v1 files.
- Forward-compatible: `sequence` and `enrichment_gated` detection types are valid schema today, runtime in v2.1+.

## Non-goals

- Activating the Python detection runner. (v2.1.)
- Implementing the feed server. (Separate gap.)
- Stripe / licence enforcement. (Separate gap.)
- Building the TinyDocs authoring workflow. (Separate gap; the schema only references TinyDocs paths.)
- Replacing the FIM subsystem (`FimConfig.cs`). FIM stays in its own shape and emits synthetic events that v2 FIM rules detect.

## Design principles

1. **One schema, two consumers.** `runs_on: agent | backend` is the discriminator. C# loader ignores backend rules; backend loader ignores agent rules.
2. **Customer-local data is never in the signed pack.** Allowlists are unsigned and local.
3. **Detection logic is one field of many.** `detection.type` is a discriminated union. Adding new types does not change the surrounding schema.
4. **Tuning is named and range-validated, not arbitrary.** No raw envvar exposure; every tuning knob is declared by the rule with min/max/default.
5. **Migration is mechanical.** Every v1 rule maps deterministically to v2 — no human judgment per rule.

## Pack structure (top-level)

```yaml
schema_version: 2
metadata:
  pack_id: base                    # base | persistence-premium | m365-pack | demo
  pack_version: "2026.21"          # year.weeknum
  tier: free                       # free | pro | msp — drives feed-side licence check
  generated_at: "2026-05-26T10:00:00Z"
  validation:
    atomic_red_team_run: "2026-05-25T03:00:00Z"
    passing: 124
    failing: 0
    pending: 3
  signature:
    algorithm: ed25519
    key_id: "tinysocs-2026"
    value: "base64..."
rules:
  - ...
```

`pack_id` + `pack_version` is the unit of distribution, signing, and validation. The signature covers a canonical JSON serialisation of the pack with the signature field cleared.

## Rule shape

```yaml
- id: "TS-001"
  name: "brute_force_logon"
  description: "Multiple failed logons (4625) from the same user"
  severity: high                   # low | medium | high | critical
  enabled: true

  runs_on: agent                   # agent | backend
  pack: base

  mitre:
    technique_id: T1110.001
    technique_name: "Brute Force: Password Guessing"
    tactic: credential-access

  docs: "tinydocs/TS-001.md"       # path inside the pack

  detection:
    type: threshold_by_key
    event_id: 4625
    channel: Security
    group_by: winlog.event_data.TargetUserName
    threshold: 15
    window_minutes: 5
    cooldown_minutes: 5

  allowlist_scopes:                # which scopes this rule honours
    - user
    - user_pattern
    - source_ip
    - source_ip_cidr

  baseline:
    enabled: false
    learning_days: 7
    keyed_by: [host, user]
    action_below_baseline: suppress  # suppress | downgrade_severity | tag

  tuning:                          # named, range-validated knobs
    threshold:
      envvar: TS001_THRESHOLD
      min: 5
      max: 100
      default: 15

  actions:
    - write_alert_doc
    - append_alert_log
```

## Detection type variants

### `threshold_by_key` (agent engine, v1-compatible)

Same semantics as today's C# engine. Counts events matching `event_id` + `channel`, grouped by `group_by`, in a sliding `window_minutes` window. Fires when count ≥ `threshold`.

```yaml
detection:
  type: threshold_by_key
  event_id: 4625
  channel: Security
  group_by: winlog.event_data.TargetUserName
  threshold: 15
  window_minutes: 5
  cooldown_minutes: 5
```

#### `field_match` (optional pre-filter)

Some agent rules only count events whose value in a named field matches one of a fixed list (e.g. credential-dumping tool names, network-enumeration binaries, AMSI-bypass substrings). The C# v1 engine already supports this via a `field_match` clause; v2 carries it forward unchanged so migration is lossless. Semantics: an event is counted toward the threshold only if `field` contains (case-insensitive substring) one of `values`. Omitted ⇒ all events matching `event_id`+`channel` count.

```yaml
detection:
  type: threshold_by_key
  event_id: 4688
  channel: Security
  group_by: winlog.event_data.NewProcessName
  threshold: 1
  window_minutes: 5
  cooldown_minutes: 60
  field_match:
    field: winlog.event_data.NewProcessName
    match: contains            # contains (default, case-insensitive) | exact
    values:
      - mimikatz
      - procdump
      - nanodump
```

8 of the 39 live agent rules use `field_match` today (TS-061, TS-082, TS-130, TS-131, TS-132, TS-134, TS-135, TS-136). It is an agent-engine concern; `kql_threshold` rules express the same logic inline in the KQL string.

### `kql_threshold` (backend engine, v2.1 runtime — schema valid today)

```yaml
detection:
  type: kql_threshold
  index: tinysocs-winlog-*
  time_field: "@timestamp"
  kql: |
    (event.code:4625 OR winlog.event_id:4625)
    AND NOT winlog.event_data.IpAddress:(127.0.0.1 OR "::1")
  group_by: [winlog.event_data.IpAddress, winlog.event_data.TargetUserName]
  threshold: 5
  window_minutes: 120
  poll_interval_minutes: 5
```

### `sequence` (backend engine, future)

Ordered or unordered multi-step detection with `same:` correlation keys and `within_minutes:` constraints.

```yaml
detection:
  type: sequence
  index: tinysocs-winlog-*
  steps:
    - id: macro_spawn
      kql: event.code:4688 AND process.parent.name:"winword.exe" AND process.name:"powershell.exe"
    - id: outbound
      kql: event.code:3 AND process.name:"powershell.exe"
      within_minutes: 5
      same: [host.name]
  group_by: [host.name]
```

### `enrichment_gated` (backend engine, future)

A base detection plus AND/OR gates that consult external context (TI, geo, off-hours, baseline).

```yaml
detection:
  type: enrichment_gated
  base:
    type: kql_threshold
    kql: event.code:4624 AND winlog.event_data.LogonType:10
    group_by: [user.name]
    threshold: 1
    window_minutes: 5
  gates:
    any:
      - threat_intel_hit: source.ip
      - off_hours: true
      - not_in_baseline: { keyed_by: [user.name], min_learning_days: 7 }
```

## Allowlist file (customer-local, unsigned)

Lives at `C:\ProgramData\TinySocs\Collector\allowlists.yml`. Never part of the signed pack. Never sent to the vendor.

```yaml
schema_version: 1
allowlists:
  - rule_id: TS-001
    scope: user
    value: svc_backup
    note: "Backup service account; expected nightly auth failures during maintenance window"
    added_by: alice@customer.com
    added_at: "2026-05-26T14:00:00Z"

  - rule_id: TS-001
    scope: source_ip_cidr
    value: "10.50.0.0/24"
    note: "Lab subnet"

  - rule_id: TS-091
    scope: process_path
    value: "C:\\Program Files\\Vendor\\agent.exe"
```

### Allowlist scope vocabulary

| Scope | Matches |
|---|---|
| `user` | exact match on the rule's user-bearing field |
| `user_pattern` | glob (e.g. `svc_*`) |
| `host` | exact host name |
| `host_pattern` | glob |
| `source_ip` | exact IP |
| `source_ip_cidr` | CIDR range |
| `process_path` | exact full path |
| `process_pattern` | glob on path |
| `event_data.<field>` | escape hatch — exact match on any event_data subfield |

Each rule declares which scopes it honours via `allowlist_scopes`. The engine refuses to load an allowlist entry whose scope is not declared on its rule (loud failure — log + skip).

### Engine merge semantics

On load:
1. Parse signed pack → in-memory rule set.
2. Parse `allowlists.yml` → entries keyed by rule_id.
3. For each rule, attach matching allowlist entries (only those whose scope is in the rule's `allowlist_scopes`).
4. At detection time: condition matches → evaluate attached allowlist → suppress if any entry matches → otherwise alert.

Engine watches `allowlists.yml` for changes (file watcher) and atomically reloads. No agent restart needed.

## Baseline semantics

Per-rule, gated by `baseline.enabled`. Engine maintains a sliding `learning_days` window of counts grouped by `baseline.keyed_by`. After learning, current observations are compared to baseline.

`action_below_baseline`:
- `suppress` — drop the alert entirely.
- `downgrade_severity` — high → medium, medium → low.
- `tag` — emit alert with `baseline.below_threshold: true` tag, no severity change.

Baseline data is stored alongside `allowlists.yml`: customer-local, not shipped to vendor.

Baseline is not built in v2.0. The field is in the schema; the engine treats `baseline.enabled: true` as a runtime warning ("baseline not yet implemented") until v2.0.x adds it. No rule in v2.0 sets `enabled: true`.

## Tuning knobs

```yaml
tuning:
  threshold:
    envvar: TS001_THRESHOLD
    min: 5
    max: 100
    default: 15
```

Each declared knob is loaded from its envvar (or operator dashboard input) at engine startup. Value is clamped to `[min, max]`. If unset, `default` is used. The engine refuses to expose a tuning knob whose name isn't on a known shortlist (`threshold`, `window_minutes`, `cooldown_minutes`, `learning_days`) — extending the shortlist is a deliberate schema change.

## Migration mapping

### C# v1 → v2 (the 39 rules in `packaging/detection/rules.yml`)

| v1 field | v2 path | Notes |
|---|---|---|
| `id`, `name`, `description`, `severity`, `enabled`, `mitre`, `actions` | unchanged | |
| `type: threshold_by_key` | `detection.type: threshold_by_key` + `runs_on: agent` | |
| `condition.event_id`, `channel`, `group_by`, `threshold`, `window_minutes`, `cooldown_minutes` | `detection.*` | |
| `condition.field_match` | `detection.field_match` | carried through verbatim; `match: contains` is the implicit default (preserves v1 case-insensitive substring semantics) |
| (none) | `pack: base` for 37 rules; `pack: demo` for `TS-001-lab`, `TS-030-lab` | |
| (none) | `allowlist_scopes` | derived per rule family (auth → user/source_ip; process → process_path/user; FIM → process_path) |
| (none) | `baseline.enabled: false` | always false in v2.0 |
| (none) | `tuning.threshold.envvar: TS{id}_THRESHOLD` | optional; only for rules where operator threshold tuning makes sense |
| (none) | `docs: tinydocs/TS-{id}.md` | path is set; the file is created later by the TinyDocs workflow |

### Python v1 → v2 (the 50 rules in `src/tinysocs/agent/detections/rules.yaml`)

| v1 field | v2 path | Notes |
|---|---|---|
| `id`, `description`, `severity`, `mitre` | unchanged | |
| `category` | dropped from rule body, surfaces as a tag via `pack` membership | |
| `kql`, `index`, `time_field`, `group_by`, `threshold` | `detection.type: kql_threshold` + `detection.*` + `runs_on: backend` | |
| `window_minutes` (if absent) | default to 60 | match current backend semantics |
| `tuning_envvars: [X]` | `tuning.threshold.envvar: X` with conservative min/max | |
| (none) | `pack: base` for most; `pack: m365-pack` for the 3 M365 rules; `pack: demo` for `*_lab` variants | |
| (none) | `enabled: false` | all backend rules are disabled in v2.0 until the runner activates in v2.1 |
| (none) | `allowlist_scopes` | derive per rule |
| (none) | `docs: tinydocs/{id}.md` | created later |

Migration is a one-shot script (Python) that reads both v1 files and emits v2 packs. The script lives in `scripts/migrate_rules_to_v2.py` and is run by the developer, not at install time.

## Pack layout on disk (vendor side)

```
packs/
├── base/
│   ├── 2026.21/
│   │   ├── pack.yml              # the signed rules
│   │   ├── pack.yml.sig          # detached signature (optional; metadata.signature is canonical)
│   │   ├── tinydocs/
│   │   │   ├── TS-001.md
│   │   │   ├── TS-010.md
│   │   │   └── ...
│   │   └── validation.json       # last Atomic Red Team results
│   └── 2026.20/...
├── m365-pack/
│   └── 2026.21/...
└── demo/
    └── 2026.21/...
```

Customer installation pulls `https://feed.tinysocs.io/packs/{pack_id}/latest` (route + auth out of scope here; see feed server design). Cache is keyed by `(pack_id, pack_version)`. Pack is only swapped if signature verifies and `schema_version` is compatible.

## What v2.0 ships

**Must build:**
- v2 schema + YAML parser (C# via YamlDotNet; Python via PyYAML).
- C# `RuleLoader` understands `runs_on` and silently skips non-agent rules.
- `allowlists.yml` shape + file watcher in C# engine.
- Dashboard UI: "Add allowlist entry" surface (rule → scope → value → note).
- Migration script `scripts/migrate_rules_to_v2.py`.
- Ed25519 signing + verification (signing key generation, embed public key in agent, signature check at pack load).
- Demo-pack split: lab rules moved out of `base` into `demo` pack.

**Schema-present-but-not-built:**
- Backend Python KQL runner (v2.1).
- `sequence` and `enrichment_gated` runtimes.
- Multi-pack composition.
- Premium tier enforcement (feed-server-side).
- Baseline engine (added incrementally — schema fields are inert until then).

## Open questions

These are the things I'd want to revisit before starting implementation:

1. **Where do allowlist entries originate in the UI?** Probably from the alert details view — "this is a false positive, allowlist [user] from this rule" — which means the FP-feedback UI is on the v2.0 path too, even though gap #8 (telemetry of FP feedback to vendor) is deferred.
2. **What happens to an allowlist entry whose rule is removed from a future pack?** Stale entry in `allowlists.yml` referencing a missing rule_id. Engine should log + skip, but should there be a "stale allowlist" indicator in the dashboard?
3. **Versioning the allowlist file itself.** If we ever need to change `allowlists.yml` schema, we need a version field. (Already present: `schema_version: 1`.)
4. **Signing key rotation.** `metadata.signature.key_id` supports rotation but we need a key-rollover process documented for v2.0.x. Probably a small operational doc, not a code change.
5. **Lab pack discoverability.** When a developer installs in dev mode, do they get the demo pack automatically, or do they have to opt in? Probably opt in via a CLI flag or env var; auto-loading lab rules in dev means dev installs see "fake" alerts which is confusing.

## Non-binding pricing / tier shape (informs `metadata.tier`)

Recorded here so the schema's `tier` field has a referent, even though prices are not yet set:

- **free**: `base` pack only, stale snapshot (refreshes weekly only via a separate stale-snapshot endpoint, no continuous updates). Base C# engine + allowlists + local Ollama assistant.
- **pro**: live `base` pack feed + premium packs (persistence-premium, m365-pack, etc.) + cloud-LLM AI assistant (Claude/GPT). Per-site flat with endpoint band TBD.
- **msp**: pro + federation hub + multi-tenant management. Per-site flat designed to enable MSP margin. Priced below Blumira/Todyl/Huntress on per-endpoint-equivalent basis.

Pricing is locked after first cohort of customer conversations, not now.
