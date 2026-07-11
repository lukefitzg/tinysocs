---
name: tinysocs-build-and-env
description: Rebuild any part of TinySocs from a clean checkout — C# agent (dotnet build/test/publish), Python services (venv, pip install -e ".[dev]", console scripts), pack signing (ed25519 keys, pack_sign.py, migrate_rules_to_v2.py), and the Windows-only Inno Setup installer. Load this when asked to build/compile/test the agent, set up a dev environment, run a FastAPI service locally, sign or migrate a rule pack, reproduce a CI failure locally, or diagnose "why didn't my new .cs file build" / "why is my YAML field not showing up at runtime" / "why does ISCC fail" / "what does the CI workflow actually run". Also covers the macOS-primary + Windows-VM dev topology (UNC shares, .venv-win) and known CI bugs (build-installer.yml OpenSearch version mismatch, xUnit not wired into ci.yml).
---

# tinysocs-build-and-env

From-scratch build instructions for every component of TinySocs, plus the
traps that have already bitten someone in this repo. All commands below were
run against `/Users/lukefitzgerald/tinysocs` on branch `fix/ci-green`
(HEAD `37005ad`) on 2026-07-11 and their output is shown verbatim where it
matters.

## 0. What you can build where

| Component | macOS | Windows |
|---|---|---|
| C# agent — Debug build/test | Yes, natively | Yes |
| C# agent — Release publish (win-x64 self-contained) | Yes (cross-compiles) | Yes |
| C# agent — **run** the built .exe | No (Worker Service uses `Microsoft.Extensions.Hosting.WindowsServices`, `System.Diagnostics.EventLog`, Windows Event Log APIs) | Yes only |
| Python services (node/feed/bot/master) — build + run | Yes | Yes |
| Pack signing / licence CLI (`pack_sign.py`, `licence.py`) | Yes (pure Python) | Yes |
| Inno Setup installer compile (`ISCC.exe`) | **No** | Yes only |
| PyInstaller EXEs (`TinySocsNode.exe` etc.) | Not verified this pass — flagged, see Open questions | Yes |

Bottom line: everything except the final installer compile and actually
running the agent can be built on macOS. This matches the repo's real dev
topology — see §7.

## 1. C# agent (`src/TinySocs.Agent`)

### Toolchain on this machine (verified 2026-07-11)

```
$ dotnet --list-sdks
8.0.416  [/usr/local/share/dotnet/sdk]
10.0.100 [/usr/local/share/dotnet/sdk]
```

`net8.0` TFM is satisfied by the 8.0.416 SDK. No `global.json` pin in repo
root. `dotnet` resolved via Homebrew (`/opt/homebrew/bin/dotnet` →
`/usr/local/share/dotnet`).

### Project shape (`src/TinySocs.Agent/TinySocs.Agent.csproj`, verified verbatim 2026-07-11)

- SDK: `Microsoft.NET.Sdk.Worker` — a Worker Service, `OutputType=Exe`, `TargetFramework=net8.0`.
- Release-only conditional block: `RuntimeIdentifier=win-x64`, `SelfContained=true`, `PublishSingleFile=true`, `InvariantGlobalization=true`. Debug is framework-dependent, no RID — builds on any OS with the SDK.
- Package refs: `YamlDotNet 15.1.0`, `BouncyCastle.Cryptography 2.4.0` (comment in the csproj: *".NET 8 BCL has no Ed25519; BouncyCastle (MIT) verifies signed packs + licence keys"*), `Microsoft.Extensions.Hosting 8.0.0` + `.WindowsServices 8.0.0`, `Microsoft.Extensions.Configuration.Binder 8.0.0`, `System.Diagnostics.EventLog 8.0.0`.
- `InternalsVisibleTo TinySocs.Agent.Tests`.

### THE compile-item allowlisting trap

This csproj does **not** use SDK-style implicit globbing. It explicitly
kills all compile items and re-adds only named paths:

```xml
<ItemGroup>
  <Compile Remove="**/*.cs" />
</ItemGroup>

<ItemGroup>
  <Compile Include="Program.cs" />
  <Compile Include="AgentService.cs" />
  <Compile Include="Configuration/**/*.cs" />
  <Compile Include="Inputs/**/*.cs" />
  <Compile Include="Models/**/*.cs" />
  <Compile Include="Queue/**/*.cs" />
  <Compile Include="Shipper/**/*.cs" />
  <Compile Include="Detection/**/*.cs" />
  <Compile Include="Notification/**/*.cs" />
</ItemGroup>
```

**Consequence you will hit**: a new top-level `.cs` file, or a file in a new
subdirectory not in that list, is **silently excluded** from the build — no
error, no warning, the class just doesn't exist to the compiler and any
`.csproj`-external reference to it fails with a plain "type not found." If
you add a new subsystem directory (e.g. `Allowlist/`), you must add
`<Compile Include="Allowlist/**/*.cs" />` to this block or nothing in it
builds. Same pattern applies to `<Content Remove="**/*.json" />` /
`<None Include="appsettings.json">` for JSON files, and
`<EmbeddedResource Remove="**/*.resx" />` for resx — all belt-and-suspenders
against imported MSBuild targets injecting stray items, but all equally
capable of eating a file you expect to be included.

### Build/test/publish commands (all verified working on macOS, 2026-07-11)

```bash
# Debug build — framework-dependent, any OS with the .NET 8 SDK
dotnet build tinysocs.sln
# verified: 0 errors, 28 warnings (all CA1416 "Windows-only API" advisory
# warnings from EventLogInput.cs — expected and harmless on macOS, the code
# only runs on Windows at runtime)

# xUnit tests — Debug, any OS
dotnet test tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj
# verified: Passed! Failed: 0, Passed: 70, Skipped: 0, Total: 70, ~0.4s
# (this is ALL 4 test files combined: DetectionEngineTests.cs [30 Fact +
# 2 Theory = 32 methods], Ed25519TestKit.cs [helper, not tests],
# LicenceReaderTests.cs, PackLoaderTests.cs)

# Release, self-contained win-x64 publish — buildable on macOS, runnable
# only on Windows. Exact command CI uses:
dotnet publish src/TinySocs.Agent/TinySocs.Agent.csproj -c Release -r win-x64 --self-contained
```

Test project (`tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj`):
plain `Microsoft.NET.Sdk`, `xunit 2.9.2` + `xunit.runner.visualstudio 2.8.2`
+ `Microsoft.NET.Test.Sdk 17.11.1`, references the agent project directly.
`DetectionEngineTests.cs` asserts the exact 19-rule enabled set in
`packaging/detection/rules.yml` (`grep -c "enabled: true"` → 19, verified
2026-07-11) — treat a change to that count as something the test suite
should catch, but see the CI gap below: **it won't catch it in CI**.

`scripts/Build-Agent.ps1` (PowerShell, cross-platform-pwsh-compatible)
wraps the same publish with `-p:PublishSingleFile=true
-p:IncludeNativeLibrariesForSelfExtract=true`, and verifies the output lands
at `src/TinySocs.Agent/bin/<Configuration>/<tfm>/<Runtime>/publish/TinySocs.Agent.exe`
— the exact path `packaging/iss/Quickstart.iss` expects.

For thresholds/window semantics of the rule engine itself, see
detection-engineering-reference. For the enabled/disabled rule inventory and
why, see tinysocs-architecture-contract.

## 2. The YamlDotNet / canonical-JSON split — a round-trip trap

Two completely different serialization paths exist in this codebase and
mixing them up wastes time.

**v1 YAML path** — `UnderscoredNamingConvention.Instance`, wired in exactly
three places (verified via `grep -n "NamingConvention" src/TinySocs.Agent/**/*.cs`):

| File | Loads |
|---|---|
| `Detection/RuleLoader.cs:24` | `packaging/detection/rules.yml` (v1 rules) |
| `Detection/RuleDocs.cs:43` | `packaging/detection/rule_docs.yml` (TinyDocs companion) |
| `Configuration/ConfigLoader.cs:32` | `appsettings.json` / agent config |

All three use `DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance).IgnoreUnmatchedProperties().Build()`.
Practical effect: snake_case YAML keys map to PascalCase C# properties
automatically, and **any YAML key with no matching property is silently
dropped** — no error. If you add a new field to a rule and it's not showing
up at runtime, check the C# model class has a matching property; the loader
will not warn you.

**v2 signed-pack path — NOT YamlDotNet.** `Detection/PackLoader.cs` reads
`pack.yml.canonical` — a JSON file, not YAML — via raw `System.Text.Json`
(`using System.Text.Json;` at PackLoader.cs:4, `JsonDocument.Parse(canonical)`
at PackLoader.cs:81, `JsonElement` property lookups by literal snake_case
name at PackLoader.cs:168-291 for fields like `pack_id`, `event_id`,
`group_by`, `window_minutes`, `field_match`, `technique_id`). There is
**no naming-convention translation layer** for v2 — it isn't needed because
the trust-path artifact is JSON.

**Consequence**: `pack.yml` (the human-authored YAML) is *not* what the
agent parses at runtime. It parses `pack.yml.canonical`, a deterministic
sorted-key compact-JSON sidecar produced by `scripts/pack_sign.py`'s
`canonical_bytes()` function. **If you hand-edit `pack.yml` and the change
doesn't show up when the agent loads a pack, you forgot to re-run
`pack_sign.py sign` to regenerate `.canonical` and `.sig`.** Editing
`pack.yml` alone does nothing at runtime — see §4 below for the exact
command.

Note this pack-load path defaults **off**:
`ContentPackConfig.Enabled = false` (`src/TinySocs.Agent/Configuration/AgentConfig.cs:146`,
verified 2026-07-11 — the outer `DetectionConfig.Enabled` at line 128 is a
different, unrelated flag defaulting `true`, don't confuse the two). Even
with v2 fully implemented, the shipped installer path is still v1
`rules.yml` — see tinysocs-architecture-contract for the full dormant-trust-path
picture.

## 3. Python services

### `pyproject.toml` (repo root, verified 2026-07-11)

- Build backend `hatchling>=1.25.0`. Package `tinysocs`, version `0.10.0`,
  `requires-python >=3.10`, licence `BSL-1.1`.
- Runtime deps include `cryptography>=42,<46` (pyproject.toml:24) — this is
  the dependency commit `37005ad` ("Fix CI: make Ruff and mypy actually
  pass, add missing cryptography dep") added; it's what `pack_sign.py` and
  `licence.py` need for ed25519 signing.
- Dev extras: `pytest>=7.4`, `pytest-cov>=4.1`, `mypy>=1.10`, `ruff>=0.6`,
  `types-requests`, `types-PyYAML`.
- Console scripts (verified `[project.scripts]` block, pyproject.toml:37-42):

  | Script | Module | Default port |
  |---|---|---|
  | `tinysocs-node` | `tinysocs.api.node:cli` | `8081` |
  | `tinysocs-feed` | `tinysocs.api.feed:cli` | `8095` |
  | `tinysocs-master` | `tinysocs.orchestrator.master:cli` | n/a — CLI, not a server |
  | `tinysocs-quickstart` | `tinysocs.launcher.quickstart:cli` | n/a |
  | `tinysocs-daily-summary` | `tinysocs.reporting.daily_summary:main` | n/a |

  **No `tinysocs-bot` console script exists**, even though it serves the
  most customer-visible surface (the dashboard at port 8090). Run it as
  `python -m tinysocs.api.bot` or via an explicit uvicorn import string.

- `[tool.ruff]`: line-length 100, target 3.10, select `E,F,W,I,N,UP`, ignore
  `E501,E402` (E402 ignored deliberately — several API modules do scoped
  mid-file imports next to usage).
- `[tool.mypy]`: `python_version=3.10`, `mypy_path=src`,
  `ignore_missing_imports=true`, `strict_optional=false`.
- `[tool.pytest.ini_options]`: `testpaths=["tests"]`, `pythonpath=["src"]`.

`requirements.txt` at repo root is a secondary/legacy install path
(unpinned-minor superset of the same deps); `pyproject.toml` is canonical.

### venv setup (macOS)

```bash
cd /Users/lukefitzgerald/tinysocs
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

System `python3` on this Mac is 3.14.0 (Homebrew,
`/opt/homebrew/bin/python3`) — verified 2026-07-11. CI matrices 3.10/3.11;
the project's `>=3.10` floor allows 3.14 but it's newer than anything CI
exercises. Pin a 3.10/3.11 interpreter for your venv if you need an exact
CI repro.

**Trap — stray global editable install**: `pip3 show -f tinysocs` on the
bare system/Homebrew pip (not a project venv) can report a stale editable
install pointing at a dead `.claude/worktrees/<name>` directory, with a
stale version and a stale `License: MIT` field (pre-dates the BSL-1.1
switch). This is install metadata, not a repo file — nothing to fix
in-repo — but if `import tinysocs` behaves unexpectedly outside a fresh
venv, run `pip3 show tinysocs` first and check `Location` /
`Editable project location`; if it's stale, `pip3 uninstall tinysocs` or
just always work inside a project-local venv.

### Running each FastAPI service locally

None of these require Windows — they only fail closed on missing
secrets/TLS, never on OS.

```bash
# Feed server — no secrets needed for /healthz
tinysocs-feed
# or: FEED_PORT=8095 python -m tinysocs.api.feed
# reads packs from TINYSOCS_PACKS_DIR (default <repo>/packs),
# keys from TINYSOCS_KEY_DIR (default <repo>/keys)

# Node API
NODE_PORT=8081 tinysocs-node

# Dashboard/bot bridge, demo mode — synthetic data, no OpenSearch/secrets
python -m tinysocs.api.bot --demo
# serves http://localhost:8090/dashboard ; --demo sets
# TINYSOCS_DEMO_MODE=1, DASHBOARD_BIND=127.0.0.1, SIEM_PASS=demo
# Outside --demo mode: requires BOT_SHARED_SECRET env, and refuses a
# non-localhost bind without a TLS cert/key pair.
```

`tinysocs-master` is a CLI, not a server (`--rules`, `--window`, `--host`,
`--deadline`, `--always-anchor`); it fans out to node URLs from
`TINYSOCS_NODES` and exits — raises if that env var is empty.

Full port inventory (feed 8095, node 8081, bot/dashboard 8090, OpenSearch
9201/5602, transport 9300): see tinysocs-config-and-flags. Operational
runbook (services under NSSM, ProgramData layout): see
tinysocs-run-and-operate.

## 4. Pack signing workflow

Two separate ed25519 keypairs exist by design — **different blast radius**
(comment in `licence.py`): `tinysocs-2026` signs content packs,
`licensing-2026` signs licence tokens. Verified present on disk 2026-07-11:

```
keys/licensing-2026.key   (0600, private)
keys/licensing-2026.pub
keys/tinysocs-2026.key    (0600, private)
keys/tinysocs-2026.pub
```

Both gitignored: `.gitignore:212` (`keys/` directory rule) plus a
standalone `*.key` glob earlier in the file (`.gitignore:177`). **Never
commit a private key** — this is a hard rule, not a suggestion; if you ever
see a `.key` file staged, unstage it and check `.gitignore` didn't get
edited.

### End-to-end demo (from `pack_sign.py`'s own docstring, commands verified present)

```bash
# Generate a new signing keypair (writes keys/<key-id>.key + .pub;
# refuses to overwrite an existing .key without --force)
python3 scripts/pack_sign.py gen-key --key-id tinysocs-2026

# Sign a pack — injects/refreshes metadata.signature, computes
# canonical_bytes() (sorted-key compact JSON, signature blanked), signs,
# writes two sidecars: pack.yml.sig (detached sig) and pack.yml.canonical
# (the exact bytes the agent verifies+loads — this is the file that matters)
python3 scripts/pack_sign.py sign packs/base/2026.23/pack.yml --key-id tinysocs-2026

# Verify — re-derives canonical_bytes(), checks algorithm==ed25519,
# optionally pins key_id, verifies the signature
python3 scripts/pack_sign.py verify packs/base/2026.23/pack.yml --key-id tinysocs-2026
```

State of packs on disk (verified 2026-07-11):

```
packs/base/2026.22/pack.yml            (unsigned)
packs/base/2026.23/pack.yml            (unsigned)
packs/base/2026.27/pack.yml            SIGNED — has .sig + .canonical
packs/demo/2026.23/pack.yml
packs/demo/2026.27/pack.yml
```

Only `base/2026.27` — the pilot pack referenced throughout CLAUDE.md and
tinysocs-architecture-contract — has the full signed artifact triplet.

### `scripts/licence.py` — licence key minting (pure local, no network)

```bash
python3 scripts/pack_sign.py gen-key --key-id licensing-2026
python3 scripts/licence.py issue --tier pro --sites 5 --sub cus_demo --key-id licensing-2026
python3 scripts/licence.py inspect <key> --key-id licensing-2026
```

Subcommands `issue` / `inspect` / `entitlement`. `TIERS = ("free", "pro",
"msp")` — matches the locked tier architecture in CLAUDE.md. Default demo
key period: 365 days. Reuses `pack_sign.py`'s key I/O directly (same
`keys/` directory, same file format). No prices anywhere in this file — do
not add any; see tinysocs-external-positioning for the pricing rule.

### `scripts/migrate_rules_to_v2.py` — the v1→v2 mechanical migration

Verified present, 2026-07-11 (`scripts/migrate_rules_to_v2.py`, 8567 bytes,
dated 2026-06-06 — this predates the ground-truth cutoff of this skill so
check `git log` if you need the exact commit). Reads
`packaging/detection/rules.yml`, emits `packs/base/<version>/pack.yml`
(`runs_on: agent`) and `packs/demo/<version>/pack.yml` (lab-only variant
IDs). Version defaults to ISO year.week. Does **not** migrate the 50-rule
Python KQL catalogue (`src/tinysocs/agent/detections/rules.yaml`) — that's
deferred to v2.1, same as the runner activation itself (see
tinysocs-research-frontier). Idempotent re-run. Emits packs with **no
signature block** — sign separately with `pack_sign.py sign`.

```bash
python3 scripts/migrate_rules_to_v2.py                       # today's ISO week
python3 scripts/migrate_rules_to_v2.py --dry-run
python3 scripts/migrate_rules_to_v2.py --version 2026.23
python3 scripts/migrate_rules_to_v2.py --input packaging/detection/rules.yml --out-dir packs
```

Any change to rule counts, signing, or the licence/feed trust path is a
pivot-critical decision — gate through tinysocs-change-control before
shipping it, even though the tooling itself runs freely in dev.

## 5. Inno Setup installer — Windows-only

`packaging/iss/Quickstart.iss` (3407 lines). Compiles only via `ISCC.exe`
(Inno Setup 6) on Windows — **cannot run on macOS**. C# publish and Python
packaging both feed into it but the compile step itself needs a Windows
box.

```powershell
# Windows only
$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
& $iscc packaging\iss\Quickstart.iss
```

Prerequisite (also Windows): `choco install innosetup -y --no-progress`.

Hard build-time requirement — the `.iss` `#error`s out entirely
(Quickstart.iss:135-139) if
`vendor\opensearch-3.3.2-windows-x64\opensearch-3.3.2\bin\opensearch.bat`
is missing. On this machine that vendor payload is genuinely present at
1.2GB.

**Sysmon install is opt-out, not opt-in** in the installer wizard (verified
2026-07-11): `SysmonInstallCheck` is a `TNewCheckBox` on the "Enhanced
Detection" wizard page, created and left at its default checked state
(Quickstart.iss:1525-1530 area), caption *"Install Sysmon with TinySocs
configuration (recommended)"*. A default, click-through install run will
install Sysmon unless the operator explicitly unchecks the box.

For the full installer flow (ProgramData layout, wizard pages, NSSM
services, scheduled tasks), see tinysocs-run-and-operate — this skill only
covers the *build* of the installer, not what it does at runtime.

## 6. CI ground truth (`.github/workflows/`)

### `ci.yml` — verified verbatim, 2026-07-11

Two jobs:

1. **`test`** (ubuntu-latest, matrix `python-version: ["3.10", "3.11"]`):
   ```bash
   python -m pip install --upgrade pip
   pip install -e ".[dev]"
   ruff check .
   mypy -p tinysocs
   pytest --cov=tinysocs --cov-report=term-missing
   ```
2. **`windows-test`** (windows-latest): sets up Python 3.11 + .NET 8.0.x,
   runs the same `pytest` command, then
   `dotnet publish src/TinySocs.Agent/TinySocs.Agent.csproj -c Release -r win-x64 --self-contained`,
   then Pester: `Invoke-Pester -Path tests/Test-InstallerModule.ps1 -Output Detailed -CI`.

**xUnit is NOT run in CI (as of 2026-07-11).** Neither job has a
`dotnet test` step. `windows-test` only *publishes* the agent (proves it
compiles for win-x64) — it never executes `DetectionEngineTests.cs`,
`PackLoaderTests.cs`, or `LicenceReaderTests.cs`. The 70 xUnit tests (30
Fact + 2 Theory in `DetectionEngineTests.cs` alone, plus
`LicenceReaderTests.cs` and `PackLoaderTests.cs`) only run when someone runs
`dotnet test` locally — see §1. If you're asked "does CI catch a broken
detection rule / a broken pack signature verify," the honest answer is no,
not today. This is itself a candidate CI-hardening item — flag it through
tinysocs-change-control rather than silently adding a `dotnet test` step,
since changing CI gating is a process decision, not a drive-by fix.

Local repro of the `test` job exactly:
```bash
cd /Users/lukefitzgerald/tinysocs
pip install -e ".[dev]"
ruff check .
mypy -p tinysocs
pytest --cov=tinysocs --cov-report=term-missing
```

### `build-installer.yml` — live bug, verified 2026-07-11

Triggers on push to `main` and `v*` tags. Pipeline: checkout → Python 3.11 +
.NET 8.0.x → `pip install -e ".[dev]"` → `scripts/Build-Agent.ps1` → cache/
download OpenSearch vendor zip → `choco install innosetup` → `ISCC.exe` →
SHA256 checksum → upload `TinySocs-Setup.exe` + `SHA256SUMS.txt` → (on `v*`
tag) create a GitHub Release.

**Version-mismatch bug**, verified verbatim:

```yaml
# build-installer.yml:44-45 — cache path/key say 3.3.2
path: vendor/opensearch-3.3.2-windows-x64
key: opensearch-3.3.2-windows-x64
...
# build-installer.yml:51 — but the actual download URL is 2.18.0
$url = "https://artifacts.opensearch.org/releases/bundle/opensearch/2.18.0/opensearch-2.18.0-windows-x64.zip"
$expectedHash = "e2db6ee1fb22e917a2f1e6c2bf2e40e2c41a3a5e5a7c8fe4f4dcf8b1bda5d7a3"  # TODO: update with actual SHA256
...
# build-installer.yml:59-61 — hash check is commented out
# if ($actualHash -ne $expectedHash) {
#   throw "SHA256 mismatch for OpenSearch download! ..."
# }
...
# build-installer.yml:62-63 — extracted into the 3.3.2-named dir regardless
New-Item -ItemType Directory -Path "vendor/opensearch-3.3.2-windows-x64" -Force
Expand-Archive -Path $zip -DestinationPath "vendor/opensearch-3.3.2-windows-x64" -Force
```

Net effect: a cache-miss CI run downloads OpenSearch **2.18.0** but unpacks
it into a directory the `.iss` `#error` guard and the real local vendor
payload both expect to contain **3.3.2** — with SHA256 verification
disabled. This has presumably never fired because the GitHub Actions cache
has stayed warm; it's a live, currently-masked bug that will bite the first
cache-miss run (new runner image, cache eviction, or someone bumping the
cache key without updating the download URL). If you're asked to fix the
OpenSearch vendor pipeline, this is the first thing to check — and it's a
platform/build-tooling fix, not a pivot-facing change, so it's a normal
gate through tinysocs-change-control (low bar, not a strategic decision).

## 7. Dev topology — macOS primary + Windows VM

This is a macOS-primary, Windows-VM-secondary setup (Parallels/VMware-style
shared folder), not two independent checkouts.

- `scripts/stage-deploy-bundle.sh` (bash, header: *"Run on the build host
  (macOS/Linux with the .NET SDK)"*) builds the win-x64 agent (`dotnet
  publish ... -c Release -o dist/agent-win-x64` — no explicit `-r win-x64`
  on the command line; relies on the csproj's Release-conditional RID block
  from §1), assembles `dist/deploy-bundle/` with the exe + `rules.yml` +
  deploy/test scripts, and generates a `RUN-ON-VM.md` runbook with the exact
  next commands to run **on the Windows VM side**
  (`Deploy-AgentUpdate.ps1 -SourceDir .`, then
  `Test-AtomicDetection.ps1 -SkipInstall`). Its own header states explicitly:
  *"This validates the DETECTION CONTENT (rules.yml, the fallback path the
  agent runs by default). It does NOT exercise the signed-feed delivery
  path — that is a separate test (Pack.Enabled=true + a signed
  .canonical/.sig on the VM)."*
- `scripts/Full-Rebuild.ps1` is meant to run from an **elevated PowerShell
  on the Windows VM**, with `$RepoRoot` pointed at a UNC share back to the
  Mac (e.g. `\\Mac\Home\.claude-worktrees\tinysocs\<worktree-name>`). It
  detects UNC paths and robocopies to `C:\TinySocs-Build` locally first,
  because — per its own comment — *"ISCC (Inno Setup compiler) cannot
  compile from UNC paths."* If you're setting up the VM side, expect to hit
  this: don't try to run `ISCC.exe` directly against the `\\Mac\Home\...`
  mount.
- `.venv-win/pyvenv.cfg` (repo root) is a **Windows-native venv**, created
  by a Windows Python install (`pythoncore-3.14-64`), targeting the repo
  mounted at `C:\Mac\Home\tinysocs`. It has `Scripts/` not `bin/` — do not
  try to activate or use it from a macOS shell.
- **Verified 2026-07-11 — not actually a trap**: `.venv-win/` is present,
  populated (has `pyvenv.cfg`), and untracked. It's true that
  `git check-ignore -v .venv-win` (the bare directory name) returns nothing
  (exit 1, no match) and the root `.gitignore` has no `.venv-win/` pattern —
  but that's the wrong test. `.venv-win/` ships its own nested
  `.gitignore` (`*`, auto-generated by the `venv` module), which already
  ignores everything inside it: `git check-ignore -v .venv-win/pyvenv.cfg`
  matches `.venv-win/.gitignore:2:*`, and `git status --short --ignored`
  shows `!! .venv-win/`. A `git add -A -n` dry run from repo root stages
  nothing under it. So there's no live staging risk today — the only gap
  is that the *directory itself* isn't named in the root `.gitignore`,
  which is cosmetic, not a hygiene bug worth fixing.
- `scripts/Doctor.ps1` (diagnostics, not a build step) pings Node (8081)
  and Bot (8090) by default — matches the FastAPI defaults in §3. Full
  diagnostics coverage: see tinysocs-diagnostics-and-tooling.

## When NOT to use this skill

- Deciding **whether** a build/CI/signing change is in scope for the pivot,
  or whether it needs sign-off — see tinysocs-change-control.
- Runtime behavior of the installed agent (ProgramData layout, NSSM
  services, ports at runtime, upgrade/uninstall flow) — see
  tinysocs-run-and-operate.
- Diagnosing a symptom in a *running* system (silent detection engine,
  shipper failures, HMAC mismatches, dashboard auth) — see
  tinysocs-debugging-playbook.
- Every configuration flag and env var, beyond what's needed to run a
  service locally for a build check — see tinysocs-config-and-flags.
- The load-bearing design decisions behind the signed-pack trust path
  (why it's dormant, what wires to what) — see
  tinysocs-architecture-contract.
- What counts as "the tests pass" from a validation-evidence standpoint
  (Atomic Red Team harness, banned efficacy numbers) — see
  tinysocs-validation-and-qa.
- Detection rule semantics, thresholds, MITRE mapping — see
  detection-engineering-reference.

## Provenance and maintenance

Authored 2026-07-11 against branch `fix/ci-green`, HEAD `37005ad`. Primary
sources, all read/verified directly in-repo this pass (not solely from the
discovery digest):

- `src/TinySocs.Agent/TinySocs.Agent.csproj` (read verbatim)
- `tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj` (read verbatim)
- `tests/TinySocs.Agent.Tests/DetectionEngineTests.cs` (fact/theory counts)
- `src/TinySocs.Agent/Configuration/AgentConfig.cs` (lines ~110-150)
- `src/TinySocs.Agent/Detection/PackLoader.cs` (JSON usage, lines 4,56-81,160-291)
- `pyproject.toml` (full)
- `.github/workflows/ci.yml` (full, verbatim)
- `.github/workflows/build-installer.yml` (OpenSearch cache/download block)
- `packaging/iss/Quickstart.iss` (Sysmon checkbox, ~line 1525-1530)
- `scripts/pack_sign.py`, `scripts/licence.py`, `scripts/migrate_rules_to_v2.py` (existence, sizes, docstrings)
- `scripts/stage-deploy-bundle.sh` (header comment)
- `.gitignore` (keys/, *.key, .venv/ rules)
- `keys/` directory listing
- `packs/` directory listing
- Cross-checked against a prior discovery-pass digest (2026-07-06 capture, a session-local scratch file — not re-derivable, ignore if absent); all status claims above were re-verified fresh against the live repo, not taken on trust.
- Live command output: `dotnet build tinysocs.sln` (0 errors, 28 CA1416 warnings), `dotnet test tests/TinySocs.Agent.Tests/...` (70 passed, 0 failed)

### Re-verification commands (run these before trusting any volatile fact above)

```bash
# .NET SDK availability
dotnet --list-sdks

# C# build/test still green
dotnet build tinysocs.sln --nologo -v q
dotnet test tests/TinySocs.Agent.Tests/TinySocs.Agent.Tests.csproj --nologo -v q

# Compile-item allowlist still explicit (no implicit globbing silently reintroduced)
grep -n "Compile Include\|Compile Remove" src/TinySocs.Agent/TinySocs.Agent.csproj

# xUnit fact/theory count in DetectionEngineTests.cs
grep -c '\[Fact\]' tests/TinySocs.Agent.Tests/DetectionEngineTests.cs
grep -c '\[Theory\]' tests/TinySocs.Agent.Tests/DetectionEngineTests.cs

# xUnit still absent from ci.yml (confirms the CI gap claim)
grep -n "dotnet test" .github/workflows/ci.yml   # expect: no output

# ContentPackConfig default still dormant
grep -n "class ContentPackConfig" -A 2 src/TinySocs.Agent/Configuration/AgentConfig.cs

# YamlDotNet usage sites unchanged (quote the glob — zsh, the dev shell here,
# expands an unquoted *.cs itself and errors with "no matches found" before
# grep ever runs)
grep -rn "NamingConvention" src/TinySocs.Agent --include='*.cs'

# PackLoader still JSON-based, not YAML
grep -n "System.Text.Json\|JsonElement" src/TinySocs.Agent/Detection/PackLoader.cs | head -3

# Signed pack inventory
find packs -name "*.canonical" -o -name "*.sig"

# Keys present and gitignored
ls keys/
git check-ignore -v keys/tinysocs-2026.key

# rules.yml enabled count (cross-check against tinysocs-architecture-contract's 19)
grep -c "enabled: true" packaging/detection/rules.yml

# OpenSearch version-mismatch bug still present
grep -n "opensearch-2.18.0\|opensearch-3.3.2\|expectedHash" .github/workflows/build-installer.yml

# Sysmon checkbox default still opt-out
grep -n "SysmonInstallCheck" packaging/iss/Quickstart.iss

# .venv-win contents still covered by its own nested .gitignore
# (bare-directory check-ignore is the wrong test — it will show exit 1/no
# match even though everything inside is ignored; check a file inside instead)
git check-ignore -v .venv-win/pyvenv.cfg; echo "exit=$?"   # exit 0, matches .venv-win/.gitignore:2:*

# pyproject console scripts unchanged
grep -n -A 6 "\[project.scripts\]" pyproject.toml

# cryptography dependency still present (added by 37005ad)
grep -n "cryptography" pyproject.toml
```

## Open questions

- PyInstaller EXE builds (`TinySocsNode.spec`, `TinySocsMaster.spec`,
  `TinySocsAnchors.spec`, `tinysocs_forwarder_winlog.spec`) were not
  exercised this pass — unclear whether they build cleanly on macOS or
  require Windows-native PyInstaller. Verify with `pyinstaller
  TinySocsNode.spec` before relying on this.
- `tools/os_license_shim.ps1` and `tools/start_shim.cmd` were not read in
  depth — names suggest OpenSearch-licensing workaround and a cmd-based
  process-start shim, both Windows-only by extension. Flag, not verified.
- `scripts/os_shim.py`, `scripts/demo_feed.sh`,
  `scripts/migrate_atomic_results_to_v2.py` were not read in depth this
  pass.
