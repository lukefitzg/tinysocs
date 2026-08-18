# Contributing

PRs and issues are welcome. This is a solo side project reviewed best-effort — see
[SUPPORT.md](SUPPORT.md) for what that means. Small, focused PRs have the best odds.

## Ground rules

- **Detection changes need evidence.** Any new or modified rule needs an Atomic Red
  Team test case (`tests/atomic-tests.yaml`) and an xUnit firing/silent test pair
  (`tests/TinySocs.Agent.Tests/`). A rule without tests won't merge.
- **PowerShell must be ASCII-only.** Windows PowerShell 5.1 mangles em-dashes and
  curly quotes under ANSI codepages — this has broken the installer repeatedly.
  Check with: `LC_ALL=C tr -d '\r' < script.ps1 | grep -n '[^ -~]'` (expect nothing).
- **CI must pass**: `ruff check .`, `mypy -p tinysocs`, `pytest`. For C# changes,
  also run `dotnet test tests/TinySocs.Agent.Tests/` locally — it's not in CI.
- **No secrets, no prices, no customer data.** `.env.example` is the template; real
  values never enter the repo.

## Licensing

TinySocs is BSL-1.1 (source-available; converts to Apache 2.0 per-version after four
years). By submitting a contribution you agree it's licensed under the project's
licence. Don't vendor in third-party code without keeping its licence and attribution.

## Dev setup

See the Development Setup section of the [README](README.md). Python services are the
iteration surface; the C# agent (`src/TinySocs.Agent/`) is the runtime-critical path.
