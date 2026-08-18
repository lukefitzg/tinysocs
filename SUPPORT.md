# Support policy

TinySocs is a solo side project, provided **as-is, with no support obligation**.
There is no SLA, no support email, no promised response time, and no guaranteed
release cadence. Issues and pull requests are welcome and read with interest —
replies are best-effort and may be slow or not come at all. If that's a dealbreaker,
this is not the SIEM for you (Wazuh and Security Onion have real communities).

## Diagnose it yourself first

TinySocs ships good diagnostics. In order:

1. **Health check** — 16 checks across services, ports, indices, and config:
   ```powershell
   Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
   Test-TinySocsHealth
   ```
   INFO/WARN on a minimal install is often structural (webhook/SMTP unconfigured,
   Sysmon declined, TLS in localhost mode). FAIL means something is actually broken —
   check [docs/troubleshooting.md](docs/troubleshooting.md) first.

2. **Smoke test** — triggers the brute-force rule end-to-end and verifies an alert
   lands in the dashboard:
   ```powershell
   Invoke-TinySocsSmokeTest
   ```

3. **Deeper diagnostics** when the above don't explain it:
   - `scripts/Doctor.ps1` — broader environment triage
   - `scripts/Diagnose-DetectionPipeline.ps1` — "my rule isn't firing" triage
   - `scripts/Test-DashboardSmoke.ps1` — dashboard/API triage

## If you file an issue

Attach a support bundle — it collects logs and config with IP addresses coarsened
for privacy:

```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\TinySocs\support\Pack-SupportBundle.ps1"
```

An issue with `Test-TinySocsHealth` output and a support bundle has a fighting chance
of an answer. "It doesn't work" does not.

## Security vulnerabilities

Not in the issue tracker — see [SECURITY.md](SECURITY.md).
