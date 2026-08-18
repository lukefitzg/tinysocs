---
name: Bug report
about: Something is broken
title: ""
labels: bug
---

<!--
TinySocs is a zero-support side project (see SUPPORT.md). Issues with diagnostic
output attached have a fighting chance of an answer; issues without it mostly don't.
-->

**What happened / what you expected**


**Health check output** (required — run in elevated PowerShell)

```
Import-Module "$env:ProgramFiles\TinySocs\modules\TinySocs.Installer.psm1"
Test-TinySocsHealth
```

```text
paste output here
```

**Environment**

- Windows version:
- TinySocs version (Add/Remove Programs):
- Install mode: localhost-only / network
- Sysmon installed: yes / no

**Support bundle** (strongly encouraged — IPs are coarsened for privacy)

```
powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\TinySocs\support\Pack-SupportBundle.ps1"
```

Attach the generated zip, or paste the relevant log excerpts.
