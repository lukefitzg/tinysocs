# Weekly validation: VM setup

**Status:** operator runbook
**Audience:** whoever owns the Windows test VM (currently: Luke)

This sets up the unattended weekly run that powers the public validation
dashboard. Design and rationale live in
[`docs/design/continuous-validation.md`](../design/continuous-validation.md);
this is the hands-on checklist.

The moving parts:

- `tests/Test-AtomicDetection.ps1` — the harness. Runs Atomic Red Team
  techniques and writes a **raw** run file.
- `scripts/normalize_validation_run.py` — turns the raw run into
  `results/<iso-week>.json` + `results/latest.json` (v2 schema).
- `scripts/run_weekly_validation.ps1` — the wrapper Task Scheduler calls. It
  pulls, runs the harness, normalises, commits, and pushes.
- `.github/workflows/pages.yml` — on push to `results/**`, rebuilds
  `summary.json` and redeploys the dashboard.

You only have to wire up two things on the VM: a **deploy key** (so the VM can
push) and a **scheduled task** (so it runs weekly). Everything else is in the
repo.

## Prerequisites

On the VM, one-time:

- TinySocs installed and running (the detection engine + OpenSearch on
  `https://localhost:9201`).
- Sysmon installed (several rules depend on it).
- Atomic Red Team available, or let the harness clone it on first run.
- `git` and a Python 3 interpreter (`python3`, `python`, or the `py` launcher)
  on `PATH`.
- The repo cloned somewhere stable, e.g. `C:\tinysocs`.
- The task must run **as an admin** (ART techniques and audit-policy changes
  need elevation).

## 1. Deploy key (so the VM can push results)

A deploy key is a repo-scoped SSH key — narrower than a personal access token
and trivial to rotate. Generate it on the VM:

```powershell
ssh-keygen -t ed25519 -C "tinysocs-vm-validation" -f $HOME\.ssh\tinysocs_deploy -N '""'
```

Add the **public** key (`tinysocs_deploy.pub`) to the repo:

> GitHub → repo → Settings → Deploy keys → Add deploy key →
> paste the contents of `tinysocs_deploy.pub` → **tick "Allow write access"**.

Tell git to use that key for this repo, and switch the remote to SSH:

```powershell
cd C:\tinysocs
git remote set-url origin git@github.com:lukefitzg/tinysocs.git
git config core.sshCommand "ssh -i $HOME/.ssh/tinysocs_deploy -o IdentitiesOnly=yes"
```

Verify the key can authenticate and push:

```powershell
ssh -i $HOME\.ssh\tinysocs_deploy -T git@github.com   # expect: "Hi lukefitzg/tinysocs! ..."
```

Set the committer identity for the unattended commits:

```powershell
git config user.name  "TinySocs Validation VM"
git config user.email "validation@tinysocs.local"
```

## 2. First manual run (no push)

Before scheduling anything, prove the chain end-to-end locally:

```powershell
cd C:\tinysocs
pwsh scripts\run_weekly_validation.ps1 -SkipPull -NoPush -HarnessArgs '-SkipInstall'
```

What success looks like:

- `logs\validation-<timestamp>.log` ends with `Weekly validation finished OK.`
- `results\<iso-week>.json` and `results\latest.json` were written/updated.
- `git log -1` shows a local `validation: <run-id> run` commit (not pushed).

If it looks right, do one real push to confirm the dashboard updates:

```powershell
pwsh scripts\run_weekly_validation.ps1 -SkipPull -HarnessArgs '-SkipInstall'
```

Watch the **Deploy Landing Page** action run in GitHub; the dashboard at
`https://lukefitzg.github.io/tinysocs/validation/` should show the new run
within a couple of minutes.

## 3. Scheduled task (weekly, unattended)

Register the task to run Sundays at 02:00, as admin, whether or not anyone is
logged in. Run this in an **elevated** PowerShell:

```powershell
$action = New-ScheduledTaskAction `
    -Execute "pwsh.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\tinysocs\scripts\run_weekly_validation.ps1" `
    -WorkingDirectory "C:\tinysocs"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2:00AM

# StartWhenAvailable = catch up if the VM was asleep at 02:00 (see "Freshness").
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Register-ScheduledTask `
    -TaskName "TinySocs Weekly Validation" `
    -Action $action -Trigger $trigger -Settings $settings `
    -RunLevel Highest `
    -User "SYSTEM"
```

> If the run needs an interactive desktop or a specific user's keychain for the
> SSH key, register it under that user account with `-User <name> -Password
> <pw>` and `-RunLevel Highest` instead of `SYSTEM`, and make sure the deploy
> key lives in that user's `$HOME\.ssh`.

Trigger it once by hand to confirm the scheduled context works (the SSH key and
`PATH` resolve differently under SYSTEM than under your interactive session):

```powershell
Start-ScheduledTask -TaskName "TinySocs Weekly Validation"
Get-ScheduledTaskInfo -TaskName "TinySocs Weekly Validation"   # LastTaskResult should be 0
```

## Freshness / self-recovery

- `-StartWhenAvailable` means a VM that was off at 02:00 runs the job when it
  next wakes, so an ordinary reboot doesn't silently skip the week.
- If a run **fails**, the wrapper aborts *before* committing — a broken run
  never publishes. The previous week's results stay up, and the dashboard's
  staleness banner appears once the last good run is more than 8 days old.
- A CI freshness check that opens an issue when `latest.json` is stale is
  tracked as a follow-up (see open question #1 in the design doc); for now the
  banner plus the weekly log is the safety net.

## Troubleshooting

| Symptom | Where to look |
|---|---|
| Task `LastTaskResult` non-zero | newest `logs\validation-*.log` — the wrapper logs the failing step |
| Push rejected / auth fails | `ssh -i ...\tinysocs_deploy -T git@github.com`; confirm the deploy key has **write** access |
| `git pull` not fast-forward | someone pushed to `results/` from elsewhere; reconcile manually, then re-run |
| Everything green but no commit | identical output to the existing week's file — nothing to commit, which is correct |
| Dashboard didn't update | check the **Deploy Landing Page** workflow run in GitHub Actions |

## Manual / ad-hoc run

To re-run validation any time (e.g. after shipping a rule):

```powershell
pwsh C:\tinysocs\scripts\run_weekly_validation.ps1
```

Or rebuild only the dashboard (no new validation) from the existing results via
the **Run workflow** button on the *Deploy Landing Page* action
(`workflow_dispatch`).
