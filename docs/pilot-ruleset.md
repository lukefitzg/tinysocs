# Pilot Ruleset — High-Fidelity Rules for First Pilots

**Status**: implemented (2026-07-04). The shortlist is now the shipped pilot base pack (`packs/base/2026.27/`).
**Author**: Luke FitzGerald + Claude session, 2026-07-04.
**Scope**: the 39 C# agent rules in `packaging/detection/rules.yml` (the only engine that fires alerts in production). The 50-rule Python catalogue is out of scope — it doesn't run.
**Companions**: `docs/icp.md` (who the pilot is for), `docs/design/rule-format-v2.md` (allowlists/tuning land there), `tests/atomic-tests.yaml` + `tests/atomic-results.json` (validation harness).

## Implementation status (2026-07-04)

This assessment was implemented. What shipped into `packaging/detection/rules.yml` and the `base/2026.27` pack:

- **20 rules enabled** (the high-fidelity pilot set): TS-001, TS-002, TS-010, TS-020, TS-061, TS-062, TS-070, TS-071, TS-080, TS-080-sys, TS-081, TS-082, TS-090, TS-110, TS-113, TS-114, TS-120, TS-130, TS-131, TS-132.
- **4 fidelity fixes** added a `field_match` so the rule matches its description instead of every event: **TS-071** (LogonType=10), **TS-070** (ServiceName = PSEXESVC/clones), **TS-090** (suspicious ImagePath), **TS-062** (ObjectName = ntds.dit / SAM/SYSTEM/SECURITY hive).
- **17 rules disabled** (`enabled: false`, retained for v2 redesign): TS-030, TS-040, TS-050, TS-060, TS-072, TS-083, TS-091, TS-092, TS-100, TS-101, TS-111, TS-112, TS-115, TS-133, TS-134, TS-135, TS-136. Each carries an inline reason.
- **Verified** by `tests/TinySocs.Agent.Tests/DetectionEngineTests.cs` (21 new xUnit tests, all green): the four filters fire on the malicious case and stay silent on the benign one, the enabled set is exactly the 20 above, and the Python-signed `base/2026.27` pack verifies + loads through the C# `PackLoader`.

**One decision changed from the original shortlist.** The draft proposed keeping the generic TS-072 and disabling TS-070/TS-090. The implementation does the opposite: TS-070 and TS-090 were given real filters (PsExec name; suspicious path) and kept, and the generic TS-072 (which matched *every* 7045) was disabled. This is strictly higher fidelity — the two malicious 7045 patterns are now named specifically, and routine software-install noise no longer alerts.

**Coverage trade to state plainly.** Disabling the noisy set removes any firing rule for six ATT&CK techniques in the pilot pack: **T1003.001** (LSASS via comsvcs — Sysmon Event 10 isn't logged), **T1547.001** (registry run key), **T1218.011** (rundll32 LOLBin), **T1055** (process injection), **T1027** (obfuscated command), **T1047** (WMI spawn). These are marked `pilot_status: deferred` in `tests/atomic-tests.yaml` and are v2 backlog (they need parent/command-line context or a tighter filter before they can fire without storming an SMB). This is a deliberate false-positive-vs-coverage trade for first pilots, not a regression.

**Still requires a Windows run.** The Atomic Red Team harness is PowerShell/Windows-only and could not run in this build environment. `docs/detection-efficacy.md` is marked superseded; a fresh `Test-AtomicDetection.ps1` run against 2026.27 is the release gate before any efficacy number is quoted.

---

## Who this list is for

Per `docs/icp.md`: a 20–150-person Windows/M365 shop with **zero security staff** — one IT generalist or an outsourced MSP — pushed into monitoring by an insurer, an audit, or a big customer's questionnaire. Every alert that fires in week one is read by a person who has never triaged a security alert. The bar is therefore:

1. **Low FP in a normal SMB estate** — standard business software, auto-updaters, maybe an RMM agent. No red team, no dev tooling assumptions.
2. **High signal when it fires** — the alert should be worth a phone call.
3. **Explainable in one sentence** to a non-technical person.

A first pilot that cries wolf on day one kills the "someone competent is watching" promise the subscription is built on. When in doubt, a rule stays off.

## Validation status: read this first

`tests/atomic-results.json` is dated **2026-03-01** and claims 100% efficacy — but it predates the June test-fidelity overhaul recorded in `tests/atomic-tests.yaml`. Several March "DETECTED" credits were earned by rule definitions that no longer exist:

- **TS-061** passed in March because it then matched *any* process creation. It has since been restricted to named dump tools (`field_match`) and the current definition has **not** been harness-validated.
- **TS-135** and **TS-136** never individually fired in March — their techniques were credited to old TS-061/TS-132 noise.
- **TS-020** — the March notes suspected a 4698 XML-parsing issue. The 2026.27 run **disproves this**: TS-020 fired cleanly on T1053.005. Resolved.
- **TS-002** was not individually exercised (the harness generated 18 failures against a threshold of 20).

**A fresh harness run against the current rule definitions is a precondition for quoting any efficacy number to a pilot prospect.** Per-rule status below reflects this honestly: "validated" means *fired in a harness run under a definition equivalent to today's*.

### 2026.27 harness run (2026-07-06) — see `docs/detection-efficacy.md`

That run happened (Win11 VM, agent build 2026-07-04). Outcomes that update the statuses below:

- **8 techniques detected by real attacks**: TS-001, TS-010, TS-020, TS-070, TS-080, TS-090, TS-130, TS-131.
- **TS-020 works** — the suspected 4698 XML-parsing bug does **not** exist (it fired cleanly). That open question is closed.
- **TS-070 and TS-090 (the two fidelity fixes) fired on real attacks** — the `field_match` filters are validated end-to-end.
- **TS-132 missed on a test-fidelity gap, not a rule fault**: its threshold-2-by-process-name needs the same downloader twice; the test ran each once. Test fixed (`tests/atomic-tests.yaml`), re-run pending.
- **Four enabled rules remain untested here** (env-limited): TS-082 (needs Defender RTP off), TS-081 (Tamper Protection off), TS-062 (a DC), TS-110 (FIM module active).
- Corrected pilot-scope efficacy: **8/9 executable enabled-rule techniques = 88.9%**, → 9/9 expected after the T1105 re-run. The raw harness headline of 57.1% counts the 6 deliberately-deferred (disabled) rules as misses and must not be quoted.

## Deployment prerequisites (fidelity depends on these)

| Prerequisite | State | Rules affected |
|---|---|---|
| 4688 process-creation auditing + command line | Enabled by `scripts/Deploy-AgentUpdate.ps1` (auditpol step) | TS-061, TS-130, TS-132 (all 4688 rules) |
| Sysmon | Bundled in installer, **optional checkbox** | TS-091/092/083/100/101/133, TS-060 |
| Sysmon ProcessAccess (Event 10) | **Disabled in shipped `sysmon-config.xml`** (empty include) | TS-060 receives zero events — dead rule as shipped |
| PowerShell ScriptBlockLogging policy | Not set by installer or deploy script | TS-030 mostly silent; TS-082 relies on Windows' automatic suspicious-block logging (which did capture the AMSI strings in the harness) |
| FIM module + curated watchlist | Ships with agent; harness env lacked the channel (SKIP) | TS-110–115 |

---

## The pilot shortlist (ranked)

14 rules. Ranking weighs FP risk first, signal value second, validation confidence third.

### 1. TS-080 — `event_log_cleared`
- **Plain English**: someone wiped the security log on one of your machines — the first thing an intruder does to cover their tracks.
- **Why low FP**: no business software clears the Security event log. Legitimate clears (a technician tidying up) are rare and worth a question anyway.
- **Tuning concern**: none. Threshold 1, 60-min cooldown.
- **Validation**: ✅ DETECTED (via the direct-alert fast-path in EventLogInput).

### 2. TS-080-sys — `event_log_cleared_system`
- **Plain English**: same as above, caught from a second vantage point (the System log, Event 104) that survives even if the Security log itself was the one wiped.
- **Why low FP**: as TS-080. Fires on clears of *any* log, but log-clearing of any kind is rare in an SMB.
- **Tuning concern**: will double-alert alongside TS-080 for a Security-log clear. Acceptable for a pilot; dedupe in v2.
- **Validation**: ⚠️ not individually credited in the March run (only TS-080 fired); mechanism is identical.

### 3. TS-010 — `local_account_created`
- **Plain English**: a new user account was created on one of your machines.
- **Why low FP**: in a 20–150-person company, account creation happens a few times a month and the IT contact either did it or wants to know who did. Even a "false" positive is a useful audit touchpoint, not noise.
- **Tuning concern**: onboarding days produce a small burst (60-min cooldown per account name contains it). MSP-managed estates where the MSP creates accounts remotely will fire it — again, arguably a feature.
- **Validation**: ✅ DETECTED.

### 4. TS-082 — `amsi_bypass`
- **Plain English**: a script on one of your machines tried to switch off Windows' built-in malware scanning for scripts.
- **Why low FP**: the matched strings (`AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer`) have essentially no legitimate reason to appear in script blocks in an SMB. This is attacker tradecraft, verbatim.
- **Tuning concern**: none material. Note it depends on 4104 events existing — Windows' automatic "suspicious" script-block logging catches these strings even without the ScriptBlockLogging policy (confirmed in harness).
- **Validation**: ✅ DETECTED (canonical AMSI-bypass one-liner, threshold 1).

### 5. TS-001 — `brute_force_logon`
- **Plain English**: someone tried 15 or more wrong passwords against the same account within five minutes.
- **Why low FP**: a human mistyping stops at 3–5. Fifteen failures in five minutes against one account is automation. The classic benign cause — a service or mapped drive with a stale saved password — retries slower than this in most cases, and when it does trip the rule, the fix (update the stale credential) is worth doing.
- **Tuning concern**: the stale-credential loop is the one plausible repeat offender; needs the v2 allowlist story eventually. Threshold 15/5 min is a sane pilot default.
- **Validation**: ✅ DETECTED (18 failures against one account).

### 6. TS-002 — `brute_force_logon_by_ip`
- **Plain English**: one computer or internet address made 20+ failed login attempts across your accounts in five minutes — password-spraying behaviour.
- **Why low FP**: same logic as TS-001, and grouping by source IP catches sprays that stay under the per-account threshold.
- **Tuning concern**: on machines exposing RDP/SMB to the internet, background scanner noise can fire this *legitimately and often* — which is signal about their exposure, but set expectations in the pilot kickoff. Local 4625s often carry `IpAddress: "-"`, which lumps into one group key.
- **Validation**: ⚠️ not individually exercised (harness ran 18 attempts vs threshold 20). Same mechanism as TS-001; close the gap in the next harness run.

### 7. TS-081 — `defender_tamper`
- **Plain English**: Windows Defender's real-time protection was turned off on one of your machines.
- **Why low FP**: fires once per event with a 60-min cooldown. The only common benign trigger is installing a third-party AV (which disables Defender) — a one-time, easily explained alert.
- **Tuning concern**: estates running non-Defender AV will have Defender already off, so the rule is silent there (no FP, but no coverage either — a scoping question for the pilot checklist).
- **Validation**: ⚠️ SKIP — Tamper Protection on the test VM blocks the simulation itself. The event source (Defender Operational 5001) is well-understood; still, label it unvalidated-by-harness.

### 8. TS-061 — `credential_dumping_tools`
- **Plain English**: a known password-stealing tool (Mimikatz and friends) was run on one of your machines.
- **Why low FP**: nobody in the ICP runs mimikatz, nanodump, or wce.exe legitimately. Two caveats: `procdump` is a legitimate sysadmin/dev tool (rare in this ICP, common in dev-heavy shops), and `sqldumper.exe` ships with SQL Server and runs on SQL crashes — an SMB with SQL Server Express could see it.
- **Tuning concern**: consider pulling `sqldumper.exe` from the match list for pilots with SQL Server. Match semantics are substring-on-process-name — verify case-insensitivity behaviour before relying on it.
- **Validation**: ⚠️ **stale** — the March pass was earned by the old unfiltered definition. The current `field_match` version has never been harness-validated against an actual named tool. Needs a mimikatz/procdump atomic before we quote it.

### 9. TS-132 — `ingress_tool_transfer`
- **Plain English**: a machine used a built-in Windows admin tool (certutil/bitsadmin) to download files from the internet — a common way malware pulls in its real payload.
- **Why low FP**: end users never run certutil or bitsadmin. Occasional legitimate certutil use (certificate maintenance) exists but is rare and low-volume; threshold 2 in 5 min filters one-offs.
- **Tuning concern**: fires on the *process*, not on evidence of an actual download URL (command-line matching would be tighter — v2 candidate).
- **Validation**: ✅ DETECTED.

### 10. TS-130 — `account_discovery`
- **Plain English**: someone ran a rapid burst of commands that list your user accounts and admin groups — what an intruder does to map out who's worth impersonating.
- **Why low FP**: threshold 5 matching binaries in 5 minutes by the same user. Normal users never do this; the customer's own IT person doing troubleshooting will occasionally trip it, which doubles as a live demo of the product working.
- **Tuning concern**: an MSP tech's scripted health-checks could fire it on every visit — needs the v2 allowlist for the MSP profile. Watch `netsh`-style overlap with TS-131.
- **Validation**: ⚠️ ERROR in March run (harness ran the fallback from a UNC path; test notes assess the rule itself as functional). Re-run needed.

### 11. TS-072 — `remote_service_install` *(carry one 7045 rule, not three — see below)*
- **Plain English**: a new background service was installed on one of your machines — legitimate software does this occasionally, attackers do it to dig in.
- **Why low FP (relative)**: service installs in an SMB happen with software installs/updates — a few per machine per month, not per day. The 60-min cooldown per service name caps repeats.
- **Tuning concern**: **TS-070, TS-072, and TS-090 all match every 7045 event** — none of them has the field filter their descriptions claim (PsExec name, non-standard path, suspicious path). One legitimate install currently produces **three differently-named alerts**. For the pilot: enable TS-072 only, disable TS-070/TS-090, and present it honestly as "new service installed" rather than "PsExec detected". Restore the three-way split with real `field_match` filters in v2.
- **Validation**: ✅ DETECTED (as were TS-070/090 — all three fire on the same event, which is the problem).

### 12. TS-113 — `fim_mass_modification`
- **Plain English**: more than 50 monitored files changed within one minute — the signature of ransomware encrypting your files.
- **Why low FP**: 50 files/minute inside the FIM watchlist (critical system files, Program Files) is not normal office behaviour. This is the alert the insurance-driven buyer is paying for.
- **Tuning concern**: FIM-specific — only as good as the watchlist. Big Windows feature updates or a restore job could plausibly cross 50/min; expect one explainable fire per estate per quarter, not per week. Verify the FIM module is actually enabled in the pilot install.
- **Validation**: ⚠️ SKIP — harness environment lacked the TinySocs-FIM channel. Needs a validated FIM environment before quoting.

### 13. TS-110 — `fim_critical_file_modified` *(enable alone — see concern)*
- **Plain English**: a critical system file — like the file that controls where your computer sends web traffic — was modified.
- **Why low FP**: hosts file, SAM, boot config change essentially never in normal operation.
- **Tuning concern**: **TS-110, TS-111, and TS-112 have byte-identical conditions** (FIM event 1002, grouped by FilePath) — every FIM modify event fires all three. Enable TS-110 only for the pilot; disable TS-111/112 until the FIM channel carries a discriminator. Note TS-111's own premise ("executable in Program Files modified") would FP on every auto-updater anyway.
- **Validation**: ⚠️ SKIP (no FIM channel in harness).

### 14. TS-114 — `fim_sensitive_file_deleted`
- **Plain English**: someone tried to delete the files where Windows stores its passwords.
- **Why low FP**: deletion attempts on SAM/SECURITY/SYSTEM hives have no benign cause.
- **Tuning concern**: FIM-specific, same watchlist dependency as above. Distinct event ID (1003), so it does not triple-fire with TS-110.
- **Validation**: ⚠️ SKIP (no FIM channel in harness).

---

## Not suitable for a first pilot

These stay off (or get fixed) before a pilot install. Grouped by failure mode.

### Will alarm on normal behaviour (day-one alert fatigue)

- **TS-092 `startup_folder_write`** — description says Startup folder; the condition counts **every Sysmon FileCreate event**. The shipped Sysmon config logs every .exe/.dll/.ps1/.bat write, all Downloads, all Outlook attachments. Threshold 1 per source image. This fires dozens of times on day one. Needs a `TargetFilename` filter before it can exist.
- **TS-091 `registry_run_key`** — same pattern: description says Run/RunOnce; the condition counts every Sysmon registry event, and the shipped config's include list has ~113 entries (services, Winlogon, IFEO, RDP settings…). Every installer and updater trips it. Atomic-validated, but validated ≠ quiet.
- **TS-134 `obfuscated_command`** — matches `-enc`, `Invoke-Expression`, `iex(` in any command line, threshold 1. Legitimate vendor installers, deployment scripts, and **especially RMM agents** (the tooling of the exact MSP channel in the ICP) use encoded PowerShell constantly. This is the single most dangerous rule for pilot credibility. Off until v2 allowlists.
- **TS-135 `lolbin_proxy_execution`** — 3× rundll32/regsvr32/mshta/wmic in 5 minutes. Windows itself spawns rundll32 routinely (printing, control panel, thumbnails); 3-in-5-min is normal desktop behaviour. Also not validated under its current definition. Needs parent/command-line context.
- **TS-136 `wmi_process_creation`** — threshold 1 on any process with a WMI parent. RMM, SCCM, and monitoring agents spawn via WMI all day. Not individually validated (March credit went to old TS-061/132/134).
- **TS-083 `timestomp_detected`** — Sysmon Event 2, and the config includes "backdated .exe anywhere"; browsers and installers legitimately set file creation times (Chrome updater is a famous FP). Low severity, low value, real noise.
- **TS-040 / TS-050 process-creation bursts** — volumetric "200 processes in 10 min" fires on builds, updates, and login storms. Low severity by design; not part of a pilot promise.

### Mislabeled — condition doesn't match the description (fix in v2, don't ship the story)

- **TS-071 `rdp_brute_force`** — description claims LogonType 10 filtering; **no such filter exists in the condition**. As implemented it is TS-002 with a lower threshold — the same attack produces two alerts with different names. Disable for pilot; add the LogonType `field_match` in v2 and it becomes a strong rule.
- **TS-070 `psexec_usage` / TS-090 `service_install_suspicious`** — no PsExec-name or path filter; both are duplicates of TS-072 (see shortlist #11).
- **TS-062 `ntds_dit_access`** — description says ntds.dit/SYSTEM hive; condition matches **any 4663 file-access audit event**, threshold 1 per machine. Mostly silent on workstations (few SACLs), potentially explosive on a server with file auditing configured. Also DC-oriented, and the ICP beachhead isn't DCs. Off until it gets an ObjectName filter.

### Dead or unverifiable as shipped

- **TS-060 `lsass_access`** — the shipped `sysmon-config.xml` has an **empty ProcessAccess include list: Sysmon Event 10 is never logged**, so this rule cannot fire at all. (If someone enables Event 10 logging, it swings to the opposite problem — AV and legitimate tools touch LSASS constantly.) The credential-dumping story is carried by TS-061 for now.
- **TS-020 `scheduled_task_created`** — the March "did not fire" was a harness artifact, not a rule fault: the 2026.27 run detected it cleanly (no 4698 parsing bug). It remains inherently mid-noise (Office/updater tasks create scheduled tasks), so it stays a watch-item for FP volume in a live pilot, but it is functional and enabled.
- **TS-030 `powershell_scriptblock_burst`** — needs the ScriptBlockLogging policy, which nothing in the install/deploy path enables; without it the rule is near-silent. Harmless to leave enabled, but not part of the pilot promise.
- **TS-100 / TS-101 (DNS volume / outbound volume)** — Sysmon-dependent volumetrics whose behaviour is entirely a function of the config's include/exclude lists; unvalidated in this shape. Not for the first pilot.
- **TS-111 / TS-112 / TS-115 (FIM)** — TS-111/112 are condition-duplicates of TS-110 (triple-fire); TS-115 (ACL changes) fires on updates. Keep TS-110/113/114 as the FIM pilot set.
- **TS-120 `agent_version_drift`** — operational hygiene, not a threat detection. Fine to leave on; don't count it in "detections" messaging.
- **TS-001-lab / TS-030-lab** — already `enabled: false`; per rule-format-v2 they belong in a `demo` pack and must never ship to a customer.

---

## Summary for the pilot conversation

Honest numbers for outreach and the pilot guide:

- **14 rules** form the pilot promise (11 event-log rules + 3 FIM rules).
- Of those, **6 are harness-validated under their current definitions** (TS-080, TS-010, TS-082, TS-001, TS-132, TS-072); the rest need one focused harness run to close the gap — that run is cheap and should happen before the first install.
- **~10 rules should be disabled or consolidated** for pilot installs (the three-way 7045 duplicate, the FIM triple-fire, and the day-one-noise set above).
- The March "100% efficacy" figure must not be quoted — it predates the current rule definitions.

This maps directly onto the strategic sequence: the pilot ruleset *is* the initial content of the signed feed, and every "fix in v2" note above (LogonType filter, TargetFilename filters, ObjectName filter, allowlists) is week-one content-cadence material.

---

## Open questions

- **Re-validation run**: when does the harness get re-run against current definitions? It gates TS-061, TS-002, TS-130, TS-135, TS-136 and the efficacy number. Highest-leverage single task on this list.
- ~~**TS-020 parsing bug**: is the 4698 TaskContent XML issue real?~~ **Resolved 2026-07-06** — TS-020 fired in the 2026.27 run; no parsing bug.
- **TS-132 threshold**: is threshold-2-by-same-binary right for `ingress_tool_transfer`? A single `certutil` download is almost never legitimate. Lower to 1, or keep 2 for FP safety? (v2 tuning decision; test fidelity fixed regardless.)
- **Sysmon in pilots**: do we recommend pilots tick the Sysmon checkbox at all, given the shortlist barely depends on it (only via FIM-independent extras)? A Sysmon-less pilot has a smaller noise surface and fewer prerequisites.
- **Disable mechanism**: pilot installs need TS-070/090/111/112 (and the noise set) off. Is that a pilot-specific `rules.yml`, or does the v2 pack format's tiering handle "pilot pack" as the first pack? (Leaning: this shortlist becomes the `base` pack content.)
- **TS-002 on internet-exposed RDP**: alert-on-scan is signal to us but may read as noise to the customer. Kickoff-call framing, threshold bump, or a "your RDP is exposed" one-time finding instead?
- **FIM watchlist audit**: TS-110/113/114 fidelity claims assume the default watchlist is tight. Nobody has reviewed `FimConfig.cs` defaults against a real estate yet.
