---
name: tinysocs-failure-archaeology
description: Chronicle of every major TinySocs investigation, dead end, revert, and recurring bug class across the repo's 366-commit history (Oct 2025 - Jul 2026) — with SHAs, root causes, and status. Load this when you need historical context before touching something ("has this broken before?", "why does this code look weird?", "is this a known trap?"), when writing a postmortem or commit message that references prior work, when deciding whether a bug is novel or a recurrence (em-dash/PS5.1, doubled directories, stale MIT claims, CI silently red), or when asked about the project's timeline, pivot history, or how a specific subsystem (dashboard, licence/signing, FIM, CI) got to its current state. Not for diagnosing a live symptom right now — that's tinysocs-debugging-playbook.
---

# TinySocs failure archaeology

The chronicle. Every entry is SYMPTOM -> ROOT CAUSE -> EVIDENCE -> STATUS, so a
future session can tell "known recurrence" from "genuinely new bug" in one
lookup. All SHAs below were re-verified directly against the repo on
2026-07-11 (`git show`, `git log`), not just read from a prior digest.

## When NOT to use this skill

- Diagnosing a symptom happening **right now** (silent detection engine, shipper
  failing, HMAC mismatch, dashboard auth broken, OpenSearch down) -> use
  `tinysocs-debugging-playbook`. This skill is "has this happened before,"
  not "what do I check next."
- Deciding whether a proposed change is even in scope for the pivot -> use
  `tinysocs-change-control`.
- Load-bearing design decisions (why the dual engine is split the way it is,
  why signed packs are dormant) -> use `tinysocs-architecture-contract`. This
  skill tells you the *history* of how we got there; that skill tells you the
  *current contract*.
- Rebuilding the toolchain from scratch -> `tinysocs-build-and-env`.

## Project timeline (commit-volume evidence: `git log --format='%ad' --date=format:'%Y-%m' | sort | uniq -c`)

| Month | Commits | Era |
|---|---|---|
| 2025-10 | 37 | Bootstrap — file uploads, no real product code yet |
| 2025-11 | 25 | Early build-out |
| 2025-12 | 10 | C# agent skeleton born (`3015f99`, `79393ea`, `fe1b330`); Winlogbeat->native-agent migration starts (`6dcd645`) |
| 2026-01 | 1 | **Near-total stall** — only `db529f0` "OpenSearch successfully stood up from install" |
| 2026-02 | 131 | **Build burst 1** — Phases 10-15: detection engine, dashboard, FIM, MITRE, threat intel |
| 2026-03 | 125 | **Build burst 2** — Phases 16-21: federation, hardening, TLS, retention, Apache->BSL licence swap |
| 2026-04 | 0 | **Total gap — zero commits** |
| 2026-05 | 2 | Pivot restart: `9bea321` (README licence fix, 05-26), `c76edb2` (CLAUDE.md + v2 design doc, 05-27) |
| 2026-06 | 29 | Pivot execution: continuous validation pipeline, v2 pack signing, licence gate, feed server, TinyDocs — most of it lands 2026-06-06 in a single day |
| 2026-07 | 4 direct + PR merges (through HEAD `37005ad`, 07-11) | Pilot base pack ship, Deploy-AgentUpdate fixes, FIM self-watch fix, CI fix |

Total: 366 commits (`git log --oneline --all`), single author (Luke
FitzGerald) throughout. The **April 2026 zero-commit gap** and the
**1-commit January** are the two biggest silences — consistent with a solo,
part-time, day-job-constrained founder, not a documented deliberate pause.
Work resumes abruptly 2026-05-26 with a licence-claim correction, and the very
next day the v2 pivot design doc lands — reads like "came back from a gap,
immediately started the strategic pivot" that CLAUDE.md now documents.

Only one non-main branch exists: `fix/ci-green` (current, 2 commits ahead of
`main`: `279e4d6`, `37005ad`; 0 behind). PR-based merges are new and rare —
PR #6 (`e820e7a`), #7 (`bbb206e`), #8 (`4a62cb7`), #9 (`347c98e`, sat ~6 days
unmerged) — everything before that (~350+ commits, Oct 2025-Jun 2026) was
direct-to-main. The shift to PRs coincides with the pivot restart, plausibly
because money-adjacent code (signing, licensing) raised the stakes, though
that's inference, not a stated rationale anywhere found.

---

## Episode 1: The dashboard two-script revert

**SYMPTOM**: Dashboard widgets stuck on "Loading..." after login, intermittently,
unreproducible in a way that could be root-caused remotely.

**ROOT CAUSE**: `src/tinysocs/api/dashboard.py` had been split into two
`<script>` blocks (a self-contained login script + a main dashboard script).
The two-script coordination had a race/ordering bug. Actual underlying trigger
was a hostname-vs-`localhost` URL mismatch, fixed separately in `61b516c`.

**EVIDENCE** (chain, verified via `git log --format='%h %ad %s' --date=iso-strict` and
parent links — chronological/causal order, all 2026-02-24):
1. `61b516c` (12:14:50 UTC) "Fix dashboard URL, unresponsive login, and Sysmon ARM64
   service detection" — the underlying hostname-vs-`localhost` URL mismatch fix,
   landed *first*, before the revert even happened.
2. `2d52c66` (14:43:14 UTC) "Fix dashboard widgets stuck on Loading after login"
   (forward-fix attempt against the two-script architecture, insufficient)
3. `f3cc418` (15:53:43 UTC) "Add failsafe timer and try/catch guards for dashboard
   widget loading" (further forward-fix hardening, also insufficient)
4. **`dd95fbd`** (20:34:41 UTC) **"Revert to single-script dashboard architecture"** —
   collapsed back to one `<script>` block, 38 insertions / 105 deletions (net code
   *removed* to fix it). Kept: per-widget try/catch in `unlockDashboard()`, a
   `_dashboardUnlocked` double-unlock guard, inline `doLogin()` handlers.
5. `06be5a2` (20:43:17 UTC) "Add standalone dashboard test server for quick
   iteration" — separate follow-on iteration tooling, built *after* the revert,
   not a failed pre-revert attempt.
6. `717274f` (21:06:04 UTC) "Fix JS syntax error in MITRE heatmap onclick handler"
7. `fb06745` (21:22:05 UTC) "Change test server to port 9999 to avoid HSTS conflict"

(Note: an earlier pass of this document had this chain backwards — listing the
test-server commits first and the URL fix last — and mistyped `f3cc418` as
`f3c4c18`, a SHA that doesn't resolve. Corrected 2026-07-11.)

**STATUS**: fixed, by architectural rollback rather than forward-fix. This is
the **only genuine `git revert`-class rollback in the repo's 366 commits**
(`git log -i --grep=revert --all` returns exactly one true hit — the other
match, `94f34e6` "Phase 20: dashboard polish," is a false positive from the
word "fixes").

**Lesson for future sessions**: if you're about to split dashboard.py's
inline `<script>` block into multiple script tags again for "clean
iteration," know that this was already tried and reverted once. If you have
a good reason to retry, add a hard integration test for widget-load ordering
first — none existed the first time.

---

## Episode 2: Recurring bug class — non-ASCII characters breaking PowerShell 5.1

**SYMPTOM (recurring, at least 6 separate commits over 5 months)**: PS1
scripts throw cascading parse errors, or silently swallow statements, when
they contain an em-dash (`—`, U+2014) or other non-ASCII character.

**ROOT CAUSE**: PowerShell 5.1 (the version shipped on Windows Server/desktop,
*not* PS7+) reads `.ps1` files without a UTF-8 BOM using the system default
codepage (Windows-1252 on English Windows). U+2014 em-dash's UTF-8 byte 0x94
maps to a right-double-quote character under CP1252, which PowerShell treats
as a string delimiter — corrupting everything after it on the line.

**EVIDENCE** (all verified via `git show`):
| Commit | Date | File | Note |
|---|---|---|---|
| `d777cb9` | 2026-02-21 | `Full-Rebuild.ps1` | "replace em dashes with ASCII hyphens to avoid PS encoding errors" |
| `d4d0b84` | 2026-02-25 | `tests/Test-AtomicDetection.ps1` | Commit body gives the CP1252/0x94 mechanism explicitly |
| `62b61b7` | 2026-02-25 | `tests/Test-AtomicDetection.ps1` | Related but distinct: here-string closing delimiter must be at column 0 — not an encoding bug, a PS1 syntax gotcha in the same file, same day |
| `5746899` | 2026-03-19 | `Full-Rebuild.ps1` | Em-dash recurs in the *same file* already fixed once in `d777cb9` |
| `e8a7e3c` | 2026-03-22 | OpenSearch watermark YAML comment | Different blast radius: em-dash in a PS-generated `opensearch.yml` comment made `opensearch-keystore.bat`'s YAML parser reject it as "unacceptable code point," **crashing OpenSearch on restart** — not just a script parse error, a production outage class |
| `94dae2b` | 2026-07-10 | `Demo-Ransomware.ps1` | Most recent occurrence, 4 months after the pattern was first named |

**STATUS**: **still recurring**. Five em-dash fixes across four distinct files
(`Full-Rebuild.ps1` x2, `Test-AtomicDetection.ps1` x1 em-dash fix, plus
`Quickstart.iss` and `Demo-Ransomware.ps1`) — `git show --stat` on each of
`d777cb9`/`d4d0b84`/`5746899`/`e8a7e3c`/`94dae2b` confirms 4 files, not 5 — and
one related-but-distinct here-string-delimiter bug (`62b61b7`, same file as
`d4d0b84`, same day, *not* an em-dash/encoding instance — it doesn't match the
skill's own re-verification grep, see Provenance) sitting alongside them in
the table above. Six commits total across the episode, spanning 2026-02-21 to
2026-07-10 — the em-dash pattern itself was still live at the second-to-last
commit in the repo as of this writing.

**Lesson for future sessions**: never type an em-dash, en-dash, curly quote,
or any non-ASCII punctuation into a `.ps1` file — use `--` or `-` instead,
always. This is worth a pre-commit grep (`grep -P '[^\x00-\x7F]' **/*.ps1`)
or CI check; none exists yet as of 2026-07-11 (verify with
`ls .github/workflows/` and check for a PS1-lint step before assuming one
was added later).

---

## Episode 3: MIT -> BSL licence whack-a-mole

**SYMPTOM**: The licence changed from Apache-2.0 to BSL-1.1 in `7860f41`
(2026-03-07), but stale "MIT" claims kept surfacing in other files for
months afterward.

**ROOT CAUSE**: No single source of truth / no grep-on-commit check tying
licence mentions to the actual `LICENSE` file. Each fix caught one surface,
missed others.

**EVIDENCE**:
| Commit | Date | Lag from LICENSE change | File |
|---|---|---|---|
| `7860f41` | 2026-03-07 | — (origin) | `LICENSE` (297 del / 97 ins, full text swap) + `pyproject.toml` version bump |
| `9bea321` | 2026-05-26 | +11 weeks | `README.md` footer — commit body explicitly frames this as a credibility risk ("customers, co-founders, journalists read the README before the LICENSE file") |
| `e820e7a` (PR #6) | 2026-06-10 | +3 months | `docs/competitive-positioning.md` — **four** more stale MIT mentions (pricing matrix, open-source row, differentiator bullet, MSSP section); commit notes some were "factually inverted, not just mislabelled" (e.g. "no commercial restrictions" is flatly wrong under BSL) |

**Re-verified 2026-07-11**: `grep -n -i "license\b" pyproject.toml` shows
`license = { text = "BSL-1.1" }` (pyproject.toml:12) — correct. A broad
`grep -ril "MIT"` across `*.md`/`*.toml`/`*.json` today returns many files,
but every hit inspected is a substring false positive (words like "submit,"
"commit," "limit," "admit") — **no live stale-MIT claim found as of
2026-07-11**. `README.md` and `CHANGELOG.md` both come back clean on direct
inspection. This matches CLAUDE.md's own note ("If you see another stale
'MIT' claim surface anywhere... fix it on sight") — the standing instruction
is a scar from this exact pattern, and as of this pass the scar hasn't
reopened.

**Could not verify**: a claim that a stray pip package-metadata artifact
(egg-info/dist-info for `tinysocs` itself, at version 0.7.0, claiming MIT,
left over from a deleted worktree) exists or ever existed. Searched
`find . -iname "*tinysocs*dist-info" -o -iname "*tinysocs*egg-info"` (repo
root, current worktree) — no hits. `pyproject.toml`'s version history does
show a real `0.7.0 -> 0.9.0` bump (`git log -p --follow -- pyproject.toml`),
so a stray 0.7.0-tagged build artifact is plausible in principle, but nothing
on disk today substantiates it and no commit fixing such an artifact was
found via `git log -i --grep`. Treat as unconfirmed — if you find one, it's
the fourth instance of this pattern and should be fixed on sight per CLAUDE.md.

**STATUS**: fixed (3 confirmed instances), pattern dormant but the standing
"fix on sight" rule in CLAUDE.md remains binding — this class of bug has
recurred 3 times already, don't assume a 4th surface doesn't exist just
because this pass didn't find one.

---

## Episode 4: Pilot ruleset cut (`ac9ef81` / merged as `347c98e`)

**Not a bug fix — the repo's best worked example of evidence-driven
de-scoping.** Included here because it's the origin of the current 19-rule
enabled count and the TS-113/TS-120 fixes CLAUDE.md references.

**WHAT HAPPENED**: `ac9ef81` (author date 2026-07-04 22:28 UTC, direct commit
on a feature branch) "Ship pilot base pack 2026.27: 20 high-fidelity rules" —
landed via PR #9 as `347c98e` (2026-07-10 23:54 UTC, squashed/re-authored 6
days later; the PR sat unmerged that whole time — first evidence in git
history of a PR sitting rather than merging same-day).

**Content** (14 files, 2066 insertions / 37 deletions):
- Fixed 4 mislabeled rules by adding real `field_match` filters: TS-071 (RDP
  LogonType 10), TS-070 (ServiceName PSEXESVC/clones), TS-090 (suspicious
  service ImagePath), TS-062 (ntds.dit + SAM/SYSTEM/SECURITY hives).
- Disabled 17 noisy/dead/duplicate rules with inline reasons: TS-030, 040,
  050, 060, 072, 083, 091, 092, 100, 101, 111, 112, 115, 133, 134, 135, 136.
- Added `tests/TinySocs.Agent.Tests/DetectionEngineTests.cs` — asserts each
  new filter fires on the malicious case and stays silent on the benign one,
  and asserts the enabled set equals the pilot set exactly (32 `[Fact]`/
  `[Theory]` methods as of 2026-07-11, `grep -c '\[Fact\]\|\[Theory\]'`).
- Created `docs/pilot-ruleset.md` (canonical source for the rule-count
  honesty language now baked into CLAUDE.md).
- Marked `docs/detection-efficacy.md` **SUPERSEDED** pending a fresh Atomic
  run against 2026.27.

**Discrepancy worth knowing**: the commit ships **20 enabled**, not 19.
`docs/pilot-ruleset.md:21-22` shows the TS-113 fix and TS-120 deferral (which
drop the count 20->19) are inside this **same** commit, not a separate later
one. CLAUDE.md's prose ("A 2026-07-08 validation pass then found two more
dead rules...") implies a discrete commit on 2026-07-08 that does not exist —
`git log -S'TS-113' --all` shows no commit between `ac9ef81`/`347c98e` and
current HEAD touching TS-113. Most likely explanation: 07-08 is when the
*analysis* happened (a VM validation run), folded into the same PR before it
merged on 07-10. Not a contradiction of substance — TS-113 and TS-120 content
is real and correctly described — but don't go looking for a standalone
2026-07-08 commit; it isn't there.

- **TS-113** (ransomware mass-modification canary) was dead: it grouped by
  `winlog.computer_name`, a field FIM events never carried, so the engine
  could never form a group key. Fixed in `FileIntegrityInput` to emit host
  identity under that field.
- **TS-120** (agent version drift) had no event source at all — nothing feeds
  an `event_id:0 / channel:heartbeat` event into the detection engine.
  Deferred (`enabled: false`) pending a v2 version-drift emitter.

**STATUS**: fixed/shipped. Current enabled count re-verified 2026-07-11:
`grep -c "enabled: true" packaging/detection/rules.yml` = 19.

**Lesson for future sessions**: this is the template for future rule cuts —
disable with an inline reason, don't delete; back every re-enable or new
`field_match` with a firing + silent xUnit pair; update the count-honesty doc
in the same commit as the count change, not later.

---

## Episode 5: v2 signed feed / licence gate / Stripe — landed in one day, CLAUDE.md never caught up

**Not a failure in the code — a documentation-drift failure**, but the
highest-value one in the repo: CLAUDE.md's line "No rule signing, no rule
feed, no licence checking, no Stripe integration. All greenfield." is
factually false as of any commit after 2026-06-06 and remains uncorrected in
the checked-in CLAUDE.md as of HEAD (2026-07-11).

**EVIDENCE** (all 2026-06-06, verified via `git show --stat`):
- `f7402bf` "Add v2 pack signing, licence gate, and TinyDocs scaffolding" —
  `scripts/pack_sign.py`, `scripts/licence.py`, `docs/design/signed-feed.md`.
- `dc1450e` "Wire C# agent to verify + load signed v2 packs" —
  `src/TinySocs.Agent/Detection/PackLoader.cs`,
  `src/TinySocs.Agent/Detection/Ed25519Verifier.cs`,
  `src/TinySocs.Agent/Detection/LicenceReader.cs`, wired into
  `OpenSearchBulkShipper.cs`.
- `02d1edf` "Publish top-20 TinyDocs and add Stripe price->tier resolver."
- `765ca80` "Add content-feed server: entitlement gate + Stripe licence
  issuance."
- `af67b09` "Bump to 0.10.0: signed feed, agent trust path, licence gate,
  billing" — the version-bump commit subject literally names all four
  capabilities CLAUDE.md says don't exist.

**STATUS**: implemented and wired, per `docs/design/rule-format-v2.md`'s own
status header ("Status: Approved, schema locked, implemented"). **But
dormant in production**: `ContentPackConfig.Enabled` defaults `false`
(`src/TinySocs.Agent/Configuration/AgentConfig.cs`), no shipping config
template turns it on, and the Inno Setup installer ships only legacy
`rules.yml` with no public key. Production installs run unsigned rules via
`RuleLoader` today. For the full current-state contract of what's dormant
vs. live, see `tinysocs-architecture-contract` — this entry is only the
"how did the doc drift happen" history.

**Lesson for future sessions**: CLAUDE.md's most recent substantive edit
touching this area is the pilot-cut commit (07-04/07-10), which only updated
the rule-count language — the "all greenfield" line has been silently stale
for over a month at any given point. When you touch anything CLAUDE.md
describes, check the file/line against current source before trusting the
prose; gate any correction to CLAUDE.md itself through
`tinysocs-change-control`.

---

## Episode 6: CI silently red for ~1 month

**SYMPTOM**: None visible day-to-day — CI kept reporting failures, but three
independent breaks stacked so nobody could see past the first one to notice
the pattern.

**ROOT CAUSE** (three unrelated breaks, all fixed in one commit):
1. **Ruff**: 868 pre-existing lint violations, mostly pyupgrade
   (`typing.List/Dict/Optional` -> `list/dict/X|None`) plus import sorting.
2. **Mypy**: the `mypy tinysocs` invocation had never once worked — bare
   positional arg is treated as a file path, and no `tinysocs/` directory
   exists at repo root (package lives at `src/tinysocs`). It had been
   silently no-op-passing (or failing for the wrong reason) since inception.
3. **Missing dependency**: `cryptography` (imported by `scripts/pack_sign.py`
   -> `scripts/licence.py` -> `tests/test_feed_server.py`) was listed only in
   `requirements.txt`, never in `pyproject.toml`'s dependencies, so
   `pip install -e ".[dev]"` (what CI actually runs) never installed it —
   Windows test job failed on collection before a single test ran.

**EVIDENCE**: `37005ad` (2026-07-11 00:35, current HEAD) "Fix CI: make Ruff
and mypy actually pass, add missing cryptography dep." Commit body states
outright: "CI has been red since at least June 10 across every run on main
and this branch." Fixing mypy properly (`mypy -p tinysocs` + `mypy_path =
"src"`) surfaced 121 real, never-before-seen type errors, several of which
were genuine latent bugs, not just annotation gaps:
- `node.py`: `hmac.new()` called with **no `import hmac`** in the hub
  registration loop — would `NameError` on every federation registration,
  never previously exercised by CI or (apparently) in practice.
- `enrich.py`/`threat_intel.py`: `asyncio.gather(return_exceptions=True)`
  results checked via `isinstance(x, Exception)`, missing `BaseException`
  subtypes like `CancelledError`.
- `master.py`: `merge_evidence()` claimed return type `list[DetectionEvidence]`
  but always returned `list[dict]` — callers were already duck-typing around
  it; annotation corrected to match reality rather than the code changed.
- `evidence.py`: `EvidenceExemplar` used `Field(None, ...)` instead of
  `Field(default=None, ...)` — the positional form isn't recognized as
  providing a default under pydantic's dataclass-transform typing.

**STATUS**: fixed at `37005ad`. Verified clean per commit message: `ruff
check .`, `mypy -p tinysocs`, `pytest` (439 passed, 20 skipped, 0 failed),
`dotnet build + test` (70/70 C# tests green) — but that last figure is a
**locally-run claim only, not CI-enforced**: `.github/workflows/ci.yml`'s only
`dotnet` step is `dotnet publish` (build-only, line 76); there is no `dotnet
test` step in `ci.yml` or `build-installer.yml` (`grep -n
'dotnet\|xunit\|pytest' .github/workflows/*.yml` shows publish/setup-dotnet
for C# and ruff/mypy/pytest for Python, nothing that invokes xUnit). That
means `DetectionEngineTests.cs` — the sole proof that the 19 enabled pilot
rules actually fire (Episode 4) — has zero CI coverage today. A future PR
could silently break rule-firing behavior with CI staying green throughout.

**Lesson for future sessions**: since this commit was still uncommitted at
the time of the fix (working-tree diff on `tests/test_feed_server.py`, an
autouse `_ensure_test_signing_key()` fixture that bootstraps a throwaway
ed25519 dev keypair when `keys/` doesn't exist in a clean checkout), a full
month of signed-feed/licence-gate work (Episode 5) landed and iterated with
**no real CI signal**. Any time you're told "CI is green," re-verify with
`git log -1 --format=%s` on the CI-workflow-relevant files rather than
trusting the badge — this project has already had a month-long false green
(more precisely, false red masking real changes, but the effect — nobody
looking — was the same).

---

## Episode 7: Deploy-AgentUpdate.ps1 double-fix evening

**SYMPTOM 1**: `Deploy-AgentUpdate.ps1` crashed immediately when invoked with
a relative `-SourceDir` (e.g. `.`).

**ROOT CAUSE 1**: `Split-Path '.' -Parent` returns an empty string; that
empty string broke `Join-Path` on an unused `$testsDir` line, aborting the
script before any real work happened.

**FIX 1**: `2125f87` (2026-07-05 21:24 UTC) "Fix Deploy-AgentUpdate.ps1 crash
on relative -SourceDir" — resolve `SourceDir` to an absolute path up front,
drop the dead line. 4-line diff.

**SYMPTOM 2** (found immediately after fixing symptom 1): binary swap during
deploy still failed / got re-locked.

**ROOT CAUSE 2**: the agent runs as an NSSM-wrapped Windows service
(`TinySocsAgent`) that auto-respawns `TinySocs.Agent.exe` on process exit.
NSSM = "Non-Sucking Service Manager," a lightweight Windows service wrapper
used to run the agent as a managed service. The script's prior approach
(`taskkill` the process, then swap the binary) raced NSSM's respawn — NSSM
would relaunch and re-lock the file before the file copy completed.

**FIX 2**: `70cf7f8` (2026-07-05 21:51 UTC, same evening) "Make
Deploy-AgentUpdate.ps1 NSSM-service aware" — stop/start the NSSM service
around the binary swap, restore the watchdog afterward, read NSSM's
`TinySocsAgent.out.log` to verify the rule count post-deploy. 98-line diff
(67 ins / 31 del). Commit notes it was verified on the Win11 VM: reloaded to
exactly 20 rules (this predates the pilot cut's 20->19 drop — `347c98e`
landed 5 days later), 9/9 audit subcategories set, no errors.

**STATUS**: both fixed, same evening, 27 minutes apart.

**Lesson for future sessions**: any script that stops/kills/replaces the
agent binary must account for NSSM's respawn behavior — a plain
`taskkill`-and-replace approach will race the service manager. Check
`tinysocs-run-and-operate` for the current NSSM service topology before
writing another deploy/update script.

---

## Episode 8: FIM monitoring its own queue and OpenSearch data

**SYMPTOM**: found via end-to-end demo (not a test, not a report — someone
watched the demo run). FIM (File Integrity Monitoring — the subsystem that
watches specific files for unauthorized changes and emits synthetic events
into the detection engine) emitted 1158 self-generated events and
false-fired TS-110/TS-114 on OpenSearch's own internal files, while the
canary rule the demo was meant to showcase (TS-113, ransomware
mass-modification, just fixed in Episode 4) was drowned out / delayed and
never fired at all.

**ROOT CAUSE** (two compounding bugs):
1. `FileSystemWatcher` (the .NET real-time file-change API) filters by
   **directory only**. The configured glob's filename filter (`*.yml`) was
   applied by FIM's periodic full-tree scan but **not** by the real-time
   watcher — so a configured watch path of
   `C:\ProgramData\TinySocs\**\*.yml` actually monitored *every file* under
   that entire tree in real time, including the agent's own event queue
   (`.jsonl` files), the FIM baseline file itself (`.json` — creating a
   save -> detect-change -> save feedback loop), and bundled OpenSearch's
   own data/log files.
2. The `C:\ProgramData\TinySocs\**\*.yml`/`.yaml` watch paths shouldn't have
   existed at all — that tree is the agent's own operational state, never
   customer data worth integrity-monitoring.

**FIX**: `279e4d6` (2026-07-11 00:13 UTC) "Fix FIM monitoring its own queue +
OpenSearch data (real-time watcher ignored glob filter)" — added
`MatchesWatchedPattern()`, applied uniformly across all four watcher event
handlers so real-time and periodic-scan agree; dropped the ProgramData YAML
watch paths entirely; FIM now watches critical OS files (hosts, SAM/SYSTEM/
SECURITY, GroupPolicy) plus the ransomware canary path only. Regression test
added; commit message states "70 tests green."

**STATUS**: fixed, immediately preceding the CI fix (Episode 6) at the tip of
the branch.

**Lesson for future sessions**: if you add or change a `FileSystemWatcher`-based
subsystem, remember its real-time event handlers do not automatically respect
a configured filename glob — you must apply the pattern match yourself in
every handler, not just in the periodic-scan code path. This is a specific,
non-obvious .NET API gotcha, not a general FIM design flaw — see
`tinysocs-architecture-contract` for FIM's synthetic-event design as a whole.

---

## Episode 9: Doubled-directory bug pattern (recurs across two subsystems)

**SYMPTOM**: package/directory restructuring left a self-nested directory
(`X/X/...`) that had to be found and pruned later.

**EVIDENCE**:
- `src/tinysocs/agent/agent/...` — an entire dead-end all-Python agent
  implementation (predates the current C# agent), deleted with the doubled
  path still in place: `src/tinysocs/node.py`,
  `src/tinysocs/agent/agent/detections/rules.yaml`,
  `src/tinysocs/agent/agent/detections/__init__.py`, plus adapters and
  pycache — all removed (`git log --diff-filter=D --all --summary`).
- `f21672a` "src layout: remove stray src/tinysocs/orchestrator/orchestrator
  and empty queue-rot" — same class of mistake in the orchestrator/federation
  subsystem, unrelated to the agent restructure.

**STATUS**: both cleaned up; the Python-agent dead end is fully gone (current
C# agent at `src/TinySocs.Agent/` is the only running agent — see
`tinysocs-architecture-contract` for why). No live doubled directory found in
current tree as of 2026-07-11 (`find src -type d -regex '.*/\([a-z_]+\)/\1$'`
returns nothing).

**Lesson for future sessions**: this is a "watch for it" pattern, not an
active bug — two independent restructures made the same mistake, so a third
is plausible if another subsystem gets a big reshuffle. Sanity-check new
`src/` layouts for self-nesting before committing.

---

## Episode 10: Detection efficacy campaign and the stale-March-figure landmine

**SYMPTOM / ARC**: a multi-month back-and-forth chasing detection efficacy
numbers, several of which are now explicitly superseded and must not be
quoted.

**EVIDENCE** (chronological):
- `13ddb86` (2026-02-26) "Improve detection efficacy from 12.5% to 82.4%
  (14/17 tests passing)" — added rules, fixed broken Atomic fallback
  commands, added harness skip conditions.
- `8d654bb` (2026-03-01) "Fix T1070.001 detection: direct-alert fast-path,
  100% efficacy (15/15)" — this is the source of the now-banned "100%"
  figure. Also added the `threshold<=1` window-bypass in `DetectionEngine`
  (fires immediately on single-occurrence events instead of waiting for
  window pruning — the closest literal "threshold bug fix" in the repo's
  history) and the `field_match` content-filter primitive later exploited in
  Episodes 4 and below.
- `cb85260` (2026-06-05) "Filter noisy detection rules and harden validation
  harness transport" — found TS-061/TS-130/TS-131 were missing the
  `field_match` their descriptions promised and were degrading to raw event
  counters (TS-061 fired critical on *every distinct process*). Also fixed
  "noise-blind attribution" in the harness — tests were validating whichever
  co-listed noisy rule fired, not the rule actually under test. **This
  specific attribution bug is flagged as still-open in `docs/roadmap.md`** —
  re-verify its current status before trusting any efficacy number derived
  from the harness; see `tinysocs-validation-and-qa` for the current
  definition of "harness-validated."
- `5eca80e` (2026-06-06) "Validate 2026-W23: 61.5% efficacy, faithful test
  fixes for next cycle" — first internally-consistent, reconciled number
  (8 DETECTED / 5 MISSED / 6 SKIPPED of 13 executed). Postmortem at
  `docs/validation/2026-W23.md`.
- Culminates in the pilot-ruleset cut (Episode 4), which disables
  persistently-noisy rules rather than continuing to chase thresholds rule by
  rule.

**STATUS**: the March "100%" figure (`8d654bb`) is **banned from all quoting**
— it predates the pilot-cut rule redefinitions and no longer describes the
current ruleset. It has been superseded by the 2026-07-08 validation run (see
`tinysocs-validation-and-qa` for current numbers and what's quotable). The
public validation dashboard and `results/latest.json` are separately known to
be stale (W23-dated) as of 2026-07-11 — that staleness is a live-data-freshness
problem, not a repeat of this historical episode; see
`tinysocs-validation-publication-campaign` for the fix plan.

**Lesson for future sessions**: every efficacy percentage in this repo's
history has been superseded by a later, more honest one. Never cite a number
without checking its date against the current ruleset — treat "efficacy: NN%"
as meaningless without a rule-set version and a run date attached.

---

## Episode 11: Pre-pivot planning-doc pruning

**WHAT HAPPENED**: on `2026-03-24`, `9ed2234` added a 511-line
`docs/phase-21-plan.md`, and the **same day** `93a31a8` removed it — commit
message: "plan is working document, not committed." Later, `2026-06-05`:
`ca3e54a` added a forward-looking `docs/roadmap.md`, and `a26939c` pruned the
last two leftover pre-pivot planning docs (`docs/phase-15-plan.md`, 794
lines; `docs/phase-18-plan.md`, 602 lines) as "superseded by
docs/roadmap.md, retained in git history and the founder's planning
archive."

**STATUS**: this is the direct origin of CLAUDE.md's standing rule "Don't
recreate `docs/phase-N-summary.md` style retrospectives unless asked" and the
"plan docs live outside git" convention referenced in
`tinysocs-change-control`.

**Lesson for future sessions**: if you're asked to write a phase-summary or
project-retrospective doc, don't commit it — this has been explicitly reverted
twice already (once same-day). Gate any exception through
`tinysocs-change-control`.

---

## Open items (not resolved by this pass — flag, don't assume)

- **`kirk.pfx`** — a leaked-credential-adjacent filename referenced only
  inside the *deleted* `docs/phase-21-plan.md` text (as a known Phase 21
  cleanup item). `git log --all --full-history --oneline -- '**/kirk.pfx'`
  returns **no results** — never committed under that path with that name,
  or removed via a history rewrite this pass didn't check for (no BFG/
  filter-repo evidence found, but reflog/orphaned-blob inspection wasn't
  done). If you're doing a secrets-focused audit, this is unfinished
  business, not a closed case.
- **Pip-metadata "MIT v0.7.0" ghost** — referenced as a supposed artifact of
  a deleted worktree; not found on disk (`find . -iname "*tinysocs*
  dist-info" -o -iname "*tinysocs*egg-info"` returns nothing) and no fixing
  commit located via `git log -i --grep`. `pyproject.toml` did bump
  `0.7.0 -> 0.9.0` at some point (confirmed via `git log -p --follow`), so
  the version number is real, but the MIT-license-ghost claim specifically
  is **unconfirmed** — see Episode 3.
- **PR #7** (`bbb206e`) — referenced in commit-subject PR-number sequence but
  its content wasn't individually inspected in this pass.
- **Deleted action-engine handlers** (`isolate_host.py`, `disable_user.py`,
  `block_ip.py` under `src/tinysocs/actions/handlers/`) — removed at some
  point; unclear whether superseded elsewhere or a scope cut. Not
  investigated.

---

## Provenance and maintenance

Authored: 2026-07-11, against branch `fix/ci-green`, HEAD `37005ad`.

Primary sources:
- `git log` / `git show` direct inspection (all SHAs in this document were
  re-verified against the live repo on 2026-07-11, not taken on trust from
  any prior digest).
- A prior-session discovery digest (a session-local scratch file — not
  re-derivable, ignore if absent) — used as a starting map, independently
  re-verified and corrected: it undercounted the em-dash/PS5.1 episode at 5
  commits where 6 exist, and mischaracterized `62b61b7` as an em-dash fix
  when it's actually an unrelated here-string-delimiter bug in the same file
  on the same day.
- `docs/pilot-ruleset.md`, `CLAUDE.md` (repo root), `CHANGELOG.md`.

Re-verification commands for the volatile facts in this document:
```bash
# Commit-volume timeline
git log --format='%ad' --date=format:'%Y-%m' | sort | uniq -c

# Total commit count
git log --oneline --all | wc -l

# Branch position
git status -sb | head -3
git rev-list --left-right --count main...fix/ci-green

# The one true revert
git log -i --grep=revert --all --oneline

# Episode 1 dashboard-revert chain order (topological, not narrative-assumed)
git log --format='%h %ad %s' --date=iso-strict 61b516c 2d52c66 f3cc418 dd95fbd 06be5a2 717274f fb06745

# CI dotnet-test coverage gap (re-check whether a test step has been added)
grep -n "dotnet\|xunit\|pytest" .github/workflows/*.yml

# Em-dash/PS5.1 recurrence count (re-check for a 7th instance)
git log --oneline --all -i --grep="em.dash\|em dash\|non-ASCII\|ASCII-only"

# Stale MIT claim re-check (inspect matches manually — most will be
# "commit"/"submit"/"limit" false positives)
grep -ril "MIT" --include="*.md" --include="*.toml" --include="*.json" . 2>/dev/null | grep -v .venv

# Pilot-cut enabled-rule count
grep -c "enabled: true" packaging/detection/rules.yml

# xUnit test count in the pilot-cut test file
grep -c '\[Fact\]\|\[Theory\]' tests/TinySocs.Agent.Tests/DetectionEngineTests.cs

# CI status / whether the fix commit is still the tip
git log -3 --oneline

# kirk.pfx open item
git log --all --full-history --oneline -- '**/kirk.pfx'
```
