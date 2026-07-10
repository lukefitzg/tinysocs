# Platform UX / Messaging Gaps vs ICP

> Status: audit complete (2026-07-06); all six MUST items implemented same day. SHOULD/COULD items remain open.
> Companion to: `docs/icp.md`, `docs/pilot-ruleset.md`, `docs/design/rule-format-v2.md`.
> Scope: UX and messaging audit only — what a non-technical SMB buyer (IT generalist or owner/MD, per `docs/icp.md` §2) experiences today. Not a code review.
>
> Evidence base: `src/tinysocs/api/dashboard.py` (the embedded web UI), `src/TinySocs.Agent/Detection/AlertWriter.cs` (webhook/email alert text), `src/tinysocs/agent/llm_*.py` (AI assistant), `src/tinysocs/reporting/` (compliance + daily summary), `docs/one-pager.md`, `docs/faq.md`, `docs/getting-started.md`.

## The yardstick

The ICP buyer has three questions: **"Are we being attacked? Are we compliant? Can I explain this to my boss?"** Every surface below is graded against those three questions, not against what a security analyst would want.

Priorities:

- **MUST** — fix before the first pilot install. A pilot that stumbles here fails in week 1.
- **SHOULD** — fix before the first paying customer. Pilot survives without it; a paying relationship doesn't.
- **COULD** — real, but defer. Doesn't block the pivot.

---

## Dimension assessments

### 1. First-run experience — FAIL the 60-second test

What a new user sees after login: the **Overview** tab with four widgets — Alert Summary (severity counts), Alert Timeline (bar chart), Fired Detections (list), Storage (disk usage). (`dashboard.py:6493–6543`)

- **No status headline.** Nothing answers "are we ok?" The user is handed counts — "3 critical, 8 high" — and must infer the answer themselves. The severity counts are the *input* to the question, not the answer.
- **No onboarding path.** First-run is a password-setup modal (`dashboard.py:6204`), then straight into the deep end. No "connect your first agent," no setup checklist, no "here's what you're looking at."
- **Empty states are dead ends.** Before data arrives, widgets show `Loading...` or blank (`dashboard.py:6101–6105`). A user whose agent isn't reporting sees the same thing as a user whose dashboard is still fetching. No "no agents reporting yet — here's how to install one."
- **Storage widget on the home screen.** Disk usage is an operator concern, not a buyer concern. It occupies one of four above-the-fold slots while "are we ok?" occupies zero.
- What's *good*: tab names (Overview / Detections / Compliance) are sane; severity colour badges scan well; demo mode (`--demo`) exists and is a genuine sales asset.

### 2. Alert clarity — written for an analyst who doesn't work here

Three surfaces, all analyst-voice:

- **Dashboard alert rows** show `brute_force_logon` (snake_case rule name), severity badge, host, count. Expanded: rule ID, description like *"Multiple failed logon attempts (4625) from the same user"* — Windows event IDs in the customer-facing string (`packaging/detection/rules.yml`, all 39 descriptions follow this pattern).
- **Slack/Teams webhook** (`AlertWriter.cs:280–282`): `🔴 *[TinySocs] [HIGH] brute_force_logon*` + the same description + `Events: 15 | Window: <timestamp>`. This lands in a channel the owner/MD may read. No "what this means," no "what to do first."
- **Email** subject defaults to `[TinySocs] Alert` (`RetryQueue.cs:223`).

Nothing anywhere says: *what happened in business terms, why it matters, what to do in the next 10 minutes, and how to tell if it's a false alarm.* The owner/MD reading a TinySocs alert cannot act on it or explain it upward — which is the exact purchase criterion.

Mitigations that already exist: the **"Ask AI" button** per widget and per detections card (`dashboard.py:6527`) can produce a plain-English explanation on demand — but it's pull, not push, requires an API key, and the user has to know to click it. The AI summarizer's output schema (`tldr` / `severity` / `next_steps` / `candidate_actions`, `llm_claude.py:374–388`) is *exactly* the right shape for this buyer — it's just not wired into the default alert experience.

Also missing: a real false-positive affordance. Status can be set to dismissed and a free-text `false-positive` tag exists (`dashboard.py:1594–1610`), but there is no one-click **"this is normal for us"** that suppresses recurrence. That button is also the prerequisite for the FP telemetry channel on the strategic roadmap.

### 3. Homepage "are we ok?" — the biggest single gap

- The dashboard has **no all-clear state at all**. Zero alerts renders as an empty list, not as reassurance. The product's most common state (quiet) — the state it will be in during 95% of a pilot — currently looks like *nothing is happening*, which is indistinguishable from *nothing is working*.
- Ironically the **daily summary email already solved this**: `daily_summary.py:281–285` renders "✅ All Quiet — No alerts in the last 24 hours across N monitored hosts." That's the right voice — an all-clear *qualified by coverage* (N hosts). It exists only in the optional email, not on the dashboard.
- Per `docs/icp.md` open questions: a false "all clear" is the trust-killing failure mode. The honest version is a status composed from checkable facts: no unresolved high/critical alerts in window + all agents heartbeating + detection pack current. If any leg fails, the status degrades ("monitoring degraded — 1 of 12 machines not reporting") rather than lying green. Ronan's AI-written narrative can layer on top later; the rule-based status must come first because it can't hallucinate.

### 4. Compliance reports — right bones, wrong labels, and a beachhead mismatch

- **Good:** genuinely one click to the tab, framework dropdown (NIST CSF 2.0 / HIPAA / PCI DSS v4.0), time window, HTML download (`dashboard.py:5530–5623`). Framework names are recognisable to the buyer.
- **Status vocabulary is internal jargon:** controls show `active` / `deployed` / `not_mapped` (`compliance_report.py:114–122`). The buyer needs "monitored and working" / "monitored, nothing detected yet (good)" / "not covered by this tool." As shipped, "deployed" reads ambiguous and "not_mapped" reads like a defect.
- **The coverage % can hurt us.** "Coverage: 42%" with no framing invites the reader (or their auditor) to conclude the product fails the framework. The honest framing: TinySocs addresses the *detection/monitoring* controls; the % should be scoped to those, with the rest explicitly marked "outside the scope of a monitoring tool."
- **Beachhead mismatch:** the first pilots (`docs/icp.md` §4) are SaaS companies hit by enterprise questionnaires and SOC 2 / ISO 27001 prep. We ship NIST/HIPAA/PCI — none of which is what their questionnaire asks. What that buyer actually needs is an **evidence artifact**: "we run continuous log monitoring and alerting; here is proof it's on, current, and tested." That's a monitoring-evidence report, not another framework mapping.
- **No PDF.** HTML download is workable but the artifact gets *attached to a questionnaire response or sent to an insurer* — it needs to look like a document, print cleanly, and carry a generated-on date and system identity.

### 5. Onboarding — good installer, then a PowerShell cliff

Install-to-dashboard is genuinely strong: one GUI installer, sensible defaults, forced password, TLS choice, Sysmon bundled (`docs/getting-started.md` step 1). Then it degrades:

- **Steps 2, 4, 5, 6, 7 all require elevated PowerShell** (health check, trigger test alert, tail `alerts.log`, `curl` the bot API, run the daily summary via `python -m`). The ICP can *install an .exe and answer questions* (`docs/icp.md` §2); five terminal steps to verify a working system is past the line.
- **The documented first-alert test is broken.** `getting-started.md` step 4 generates **6** failed logons; the 2026.27 pilot pack thresholds are **15** (TS-001) and **20** (TS-002) — the validation harness itself needed 18 attempts (`docs/pilot-ruleset.md:42`). A new user follows the doc exactly, no alert fires, and their first hour ends with "is this thing even on?" This is a stale doc from before the threshold retuning.
- **Verification points at the wrong UI.** Steps 4–5 send the user to `alerts.log` and OpenSearch Dashboards (`:5602`) instead of the TinySocs dashboard we want them to live in. First-alert verification should happen where they'll work.
- `Invoke-TinySocsSmokeTest` already does end-to-end verification and is buried as "optional." It (or an installer-triggered equivalent) should be the canonical path, with the *result* surfaced in the dashboard.

### 6. Language / terminology — jargon inventory

From the UI text in `dashboard.py` (line refs from the audit inventory):

| Surface | Term(s) | ICP impact |
|---|---|---|
| Detections tab / cards | "Fired Detections", snake_case rule names, severity `info` | "Fired" is engine-speak; rule names are identifiers, not titles |
| Alert descriptions | Windows event IDs — "(4625)", "(4720)" | Meaningless to the buyer; belongs in expandable detail |
| Nav / Sites tab | "Federation", node IDs, certificate badges "pinned/mismatch/unpinned" | Multi-site is MSP-facing; a single-site SMB sees a tab they can't parse |
| Settings | "HEC tokens", "HTTP Event Collector", "SIEM URL", "LLM Provider", ledger/anchor terms | Four-tab settings modal is operator-grade |
| Data tab | "KQL", index names `tinysocs-winlog-*`, channels | Power-user surface presented as a peer tab |
| Compliance | `active/deployed/not_mapped`, "coverage %" | See §4 |
| Errors | "SIEM not connected — check that OpenSearch is running" | Names two internal components; the fix is a service restart the user doesn't know about |
| Docs/marketing | "Lightweight AI-Powered SIEM" (one-pager H1), Splunk/Elastic/Sentinel comparisons (FAQ Q1), "20 high-fidelity rules mapped to 17 MITRE ATT&CK techniques across 9 tactics" | The buyer doesn't know what a SIEM is and isn't comparing against Splunk — they're comparing against *doing nothing* or an MSP quote. `docs/icp.md` §6 already has the right headline; the collateral doesn't use it |

One direct contradiction to fix on sight: **FAQ "Can I write custom detection rules? Yes — use the Rule Builder"** (`docs/faq.md:36–38`) is the DIY-platform pitch the pivot explicitly abandons ("customer never edits a rule file"). Selling rule-authoring to this ICP re-creates the churn problem the subscription exists to solve.

---

## Prioritised gap list

Effort tags assume part-time founder evenings: **S** ≤ a day, **M** = a weekend, **L** = multiple weekends.

### MUST — before first pilot install

| # | Gap | Fix | Effort |
|---|---|---|---|
| M1 | No "are we ok?" answer on the dashboard | Status headline at top of Overview, composed from checkable facts: unresolved high/critical count + agents heartbeating + pack version/freshness. Three states: **All clear** (qualified: "across N machines") / **Needs attention** / **Monitoring degraded** (agent down ≠ silently green). Reuse the daily-summary "All Quiet" logic (`daily_summary.py:263–285`). Rule-based, not LLM — it must be unable to lie. | M |
| M2 | Documented first-alert test can't fire the rule (6 attempts vs threshold 15/18+) | Fix `getting-started.md` step 4 to ≥20 attempts; better, make `Invoke-TinySocsSmokeTest` the canonical step and have its synthetic alert appear *in the dashboard* with a "this was a test" marker. First session must end with a visible alert. | S |
| M3 | Alerts unreadable by the buyer | For the **20 enabled rules only**: human title ("Repeated failed logins — possible password guessing"), one-line "what this means", 2–3 "do this first" steps, one "likely false alarm if…" line. This is TinyDocs top-20 (strategic gap #5) surfaced in the alert expansion — same content, one authoring pass, ~20 × 15 min. Ship as static per-rule content keyed by rule ID; no engine change. | M |
| M4 | Webhook/email alert text is engine-speak | Use the M3 human titles in `AlertWriter.cs` webhook text and email subjects (`[TinySocs] HIGH: Repeated failed logins on RECEPTION-PC`). Keep rule ID in the body for support. | S |
| M5 | Empty states are dead ends | Replace `Loading...`/blank with instructive empties: "No machines reporting yet → install the agent (link)"; "No alerts in the last 7 days — monitoring is active on N machines" (ties into M1). | S |
| M6 | Collateral leads with SIEM-speak; FAQ sells rule-authoring (anti-pivot) | Rewrite one-pager H1/problem section to `icp.md` §6 language ("Always-on security monitoring for companies without a security team"); demote the Splunk comparison; reframe the custom-rules FAQ answer around allowlists/tuning-as-a-service. Docs only. | S |

### SHOULD — before first paying customer

| # | Gap | Fix | Effort |
|---|---|---|---|
| S1 | Compliance status vocabulary + coverage % framing | Rename statuses in report + UI to buyer terms; scope coverage % to monitorable controls; add plain-English intro paragraph per report ("what this document proves"). | S–M |
| S2 | No questionnaire/insurer evidence artifact (the beachhead's actual ask) | A "Monitoring Evidence" report: system identity, install date, N machines monitored, pack version + validation date, alert/response stats, generated-on. Print-clean HTML first; PDF when it earns it. This is the artifact the buyer forwards to the enterprise customer or insurer. | M |
| S3 | No one-click FP affordance | "This is normal for us" button on alert rows → suppress/acknowledge recurrence for that key + record structured FP locally. Prerequisite for the post-first-customer FP telemetry channel; designs against v2 allowlists (`rule-format-v2.md`) — don't invent a parallel suppression mechanism. | M |
| S4 | Onboarding still PowerShell-heavy after M2 | Move health-check results into the dashboard (a "System health: 16/16" card or settings panel); collapse getting-started verification to "open the dashboard, confirm the status headline is green." | M |
| S5 | Jargon surfaces in default view | "Fired Detections" → "Alerts"; hide **Sites** tab when single-node; move event IDs/index names into expandable detail; sweep settings help text. | S–M |
| S6 | AI assistant is pull-only | Auto-generated daily/weekly plain-English summary shown on Overview (the full Ronan idea), clearly labelled as AI-written, layered *on top of* the M1 rule-based status — never replacing it. | M |
| S7 | Severity taxonomy unexplained (and `info` noise) | Map severities to response expectations in UI copy: critical/high = "act today", medium = "review this week", low = "awareness". Drop `info` from buyer-facing views. | S |

### COULD — defer

| # | Gap | Note |
|---|---|---|
| C1 | Event Explorer / KQL / Rule Builder exposed as peer tabs | Power-user surfaces. Consider an "advanced" grouping post-pivot; Rule Builder's existence contradicts the managed-content story long-term — decide its fate alongside tiering, not now. |
| C2 | MITRE heatmap framing for buyers | Analyst artifact; fine as-is for the demo, low ICP value. |
| C3 | Daily email polish (monospace snake_case rule names → M3 titles) | Inherits M3 content cheaply; not blocking. |
| C4 | Glossary/tooltips across the UI | Nice, unbounded; M3/S5 remove the worst offenders first. |
| C5 | Federation/Sites UX explanation | Matters for Profile B (MSP) — court in parallel, per `icp.md` §3; not for first pilots. |
| C6 | Docs restructure (operator vs buyer reading paths) | After pilot feedback shows which docs prospects actually open. |

---

## Tensions worth keeping visible

1. **Honest all-clear vs simple all-clear.** The green tick sells; the *qualified* green tick survives the first incident. M1's degraded state ("1 of 12 machines not reporting") is the trust moat — resist simplifying it away for the demo.
2. **Rule Builder vs the pivot.** Every UI affordance that invites rule-editing recruits the customer into the job the subscription is supposed to take away. The audit flags copy (M6) now; the product decision (hide/gate the builder) belongs to the tiering work.
3. **AI as the answer vs AI as the garnish.** The assistant's output schema is already buyer-shaped, which tempts using the LLM as the primary explanation layer. But the ICP includes air-gapped/no-key installs (Ollama optional) — M3's static per-rule content must carry the load with the AI enhancing, not gatekeeping, comprehension.

## Open questions

- Does the beachhead buyer accept "we satisfy the monitoring control" (S2 evidence report) without a SOC 2 / ISO 27001-labelled mapping? First 3 pilot conversations answer this — don't build the mapping speculatively.
- Where does M3 per-rule content live — in the v2 rule schema (`user_title`, `triage` fields) or a sidecar TinyDocs file keyed by rule ID? Schema-adjacent decision; belongs in `rule-format-v2.md` open questions before authoring starts.
- M1 status thresholds: does one unresolved *medium* alert break the all-clear, or only high/critical? Recommend high/critical-only with medium counted in a subordinate line, but validate against pilot FP rates.
- Should the demo mode (`--demo`) seed a *quiet* environment (realistic) or an *eventful* one (current synthetic data)? Sales wants eventful; expectation-setting wants quiet-with-one-test-alert.
