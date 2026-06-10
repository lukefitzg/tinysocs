# TinySocs — Ideal Customer Profile

> Status: draft. Working doc for GTM, landing page, and outreach targeting.
> Companion to: `docs/competitive-positioning.md`, `docs/mssp-guide.md`, `docs/pilot-guide.md`.
> Prices deliberately omitted — tier architecture is free / pro / msp; pricing lands after first customer conversations.

## How to use this doc

This defines *who we sell to first*, not everyone we could ever serve. The landing page, the outreach list, and the first 3–5 pilots should all be aimed at the **beachhead** (Section 4). Everything else is context so we don't accidentally widen the aim. If a prospect doesn't match the beachhead, they're a "later," not a "no."

There are two distinct profiles, because there are two distinct buyers:

- **Profile A — the SMB end-customer** who runs TinySocs on their own estate.
- **Profile B — the MSP / IT shop** who deploys it across many client estates as a managed service. (One MSP = many endpoints, so this is the leverage play for a part-time founder.)

---

## 1. The forcing function (why anyone buys *now*)

Security monitoring is a "should-do," not a "building's-on-fire" purchase — until something external makes it urgent. We do not sell to people who *should* care; we sell to people who have a **dated, external reason** they must act. Those triggers, in rough order of how reliably they unlock budget:

1. **A blocked deal.** A bigger customer's security questionnaire / vendor-risk review demands "do you have log monitoring and alerting?" and the prospect can't say yes. Revenue is on hold. Fastest-closing trigger.
2. **A cyber-insurance renewal.** Insurer now requires monitoring/EDR-class controls to renew or to avoid a premium hike. Hard deadline, named cost.
3. **A compliance/audit obligation.** HIPAA, PCI DSS, NIST CSF, ISO 27001 prep, or (IE/EU) NIS2 / Cyber Essentials. We have one-click reports for NIST CSF 2.0, HIPAA, PCI DSS v4.0 — lean on these where they apply.
4. **A recent incident or near-miss** (theirs or a peer's). Emotional + budget unlock, but unpredictable timing.

**Targeting rule:** lead generation should hunt for the *trigger*, not the company. "Just raised a Series A and selling to enterprise" (→ questionnaires). "HIPAA-covered." "Insurance renewal this quarter." That's the search, not "SMBs in Ireland."

---

## 2. Profile A — the SMB end-customer

| Dimension | Ideal | Notes |
|---|---|---|
| **Headcount** | 20–150 staff | Big enough to have a forcing function and budget; small enough to have no security team. |
| **Endpoints** | 10–100 | Technical sweet spot of a single TinyBox node. >100 needs federation. |
| **OS estate** | Windows / Microsoft 365 centric | Agent is Windows-only today. Mac/Linux-heavy = blind spots (see anti-ICP). |
| **Security staff** | Zero dedicated | One IT generalist, an office manager wearing the IT hat, or an outsourced MSP. |
| **IT maturity** | Has *some* IT ownership | Someone can install an .exe and answer questions. Total greenfield-no-IT is too high-touch for now. |
| **Trigger present** | Yes (Section 1) | No trigger = not in the beachhead, regardless of fit. |

**The buyer / persona.** Usually *not* a security person. It's the owner/MD, the ops or finance lead who got handed the questionnaire, or the lone IT manager. Their three questions are: *"Are we being attacked? Are we covered? Can I explain this to my boss / customer / auditor?"* They buy outcomes and peace of mind, not detection rules.

**What they're actually buying.** Not the software. They're buying *"someone competent is watching, it's current, and I have proof."* That maps to the pivot: the platform gets them monitoring; the **subscription** keeps the detections current, validated, and signed so they never have to think about it.

**Where to find them.** Founder/peer networks (NDRC / Enterprise Ireland / PorterShed / Dogpatch alumni — B2B SaaS that just hit the enterprise-questionnaire wall), vertical communities (clinics, accountancy, legal, fintech-adjacent), LinkedIn by trigger, ProductHunt for the tech-literate end. **Not** the day-job network.

---

## 3. Profile B — the MSP / IT shop (channel)

| Dimension | Ideal | Notes |
|---|---|---|
| **Type** | Small/regional MSP or IT consultancy | Serves SMBs that can't afford enterprise SIEM. |
| **Client base** | 5–50 SMB clients | Enough to make a per-seat margin matter. |
| **Current security offer** | None, or reselling something they hate | The gap: they skip monitoring or lose margin reselling a cloud SIEM. |
| **Margin model** | Wants service margin, not box-resale | TinySocs lets them charge for the managed service + content. |

**Why MSPs are the leverage play.** One MSP relationship deploys across many client estates — the answer to "how does a part-time founder get distribution?" The federated multi-site architecture and per-client data isolation already exist (`docs/mssp-guide.md`). The locked **msp tier** is built for exactly this.

**What they're buying.** A monitoring offering they can put their name on, with margin in the service, plus a *content feed they don't have to maintain* — they get to look like a security shop without hiring a detection engineer.

**The catch to respect.** MSPs are a slower, higher-trust sale than a single triggered SMB. Good for durable revenue, wrong as the *first* proof point. Court them in parallel; don't make them the first pilot.

---

## 4. Recommended beachhead (aim here first)

**Irish/UK B2B SaaS & tech companies, ~20–120 staff, Microsoft/Windows shops, who have just hit the enterprise security-questionnaire / SOC 2 / ISO 27001 wall.**

Why this wedge for the first 3–5 pilots:

- **Acute, dated trigger.** A blocked or at-risk deal is the most reliable budget-unlocker, and these companies feel it this quarter, not someday.
- **Articulate, fast-moving buyers.** Founders and ops leads who make decisions in days, give clear feedback, and don't need three approval layers — ideal for learning during pilots.
- **Founder-reachable.** This is your own ecosystem (the NDRC/EI/accelerator world). Warm intros exist. *(This is also exactly what Frankli was — a B2B SaaS that needed security posture to sell up-market.)*
- **Windows/M365 common**, so the agent fits without caveats.
- **They get software**, so a ProductHunt + landing-page motion works on them.

**Secondary beachhead (court in parallel, don't lead with):** regulated SMBs (dental/clinics, accountancy, legal) reached *through* an MSP, using the compliance-report angle. Stickier, slower, better once there's a reference customer.

---

## 5. Anti-ICP (actively disqualify — saves your time)

- **Mac- or Linux-heavy estates** (design agencies, dev-heavy infra shops). No agent for them today; you'd be selling blind spots.
- **>150 staff / >100 endpoints on one site.** Outgrows a single node; federation is more than a first pilot should carry.
- **No IT ownership at all.** Nobody to install or answer questions = a services engagement you can't staff part-time.
- **No trigger, "just curious."** Tyre-kickers. Park them on the email list, don't pilot them.
- **Enterprises wanting SLAs / 24-7 vendor support / SOAR auto-response.** Out of scope; be honest and pass.
- **Fully cloud-native, no Windows host to run it on.** No deployment surface.

---

## 6. Messaging hooks (the landing page should fall out of this)

Aimed at the beachhead buyer, in their language, not ours:

- **Headline candidate:** "Always-on security monitoring for companies without a security team." (Note: *always-on / 24-7 automated*, not "staffed SOC" — keep it honest.)
- **Pain mirror:** "A customer sent you a security questionnaire and you can't tick the monitoring box. Renew your cyber insurance. Pass the audit. Without hiring a security team you don't have."
- **Mechanism, one line:** "Installs in minutes. Watches your machines 24-7. The detections stay current automatically — you never touch a rule."
- **Trust line (the moat):** "Every detection is tested against real attacks and signed before it reaches you." (This is the content-feed differentiator — see Section 7.)
- **CTA for first phase:** email capture / "get on the early list" (Loops.so), not "buy now."

---

## 7. Why this ICP fits the pivot (keep us honest)

The reason this ICP is *durable*, not just sellable, is that the beachhead's real need is **"keep it current and prove it,"** which is a subscription need, not a one-off software need. The platform gets them in the door; the recurring revenue is the validated, signed content feed. If we ever find ourselves selling the software as the product to this ICP, we've drifted off the pivot.

---

## 8. Pilot-fit checklist (qualify in one call)

A prospect is a good first pilot if **all** are true:

- [ ] Windows / M365 estate, 10–100 endpoints.
- [ ] No dedicated security staff, but someone owns IT enough to install + respond.
- [ ] A live trigger (questionnaire / insurance / audit / incident) with a rough date.
- [ ] A named human who feels the pain and can say yes.
- [ ] Willing to run it in a *live* environment (a pilot in a lab tells us nothing).
- [ ] Reachable warm or one-hop, not a cold enterprise.

---

## Open questions

- **Beachhead confirmation:** commit the first 3–5 pilots to the SaaS/questionnaire wedge, or split effort with the MSP/compliance route from day one? (Recommendation: SaaS wedge first, MSP in parallel-but-secondary.)
- **Geography:** Ireland-first for warm-intro density, or Ireland + UK from the start?
- **Compliance fit gap:** our one-click reports cover NIST CSF / HIPAA / PCI, but the SaaS-questionnaire buyer often wants SOC 2 / ISO 27001 evidence. Is "we satisfy the *monitoring/logging* control" enough for them, or is there a mapping gap to close?
- **The "all-clear" homepage:** Ronan's AI-summary-on-the-homepage idea is a strong sales artifact — but a false "all clear" is the one failure mode that kills trust. How do we show confidence honestly rather than a green tick that can lie?
