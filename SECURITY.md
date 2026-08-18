# Security policy

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting** on this repository
(Security tab → "Report a vulnerability"). Please don't open public issues for
security problems.

This is a solo, unfunded side project: reports are triaged best-effort, there is no
bounty, and no response-time commitment. Credible reports will be fixed as time
allows and credited in the changelog if you want credit.

## Scope and threat model — read before reporting

TinySocs is designed to run on **localhost or a trusted LAN**, operated by the person
who installed it. Several things you might find are **known, documented limitations**
rather than undisclosed vulnerabilities — check
[KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md) first. In particular:

- Dashboard API routes require a Bearer session (deny-by-default middleware as of
  2026-08-18), but the recommended posture is still the localhost-only default bind;
  exposing the dashboard beyond a trusted network is explicitly unsupported.
- TLS verification is disabled by default in several internal hops (self-signed-cert
  topology).
- Federation is experimental and assumes all nodes are operated by the same person.

Reports that these exist as designed won't be treated as new findings — but reports
of ways to exploit them *from outside the documented trust boundary* (e.g. from an
unauthenticated network position against a default localhost-only install, or a
browser-based attack like DNS rebinding/CSRF that reaches the localhost dashboard)
are exactly what this policy is for.

## Supported versions

Only the latest release. There are no backports.
