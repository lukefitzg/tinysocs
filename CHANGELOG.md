# Changelog

All notable changes to TinySocs are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] — 2026-06-06

Detection-content-as-a-service foundations: the signed-feed trust core, agent-side
enforcement, the licence gate, the vendor feed server, and the Stripe billing webhook.
The full revenue loop (subscription → signed licence key → live channel + premium pack
→ cancel revokes → agent verifies offline) now runs end-to-end on a laptop with no
cloud account. See `docs/design/signed-feed.md` and `docs/roadmap.md`.

### Added

- **Signed rules feed (trust core)** — `scripts/pack_sign.py` signs and verifies v2 rule
  packs with ed25519 over canonical JSON, persisting a `pack.yml.canonical` sidecar of
  the exact signed bytes so the agent verifies and loads those bytes rather than
  reconstructing them from YAML (removes cross-language drift).
- **Agent trust path (C#)** — `Ed25519Verifier`, `PackLoader`, and `LicenceReader` under
  `src/TinySocs.Agent/Detection/`: the agent ed25519-verifies a signed pack, pins the
  signing `key_id`, gates content by licence entitlement, reads its tier offline, and
  refuses tampered or untrusted packs. Wired through `OpenSearchBulkShipper`. Uses
  BouncyCastle.Cryptography (.NET 8 BCL has no Ed25519). Covered by a committed xUnit
  trust suite (22 tests).
- **Licence keys + entitlement** — `scripts/licence.py` mints and verifies offline-
  readable licence tokens (base64url payload + ed25519 signature) with a 14-day grace
  window; `scripts/stripe_pricing.py` maps opaque Stripe price ids to the locked
  free/pro/msp tiers. No prices in the repo.
- **Vendor feed server** — `src/tinysocs/api/feed.py`, a small FastAPI app: an
  entitlement-gated mint endpoint that 302s to short-TTL signed blob URLs, plus a Stripe
  webhook that mints and revokes licence keys with no Stripe SDK (HMAC-verified
  signatures). Reuses the same `licence.py` decision the agent enforces. Revocation state
  in `feed_store.py`. Covered by `tests/test_feed_server.py` (11 tests).
- **Lagged free snapshot + feed index** — `packs/base/2026.22` (one version behind live)
  and `packs/base/index.json` so the free tier resolves to a stale snapshot while pro/msp
  get the live channel.
- **One-command demo** — `scripts/demo_feed.sh` runs the whole revenue loop locally
  (signs into a throwaway temp root so the tracked `packs/` tree is never mutated).

## [0.9.0] — 2026-03-02

Phase 17: "First Light" — Demo-ready federation and pilot launch infrastructure.

### Added

- **Demo / Sandbox Mode** — launch with `python -m tinysocs.api.bot --demo` to serve a fully functional dashboard with synthetic security data from a 3-host scenario (RECEPTION-PC, FILESERVER-01, DC-01). No OpenSearch or Windows required. All 5 dashboard tabs populate with realistic data: 42 alerts over 24 hours, 7 fired detections with threat intel enrichment, fleet health for 3 hosts, compliance reports, and version drift. AI assistant works normally against synthetic data.
- **Sites Tab** — new dashboard tab showing all configured TinySocs nodes with per-site health, ledger status, version tracking, and detection activity. Queries each node's `/meta` and `/evidence/head` endpoints. Status indicators: green (healthy), amber (warning — stale anchor), red (unreachable). In demo mode, shows 3 synthetic MSSP client sites (acme-law, mainst-dental, harbor-ins). Tab is hidden in single-node deployments.
- **Release Pipeline** — GitHub Actions workflow builds C# agent, caches OpenSearch vendor payload (~300 MB), compiles Inno Setup installer, generates SHA256 checksums, and creates GitHub Releases on version tags. Tag `v0.9.0` to publish.
- **Landing Page** — static HTML/CSS page for GitHub Pages with feature grid, competitive comparison table, detection coverage stats, and download button linking to latest GitHub Release.
- **Pilot & MSSP Outreach Kit** — demo walkthrough script, competitive positioning vs Blumira/Todyl/Perch/Elastic, and email templates for pilot and MSSP outreach.

### Changed

- Version bumped to 0.9.0 across `pyproject.toml` and `Quickstart.iss`
- `bot.py` CLI accepts `--demo` flag; `BOT_SHARED_SECRET` not required in demo mode
- Demo banner displayed across all tabs when demo mode is active

### Fixed

- Dashboard tab navigation now supports 6 tabs (Sites, Overview, Fleet, Data, Detections, Compliance) with URL hash persistence and back/forward navigation

## [0.7.0] — 2026-02-15

Phases 1–16: Full SIEM platform with 89 detection rules (33 MITRE ATT&CK techniques, 11 tactics), AI assistant, compliance reporting (NIST CSF 2.0, HIPAA, PCI DSS v4.0), threat intel enrichment (AbuseIPDB, AlienVault OTX, GreyNoise), file integrity monitoring, version drift detection, federated master/node architecture, and HTTPS dashboard with session-based auth.
