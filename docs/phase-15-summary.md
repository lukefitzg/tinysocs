# Phase 15 Summary — Intelligence & Detection

**Theme:** "Know your enemy"

## Overview

Phase 15 added intelligence and detection depth to TinySocs. Alerts are now enriched with external threat context from AbuseIPDB, AlienVault OTX, and GreyNoise. File integrity monitoring detects changes to critical system files — a compliance requirement across NIST CSF, HIPAA, and PCI-DSS. Every detection rule carries machine-readable MITRE ATT&CK annotations with a dashboard coverage heatmap and downloadable Navigator layer. Adversary simulation coverage expanded from 12 to 19 Atomic Red Team technique mappings with structured JSON output. Agent version drift detection alerts operators to outdated agents. All dashboard cards are now collapsible with localStorage persistence.

**Stats:** 28 modified/new files, ~2,800 lines added across 7 milestones (M0–M6), 84 rules total covering 32 MITRE techniques across 11 tactics.

## Commits

All changes delivered as uncommitted work on branch `claude/friendly-yonath`.

## Milestones Delivered

### M0 — Threat Intelligence Enrichment

**Goal:** Enrich alerts with external threat context (AbuseIPDB, OTX, GreyNoise).

**Files:**
- `src/tinysocs/agent/threat_intel.py` (new) — Provider abstraction: `ThreatIntelProvider` base class, `AbuseIPDBProvider`, `AlienVaultOTXProvider`, `GreyNoiseCommunityProvider`. Each has `is_configured()`, rate limit tracking, graceful degradation.
- `src/tinysocs/agent/threat_cache.py` (new) — SQLite-backed TTL cache for API responses. TTL: 24h for IPs, 7d for domains. Size limit: 100K entries with LRU eviction.
- `src/tinysocs/agent/enrich.py` (expanded) — Full enrichment pipeline: `enrich_alert()` extracts IOCs, runs providers in parallel, merges results, computes composite threat_level (high/medium/low/none).
- `src/tinysocs/api/dashboard.py` — Threat badges on alert cards, enrichment popover, Settings panel with per-provider API key fields and test button, enrichment status in fleet health.
- `config/assistant.env` — New env vars: `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY`
- `tests/test_threat_intel.py` (new) — 31 tests for providers, cache, and enrichment pipeline

**How it works:**
- When an alert fires, the enrichment pipeline extracts IPs/domains/hashes. It checks the SQLite cache first (24h TTL for IPs). On cache miss, enabled providers are queried in parallel with timeout. Results are attached as `alert.enrichment` and a composite `threat_level` is calculated.
- Dashboard shows coloured threat badges (red/orange/yellow/green shield icon). Click reveals provider details.
- The AI assistant receives enrichment context for better recommendations.

### M1 — Dashboard Widget Collapsibility

**Goal:** Every dashboard card should be collapsible with click-to-collapse.

**Files:**
- `src/tinysocs/api/dashboard.py` — Generic collapse CSS (`.card-body.collapsed`, max-height transition), chevron on every card header, `toggleCardCollapse(id)` with localStorage persistence, `restoreCollapseState()` on page load, `ensureCardExpanded(id)` for programmatic expansion.

**Cards made collapsible (7 + 1):**
Alert Summary, Alert Timeline, Fired Detections, Fleet Health, Event Explorer, Alert Rules, Compliance Coverage. Event Explorer changed from collapsed-by-default to expanded-by-default (consistent with all cards). MITRE ATT&CK Coverage card (M3) also collapsible.

### M2 — File Integrity Monitoring (FIM)

**Goal:** Monitor critical system files for changes (compliance requirement for NIST, HIPAA, PCI-DSS).

**Files:**
- `src/TinySocs.Agent/Inputs/FileIntegrityInput.cs` (new) — FIM input using FileSystemWatcher + periodic hash scan. SHA-256 hashing, baseline at `fim-baseline.json`.
- `src/TinySocs.Agent/Configuration/FimConfig.cs` (new) — FIM config model
- `src/TinySocs.Agent/Inputs/InputFactory.cs` — Added `type: fim` registration
- `src/TinySocs.Agent/Configuration/AgentConfig.cs` — FIM config support
- `config/agent-config.example.yml` — FIM input configuration section
- `packaging/detection/rules.yml` — 6 new C# rules: TS-110 (critical file modified), TS-111 (executable replaced), TS-112 (TinySocs config tampered), TS-113 (mass file modification), TS-114 (sensitive file deleted), TS-115 (permission change)
- `src/tinysocs/agent/detections/rules.yaml` — 4 Python FIM rules: fim_critical_file_modified, fim_mass_modification, fim_config_tampered, fim_sensitive_file_deleted
- Compliance framework updates: NIST CSF, HIPAA, PCI-DSS updated for FIM coverage
- `tests/test_fim_rules.py` (new) — 6 FIM rule tests

### M3 — MITRE ATT&CK Native Integration

**Goal:** Every detection rule carries machine-readable MITRE ATT&CK annotations. Dashboard coverage heatmap. Navigator layer.

**Files:**
- `packaging/detection/rules.yml` — Added `mitre:` field to all C# rules + 5 new gap-coverage rules (TS-130 through TS-134)
- `src/tinysocs/agent/detections/rules.yaml` — Added `mitre:` field to all ~35+ Python rules + 5 new gap-coverage rules (account_discovery, system_network_discovery, ingress_tool_transfer, process_injection_sysmon, obfuscated_command_line)
- `src/tinysocs/reporting/mitre_coverage.py` (new) — Coverage calculator + Navigator layer generator. Functions: `load_all_rules()`, `extract_mitre_annotations()`, `calculate_coverage()`, `generate_navigator_layer()`, `generate_coverage_markdown()`. CLI: `python -m tinysocs.reporting.mitre_coverage`
- `src/tinysocs/api/dashboard.py` — MITRE ATT&CK Coverage widget with tactic heatmap, summary stats, Navigator layer download. API endpoints: `/api/mitre/coverage`, `/api/mitre/navigator-layer`
- `tests/test_mitre_coverage.py` (new) — 19 tests
- `docs/detection-coverage.md` — Now auto-generated from rule annotations

**Coverage result:** 84 rules, 32 unique techniques, 11 out of 14 tactics covered.

### M4 — Atomic Red Team Detection Validation

**Goal:** Extend adversary simulation infrastructure with new technique mappings and structured JSON output.

**Files:**
- `tests/atomic-tests.yaml` — Extended from 12 to 19 technique mappings (added T1087.001, T1018, T1105, T1055, T1027, T1565.001, T1047)
- `tests/Test-AtomicDetection.ps1` — Added `-OutputJson` parameter, structured JSON output (`atomic-results.json`), results include technique_id, status, expected_rules, detected_rules
- `docs/detection-efficacy.md` — Updated to reflect 19 test mappings, added Output Files and Navigator Layer Integration sections

**New technique mappings:**

| Technique | Name | Expected Rules | Sysmon Required |
|-----------|------|----------------|-----------------|
| T1087.001 | Account Discovery | account_discovery | No |
| T1018 | Remote System Discovery | system_network_discovery | No |
| T1105 | Ingress Tool Transfer | ingress_tool_transfer | Yes |
| T1055 | Process Injection | process_injection_sysmon | Yes |
| T1027 | Obfuscated Files or Information | obfuscated_command_line | No |
| T1565.001 | Stored Data Manipulation | TS-110, fim_critical_file_modified | No |
| T1047 | Windows Management Instrumentation | TS-134 | No |

### M5 — Agent Version Awareness & Update Notifications

**Goal:** Make agent version drift visible to operators.

**Files:**
- `config/version-manifest.json` (new) — Version manifest with current_version, minimum_compatible, components, changelog_url
- `src/tinysocs/reporting/version_check.py` (new) — Version comparison logic, fleet version checking
- `packaging/detection/rules.yml` — New rule TS-120 (agent version drift)
- `src/tinysocs/api/dashboard.py` — Version drift banner, `/api/version/status` endpoint, fleet health version badges
- `tests/test_version_check.py` (new) — Version check tests

### M6 — Documentation Update

**Goal:** Update all docs for Phase 15.

**Files updated:**
- `docs/getting-started.md` — Updated dashboard features list, Phase 15 callout
- `docs/troubleshooting.md` — 4 new Phase 15 issues (threat intel unconfigured, FIM not generating alerts, MITRE widget shows 0, version drift banner persists)
- `docs/detection-coverage.md` — Now auto-generated via `python -m tinysocs.reporting.mitre_coverage --output-md`
- `docs/detection-efficacy.md` — Updated for 19 test mappings
- `README.md` — Updated feature list
- `docs/operator-runbook.md` — New sections for threat intel, FIM, MITRE coverage, version awareness
- `docs/phase-15-summary.md` — This document

## New Files

| File | Purpose | Lines |
|------|---------|-------|
| `src/tinysocs/agent/threat_intel.py` | Threat intelligence provider framework | ~200 |
| `src/tinysocs/agent/threat_cache.py` | SQLite-backed TTL cache for API responses | ~150 |
| `src/tinysocs/reporting/mitre_coverage.py` | MITRE ATT&CK coverage calculator + Navigator layer | ~350 |
| `src/tinysocs/reporting/version_check.py` | Version comparison and fleet check | ~100 |
| `src/TinySocs.Agent/Inputs/FileIntegrityInput.cs` | File Integrity Monitoring input | ~200 |
| `src/TinySocs.Agent/Configuration/FimConfig.cs` | FIM configuration model | ~30 |
| `config/version-manifest.json` | Version manifest | ~15 |
| `tests/test_threat_intel.py` | Threat intel + cache + enrichment tests (31 tests) | ~350 |
| `tests/test_mitre_coverage.py` | MITRE coverage tests (19 tests) | ~220 |
| `tests/test_fim_rules.py` | FIM rule validation tests (6 tests) | ~80 |
| `tests/test_version_check.py` | Version check tests | ~60 |
| `docs/phase-15-summary.md` | This summary | — |

## Modified Files

| File | Changes |
|------|---------|
| `src/tinysocs/api/dashboard.py` | Threat intel badges (M0), widget collapsibility (M1), MITRE coverage widget (M3), version drift banner (M5) |
| `src/tinysocs/agent/enrich.py` | Expanded from rDNS-only to full enrichment pipeline with threat intel providers (M0) |
| `src/tinysocs/agent/detections/rules.yaml` | MITRE annotations on all rules, 4 FIM rules, 5 gap-coverage rules (M2, M3) |
| `packaging/detection/rules.yml` | MITRE annotations on all rules, 6 FIM rules (TS-110–115), TS-120 version drift, 5 gap-coverage rules (TS-130–134) (M2, M3, M5) |
| `src/tinysocs/agent/actions.yaml` | Action snippets for 9 new rules (M2, M3) |
| `config/agent-config.example.yml` | FIM input configuration section (M2) |
| `config/assistant.env` | Threat intel API key env vars (M0) |
| `src/TinySocs.Agent/Inputs/InputFactory.cs` | FIM input type registration (M2) |
| `src/TinySocs.Agent/Configuration/AgentConfig.cs` | FIM config support (M2) |
| `src/tinysocs/reporting/frameworks/nist_csf.yaml` | FIM control mappings (M2) |
| `src/tinysocs/reporting/frameworks/hipaa.yaml` | FIM control mappings (M2) |
| `src/tinysocs/reporting/frameworks/pci_dss.yaml` | FIM control mappings (M2) |
| `tests/atomic-tests.yaml` | 7 new technique mappings (M4) |
| `tests/Test-AtomicDetection.ps1` | JSON output, extended mappings (M4) |
| `docs/getting-started.md` | Phase 15 features (M6) |
| `docs/troubleshooting.md` | 4 new Phase 15 items (M6) |
| `docs/detection-efficacy.md` | Updated for 19 tests (M6) |
| `docs/detection-coverage.md` | Now auto-generated from MITRE annotations (M6) |

## Test Summary

| Test File | Count | Notes |
|-----------|-------|-------|
| `test_threat_intel.py` | 31 | Providers, cache, enrichment pipeline |
| `test_mitre_coverage.py` | 19 | Rule loading, coverage calculation, Navigator layer, markdown |
| `test_fim_rules.py` | 6 | FIM rule structure and compliance mapping |
| `test_version_check.py` | ~8 | Version manifest, comparison logic |
| Pre-existing Python tests | ~150 | All passing (Phases 12–14) |

## Acceptance Criteria Validation

### M0 — Threat Intelligence Enrichment

| Criterion | Status |
|-----------|--------|
| `ThreatIntelProvider` base class with `AbuseIPDBProvider`, `AlienVaultOTXProvider`, `GreyNoiseCommunityProvider` | ✅ Met |
| SQLite-backed TTL cache (24h IPs, 7d domains, 100K entry limit with LRU eviction) | ✅ Met |
| `enrich_alert()` extracts IOCs, queries providers in parallel, computes composite threat_level | ✅ Met |
| Graceful degradation when providers are unconfigured or rate-limited | ✅ Met |
| Dashboard threat badges (coloured shield icons) with enrichment popover | ✅ Met |
| Settings panel with per-provider API key fields and test button | ✅ Met |
| AI assistant receives enrichment context for recommendations | ✅ Met |
| 31 unit tests for providers, cache, and enrichment pipeline | ✅ Met |
| Installer wizard page for API keys | ❌ Deferred to installer update |

### M1 — Dashboard Widget Collapsibility

| Criterion | Status |
|-----------|--------|
| Generic collapse CSS with max-height transition | ✅ Met |
| Chevron toggle on every card header | ✅ Met |
| `toggleCardCollapse(id)` with localStorage persistence | ✅ Met |
| `restoreCollapseState()` on page load | ✅ Met |
| `ensureCardExpanded(id)` for programmatic expansion | ✅ Met |
| All 7 existing cards + MITRE card collapsible | ✅ Met |
| Event Explorer consistent (expanded-by-default like all cards) | ✅ Met |

### M2 — File Integrity Monitoring (FIM)

| Criterion | Status |
|-----------|--------|
| `FileIntegrityInput.cs` with FileSystemWatcher + periodic hash scan | ✅ Met |
| SHA-256 hashing with baseline at `fim-baseline.json` | ✅ Met |
| 6 C# FIM rules (TS-110 through TS-115) | ✅ Met |
| 4 Python FIM rules | ✅ Met |
| Compliance framework updates (NIST CSF, HIPAA, PCI-DSS) for FIM | ✅ Met |
| FIM input type registered in InputFactory | ✅ Met |
| 6 FIM rule tests | ✅ Met |
| Re-baseline CLI (`TinySocs.Agent.exe --fim-rebaseline`) | ❌ Requires testing on live agent |

### M3 — MITRE ATT&CK Native Integration

| Criterion | Status |
|-----------|--------|
| `mitre:` field on all C# rules in `rules.yml` | ✅ Met |
| `mitre:` field on all Python rules in `rules.yaml` | ✅ Met |
| 5 new gap-coverage C# rules (TS-130 through TS-134) | ✅ Met |
| 5 new gap-coverage Python rules | ✅ Met |
| `mitre_coverage.py` with coverage calculator + Navigator layer generator | ✅ Met |
| Dashboard MITRE ATT&CK Coverage widget with tactic heatmap | ✅ Met |
| `/api/mitre/coverage` and `/api/mitre/navigator-layer` endpoints | ✅ Met |
| `docs/detection-coverage.md` auto-generated from annotations | ✅ Met |
| 84 rules, 32 techniques, 11 tactics | ✅ Met |
| 19 unit tests | ✅ Met |

### M4 — Atomic Red Team Detection Validation

| Criterion | Status |
|-----------|--------|
| Extended from 12 to 19 technique mappings in `atomic-tests.yaml` | ✅ Met |
| `-OutputJson` parameter with structured `atomic-results.json` output | ✅ Met |
| Results include technique_id, status, expected_rules, detected_rules | ✅ Met |
| `detection-efficacy.md` updated for 19 mappings | ✅ Met |
| Actual detection rates measured on live VM | ❌ Infrastructure ready; requires live Windows VM with TinySocs installed |

### M5 — Agent Version Awareness & Update Notifications

| Criterion | Status |
|-----------|--------|
| `version-manifest.json` with current_version, minimum_compatible, components | ✅ Met |
| `version_check.py` with comparison logic and fleet checking | ✅ Met |
| TS-120 agent version drift rule | ✅ Met |
| Dashboard version drift banner | ✅ Met |
| `/api/version/status` endpoint | ✅ Met |
| Fleet health version badges | ✅ Met |
| Version check tests | ✅ Met |

### M6 — Documentation Update

| Criterion | Status |
|-----------|--------|
| `getting-started.md` updated with Phase 15 features | ✅ Met |
| `troubleshooting.md` has 4 new Phase 15 items | ✅ Met |
| `detection-coverage.md` auto-generated via MITRE coverage CLI | ✅ Met |
| `detection-efficacy.md` updated for 19 test mappings | ✅ Met |
| `README.md` feature list current | ✅ Met |
| `operator-runbook.md` covers threat intel, FIM, MITRE, version awareness | ✅ Met |
| `phase-15-summary.md` created | ✅ Met |

## Items Not Implemented

| Item | Reason |
|------|--------|
| Installer wizard pages for threat intel API keys | Requires Inno Setup packaging iteration; keys configurable via `assistant.env` |
| FIM re-baseline CLI on live agent | Requires testing against running C# agent binary |
| Actual Atomic Red Team execution results | Test infrastructure ready with 19 mappings; requires live Windows VM with TinySocs installed |
| False positive baseline measurement | Requires 30-minute idle monitoring on live deployment |
| Remote version check | Disabled by default; URL-based check implemented but untested against production endpoint |
| Privilege Escalation, Reconnaissance, Resource Development tactics | No Windows event sources readily available for these tactics without additional instrumentation |
