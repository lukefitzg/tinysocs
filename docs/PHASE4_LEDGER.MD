# TinySOCS — Phase 4: Ledger Anchoring, Verification & Retention

## Executive Summary
Phase 4 ensures evidentiary integrity across federation by (1) anchoring each node’s current ledger head into OpenSearch (`tinysocs_anchors`), (2) verifying node heads against their last anchor, and (3) pruning old anchors and local JSONL files automatically.

## Anchor Model (OpenSearch)
Index alias: `tinysocs_anchors` (write index pinned; template installed).  
Mapping (essential): `anchored_at` is a `date`.

Anchor doc shape:
- `node_url` (keyword)
- `node_id` (keyword)
- `ok` (boolean)
- `sequence` (integer)
- `head_sha256` (keyword)
- `capability` (keyword; usually `ledger`)
- `anchored_at` (date)
- `run` (object)
  - `rules` (keyword)
  - `window` (keyword)
  - `items` (integer)
  - `privacy_mode` (keyword)

## Master Flow
1. Fan-out to Node API `/agg` with `rules` + `window`.
2. Read each node’s `/evidence/head`.
3. Index anchor doc (one per node) into `tinysocs_anchors` with timestamp.
4. All network calls use retry + jitter (env-controlled).

## Verification Flow
- `python -m tinysocs.orchestrator.check_ledger --verify`
  - Fetch `/evidence/head` for each node
  - Query latest anchor doc per node
  - Emit per-node row: `{node, ok, reason, sequence, current_head, anchored_head, anchored_at}`

## Retention
- Script `scripts/Ledger_Health.ps1`:
  - Deletes anchors older than 30 days via the alias (`_delete_by_query` on `anchored_at`).
  - Deletes on-disk ledger `*.jsonl` older than 14 days.
  - Appends verification results to `logs/ledger-health.json`.

## Failure Modes
- `no_anchor`: node never anchored yet.
- `head_mismatch`: node’s current head differs from the last anchored head.
- `prev_link_mismatch` / `sequence_gap`: local ledger structural integrity error (tamper/rollback).
- `anchor_query_failed`: OpenSearch not reachable or mapping missing.