# TinySOCS — Ledger Runbook

## Repairing a Corrupted Node Ledger
1. Stop writes to the node (pause master).
2. Inspect `ledger\node-*.jsonl` and the matching `.head` file.
3. If a mid-file line was edited or removed:
   - Restore from backup if available; otherwise truncate to the last known-good line.
   - Recompute head by appending a new entry normally via `/evidence/append` or on next master run.
4. Run master once to re-anchor (5-minute window). Confirm:
   - `python -m tinysocs.orchestrator.check_ledger --verify` → `ok:true`
   - The newest anchor sorts correctly by `anchored_at`.

## Forensics (Tamper Drill)
- Flip a hex in the last entry’s `head_prev` or `payload_sha256` → verify should flag `ledger` / `prev_link_mismatch` or `head_mismatch`.
- Restore file from `.bak` → verify returns green.

## Scheduled Ops
- `TinySOCS_Master_Daily` (03:30): fan-out + anchor.
- `TinySOCS_Ledger_Health` (03:35): verify + retention.