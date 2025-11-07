from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Resolve and ensure the ledger directory exists
LEDGER_DIR = Path(os.getenv("TINYSOCS_LEDGER_DIR", "ledger")).resolve()
LEDGER_DIR.mkdir(parents=True, exist_ok=True)

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _canon(obj: Any) -> bytes:
    # Canonical JSON (stable ordering, compact) for hashing
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

@dataclass
class EvidenceLedgerEntry:
    node_id: str
    sequence: int
    ts_utc: str
    head_prev: Optional[str]  # previous head digest (or None for genesis)
    payload_sha256: str       # sha256 of compact evidence batch payload (not the full logs)
    head_sha256: str          # sha256 of the entry itself (computed)

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

def _node_file(node_id: str) -> Path:
    return LEDGER_DIR / f"{node_id}.jsonl"

def _head_file(node_id: str) -> Path:
    return LEDGER_DIR / f"{node_id}.head"

def _read_head(node_id: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Read the cached head pointer. Be tolerant to UTF-8 BOM and stray whitespace.
    Format: '<seq> <sha256>'
    """
    hf = _head_file(node_id)
    if not hf.exists():
        return (None, None)
    try:
        # 'utf-8-sig' will transparently drop a BOM if present
        raw = hf.read_text(encoding="utf-8-sig").strip()
        if not raw:
            return (None, None)
        parts = raw.split()
        if len(parts) != 2:
            return (None, None)
        seq_s, h = parts
        return (int(seq_s), h)
    except Exception:
        return (None, None)

def _write_head(node_id: str, seq: int, head: str) -> None:
    # Write without BOM; callers only read with utf-8-sig, so either way is safe
    _head_file(node_id).write_text(f"{seq} {head}", encoding="utf-8")

def append_entry(node_id: str, payload: Dict[str, Any]) -> EvidenceLedgerEntry:
    f = _node_file(node_id)
    f.parent.mkdir(parents=True, exist_ok=True)

    seq_prev, head_prev = _read_head(node_id)
    seq = 0 if seq_prev is None else seq_prev + 1

    payload_sha = _sha256_hex(_canon(payload))
    core = {
        "node_id": node_id,
        "sequence": seq,
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "head_prev": head_prev,
        "payload_sha256": payload_sha,
    }
    head_sha = _sha256_hex(_canon(core))
    entry = EvidenceLedgerEntry(head_sha256=head_sha, **core)

    # Append a single compact JSON line; no BOM on write
    with f.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(entry.to_json(), ensure_ascii=False, separators=(",", ":")) + "\n")

    _write_head(node_id, seq, head_sha)
    return entry

def verify_chain(node_id: str) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Verify the JSONL chain for a node:
      - each line must be valid JSON (tolerate BOM/whitespace/blank lines)
      - head_sha256 must match the canonical hash of the core fields
      - head_prev must equal the previous entry's head
      - sequence must be contiguous (prev + 1)
    Returns (ok, last_seq, last_head_or_reason)
    """
    f = _node_file(node_id)
    if not f.exists():
        return (True, None, None)

    prev_head: Optional[str] = None
    prev_seq: int = -1

    # 'utf-8-sig' drops BOM if the first line/file was saved with one
    with f.open("r", encoding="utf-8-sig") as fp:
        for raw in fp:
            line = raw.lstrip("\ufeff").strip()
            if not line:
                # skip empty/whitespace lines defensively
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                # Return the next expected sequence as the failure point, with a clear reason
                return (False, prev_seq + 1 if prev_seq >= 0 else 0, "invalid_json")

            core = {k: e[k] for k in ("node_id", "sequence", "ts_utc", "head_prev", "payload_sha256")}
            calc_head = _sha256_hex(_canon(core))

            if calc_head != e.get("head_sha256"):
                return (False, e.get("sequence"), "head_mismatch")
            if e.get("head_prev") != prev_head:
                return (False, e.get("sequence"), "prev_link_mismatch")
            if e.get("sequence", -1) != prev_seq + 1:
                return (False, e.get("sequence"), "sequence_gap")

            prev_head = calc_head
            prev_seq = e["sequence"]

    return (True, prev_seq, prev_head)
