from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, os
from typing import Optional, Dict, Any, Tuple

LEDGER_DIR = Path(os.getenv("TINYSOCS_LEDGER_DIR", "ledger")).resolve()
LEDGER_DIR.mkdir(parents=True, exist_ok=True)

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _canon(obj: Any) -> bytes:
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
    hf = _head_file(node_id)
    if not hf.exists(): return (None, None)
    try:
        seq_s, h = hf.read_text(encoding="utf-8").strip().split(" ", 1)
        return (int(seq_s), h)
    except Exception:
        return (None, None)

def _write_head(node_id: str, seq: int, head: str) -> None:
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

    with f.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(entry.to_json(), ensure_ascii=False) + "\n")

    _write_head(node_id, seq, head_sha)
    return entry

def verify_chain(node_id: str) -> Tuple[bool, Optional[int], Optional[str]]:
    f = _node_file(node_id)
    if not f.exists(): return (True, None, None)
    prev_head = None
    prev_seq = -1
    with f.open("r", encoding="utf-8") as fp:
        for line in fp:
            e = json.loads(line)
            core = {k: e[k] for k in ("node_id","sequence","ts_utc","head_prev","payload_sha256")}
            calc_head = _sha256_hex(_canon(core))
            if calc_head != e.get("head_sha256"): return (False, e.get("sequence"), "head_mismatch")
            if e.get("head_prev") != prev_head:   return (False, e.get("sequence"), "prev_link_mismatch")
            if e.get("sequence", -1) != prev_seq + 1: return (False, e.get("sequence"), "sequence_gap")
            prev_head = calc_head
            prev_seq = e["sequence"]
    return (True, prev_seq, prev_head)