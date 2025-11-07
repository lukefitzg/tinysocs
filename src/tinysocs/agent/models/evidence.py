# tinysocs/agent/models/evidence.py
"""
TinySocs Evidence Models (Pydantic)

Canonical schema used by Node API and Master to exchange *intelligence* (not raw logs).

- EvidenceExemplar: minimal, privacy-conscious example.
- DetectionEvidence: aggregate signal for a rule+window(+host).

Stable hash over (rule, window, host, count, summary, exemplars).
`generated_at` and `hash` are excluded from the hash input.

Run tests:
  python tinysocs/agent/models/evidence.py
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import hashlib
import json
import sys
import unittest

from pydantic import BaseModel, Field, validator


ISO_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def _dt_to_rfc3339_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    s = dt.strftime(ISO_FMT)
    if s.endswith(".000000Z"):
        s = s.replace(".000000Z", "Z")
    return s


class EvidenceExemplar(BaseModel):
    timestamp: datetime = Field(..., description="UTC timestamp")
    id: Optional[str] = Field(None, description="Optional stable ingest/event id")
    message: Optional[str] = Field(None, description="Short summary (avoid raw PII)")
    fields: Optional[Dict[str, Any]] = Field(default=None, description="Sparse high-signal fields")

    class Config:
        frozen = True

    def canonical(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"timestamp": _dt_to_rfc3339_z(self.timestamp)}
        if self.id is not None: d["id"] = self.id
        if self.message is not None: d["message"] = self.message
        if self.fields is not None:
            def sort_obj(o: Any) -> Any:
                if isinstance(o, dict):
                    return {k: sort_obj(o[k]) for k in sorted(o.keys())}
                if isinstance(o, list):
                    return [sort_obj(x) for x in o]
                return o
            d["fields"] = sort_obj(self.fields)
        return d


class DetectionEvidence(BaseModel):
    rule: str = Field(..., min_length=1)
    window: str = Field(..., min_length=1)
    host: Optional[str] = None
    count: int = Field(..., ge=0)
    summary: Dict[str, Any] = Field(default_factory=dict)
    exemplars: List[EvidenceExemplar] = Field(default_factory=list)
    generated_at: Optional[datetime] = None
    hash: Optional[str] = None

    @validator("window")
    def _window_not_blank(cls, v: str) -> str:
        if not v.strip(): raise ValueError("window cannot be blank")
        return v

    def _canonical_payload(self) -> Dict[str, Any]:
        def sort_obj(o: Any) -> Any:
            if isinstance(o, dict):
                return {k: sort_obj(o[k]) for k in sorted(o.keys())}
            if isinstance(o, list):
                return [sort_obj(x) for x in o]
            return o
        return {
            "rule": self.rule,
            "window": self.window,
            "host": self.host,
            "count": self.count,
            "summary": sort_obj(self.summary),
            "exemplars": [ex.canonical() for ex in self.exemplars],
        }

    @staticmethod
    def _hash_dict(d: Dict[str, Any]) -> str:
        s = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    def compute_hash(self) -> str:
        return self._hash_dict(self._canonical_payload())

    def materialize(self) -> "DetectionEvidence":
        if self.generated_at is None:
            self.generated_at = datetime.now(timezone.utc)
        self.hash = self.compute_hash()
        return self


# ---------------------------
# Unit Tests
# ---------------------------

class TestEvidenceHash(unittest.TestCase):
    def _mk(self) -> DetectionEvidence:
        base_time = datetime(2025, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
        ex1 = EvidenceExemplar(
            timestamp=base_time,
            id="abc123",
            message="proc: cmd.exe /c whoami",
            fields={"user": "noemi", "event_id": 1, "meta": {"a": 2, "b": [1, 0]}},
        )
        ex2 = EvidenceExemplar(
            timestamp=base_time,
            id="def456",
            fields={"user": "SYSTEM", "event_id": 1},
        )
        return DetectionEvidence(
            rule="sysmon_proc_creation",
            window="15m",
            host="HOST-A",
            count=42,
            summary={"top_users": ["noemi", "SYSTEM"], "rule_ver": 3},
            exemplars=[ex1, ex2],
        )

    def test_hash_stable_same_inputs(self):
        a = self._mk().materialize()
        b = self._mk().materialize()
        self.assertEqual(a.hash, b.hash)

    def test_hash_changes_when_count_changes(self):
        a = self._mk().materialize()
        b = self._mk()
        b.count = a.count + 1
        b.materialize()
        self.assertNotEqual(a.hash, b.hash)

    def test_hash_changes_when_exemplar_order_changes(self):
        a = self._mk().materialize()
        b = self._mk()
        b.exemplars = list(reversed(b.exemplars))
        b.materialize()
        self.assertNotEqual(a.hash, b.hash)

    def test_hash_ignores_generated_at(self):
        base = self._mk()
        base.materialize()
        h1 = base.hash
        base.generated_at = datetime(2030, 1, 1, tzinfo=timezone.utc)
        h2 = base.compute_hash()
        self.assertEqual(h1, h2)

    def test_rfc3339_serialization(self):
        ex = EvidenceExemplar(timestamp=datetime(2025, 10, 15, 12, 0, 0))
        self.assertTrue(ex.canonical()["timestamp"].endswith("Z"))


if __name__ == "__main__":
    import unittest
    res = unittest.main(verbosity=2, exit=False)
    sys.exit(0 if res.result.wasSuccessful() else 1)
