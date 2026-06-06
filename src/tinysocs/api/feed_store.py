"""Tiny JSON-backed store for issued licence keys and the revocation set.

The feed server's one piece of authoritative state that the offline licence
token cannot carry itself (docs/design/signed-feed.md -> Part 4.5): the set of
`nonce`s that have been killed (refund / chargeback / re-issue) plus a record of
what was issued, so a Stripe `subscription.updated` can revoke the prior key for
the same customer before minting a replacement.

Deliberately a flat JSON file, not a database: a part-time founder running one
process does not need Postgres for a revocation list that fits in memory. The
path lives under data/ (gitignored) -- it holds customer subscription ids, so it
is operational state, never committed. Swap for a real datastore when there is a
second process or a real fleet; the surface (record_issue / revoke_* / is_revoked)
stays the same.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

_DEFAULT_STORE = Path(
    os.getenv("TINYSOCS_FEED_STORE", "data/feed/licence_store.json")
)


class LicenceStore:
    """File-backed {issued, revoked}. Process-local lock; safe for one worker."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path or _DEFAULT_STORE)
        self._lock = threading.Lock()
        self._data: dict = {"issued": {}, "revoked": []}
        self._load()

    # ---- persistence --------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            loaded = json.loads(self._path.read_text(encoding="utf-8"))
            self._data["issued"] = dict(loaded.get("issued", {}))
            self._data["revoked"] = list(loaded.get("revoked", []))
        except (ValueError, OSError):
            # A corrupt store must not crash the gate; start empty and let the
            # next write heal it. Loud-but-non-fatal is the right failure here.
            print(f"[feed-store] WARN: could not read {self._path}; starting empty",
                  flush=True)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self._path)  # atomic swap

    # ---- mutations ----------------------------------------------------------

    def record_issue(self, payload: dict, token: str) -> None:
        """Remember a freshly-minted key, keyed by its unique nonce."""
        nonce = payload.get("nonce")
        if not nonce:
            return
        with self._lock:
            self._data["issued"][nonce] = {
                "sub": payload.get("sub", ""),
                "tier": payload.get("tier", "free"),
                "sites": payload.get("sites", 0),
                "iat": payload.get("iat", 0),
                "exp": payload.get("exp", 0),
                "token": token,
                "recorded_at": int(time.time()),
            }
            self._save()

    def revoke(self, nonce: str) -> bool:
        """Kill one key by nonce. Returns True if it was newly revoked."""
        if not nonce:
            return False
        with self._lock:
            if nonce in self._data["revoked"]:
                return False
            self._data["revoked"].append(nonce)
            self._save()
            return True

    def revoke_subscription(self, sub: str) -> list[str]:
        """Revoke every still-live key issued for a Stripe customer.

        Used by subscription.updated (revoke the old key before minting the new
        one) and subscription.deleted (cancel). Returns the nonces revoked.
        """
        if not sub:
            return []
        with self._lock:
            killed: list[str] = []
            for nonce, rec in self._data["issued"].items():
                if rec.get("sub") == sub and nonce not in self._data["revoked"]:
                    self._data["revoked"].append(nonce)
                    killed.append(nonce)
            if killed:
                self._save()
            return killed

    # ---- queries ------------------------------------------------------------

    def is_revoked(self, nonce: str | None) -> bool:
        if not nonce:
            return False
        return nonce in self._data["revoked"]

    def snapshot(self) -> dict:
        """Shallow copy for inspection / tests."""
        with self._lock:
            return {
                "issued": dict(self._data["issued"]),
                "revoked": list(self._data["revoked"]),
            }
