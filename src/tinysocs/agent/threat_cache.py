"""
SQLite-backed TTL cache for threat intelligence API responses.

Avoids hammering free-tier APIs by caching results with configurable TTLs.
Default: 24h for IP lookups, 7 days for domain/hash lookups.
Size limit: 100K entries with LRU eviction.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH_WIN = Path(os.getenv("ProgramData", "C:\\ProgramData")) / "TinySocs" / "Assistant" / "threat_cache.db"
_DEFAULT_DB_PATH_NIX = Path("/var/lib/tinysocs/threat_cache.db")
_MAX_ENTRIES = 100_000


class ThreatCache:
    """SQLite-backed TTL cache for threat intel results."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path:
            self._db_path = Path(db_path)
        elif os.name == "nt":
            self._db_path = _DEFAULT_DB_PATH_WIN
        else:
            self._db_path = _DEFAULT_DB_PATH_NIX

        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Create the cache table if it doesn't exist."""
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS threat_cache (
                        ioc_type    TEXT NOT NULL,
                        ioc_value   TEXT NOT NULL,
                        provider    TEXT NOT NULL,
                        result_json TEXT NOT NULL,
                        cached_at   REAL NOT NULL,
                        ttl_seconds INTEGER NOT NULL,
                        PRIMARY KEY (ioc_type, ioc_value, provider)
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_cache_expiry
                    ON threat_cache (cached_at, ttl_seconds)
                """)
        except Exception as e:
            logger.warning("Failed to initialize threat cache at %s: %s", self._db_path, e)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5.0)

    def get(self, ioc_type: str, ioc_value: str, provider: str) -> Optional[Dict[str, Any]]:
        """Return cached result if still valid (within TTL), else None."""
        try:
            with self._lock, self._connect() as conn:
                row = conn.execute(
                    "SELECT result_json, cached_at, ttl_seconds FROM threat_cache "
                    "WHERE ioc_type = ? AND ioc_value = ? AND provider = ?",
                    (ioc_type, ioc_value, provider),
                ).fetchone()
                if row is None:
                    return None
                result_json, cached_at, ttl = row
                if time.time() - cached_at > ttl:
                    # Expired — delete and return None
                    conn.execute(
                        "DELETE FROM threat_cache WHERE ioc_type = ? AND ioc_value = ? AND provider = ?",
                        (ioc_type, ioc_value, provider),
                    )
                    return None
                return json.loads(result_json)
        except Exception as e:
            logger.warning("Cache read error: %s", e)
            return None

    def put(self, ioc_type: str, ioc_value: str, provider: str,
            result: Dict[str, Any], ttl_seconds: int = 86400) -> None:
        """Store a result in the cache with the given TTL."""
        try:
            result_json = json.dumps(result, default=str)
            with self._lock, self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO threat_cache "
                    "(ioc_type, ioc_value, provider, result_json, cached_at, ttl_seconds) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (ioc_type, ioc_value, provider, result_json, time.time(), ttl_seconds),
                )
                self._maybe_evict(conn)
        except Exception as e:
            logger.warning("Cache write error: %s", e)

    def _maybe_evict(self, conn: sqlite3.Connection) -> None:
        """Evict oldest entries if cache exceeds size limit."""
        count = conn.execute("SELECT COUNT(*) FROM threat_cache").fetchone()[0]
        if count > _MAX_ENTRIES:
            excess = count - _MAX_ENTRIES + 1000  # evict 1000 extra for headroom
            conn.execute(
                "DELETE FROM threat_cache WHERE rowid IN "
                "(SELECT rowid FROM threat_cache ORDER BY cached_at ASC LIMIT ?)",
                (excess,),
            )

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        try:
            with self._lock, self._connect() as conn:
                now = time.time()
                cursor = conn.execute(
                    "DELETE FROM threat_cache WHERE (cached_at + ttl_seconds) < ?",
                    (now,),
                )
                return cursor.rowcount
        except Exception as e:
            logger.warning("Cache cleanup error: %s", e)
            return 0

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        try:
            with self._lock, self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) FROM threat_cache").fetchone()[0]
                now = time.time()
                valid = conn.execute(
                    "SELECT COUNT(*) FROM threat_cache WHERE (cached_at + ttl_seconds) >= ?",
                    (now,),
                ).fetchone()[0]
                expired = total - valid
                by_provider = {}
                for row in conn.execute(
                    "SELECT provider, COUNT(*) FROM threat_cache "
                    "WHERE (cached_at + ttl_seconds) >= ? GROUP BY provider",
                    (now,),
                ):
                    by_provider[row[0]] = row[1]
                return {
                    "total_entries": total,
                    "valid_entries": valid,
                    "expired_entries": expired,
                    "by_provider": by_provider,
                    "db_path": str(self._db_path),
                }
        except Exception as e:
            logger.warning("Cache stats error: %s", e)
            return {"total_entries": 0, "error": str(e)}

    def clear(self) -> None:
        """Remove all entries."""
        try:
            with self._lock, self._connect() as conn:
                conn.execute("DELETE FROM threat_cache")
        except Exception as e:
            logger.warning("Cache clear error: %s", e)
