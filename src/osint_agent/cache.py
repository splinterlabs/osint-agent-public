"""TTL-based file cache for API responses."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def make_request_cache_key(
    method: str,
    url: str,
    params: dict | None = None,
    json_data: dict | None = None,
    form_data: dict | None = None,
) -> str:
    """Generate a deterministic cache key from HTTP request parameters.

    Produces a 32-char hex digest that is filesystem-safe and
    collision-resistant.
    """
    parts = [method.upper(), url]
    if params:
        parts.append(json.dumps(sorted(params.items()), sort_keys=True, default=str))
    if json_data:
        parts.append("json:" + json.dumps(json_data, sort_keys=True, default=str))
    if form_data:
        parts.append("form:" + json.dumps(sorted(form_data.items()), sort_keys=True, default=str))
    key_string = "|".join(parts)
    return hashlib.sha256(key_string.encode()).hexdigest()[:32]


class ThreatContextCache:
    """TTL-based file cache for threat context and API responses."""

    def __init__(self, cache_dir: Path | str, ttl_hours: int = 1):
        self.cache_dir = Path(cache_dir)
        self.ttl = timedelta(hours=ttl_hours)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, key: str) -> Path:
        """Get the file path for a cache key."""
        # Sanitize key for filesystem
        safe_key = "".join(c if c.isalnum() or c in "-_" else "_" for c in key)
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str) -> Any | None:
        """Retrieve cached value if it exists."""
        path = self._cache_path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return data.get("value")
        except (json.JSONDecodeError, KeyError):
            return None

    def is_stale(self, key: str) -> bool:
        """Check if cached value has exceeded TTL."""
        path = self._cache_path(key)
        if not path.exists():
            return True
        try:
            data = json.loads(path.read_text())
            cached_at = datetime.fromisoformat(data["cached_at"])
            now = datetime.now(UTC)
            # Handle naive timestamps from older cache entries
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=UTC)
            return now - cached_at > self.ttl
        except (json.JSONDecodeError, KeyError, ValueError):
            return True

    def set(self, key: str, value: Any) -> None:
        """Store value in cache with timestamp (atomic write)."""
        path = self._cache_path(key)
        fd, tmp_path = tempfile.mkstemp(
            dir=self.cache_dir,
            prefix=".cache_",
            suffix=".json.tmp",
        )
        try:
            with open(fd, "w") as f:
                json.dump(
                    {
                        "value": value,
                        "cached_at": datetime.now(UTC).isoformat(),
                    },
                    f,
                    indent=2,
                )
            os.replace(tmp_path, path)
        except Exception:
            Path(tmp_path).unlink(missing_ok=True)
            raise

    def delete(self, key: str) -> bool:
        """Remove a cached value."""
        path = self._cache_path(key)
        if path.exists():
            path.unlink()
            return True
        return False

    def clear(self) -> int:
        """Clear all cached values. Returns count of deleted files."""
        count = 0
        for path in self.cache_dir.glob("*.json"):
            path.unlink()
            count += 1
        return count

    def get_or_fetch(
        self,
        key: str,
        fetch_fn: Callable[[], Any],
        force_refresh: bool = False,
    ) -> Any:
        """Get cached value or fetch fresh data.

        Args:
            key: Cache key
            fetch_fn: Function to call if cache miss/stale
            force_refresh: Skip cache and fetch fresh data

        Returns:
            Cached or freshly fetched value
        """
        if not force_refresh and not self.is_stale(key):
            cached = self.get(key)
            if cached is not None:
                return cached

        # Fetch fresh data
        value = fetch_fn()
        self.set(key, value)
        return value
