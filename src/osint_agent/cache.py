"""TTL-based file cache for API responses."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional


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

    def get(self, key: str) -> Optional[Any]:
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
            return datetime.now() - cached_at > self.ttl
        except (json.JSONDecodeError, KeyError, ValueError):
            return True

    def set(self, key: str, value: Any) -> None:
        """Store value in cache with timestamp."""
        path = self._cache_path(key)
        path.write_text(
            json.dumps(
                {
                    "value": value,
                    "cached_at": datetime.now().isoformat(),
                },
                indent=2,
            )
        )

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
        fetch_fn: callable,
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
        if not force_refresh:
            cached = self.get(key)
            if cached is not None and not self.is_stale(key):
                return cached

        # Fetch fresh data
        value = fetch_fn()
        self.set(key, value)
        return value
