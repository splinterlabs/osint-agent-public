"""Unit tests for TTL-based file cache."""

import json
from datetime import datetime, timedelta

import pytest

from osint_agent.cache import ThreatContextCache


@pytest.fixture
def cache(tmp_path):
    """Create a cache with a temporary directory."""
    return ThreatContextCache(tmp_path / "cache", ttl_hours=1)


class TestCacheInit:
    """Tests for cache initialization."""

    def test_creates_directory(self, tmp_path):
        cache_dir = tmp_path / "cache"
        assert not cache_dir.exists()
        ThreatContextCache(cache_dir)
        assert cache_dir.exists()

    def test_accepts_string_path(self, tmp_path):
        cache = ThreatContextCache(str(tmp_path / "cache"))
        assert cache.cache_dir.exists()

    def test_custom_ttl(self, tmp_path):
        cache = ThreatContextCache(tmp_path / "cache", ttl_hours=24)
        assert cache.ttl == timedelta(hours=24)


class TestCacheKeyPath:
    """Tests for cache key sanitization."""

    def test_simple_key(self, cache):
        path = cache._cache_path("simple-key")
        assert path.name == "simple-key.json"

    def test_key_with_special_chars(self, cache):
        path = cache._cache_path("CVE-2024-1234/detail?q=1")
        assert "/" not in path.name
        assert "?" not in path.name
        assert path.name.endswith(".json")

    def test_key_with_colons(self, cache):
        path = cache._cache_path("https://api.example.com")
        assert ":" not in path.name


class TestCacheSetGet:
    """Tests for basic set/get operations."""

    def test_set_and_get(self, cache):
        cache.set("key1", {"data": "value"})
        result = cache.get("key1")
        assert result == {"data": "value"}

    def test_get_missing_key(self, cache):
        assert cache.get("nonexistent") is None

    def test_set_overwrites(self, cache):
        cache.set("key1", "old")
        cache.set("key1", "new")
        assert cache.get("key1") == "new"

    def test_set_string_value(self, cache):
        cache.set("key1", "hello")
        assert cache.get("key1") == "hello"

    def test_set_list_value(self, cache):
        cache.set("key1", [1, 2, 3])
        assert cache.get("key1") == [1, 2, 3]

    def test_set_numeric_value(self, cache):
        cache.set("key1", 42)
        assert cache.get("key1") == 42

    def test_set_null_value(self, cache):
        cache.set("key1", None)
        # JSON null round-trips to None, but get() returns None for "not found" too
        # The stored data wraps the value, so get() should return None (the value)
        result = cache.get("key1")
        assert result is None

    def test_stored_as_valid_json(self, cache):
        cache.set("key1", {"nested": [1, 2]})
        path = cache._cache_path("key1")
        data = json.loads(path.read_text())
        assert "value" in data
        assert "cached_at" in data
        assert data["value"] == {"nested": [1, 2]}


class TestCacheStaleness:
    """Tests for TTL-based staleness checking."""

    def test_fresh_entry_not_stale(self, cache):
        cache.set("key1", "value")
        assert cache.is_stale("key1") is False

    def test_missing_key_is_stale(self, cache):
        assert cache.is_stale("nonexistent") is True

    def test_expired_entry_is_stale(self, tmp_path):
        # Use very short TTL
        cache = ThreatContextCache(tmp_path / "cache", ttl_hours=0)
        # Manually write a cache entry with old timestamp
        path = cache._cache_path("old_key")
        old_time = datetime.now() - timedelta(hours=2)
        path.write_text(json.dumps({
            "value": "old_data",
            "cached_at": old_time.isoformat(),
        }))
        assert cache.is_stale("old_key") is True

    def test_corrupted_file_is_stale(self, cache):
        path = cache._cache_path("corrupt")
        path.write_text("not valid json{{{")
        assert cache.is_stale("corrupt") is True

    def test_missing_timestamp_is_stale(self, cache):
        path = cache._cache_path("no_ts")
        path.write_text(json.dumps({"value": "data"}))
        assert cache.is_stale("no_ts") is True


class TestCacheDelete:
    """Tests for cache deletion."""

    def test_delete_existing(self, cache):
        cache.set("key1", "value")
        assert cache.delete("key1") is True
        assert cache.get("key1") is None

    def test_delete_nonexistent(self, cache):
        assert cache.delete("nonexistent") is False

    def test_delete_removes_file(self, cache):
        cache.set("key1", "value")
        path = cache._cache_path("key1")
        assert path.exists()
        cache.delete("key1")
        assert not path.exists()


class TestCacheClear:
    """Tests for clearing all cache entries."""

    def test_clear_empty(self, cache):
        assert cache.clear() == 0

    def test_clear_multiple(self, cache):
        cache.set("key1", "val1")
        cache.set("key2", "val2")
        cache.set("key3", "val3")
        count = cache.clear()
        assert count == 3
        assert cache.get("key1") is None
        assert cache.get("key2") is None
        assert cache.get("key3") is None

    def test_clear_returns_count(self, cache):
        cache.set("a", 1)
        cache.set("b", 2)
        assert cache.clear() == 2


class TestCacheGetOrFetch:
    """Tests for cache-or-fetch pattern."""

    def test_cache_miss_calls_fetch(self, cache):
        call_count = 0

        def fetcher():
            nonlocal call_count
            call_count += 1
            return {"fetched": True}

        result = cache.get_or_fetch("key1", fetcher)
        assert result == {"fetched": True}
        assert call_count == 1

    def test_cache_hit_skips_fetch(self, cache):
        cache.set("key1", {"cached": True})
        call_count = 0

        def fetcher():
            nonlocal call_count
            call_count += 1
            return {"fetched": True}

        result = cache.get_or_fetch("key1", fetcher)
        assert result == {"cached": True}
        assert call_count == 0

    def test_force_refresh_calls_fetch(self, cache):
        cache.set("key1", {"cached": True})
        call_count = 0

        def fetcher():
            nonlocal call_count
            call_count += 1
            return {"refreshed": True}

        result = cache.get_or_fetch("key1", fetcher, force_refresh=True)
        assert result == {"refreshed": True}
        assert call_count == 1

    def test_stale_entry_calls_fetch(self, tmp_path):
        cache = ThreatContextCache(tmp_path / "cache", ttl_hours=0)
        # Write old entry
        path = cache._cache_path("stale_key")
        old_time = datetime.now() - timedelta(hours=2)
        path.write_text(json.dumps({
            "value": "old",
            "cached_at": old_time.isoformat(),
        }))

        result = cache.get_or_fetch("stale_key", lambda: "fresh")
        assert result == "fresh"

    def test_fetch_result_is_cached(self, cache):
        cache.get_or_fetch("key1", lambda: "first_fetch")
        # Verify it's now cached
        assert cache.get("key1") == "first_fetch"
