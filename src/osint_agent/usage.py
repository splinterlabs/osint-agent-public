"""Per-investigation usage tracking for MCP tool calls and API requests."""

from __future__ import annotations

import functools
import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

_tracker_lock = threading.Lock()
_tracker: UsageTracker | None = None


class UsageTracker:
    """Thread-safe tracker for MCP tool invocations and HTTP API requests."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._investigation_name: str = ""
        self._tool_calls: dict[str, dict[str, int]] = defaultdict(
            lambda: {"calls": 0, "errors": 0}
        )
        self._api_requests: dict[str, dict[str, int]] = defaultdict(
            lambda: {"calls": 0, "errors": 0}
        )
        self._started_at: str | None = None

    def reset(self, investigation_name: str) -> None:
        """Reset all counters for a new investigation."""
        with self._lock:
            self._investigation_name = investigation_name
            self._tool_calls = defaultdict(lambda: {"calls": 0, "errors": 0})
            self._api_requests = defaultdict(lambda: {"calls": 0, "errors": 0})
            self._started_at = datetime.now(timezone.utc).isoformat()
            logger.info(f"Usage tracker reset for investigation: {investigation_name}")

    def record_tool_call(self, tool_name: str, error: bool = False) -> None:
        """Record a tool invocation."""
        with self._lock:
            self._tool_calls[tool_name]["calls"] += 1
            if error:
                self._tool_calls[tool_name]["errors"] += 1

    def record_api_request(self, service: str, error: bool = False) -> None:
        """Record an HTTP API request."""
        with self._lock:
            self._api_requests[service]["calls"] += 1
            if error:
                self._api_requests[service]["errors"] += 1

    def get_stats(self) -> dict[str, Any]:
        """Return a snapshot of current usage statistics."""
        with self._lock:
            total_tool_calls = sum(v["calls"] for v in self._tool_calls.values())
            total_tool_errors = sum(v["errors"] for v in self._tool_calls.values())
            total_api_calls = sum(v["calls"] for v in self._api_requests.values())
            total_api_errors = sum(v["errors"] for v in self._api_requests.values())

            return {
                "investigation": self._investigation_name,
                "started_at": self._started_at,
                "snapshot_at": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total_tool_calls": total_tool_calls,
                    "total_tool_errors": total_tool_errors,
                    "total_api_requests": total_api_calls,
                    "total_api_errors": total_api_errors,
                },
                "tool_calls": dict(self._tool_calls),
                "api_requests": dict(self._api_requests),
            }


def get_usage_tracker() -> UsageTracker:
    """Get or create the module-level UsageTracker singleton."""
    global _tracker
    if _tracker is None:
        with _tracker_lock:
            if _tracker is None:
                _tracker = UsageTracker()
    return _tracker


def track_tool(tool_name: str) -> Callable[..., Any]:
    """Decorator to record MCP tool invocations.

    Place inside (below) @mcp.tool() so it wraps the function directly:

        @mcp.tool()
        @track_tool("lookup_cve")
        def lookup_cve(cve_id: str) -> str:
            ...
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tracker = get_usage_tracker()
            try:
                result = func(*args, **kwargs)
                tracker.record_tool_call(tool_name)
                return result
            except Exception:
                tracker.record_tool_call(tool_name, error=True)
                raise

        return wrapper

    return decorator
