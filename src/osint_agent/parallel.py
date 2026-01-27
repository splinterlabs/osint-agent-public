"""Parallel execution utilities for OSINT agent.

Provides ThreadPoolExecutor-based parallelism for IOC lookups,
campaign correlation, feed processing, and vendor searches.

All functions handle errors gracefully - failed tasks do not crash
the entire batch. Partial results are returned with error logging.
"""

from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Any, Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")

logger = logging.getLogger(__name__)

# Default worker pool sizes
DEFAULT_IOC_LOOKUP_WORKERS = 10
DEFAULT_CAMPAIGN_CORRELATION_WORKERS = 20
DEFAULT_FEED_PROCESSING_WORKERS = 10
DEFAULT_VENDOR_SEARCH_WORKERS = 5
MAX_CONCURRENT_REQUESTS = 50


def _load_parallelism_config() -> dict[str, Any]:
    """Load parallelism configuration from config/settings.json."""
    config_paths = [
        Path(__file__).parent.parent.parent / "config" / "settings.json",
        Path("config/settings.json"),
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path) as f:
                    data = json.load(f)
                    return data.get("parallelism", {})
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load parallelism config: {e}")

    return {}


_config: dict[str, Any] | None = None


def get_config() -> dict[str, Any]:
    """Get parallelism configuration (lazy loaded)."""
    global _config
    if _config is None:
        _config = _load_parallelism_config()
    return _config


def get_workers(key: str, default: int) -> int:
    """Get worker count from config or use default."""
    config = get_config()
    if not config.get("enabled", True):
        return 1  # Disable parallelism by returning 1 worker
    return config.get(key, default)


@dataclass
class ParallelMetrics:
    """Metrics for parallel operations."""

    operation: str
    workers: int
    tasks_submitted: int
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_time_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.tasks_submitted == 0:
            return 0.0
        return self.tasks_completed / self.tasks_submitted

    def log_summary(self) -> None:
        logger.info(
            f"{self.operation}: {self.tasks_completed}/{self.tasks_submitted} "
            f"succeeded ({self.success_rate:.0%}) in {self.total_time_seconds:.2f}s "
            f"with {self.workers} workers"
        )


def parallel_map(
    fn: Callable[[T], R],
    items: Iterable[T],
    max_workers: int = 10,
    label: str = "parallel_map",
) -> list[R | None]:
    """Execute fn on each item in parallel, returning results in input order.

    Failed tasks return None instead of crashing the batch.

    Args:
        fn: Function to apply to each item
        items: Iterable of items to process
        max_workers: Maximum concurrent workers
        label: Label for logging

    Returns:
        List of results in same order as input. Failed items are None.
    """
    items_list = list(items)
    if not items_list:
        return []

    # For single items, skip thread pool overhead
    if len(items_list) == 1:
        try:
            return [fn(items_list[0])]
        except Exception as e:
            logger.warning(f"{label}[0] failed: {e}")
            return [None]

    metrics = ParallelMetrics(
        operation=label,
        workers=min(max_workers, len(items_list)),
        tasks_submitted=len(items_list),
    )
    start = monotonic()
    results: list[R | None] = [None] * len(items_list)

    with ThreadPoolExecutor(max_workers=metrics.workers) as executor:
        future_to_idx = {
            executor.submit(fn, item): idx for idx, item in enumerate(items_list)
        }

        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
                metrics.tasks_completed += 1
            except Exception as e:
                logger.warning(f"{label}[{idx}] failed: {e}")
                metrics.tasks_failed += 1
                metrics.errors.append(f"[{idx}]: {e}")

    metrics.total_time_seconds = monotonic() - start
    metrics.log_summary()

    return results


def parallel_filter_map(
    fn: Callable[[T], R | None],
    items: Iterable[T],
    max_workers: int = 10,
    label: str = "parallel_filter_map",
) -> list[R]:
    """Execute fn on each item in parallel, filter out None results.

    Args:
        fn: Function to apply (return None to exclude)
        items: Iterable of items to process
        max_workers: Maximum concurrent workers
        label: Label for logging

    Returns:
        List of non-None results (order not guaranteed).
    """
    results = parallel_map(fn, items, max_workers=max_workers, label=label)
    return [r for r in results if r is not None]


def parallel_collect_sets(
    fn: Callable[[T], set[R] | None],
    items: Iterable[T],
    max_workers: int = 10,
    label: str = "parallel_collect",
) -> set[R]:
    """Execute fn on each item in parallel, collecting results into a set.

    Thread-safe aggregation using a lock.

    Args:
        fn: Function returning a set of values (or None)
        items: Iterable of items to process
        max_workers: Maximum concurrent workers
        label: Label for logging

    Returns:
        Combined set of all results.
    """
    items_list = list(items)
    if not items_list:
        return set()

    collected: set[R] = set()
    lock = threading.Lock()
    metrics = ParallelMetrics(
        operation=label,
        workers=min(max_workers, len(items_list)),
        tasks_submitted=len(items_list),
    )
    start = monotonic()

    def _execute(item: T) -> None:
        result = fn(item)
        if result is not None:
            with lock:
                collected.update(result)

    with ThreadPoolExecutor(max_workers=metrics.workers) as executor:
        futures = [executor.submit(_execute, item) for item in items_list]
        for future in as_completed(futures):
            try:
                future.result()
                metrics.tasks_completed += 1
            except Exception as e:
                metrics.tasks_failed += 1
                logger.warning(f"{label} task failed: {e}")

    metrics.total_time_seconds = monotonic() - start
    metrics.log_summary()

    return collected
