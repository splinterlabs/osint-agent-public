"""Per-investigation step logging to JSONL files.

Moves verbose enrichment details (raw API responses, intermediate results)
out of the console and into persistent log files.  The final verdict/report
stays fully visible; only the enrichment noise is redirected.

Log files live in ``data/logs/investigations/`` with naming
``investigate_{indicator}_{timestamp}.jsonl``.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default directory for investigation logs
DEFAULT_LOG_DIR = Path(__file__).parent.parent.parent / "data" / "logs" / "investigations"


def _sanitize_filename(name: str) -> str:
    """Turn an arbitrary indicator string into a safe filename component.

    Colons, slashes, spaces, and other non-alphanumeric characters are
    replaced with underscores, then collapsed and trimmed.
    """
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
    safe = re.sub(r"_+", "_", safe)
    return safe.strip("_")[:120]


class InvestigationLogger:
    """Append-only JSONL logger for a single investigation."""

    def __init__(self, indicator: str, log_dir: Path | None = None) -> None:
        self._log_dir = log_dir or DEFAULT_LOG_DIR
        self._log_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_indicator = _sanitize_filename(indicator)
        self._filename = f"investigate_{safe_indicator}_{ts}.jsonl"
        self._path = self._log_dir / self._filename
        self._step_counter = 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def filename(self) -> str:
        return self._filename

    # ------------------------------------------------------------------
    # Writers
    # ------------------------------------------------------------------

    def write_header(
        self,
        indicator: str,
        indicator_type: str,
        investigation_name: str = "",
    ) -> None:
        """Write the opening ``investigation_start`` entry."""
        self._append(
            {
                "event": "investigation_start",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "investigation_name": investigation_name,
                "timestamp": _now_iso(),
            }
        )

    def log_step(
        self,
        source: str,
        indicator: str,
        status: str,
        summary: str,
        raw_result: Any = None,
    ) -> int:
        """Append one enrichment step and return its 1-based step number."""
        self._step_counter += 1
        self._append(
            {
                "event": "enrichment_step",
                "step": self._step_counter,
                "source": source,
                "indicator": indicator,
                "status": status,
                "summary": summary,
                "raw_result": raw_result,
                "timestamp": _now_iso(),
            }
        )
        return self._step_counter

    def write_conclusion(
        self,
        verdict: str,
        confidence: str,
        risk_level: str,
        summary: str,
        coverage: list[dict[str, str]] | None = None,
    ) -> None:
        """Write the closing ``investigation_conclusion`` entry."""
        self._append(
            {
                "event": "investigation_conclusion",
                "verdict": verdict,
                "confidence": confidence,
                "risk_level": risk_level,
                "summary": summary,
                "coverage": coverage or [],
                "total_steps": self._step_counter,
                "timestamp": _now_iso(),
            }
        )

    # ------------------------------------------------------------------
    # Reader
    # ------------------------------------------------------------------

    def read_log(self) -> list[dict[str, Any]]:
        """Read all JSONL entries back as a list of dicts."""
        if not self._path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _append(self, record: dict[str, Any]) -> None:
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
