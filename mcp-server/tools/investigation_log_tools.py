"""MCP tools for investigation step logging.

Provides tools to persist raw enrichment results to a per-investigation
JSONL log file so that console output stays compact while full data
remains accessible for ``/review`` and post-hoc analysis.
"""

import json
import logging
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from osint_agent.investigation_log import InvestigationLogger
from osint_agent.usage import track_tool

logger = logging.getLogger("osint-mcp.investigation-log")

# Module-level current logger, set by start_new_log()
_current_logger: Optional[InvestigationLogger] = None


def start_new_log(investigation_name: str) -> str:
    """Create a new InvestigationLogger for the current investigation.

    Called from ``start_investigation`` in context_tools.  Returns the
    log file path so it can be included in the response JSON.
    """
    global _current_logger
    _current_logger = InvestigationLogger(investigation_name)
    logger.info(f"Investigation log started: {_current_logger.path}")
    return str(_current_logger.path)


def get_current_logger() -> Optional[InvestigationLogger]:
    """Return the current investigation logger (may be None)."""
    return _current_logger


def register_tools(mcp: FastMCP) -> None:
    """Register investigation log tools with the MCP server."""

    @mcp.tool()
    @track_tool("log_investigation_step")
    def log_investigation_step(
        source: str,
        indicator: str,
        status: str,
        summary: str,
        raw_result: str = "{}",
    ) -> str:
        """Log an enrichment step to the investigation JSONL file.

        Call this after each enrichment tool during an investigation to
        persist the full raw result.  The console should show only a
        compact one-liner; the raw data lives in the log.

        Args:
            source: Tool / data source name (e.g. "NVD/KEV", "Shodan", "OTX")
            indicator: The indicator that was queried
            status: Step outcome — "checked", "error", or "skipped"
            summary: One-line human-readable summary of the result
            raw_result: Full JSON result string from the enrichment tool

        Returns:
            JSON string with step number and log file path.
        """
        cur = get_current_logger()
        if cur is None:
            return json.dumps({"error": "No active investigation log. Call start_investigation first."})

        try:
            parsed_raw = json.loads(raw_result)
        except (json.JSONDecodeError, TypeError):
            parsed_raw = raw_result

        step_num = cur.log_step(
            source=source,
            indicator=indicator,
            status=status,
            summary=summary,
            raw_result=parsed_raw,
        )

        return json.dumps({
            "status": "logged",
            "step": step_num,
            "source": source,
            "log_file": str(cur.path),
        })

    @mcp.tool()
    @track_tool("log_investigation_conclusion")
    def log_investigation_conclusion(
        verdict: str,
        confidence: str,
        risk_level: str,
        summary: str,
        coverage_json: str = "[]",
    ) -> str:
        """Log the investigation conclusion to the JSONL file.

        Call this at report synthesis time to persist the verdict and
        coverage table alongside the enrichment steps.

        Args:
            verdict: Malicious | Suspicious | Benign | Inconclusive
            confidence: High | Medium | Low
            risk_level: Critical | High | Medium | Low | Info
            summary: 2-3 sentence synthesis
            coverage_json: JSON array of coverage rows [{source, status, finding}]

        Returns:
            JSON string confirming the conclusion was logged.
        """
        cur = get_current_logger()
        if cur is None:
            return json.dumps({"error": "No active investigation log. Call start_investigation first."})

        try:
            coverage = json.loads(coverage_json)
        except (json.JSONDecodeError, TypeError):
            coverage = []

        cur.write_conclusion(
            verdict=verdict,
            confidence=confidence,
            risk_level=risk_level,
            summary=summary,
            coverage=coverage,
        )

        return json.dumps({
            "status": "conclusion_logged",
            "verdict": verdict,
            "log_file": str(cur.path),
        })

    @mcp.tool()
    @track_tool("get_investigation_log")
    def get_investigation_log(log_file: Optional[str] = None) -> str:
        """Read back all entries from an investigation log.

        Enables ``/review`` and other tools to access the raw enrichment
        data that was persisted during the investigation.

        Args:
            log_file: Optional log filename (not path). Must exist in logs/investigations/.
                Path traversal attempts are blocked for security.

        Returns:
            JSON string with all log entries.
        """
        # Define safe log directory (absolute path)
        from pathlib import Path
        LOGS_DIR = (Path(__file__).parent.parent.parent / "data" / "logs" / "investigations").resolve()

        if log_file:
            # Security: Extract only filename component to prevent path traversal
            safe_filename = Path(log_file).name

            # Reject if input contains path separators or traversal attempts
            if "/" in log_file or "\\" in log_file or ".." in log_file:
                logger.warning(f"Path traversal attempt blocked: {log_file}")
                return json.dumps({"error": "Invalid log_file: path traversal detected"})

            # Construct path within safe directory
            path = LOGS_DIR / safe_filename

            # Verify resolved path is still within LOGS_DIR (defense in depth)
            try:
                resolved_path = path.resolve()
                resolved_path.relative_to(LOGS_DIR)
            except ValueError:
                logger.warning(f"Path escape attempt blocked: {log_file}")
                return json.dumps({"error": "Invalid log_file: must be within investigations directory"})

            path = resolved_path
        else:
            cur = get_current_logger()
            if cur is None:
                return json.dumps({"error": "No active investigation log and no log_file provided."})
            path = cur.path

        if not path.exists():
            return json.dumps({"error": f"Log file not found: {path.name}"})

        entries = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            # Skip malformed lines instead of failing entire read
                            logger.warning(f"Skipping malformed line in {path.name}")
                            continue
        except (OSError, PermissionError) as e:
            logger.error(f"Failed to read log file {path.name}: {e}")
            return json.dumps({"error": "Failed to read log file"})

        return json.dumps({
            "log_file": path.name,  # Only expose filename, not full path
            "entry_count": len(entries),
            "entries": entries,
        }, indent=2, default=str)
