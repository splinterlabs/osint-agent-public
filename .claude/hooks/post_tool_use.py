#!/usr/bin/env python3
"""PostToolUse hook - Extract IOCs from tool output and save to database."""

import json
import logging
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

# Project root is 3 levels up from .claude/hooks/
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Add src to path for imports
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from osint_agent.extractors import extract_iocs

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
IOC_DB_PATH = PROJECT_ROOT / "data" / "iocs.db"
LOG_PATH = PROJECT_ROOT / "data" / "logs" / "ioc_extractions.jsonl"


def init_database() -> None:
    """Initialize SQLite database with schema."""
    IOC_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(IOC_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            hit_count INTEGER DEFAULT 1,
            UNIQUE(type, value)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_first_seen ON iocs(first_seen)")

    conn.commit()
    conn.close()


def save_to_database(iocs: dict[str, list[str]], source: str) -> None:
    """Save extracted IOCs to SQLite database."""
    init_database()

    conn = sqlite3.connect(IOC_DB_PATH)
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat() + "Z"

    for ioc_type, values in iocs.items():
        for value in values:
            cursor.execute("""
                INSERT INTO iocs (type, value, source, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(type, value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    hit_count = hit_count + 1
            """, (ioc_type, value, source, now, now))

    conn.commit()
    conn.close()


def log_extraction(tool_name: str, iocs: dict[str, list[str]]) -> None:
    """Log extraction to JSONL file."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_tool": tool_name,
        "ioc_counts": {k: len(v) for k, v in iocs.items()},
        "total_iocs": sum(len(v) for v in iocs.values()),
    }

    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def main() -> None:
    """Hook entry point - reads hook input from stdin."""
    try:
        hook_input = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        logger.error("Invalid JSON input")
        return

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})
    tool_output = hook_input.get("tool_output", "")

    # Only process WebFetch and Read tools
    if tool_name not in ["WebFetch", "Read"]:
        return

    try:
        content = str(tool_output)
        extracted_iocs = extract_iocs(content)

        if extracted_iocs:
            source = tool_input.get("url", tool_input.get("file_path", tool_name))
            save_to_database(extracted_iocs, source)
            log_extraction(tool_name, extracted_iocs)

            total = sum(len(v) for v in extracted_iocs.values())
            logger.info(f"Extracted {total} IOCs from {tool_name}: {list(extracted_iocs.keys())}")

    except Exception as e:
        # Never let extraction errors break the tool pipeline
        logger.error(f"IOC extraction failed (non-fatal): {e}")


if __name__ == "__main__":
    main()
