#!/usr/bin/env python3
"""PreToolUse hook - Validate WebFetch URLs and enforce rate limiting.

This hook runs before WebFetch tool executions and:
- Validates URLs against allowed domain list
- Enforces per-domain rate limits
- Logs blocked requests for audit
- Provides feedback when requests are blocked

Design goals:
- Security: Only allow access to configured OSINT sources
- Reliability: Prevent API rate limit exhaustion
- Audit: Log all blocked requests
"""

import json
import logging
import sqlite3
import sys
import warnings
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

# Suppress datetime.utcnow() deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*utcnow.*")

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

# Project root is 3 levels up from .claude/hooks/
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Configuration paths
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
ALLOWED_DOMAINS_PATH = CONFIG_DIR / "allowed_domains.json"
RATE_LIMIT_DB_PATH = DATA_DIR / "rate_limits.db"
BLOCKED_LOG_PATH = DATA_DIR / "logs" / "blocked_requests.jsonl"


def load_allowed_domains() -> dict[str, Any]:
    """Load allowed domains configuration."""
    if not ALLOWED_DOMAINS_PATH.exists():
        logger.warning("allowed_domains.json not found, all domains blocked")
        return {"domains": {}}

    try:
        with open(ALLOWED_DOMAINS_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to load allowed_domains.json: {e}")
        return {"domains": {}}


def init_rate_limit_db() -> None:
    """Initialize rate limit tracking database."""
    RATE_LIMIT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(RATE_LIMIT_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_domain ON requests(domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)")

    conn.commit()
    conn.close()


def check_rate_limit(domain: str, rate_limit: int, window_seconds: int) -> tuple[bool, int]:
    """Check if domain is within rate limit.

    Args:
        domain: Domain to check
        rate_limit: Max requests allowed in window
        window_seconds: Time window in seconds

    Returns:
        Tuple of (is_allowed, current_count)
    """
    init_rate_limit_db()

    conn = sqlite3.connect(RATE_LIMIT_DB_PATH)
    cursor = conn.cursor()

    # Calculate window start
    window_start = (datetime.utcnow() - timedelta(seconds=window_seconds)).isoformat() + "Z"

    # Count requests in window
    cursor.execute(
        "SELECT COUNT(*) FROM requests WHERE domain = ? AND timestamp > ?",
        (domain, window_start),
    )
    count = cursor.fetchone()[0]

    conn.close()

    return count < rate_limit, count


def record_request(domain: str) -> None:
    """Record a request for rate limiting."""
    init_rate_limit_db()

    conn = sqlite3.connect(RATE_LIMIT_DB_PATH)
    cursor = conn.cursor()

    now = datetime.utcnow().isoformat() + "Z"
    cursor.execute("INSERT INTO requests (domain, timestamp) VALUES (?, ?)", (domain, now))

    # Cleanup old entries (older than 1 hour)
    cleanup_time = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"
    cursor.execute("DELETE FROM requests WHERE timestamp < ?", (cleanup_time,))

    conn.commit()
    conn.close()


def log_blocked_request(url: str, reason: str, domain: str) -> None:
    """Log blocked request for audit."""
    BLOCKED_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "url": url,
        "domain": domain,
        "reason": reason,
    }

    with open(BLOCKED_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def validate_url(url: str) -> dict[str, Any]:
    """Validate URL against allowed domains and rate limits.

    Args:
        url: URL to validate

    Returns:
        Dict with validation result:
        - allowed: bool
        - reason: str (if blocked)
        - domain: str
        - category: str (if allowed)
    """
    # Parse URL
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Handle empty domain
        if not domain:
            return {
                "allowed": False,
                "reason": "Invalid URL: no domain found",
                "domain": "",
            }

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

    except Exception as e:
        return {
            "allowed": False,
            "reason": f"URL parsing failed: {e}",
            "domain": "",
        }

    # Load allowed domains
    config = load_allowed_domains()
    domains = config.get("domains", {})

    # Check if domain is allowed
    if domain not in domains:
        # Check for subdomain match (e.g., api.example.com matches example.com)
        parent_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain
        if parent_domain not in domains:
            log_blocked_request(url, "Domain not in allowlist", domain)
            return {
                "allowed": False,
                "reason": f"Domain '{domain}' is not in the allowed domains list. "
                          f"Add it to config/allowed_domains.json to enable access.",
                "domain": domain,
            }
        domain = parent_domain

    domain_config = domains[domain]
    rate_limit = domain_config.get("rate_limit", 60)
    window_seconds = domain_config.get("window_seconds", 60)
    category = domain_config.get("category", "unknown")

    # Check rate limit
    is_allowed, current_count = check_rate_limit(domain, rate_limit, window_seconds)

    if not is_allowed:
        log_blocked_request(url, "Rate limit exceeded", domain)
        return {
            "allowed": False,
            "reason": f"Rate limit exceeded for {domain}: {current_count}/{rate_limit} "
                      f"requests in {window_seconds}s window. Please wait.",
            "domain": domain,
        }

    # Record this request
    record_request(domain)

    return {
        "allowed": True,
        "domain": domain,
        "category": category,
        "rate_limit_status": f"{current_count + 1}/{rate_limit}",
    }


def main() -> None:
    """Hook entry point - reads hook input from stdin, outputs decision."""
    try:
        hook_input = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        logger.error("Invalid JSON input")
        # Allow on error to not break workflow
        print(json.dumps({"decision": "allow"}))
        return

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Only validate WebFetch tool
    if tool_name != "WebFetch":
        print(json.dumps({"decision": "allow"}))
        return

    url = tool_input.get("url", "")
    if not url:
        print(json.dumps({"decision": "allow"}))
        return

    # Validate the URL
    result = validate_url(url)

    if result["allowed"]:
        logger.info(f"Allowed: {url} ({result['category']}) [{result['rate_limit_status']}]")
        print(json.dumps({"decision": "allow"}))
    else:
        logger.warning(f"Blocked: {url} - {result['reason']}")
        print(json.dumps({
            "decision": "block",
            "message": result["reason"],
        }))


if __name__ == "__main__":
    main()
