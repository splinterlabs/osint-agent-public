#!/usr/bin/env python3
"""SessionStart hook - Load threat context at session start.

This hook runs when a Claude Code session starts and provides context about:
- Recent critical CVEs (CVSS 8.0+)
- Recent CISA KEV additions
- Watchlist status
- IOC database summary

Design goals:
- Non-blocking: Uses cached data when available
- Fast: Target <2s with cold cache, <0.5s with warm cache
- Informative: Provides actionable threat intelligence
"""

import json
import logging
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Project root is 3 levels up from .claude/hooks/
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Add src to path for imports
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from osint_agent.clients.nvd import NVDClient
from osint_agent.clients.cisa_kev import CISAKEVClient
from osint_agent.cache import ThreatContextCache

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)

# Configuration
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_DIR = PROJECT_ROOT / "config"
IOC_DB_PATH = DATA_DIR / "iocs.db"
WATCHLIST_PATH = CONFIG_DIR / "watchlist.json"

# Cache configuration
CACHE_TTL_HOURS = 4  # Cache validity period


def load_watchlist() -> dict[str, Any]:
    """Load watchlist configuration."""
    if not WATCHLIST_PATH.exists():
        return {"vendors": [], "products": [], "cves": []}

    try:
        with open(WATCHLIST_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to load watchlist: {e}")
        return {"vendors": [], "products": [], "cves": []}


def get_ioc_summary() -> dict[str, Any]:
    """Get summary of IOC database."""
    if not IOC_DB_PATH.exists():
        return {"total": 0, "by_type": {}, "recent_24h": 0}

    try:
        conn = sqlite3.connect(IOC_DB_PATH)
        cursor = conn.cursor()

        # Total IOCs
        cursor.execute("SELECT COUNT(*) FROM iocs")
        total = cursor.fetchone()[0]

        # By type
        cursor.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type")
        by_type = dict(cursor.fetchall())

        # Recent 24h
        yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z"
        cursor.execute("SELECT COUNT(*) FROM iocs WHERE first_seen > ?", (yesterday,))
        recent = cursor.fetchone()[0]

        conn.close()

        return {"total": total, "by_type": by_type, "recent_24h": recent}

    except sqlite3.Error as e:
        logger.warning(f"Failed to read IOC database: {e}")
        return {"total": 0, "by_type": {}, "recent_24h": 0}


def get_recent_cves(cache: ThreatContextCache) -> list[dict[str, Any]]:
    """Get recent critical CVEs (cached)."""
    cache_key = "recent_critical_cves"
    cached = cache.get(cache_key)
    if cached and not cache.is_stale(cache_key):
        logger.debug("Using cached CVE data")
        return cached

    try:
        client = NVDClient()
        cves = client.get_critical(cvss_min=8.0, days=7, max_results=10)

        # Simplify for context
        simplified = [
            {
                "id": c["id"],
                "cvss": c.get("cvss_v3_score"),
                "description": c.get("description", "")[:200],
            }
            for c in cves
        ]

        cache.set(cache_key, simplified)
        return simplified

    except Exception as e:
        logger.warning(f"Failed to fetch CVEs: {e}")
        return []


def get_recent_kev(cache: ThreatContextCache) -> list[dict[str, Any]]:
    """Get recent KEV additions (cached)."""
    cache_key = "recent_kev"
    cached = cache.get(cache_key)
    if cached and not cache.is_stale(cache_key):
        logger.debug("Using cached KEV data")
        return cached

    try:
        client = CISAKEVClient()
        entries = client.get_recent(days=7)

        # Simplify for context
        simplified = [
            {
                "cve_id": e.get("cve_id"),
                "vendor": e.get("vendor"),
                "product": e.get("product"),
                "due_date": e.get("due_date"),
            }
            for e in entries[:10]
        ]

        cache.set(cache_key, simplified)
        return simplified

    except Exception as e:
        logger.warning(f"Failed to fetch KEV: {e}")
        return []


def check_watchlist_alerts(
    watchlist: dict[str, Any],
    recent_cves: list[dict],
    recent_kev: list[dict],
) -> list[str]:
    """Check if any watchlist items have new activity."""
    alerts = []

    watched_vendors = set(v.lower() for v in watchlist.get("vendors", []))
    watched_products = set(p.lower() for p in watchlist.get("products", []))
    watched_cves = set(watchlist.get("cves", []))

    # Check KEV for watched vendors/products
    for entry in recent_kev:
        vendor = entry.get("vendor", "").lower()
        product = entry.get("product", "").lower()

        if vendor in watched_vendors:
            alerts.append(
                f"KEV Alert: {entry['cve_id']} affects watched vendor '{entry['vendor']}'"
            )
        if product in watched_products:
            alerts.append(
                f"KEV Alert: {entry['cve_id']} affects watched product '{entry['product']}'"
            )

    # Check for specific watched CVEs
    kev_cve_ids = set(e.get("cve_id") for e in recent_kev)
    for cve in watched_cves:
        if cve in kev_cve_ids:
            alerts.append(f"KEV Alert: Watched CVE {cve} added to KEV catalog")

    return alerts


def generate_context() -> dict[str, Any]:
    """Generate threat context for session start."""
    cache = ThreatContextCache(DATA_DIR / "cache", ttl_hours=CACHE_TTL_HOURS)

    # Load data (uses cache when available)
    watchlist = load_watchlist()
    ioc_summary = get_ioc_summary()
    recent_cves = get_recent_cves(cache)
    recent_kev = get_recent_kev(cache)

    # Check for watchlist alerts
    alerts = check_watchlist_alerts(watchlist, recent_cves, recent_kev)

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "alerts": alerts,
        "summary": {
            "critical_cves_7d": len(recent_cves),
            "kev_additions_7d": len(recent_kev),
            "iocs_tracked": ioc_summary["total"],
            "iocs_24h": ioc_summary["recent_24h"],
        },
        "recent_critical_cves": recent_cves[:5],
        "recent_kev": recent_kev[:5],
        "watchlist_vendors": watchlist.get("vendors", []),
        "watchlist_products": watchlist.get("products", []),
    }


def main() -> None:
    """Hook entry point - outputs context to stdout."""
    try:
        context = generate_context()

        # Format output for Claude Code
        output_lines = []

        if context["alerts"]:
            output_lines.append("## Watchlist Alerts")
            for alert in context["alerts"]:
                output_lines.append(f"- {alert}")
            output_lines.append("")

        summary = context["summary"]
        output_lines.append("## Threat Intelligence Summary")
        output_lines.append(f"- Critical CVEs (7d): {summary['critical_cves_7d']}")
        output_lines.append(f"- KEV Additions (7d): {summary['kev_additions_7d']}")
        output_lines.append(f"- IOCs Tracked: {summary['iocs_tracked']}")
        output_lines.append(f"- IOCs (24h): {summary['iocs_24h']}")
        output_lines.append("")

        if context["recent_critical_cves"]:
            output_lines.append("## Recent Critical CVEs")
            for cve in context["recent_critical_cves"]:
                output_lines.append(f"- **{cve['id']}** (CVSS {cve['cvss']})")
            output_lines.append("")

        if context["recent_kev"]:
            output_lines.append("## Recent KEV Additions")
            for kev in context["recent_kev"]:
                output_lines.append(
                    f"- **{kev['cve_id']}**: {kev['vendor']} {kev['product']} (due: {kev['due_date']})"
                )

        print("\n".join(output_lines))

    except Exception as e:
        logger.error(f"SessionStart hook failed: {e}")
        # Output minimal context on failure
        print("## Threat Intelligence\nContext loading failed. Use MCP tools for live data.")


if __name__ == "__main__":
    main()
