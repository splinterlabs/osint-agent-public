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
import re
import sqlite3
import sys
import warnings
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Suppress datetime.utcnow() deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*utcnow.*")

# Project root is 3 levels up from .claude/hooks/
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Add src to path for imports
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from osint_agent.clients.nvd import NVDClient
from osint_agent.clients.cisa_kev import CISAKEVClient
from osint_agent.cache import ThreatContextCache

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

# Configuration
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_DIR = PROJECT_ROOT / "config"
IOC_DB_PATH = DATA_DIR / "iocs.db"
WATCHLIST_PATH = CONFIG_DIR / "watchlist.json"

# Cache configuration
CACHE_TTL_HOURS = 12  # Cache validity period


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
        cves = client.get_critical(cvss_min=8.0, days=21, max_results=100)

        # Simplify for context but preserve watchlist-relevant fields
        simplified = [
            {
                "id": c["id"],
                "cvss": c.get("cvss_v3_score"),
                "description": c.get("description", ""),
                "affected_products": c.get("affected_products", []),
            }
            for c in cves
        ]

        cache.set(cache_key, simplified)
        return simplified

    except Exception as e:
        logger.warning(f"Failed to fetch CVEs: {e}")
        return []


def get_watchlist_cves(
    cache: ThreatContextCache, products: list[str]
) -> list[dict[str, Any]]:
    """Search for CVEs affecting watchlist products using keyword search.

    This catches CVEs that may only have vendor-assigned (secondary) CVSS scores,
    which aren't returned by severity-based NVD searches.
    """
    if not products:
        return []

    cache_key = "watchlist_product_cves"
    cached = cache.get(cache_key)
    if cached and not cache.is_stale(cache_key):
        logger.debug("Using cached watchlist CVE data")
        return cached

    try:
        client = NVDClient()
        all_cves = []
        seen_ids = set()

        # Search for top 15 products (to limit API calls while covering key products)
        for product in products[:15]:
            try:
                cves = client.search_by_keyword(product, days=30, max_results=10)
                for c in cves:
                    if c["id"] not in seen_ids:
                        # Only include high-severity CVEs
                        if c.get("cvss_v3_score", 0) >= 8.0:
                            all_cves.append(
                                {
                                    "id": c["id"],
                                    "cvss": c.get("cvss_v3_score"),
                                    "description": c.get("description", ""),
                                    "affected_products": c.get("affected_products", []),
                                    "matched_keyword": product,
                                }
                            )
                            seen_ids.add(c["id"])
            except Exception as e:
                logger.debug(f"Keyword search for '{product}' failed: {e}")
                continue

        # Sort by CVSS
        all_cves.sort(key=lambda x: x.get("cvss", 0), reverse=True)

        cache.set(cache_key, all_cves)
        return all_cves

    except Exception as e:
        logger.warning(f"Failed to fetch watchlist CVEs: {e}")
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


def truncate_description(description: str, max_length: int = 80) -> str:
    """Truncate description to max_length, breaking at word boundary."""
    if not description:
        return ""
    # Clean up whitespace and newlines
    desc = " ".join(description.split())
    if len(desc) <= max_length:
        return desc
    # Find last space before max_length
    truncated = desc[:max_length].rsplit(" ", 1)[0]
    return truncated + "..."


def check_watchlist_alerts(
    watchlist: dict[str, Any],
    recent_cves: list[dict],
    recent_kev: list[dict],
) -> list[dict]:
    """Check if any watchlist items have new activity.

    Returns list of alert dicts with: type, cve_id, cvss, reasons, description
    """
    alerts = []

    watched_vendors = set(v.lower() for v in watchlist.get("vendors", []))
    watched_products = set(p.lower() for p in watchlist.get("products", []))
    watched_cves = set(watchlist.get("cves", []))
    watched_keywords = [k.lower() for k in watchlist.get("keywords", [])]

    # Check recent CVEs for watched vendors/products/keywords
    for cve in recent_cves:
        cve_id = cve.get("id", "")
        matched_reasons = []
        matched_products = []  # Track matched product names for display

        # Check affected products from CPE data
        for product_info in cve.get("affected_products", []):
            vendor = product_info.get("vendor", "").lower().replace("_", " ")
            product = product_info.get("product", "").lower().replace("_", " ")

            if vendor in watched_vendors:
                matched_reasons.append(f"vendor '{vendor}'")
            if product in watched_products:
                matched_reasons.append(f"product '{product}'")
                matched_products.append(product)

            # Also check partial matches with word boundary awareness
            # (e.g., "n8n" in "n8n workflow" but NOT "unifi" in "unified")
            for watched_prod in watched_products:
                if watched_prod in product and f"product '{product}'" not in matched_reasons:
                    # Require match at word boundary (start, end, or surrounded by spaces/punctuation)
                    pattern = rf"(^|[\s_\-]){re.escape(watched_prod)}($|[\s_\-])"
                    if re.search(pattern, product):
                        matched_reasons.append(
                            f"product '{product}' (matches '{watched_prod}')"
                        )
                        matched_products.append(watched_prod)

        # Check if CVE was found via watchlist keyword search
        matched_keyword = cve.get("matched_keyword", "")
        if matched_keyword and matched_keyword.lower() in watched_products:
            matched_reasons.append(f"product '{matched_keyword}'")
            matched_products.append(matched_keyword)

        # Check description for keyword matches
        description = cve.get("description", "")
        description_lower = description.lower()
        for keyword in watched_keywords:
            if keyword in description_lower:
                matched_reasons.append(f"keyword '{keyword}'")

        # Generate alert if any matches found
        if matched_reasons:
            cvss = cve.get("cvss", "?")
            # Deduplicate reasons
            unique_reasons = list(dict.fromkeys(matched_reasons))
            unique_products = list(dict.fromkeys(matched_products))
            alerts.append({
                "type": "cve",
                "cve_id": cve_id,
                "cvss": cvss,
                "reasons": unique_reasons[:3],
                "products": unique_products,
                "description": truncate_description(description, 70),
            })

    # Check KEV for watched vendors/products
    for entry in recent_kev:
        vendor = entry.get("vendor", "").lower()
        product = entry.get("product", "").lower()
        vendor_display = entry.get("vendor", "")
        product_display = entry.get("product", "")

        if vendor in watched_vendors:
            alerts.append({
                "type": "kev",
                "cve_id": entry["cve_id"],
                "vendor": vendor_display,
                "product": product_display,
                "due_date": entry.get("due_date"),
                "reason": f"affects watched vendor '{vendor_display}'",
            })
        elif product in watched_products:
            alerts.append({
                "type": "kev",
                "cve_id": entry["cve_id"],
                "vendor": vendor_display,
                "product": product_display,
                "due_date": entry.get("due_date"),
                "reason": f"affects watched product '{product_display}'",
            })

    # Check for specific watched CVEs
    kev_cve_ids = set(e.get("cve_id") for e in recent_kev)
    for cve in watched_cves:
        if cve in kev_cve_ids:
            alerts.append({
                "type": "kev_watched",
                "cve_id": cve,
                "reason": "watched CVE added to KEV catalog",
            })

    return alerts


def generate_context() -> dict[str, Any]:
    """Generate threat context for session start."""
    cache = ThreatContextCache(DATA_DIR / "cache", ttl_hours=CACHE_TTL_HOURS)

    # Load data (uses cache when available)
    watchlist = load_watchlist()
    ioc_summary = get_ioc_summary()
    recent_cves = get_recent_cves(cache)
    recent_kev = get_recent_kev(cache)

    # Also search for watchlist products (catches CVEs with vendor-only CVSS)
    watchlist_products = watchlist.get("products", [])
    watchlist_cves = get_watchlist_cves(cache, watchlist_products)

    # Merge CVE lists, avoiding duplicates
    seen_ids = {c["id"] for c in recent_cves}
    all_cves = recent_cves.copy()
    for cve in watchlist_cves:
        if cve["id"] not in seen_ids:
            all_cves.append(cve)
            seen_ids.add(cve["id"])

    # Check for watchlist alerts using merged list
    alerts = check_watchlist_alerts(watchlist, all_cves, recent_kev)

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "alerts": alerts,
        "summary": {
            "critical_cves_21d": len(all_cves),
            "kev_additions_7d": len(recent_kev),
            "iocs_tracked": ioc_summary["total"],
            "iocs_24h": ioc_summary["recent_24h"],
        },
        "recent_critical_cves": all_cves[:5],
        "recent_kev": recent_kev[:5],
        "watchlist_vendors": watchlist.get("vendors", []),
        "watchlist_products": watchlist.get("products", []),
    }


def severity_indicator(cvss: float | str | None) -> str:
    """Return emoji indicator based on CVSS score."""
    try:
        score = float(cvss) if cvss else 0
    except (ValueError, TypeError):
        return "⚪"  # Unknown

    if score >= 9.0:
        return "🔴"  # Critical
    elif score >= 7.0:
        return "🟠"  # High
    elif score >= 4.0:
        return "🟡"  # Medium
    else:
        return "🟢"  # Low


def format_alert(alert: dict) -> str:
    """Format a single alert dict into a readable string."""
    if alert["type"] == "cve":
        # Format: 🔴 CVE-ID (CVSS): Description...
        cve_id = alert["cve_id"]
        cvss = alert["cvss"]
        desc = alert.get("description", "")
        indicator = severity_indicator(cvss)

        if desc:
            return f"{indicator} **{cve_id}** ({cvss}): {desc}"
        else:
            return f"{indicator} **{cve_id}** ({cvss})"

    elif alert["type"] == "kev":
        # KEV entries are always critical (actively exploited)
        return (
            f"⚡ **{alert['cve_id']}** - {alert['vendor']} {alert['product']} "
            f"(due: {alert.get('due_date', 'N/A')})"
        )

    elif alert["type"] == "kev_watched":
        return f"⚡ **{alert['cve_id']}** - watched CVE added to KEV catalog"

    else:
        # Fallback for unknown types
        return str(alert)


def get_alert_group_key(alert: dict) -> str:
    """Get grouping key for an alert (product name or category)."""
    if alert["type"] == "cve":
        products = alert.get("products", [])
        if products:
            # Use first matched product, normalized
            return products[0].lower()
        # Check reasons for keyword matches
        reasons = alert.get("reasons", [])
        for reason in reasons:
            if "keyword" in reason:
                # Extract keyword from "keyword 'xyz'"
                match = re.search(r"keyword '([^']+)'", reason)
                if match:
                    return f"_keyword_{match.group(1)}"
        return "_other"
    elif alert["type"] in ("kev", "kev_watched"):
        return "_kev"
    return "_other"


def format_group_header(group_key: str) -> str:
    """Format a group header from its key."""
    if group_key == "_kev":
        return "⚡ KEV (Active Exploitation)"
    elif group_key.startswith("_keyword_"):
        keyword = group_key.replace("_keyword_", "")
        return f"🔍 {keyword.title()}"
    elif group_key == "_other":
        return "📋 Other"
    else:
        # Product name - capitalize properly
        return f"📦 {group_key.title()}"


def format_output(context: dict[str, Any], full: bool = False) -> str:
    """Format context for output. Compact by default, full with --full flag."""
    output_lines = []

    if context["alerts"]:
        output_lines.append("## Watchlist Alerts")

        # Group alerts by product/category
        from collections import defaultdict
        groups: dict[str, list[dict]] = defaultdict(list)

        for alert in context["alerts"]:
            key = get_alert_group_key(alert)
            groups[key].append(alert)

        # Sort groups: products first (alphabetically), then keywords, then KEV, then other
        def group_sort_key(key: str) -> tuple[int, str]:
            if key == "_kev":
                return (0, key)  # KEV first (most actionable)
            elif key.startswith("_keyword_"):
                return (2, key)  # Keywords after products
            elif key == "_other":
                return (3, key)  # Other last
            else:
                return (1, key)  # Products second, alphabetically

        sorted_groups = sorted(groups.keys(), key=group_sort_key)

        for group_key in sorted_groups:
            group_alerts = groups[group_key]
            # Sort alerts within group by CVSS (highest first)
            group_alerts.sort(
                key=lambda a: float(a.get("cvss", 0) or 0),
                reverse=True
            )

            output_lines.append(f"### {format_group_header(group_key)}")
            for alert in group_alerts:
                output_lines.append(f"- {format_alert(alert)}")

        output_lines.append("")

    summary = context["summary"]
    output_lines.append("## Threat Intelligence Summary")
    output_lines.append(f"- Critical CVEs (21d): {summary['critical_cves_21d']}")
    output_lines.append(f"- KEV Additions (7d): {summary['kev_additions_7d']}")
    output_lines.append(f"- IOCs Tracked: {summary['iocs_tracked']}")
    output_lines.append(f"- IOCs (24h): {summary['iocs_24h']}")

    if full:
        output_lines.append("")

        if context["recent_critical_cves"]:
            output_lines.append("## Recent Critical CVEs")
            for cve in context["recent_critical_cves"]:
                desc = truncate_description(cve.get("description", ""), 60)
                indicator = severity_indicator(cve.get("cvss"))
                if desc:
                    output_lines.append(f"- {indicator} **{cve['id']}** ({cve['cvss']}): {desc}")
                else:
                    output_lines.append(f"- {indicator} **{cve['id']}** ({cve['cvss']})")
            output_lines.append("")

        if context["recent_kev"]:
            output_lines.append("## Recent KEV Additions")
            for kev in context["recent_kev"]:
                output_lines.append(
                    f"- ⚡ **{kev['cve_id']}**: {kev['vendor']} {kev['product']} (due: {kev['due_date']})"
                )

    return "\n".join(output_lines)


def main() -> None:
    """Hook entry point - outputs context to stdout.

    Usage:
        session_start.py          # Compact output (alerts + stats)
        session_start.py --full   # Full output (alerts + stats + CVE/KEV details)
    """
    full = "--full" in sys.argv

    try:
        context = generate_context()
        print(format_output(context, full=full))

    except Exception as e:
        logger.error(f"SessionStart hook failed: {e}")
        # Output minimal context on failure
        print("## Threat Intelligence\nContext loading failed. Use MCP tools for live data.")


if __name__ == "__main__":
    main()
