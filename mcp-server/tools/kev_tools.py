"""CISA Known Exploited Vulnerabilities (KEV) tools."""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from osint_agent.clients.cisa_kev import CISAKEVClient

logger = logging.getLogger("osint-mcp.kev")

# Lazy singleton
_client: Optional[CISAKEVClient] = None


def get_client() -> CISAKEVClient:
    """Get or create KEV client singleton."""
    global _client
    if _client is None:
        _client = CISAKEVClient()
    return _client


def register_tools(mcp: FastMCP) -> None:
    """Register KEV tools with the MCP server."""

    @mcp.tool()
    def check_kev(cve_id: str) -> str:
        """Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-3400")

        Returns:
            JSON string with KEV entry details if found, or status indicating not found.
        """
        logger.info(f"Checking KEV for: {cve_id}")

        kev = get_client()
        entry = kev.lookup(cve_id)

        if entry:
            return json.dumps(
                {
                    "in_kev": True,
                    "details": entry,
                },
                indent=2,
            )
        else:
            return json.dumps(
                {
                    "in_kev": False,
                    "cve_id": cve_id,
                    "message": "CVE not found in CISA KEV catalog",
                },
                indent=2,
            )

    @mcp.tool()
    def search_kev_vendor(vendor: str) -> str:
        """Find Known Exploited Vulnerabilities for a specific vendor.

        Args:
            vendor: Vendor name to search (case-insensitive partial match)

        Returns:
            JSON string with list of KEV entries for the vendor.
        """
        logger.info(f"Searching KEV for vendor: {vendor}")

        kev = get_client()
        entries = kev.get_by_vendor(vendor)

        return json.dumps(
            {
                "vendor_query": vendor,
                "count": len(entries),
                "entries": entries,
            },
            indent=2,
        )

    @mcp.tool()
    def get_kev_stats() -> str:
        """Get statistics about CISA's Known Exploited Vulnerabilities catalog.

        Returns:
            JSON string with catalog statistics including total count,
            version, and top vendors.
        """
        logger.info("Getting KEV statistics")

        kev = get_client()
        stats = kev.get_stats()

        return json.dumps(stats, indent=2)
