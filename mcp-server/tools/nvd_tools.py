"""NVD (National Vulnerability Database) tools."""

from __future__ import annotations

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from osint_agent.clients.nvd import NVDClient

logger = logging.getLogger("osint-mcp.nvd")

# Lazy singleton
_client: Optional[NVDClient] = None


def get_client() -> NVDClient:
    """Get or create NVD client singleton."""
    global _client
    if _client is None:
        _client = NVDClient()
    return _client


def register_tools(mcp: FastMCP) -> None:
    """Register NVD tools with the MCP server."""

    @mcp.tool()
    def lookup_cve(cve_id: str) -> str:
        """Look up CVE details from NVD with active exploitation status from CISA KEV.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-3400")

        Returns:
            JSON string with CVE details including CVSS score, description,
            affected products, and whether it's actively exploited.
        """
        from tools.kev_tools import get_client as get_kev_client

        logger.info(f"Looking up CVE: {cve_id}")

        nvd = get_client()
        kev = get_kev_client()

        # Get CVE details from NVD
        cve_data = nvd.lookup(cve_id)
        if not cve_data:
            return json.dumps({"error": f"CVE {cve_id} not found in NVD"})

        # Check KEV for active exploitation status
        kev_entry = kev.lookup(cve_id)
        cve_data["actively_exploited"] = kev_entry is not None
        if kev_entry:
            cve_data["kev_details"] = {
                "date_added": kev_entry.get("date_added"),
                "required_action": kev_entry.get("required_action"),
                "due_date": kev_entry.get("due_date"),
                "known_ransomware_use": kev_entry.get("known_ransomware_use"),
            }

        return json.dumps(cve_data, indent=2, default=str)

    @mcp.tool()
    def get_critical_cves(
        cvss_min: float = 8.0,
        days: int = 7,
        max_results: int = 50,
    ) -> str:
        """Get recent high-severity vulnerabilities from NVD.

        Args:
            cvss_min: Minimum CVSS v3 score (default: 8.0 for high/critical)
            days: Number of days to look back (default: 7)
            max_results: Maximum number of results to return (default: 50)

        Returns:
            JSON string with list of critical CVEs including scores and descriptions.
        """
        logger.info(f"Getting critical CVEs: cvss_min={cvss_min}, days={days}")

        nvd = get_client()
        cves = nvd.get_critical(cvss_min=cvss_min, days=days, max_results=max_results)

        return json.dumps(
            {
                "count": len(cves),
                "parameters": {
                    "cvss_min": cvss_min,
                    "days": days,
                    "max_results": max_results,
                },
                "cves": cves,
            },
            indent=2,
            default=str,
        )
