"""AlienVault OTX threat intelligence tools."""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from osint_agent.clients.otx import OTXClient

logger = logging.getLogger("osint-mcp.otx")

# Lazy singleton
_client: Optional[OTXClient] = None


def get_client() -> OTXClient:
    """Get or create OTX client singleton."""
    global _client
    if _client is None:
        _client = OTXClient()
    return _client


def register_tools(mcp: FastMCP) -> None:
    """Register OTX tools with the MCP server."""

    @mcp.tool()
    def lookup_ioc_otx(indicator: str, indicator_type: str) -> str:
        """Look up an IOC in AlienVault OTX for threat intelligence.

        Args:
            indicator: The indicator value (IP, domain, hash, URL, CVE)
            indicator_type: Type of indicator - one of:
                ipv4, ipv6, domain, url, md5, sha1, sha256, cve

        Returns:
            JSON string with OTX intelligence including pulse references,
            reputation, and related threat context.
        """
        logger.info(f"Looking up {indicator_type}: {indicator} in OTX")

        client = get_client()

        try:
            result = client.get_indicator_full(indicator_type, indicator)

            return json.dumps(
                {
                    "source": "AlienVault OTX",
                    "indicator": indicator,
                    "type": indicator_type,
                    "data": result,
                },
                indent=2,
                default=str,
            )
        except Exception as e:
            logger.error(f"OTX lookup failed: {e}")
            return json.dumps(
                {
                    "error": str(e),
                    "indicator": indicator,
                    "type": indicator_type,
                }
            )

    @mcp.tool()
    def search_otx_pulses(query: str, max_results: int = 20) -> str:
        """Search OTX threat intelligence pulses.

        Pulses are collections of IOCs and context shared by the
        security community about threats, malware, and campaigns.

        Args:
            query: Search query (malware name, CVE, threat actor, etc.)
            max_results: Maximum number of pulses to return (default: 20)

        Returns:
            JSON string with matching pulses including IOCs and context.
        """
        logger.info(f"Searching OTX pulses: {query}")

        client = get_client()

        try:
            pulses = client.search_pulses(query, max_results=max_results)

            return json.dumps(
                {
                    "source": "AlienVault OTX",
                    "query": query,
                    "count": len(pulses),
                    "pulses": pulses,
                },
                indent=2,
                default=str,
            )
        except Exception as e:
            logger.error(f"OTX pulse search failed: {e}")
            return json.dumps({"error": str(e), "query": query})

    @mcp.tool()
    def get_otx_pulse(pulse_id: str) -> str:
        """Get details of a specific OTX pulse.

        Args:
            pulse_id: The OTX pulse ID

        Returns:
            JSON string with pulse details including all IOCs.
        """
        logger.info(f"Getting OTX pulse: {pulse_id}")

        client = get_client()

        try:
            pulse = client.get_pulse(pulse_id)

            return json.dumps(
                {
                    "source": "AlienVault OTX",
                    "pulse": pulse,
                },
                indent=2,
                default=str,
            )
        except Exception as e:
            logger.error(f"OTX pulse fetch failed: {e}")
            return json.dumps({"error": str(e), "pulse_id": pulse_id})

    @mcp.tool()
    def get_otx_subscribed(
        modified_since: Optional[str] = None,
        max_results: int = 50,
    ) -> str:
        """Get recent pulses from OTX subscriptions.

        Requires an OTX API key with subscriptions configured.

        Args:
            modified_since: ISO timestamp to filter by (e.g., "2024-01-01T00:00:00")
            max_results: Maximum number of pulses to return (default: 50)

        Returns:
            JSON string with subscribed pulses.
        """
        logger.info(f"Getting OTX subscribed pulses (since: {modified_since})")

        client = get_client()

        try:
            pulses = client.get_subscribed_pulses(
                modified_since=modified_since,
                max_results=max_results,
            )

            return json.dumps(
                {
                    "source": "AlienVault OTX",
                    "modified_since": modified_since,
                    "count": len(pulses),
                    "pulses": pulses,
                },
                indent=2,
                default=str,
            )
        except Exception as e:
            logger.error(f"OTX subscribed pulses failed: {e}")
            return json.dumps({"error": str(e)})
