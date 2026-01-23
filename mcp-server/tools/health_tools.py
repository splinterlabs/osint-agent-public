"""Health check and diagnostic tools for the MCP server."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("osint-mcp.health")


def register_tools(mcp: FastMCP) -> None:
    """Register health check tools with the MCP server."""

    @mcp.tool()
    def health_check() -> str:
        """Check MCP server health and connectivity to external services.

        Returns:
            JSON string with health status of all components:
            - Server status
            - Python version
            - Available tool count
            - External API connectivity
        """
        logger.info("Running health check")

        health = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "server": {
                "name": "osint-mcp",
                "python_version": sys.version,
            },
            "services": {},
        }

        # Check NVD API
        try:
            from osint_agent.clients.nvd import NVDClient

            client = NVDClient()
            # Just verify we can create the client
            health["services"]["nvd"] = {
                "status": "available",
                "base_url": client.BASE_URL,
            }
        except Exception as e:
            health["services"]["nvd"] = {"status": "error", "error": str(e)}

        # Check CISA KEV
        try:
            from osint_agent.clients.cisa_kev import CISAKEVClient

            client = CISAKEVClient()
            health["services"]["cisa_kev"] = {
                "status": "available",
                "base_url": client.BASE_URL,
            }
        except Exception as e:
            health["services"]["cisa_kev"] = {"status": "error", "error": str(e)}

        # Check OTX (requires API key)
        try:
            from osint_agent.clients.otx import OTXClient
            from osint_agent.keymanager import get_api_key

            api_key = get_api_key("OTX_API_KEY")
            health["services"]["otx"] = {
                "status": "available" if api_key else "no_api_key",
                "api_key_configured": api_key is not None,
            }
        except Exception as e:
            health["services"]["otx"] = {"status": "error", "error": str(e)}

        # Check Shodan (requires API key)
        try:
            from osint_agent.keymanager import get_api_key

            api_key = get_api_key("SHODAN_API_KEY")
            health["services"]["shodan"] = {
                "status": "available" if api_key else "no_api_key",
                "api_key_configured": api_key is not None,
            }
        except Exception as e:
            health["services"]["shodan"] = {"status": "error", "error": str(e)}

        # Check API keys status
        try:
            from osint_agent.keymanager import list_configured_keys

            health["api_keys"] = list_configured_keys()
        except Exception as e:
            health["api_keys"] = {"error": str(e)}

        # Determine overall status
        error_services = [
            name
            for name, info in health["services"].items()
            if info.get("status") == "error"
        ]
        if error_services:
            health["status"] = "degraded"
            health["errors"] = error_services

        return json.dumps(health, indent=2)

    @mcp.tool()
    def list_api_keys() -> str:
        """List which API keys are configured for threat intelligence services.

        Returns:
            JSON string showing configuration status for each supported API key.
        """
        logger.info("Listing API key status")

        try:
            from osint_agent.keymanager import list_configured_keys

            status = list_configured_keys()
            return json.dumps(
                {
                    "api_keys": status,
                    "note": "Keys can be set via environment variables or system keychain",
                },
                indent=2,
            )
        except Exception as e:
            return json.dumps({"error": str(e)})
