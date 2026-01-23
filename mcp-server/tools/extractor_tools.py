"""IOC extraction tools."""

import json
import logging

from mcp.server.fastmcp import FastMCP

from osint_agent.extractors import extract_iocs

logger = logging.getLogger("osint-mcp.extractors")


def register_tools(mcp: FastMCP) -> None:
    """Register extractor tools with the MCP server."""

    @mcp.tool()
    def extract_iocs_from_text(content: str) -> str:
        """Extract Indicators of Compromise (IOCs) from text content.

        Extracts and validates: IPv4/IPv6 addresses, domains, URLs, email addresses,
        MD5/SHA1/SHA256 hashes, and CVE identifiers. Handles defanged IOCs
        (e.g., hxxp://, [.]com) and filters false positives.

        Args:
            content: Text content to search for IOCs (max 500KB)

        Returns:
            JSON string with extracted IOCs grouped by type.
        """
        logger.info(f"Extracting IOCs from {len(content)} characters of text")

        iocs = extract_iocs(content)

        # Count total IOCs
        total = sum(len(v) for v in iocs.values())

        return json.dumps(
            {
                "total_iocs": total,
                "iocs": iocs,
            },
            indent=2,
        )
