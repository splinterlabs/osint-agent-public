"""STIX 2.1 export tools."""

from __future__ import annotations

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from osint_agent.stix_export import iocs_to_stix_bundle

logger = logging.getLogger("osint-mcp.stix")


def register_tools(mcp: FastMCP) -> None:
    """Register STIX export tools with the MCP server."""

    @mcp.tool()
    def iocs_to_stix(
        iocs_json: str,
        labels: Optional[str] = None,
        create_indicators: bool = True,
    ) -> str:
        """Convert extracted IOCs to a STIX 2.1 bundle.

        Args:
            iocs_json: JSON string of IOCs (output from extract_iocs_from_text)
                or dict with IOC types as keys and lists of values
            labels: Comma-separated labels to apply (e.g., "malware,apt")
            create_indicators: Also create Indicator objects with STIX patterns (default: True)

        Returns:
            JSON string containing STIX 2.1 bundle with observables and indicators.
        """
        logger.info("Converting IOCs to STIX bundle")

        # Parse IOCs input
        try:
            iocs_data = json.loads(iocs_json)
            # Handle output from extract_iocs_from_text which has nested structure
            if "iocs" in iocs_data:
                iocs = iocs_data["iocs"]
            else:
                iocs = iocs_data
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid JSON input: {e}"})

        # Parse labels
        label_list = None
        if labels:
            label_list = [label.strip() for label in labels.split(",")]

        # Create STIX bundle
        bundle = iocs_to_stix_bundle(
            iocs=iocs,
            labels=label_list,
            create_indicators=create_indicators,
        )

        return bundle.to_json(indent=2)
