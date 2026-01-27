"""Context management tools for maintaining investigation state."""

import json
import logging
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from osint_agent.context import ContextManager
from osint_agent.usage import get_usage_tracker, track_tool
from tools.investigation_log_tools import start_new_log

logger = logging.getLogger("osint-mcp.context")

# Default context directory
CONTEXT_DIR = Path(__file__).parent.parent.parent / "data" / "context"

# Lazy singleton
_manager: Optional[ContextManager] = None


def get_manager() -> ContextManager:
    """Get or create context manager singleton."""
    global _manager
    if _manager is None:
        _manager = ContextManager(CONTEXT_DIR)
    return _manager


def register_tools(mcp: FastMCP) -> None:
    """Register context management tools with the MCP server."""

    @mcp.tool()
    @track_tool("get_context_summary")
    def get_context_summary() -> str:
        """Get a summary of the current context state.

        Returns:
            JSON string with summary of all context tiers including
            investigation status, IOC count, and findings.
        """
        logger.info("Getting context summary")

        manager = get_manager()
        summary = manager.get_summary()

        return json.dumps(
            {"context_summary": summary},
            indent=2,
        )

    @mcp.tool()
    @track_tool("get_context")
    def get_context(tier: str, key: Optional[str] = None) -> str:
        """Get context data from a specific tier.

        Args:
            tier: Context tier - one of:
                - strategic: Long-term objectives and threat landscape
                - operational: Current investigation scope
                - tactical: Session priorities, active IOCs, findings
                - technical: API configs and tool settings
                - security: Classification and handling rules
            key: Optional specific key to retrieve

        Returns:
            JSON string with context data.
        """
        logger.info(f"Getting context: tier={tier}, key={key}")

        manager = get_manager()

        try:
            data = manager.get(tier, key)
            return json.dumps(
                {"tier": tier, "key": key, "data": data},
                indent=2,
                default=str,
            )
        except ValueError as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    @track_tool("set_context")
    def set_context(tier: str, key: str, value_json: str) -> str:
        """Set a context value.

        Args:
            tier: Context tier
            key: Key to set
            value_json: JSON-encoded value to set

        Returns:
            Confirmation message.
        """
        logger.info(f"Setting context: tier={tier}, key={key}")

        manager = get_manager()

        try:
            value = json.loads(value_json)
        except json.JSONDecodeError:
            # Treat as string if not valid JSON
            value = value_json

        try:
            manager.set(tier, key, value)
            return json.dumps(
                {"status": "success", "tier": tier, "key": key},
                indent=2,
            )
        except ValueError as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    @track_tool("start_investigation")
    def start_investigation(
        name: str,
        description: str = "",
        scope: str = "",
        stakeholders: Optional[str] = None,
    ) -> str:
        """Start a new investigation.

        This resets operational and tactical context tiers.

        Args:
            name: Investigation name
            description: Investigation description
            scope: Investigation scope
            stakeholders: Comma-separated list of stakeholders

        Returns:
            Confirmation with investigation details.
        """
        logger.info(f"Starting investigation: {name}")

        manager = get_manager()

        stakeholder_list = None
        if stakeholders:
            stakeholder_list = [s.strip() for s in stakeholders.split(",")]

        manager.start_investigation(
            name=name,
            description=description,
            scope=scope,
            stakeholders=stakeholder_list,
        )

        get_usage_tracker().reset(name)
        log_file = start_new_log(name)

        return json.dumps(
            {
                "status": "investigation_started",
                "name": name,
                "log_file": log_file,
                "message": "Operational and tactical contexts have been reset.",
            },
            indent=2,
        )

    @mcp.tool()
    @track_tool("add_ioc_to_context")
    def add_ioc_to_context(
        ioc_type: str,
        value: str,
        confidence: float = 0.5,
        source: str = "",
        tags: Optional[str] = None,
    ) -> str:
        """Add an IOC to the tactical context.

        Args:
            ioc_type: Type (ipv4, ipv6, domain, url, md5, sha1, sha256, email)
            value: IOC value
            confidence: Confidence level 0.0-1.0 (default: 0.5)
            source: Source of the IOC
            tags: Comma-separated tags

        Returns:
            Confirmation with IOC details.
        """
        logger.info(f"Adding IOC: {ioc_type}:{value[:30]}...")

        manager = get_manager()

        tag_list = None
        if tags:
            tag_list = [t.strip() for t in tags.split(",")]

        manager.add_ioc(
            ioc_type=ioc_type,
            value=value,
            confidence=confidence,
            source=source,
            tags=tag_list,
        )

        return json.dumps(
            {
                "status": "ioc_added",
                "type": ioc_type,
                "value": value,
                "confidence": confidence,
            },
            indent=2,
        )

    @mcp.tool()
    @track_tool("add_finding")
    def add_finding(
        title: str,
        description: str,
        confidence: float = 0.5,
        evidence: Optional[str] = None,
    ) -> str:
        """Add a finding to the tactical context.

        Args:
            title: Finding title
            description: Finding description
            confidence: Confidence level 0.0-1.0 (default: 0.5)
            evidence: Comma-separated evidence references

        Returns:
            Confirmation with finding details.
        """
        logger.info(f"Adding finding: {title}")

        manager = get_manager()

        evidence_list = None
        if evidence:
            evidence_list = [e.strip() for e in evidence.split(",")]

        manager.add_finding(
            title=title,
            description=description,
            confidence=confidence,
            evidence=evidence_list,
        )

        return json.dumps(
            {
                "status": "finding_added",
                "title": title,
                "confidence": confidence,
            },
            indent=2,
        )

    @mcp.tool()
    @track_tool("get_active_iocs")
    def get_active_iocs() -> str:
        """Get all active IOCs from tactical context.

        Returns:
            JSON string with list of active IOCs.
        """
        logger.info("Getting active IOCs")

        manager = get_manager()
        iocs = manager.get("tactical", "active_iocs") or []

        return json.dumps(
            {
                "count": len(iocs),
                "iocs": iocs,
            },
            indent=2,
            default=str,
        )

    @mcp.tool()
    @track_tool("get_findings")
    def get_findings() -> str:
        """Get all findings from tactical context.

        Returns:
            JSON string with list of findings.
        """
        logger.info("Getting findings")

        manager = get_manager()
        findings = manager.get("tactical", "findings") or []

        return json.dumps(
            {
                "count": len(findings),
                "findings": findings,
            },
            indent=2,
            default=str,
        )

    @mcp.tool()
    @track_tool("get_investigation_usage")
    def get_investigation_usage() -> str:
        """Get usage statistics for the current investigation.

        Returns tool call counts and API request counts accumulated since
        the last call to start_investigation(). Also persists the snapshot
        to the tactical context tier.

        Returns:
            JSON string with usage statistics including per-tool and
            per-service breakdowns.
        """
        logger.info("Getting investigation usage stats")

        tracker = get_usage_tracker()
        stats = tracker.get_stats()

        # Persist to tactical context
        manager = get_manager()
        manager.set("tactical", "usage_stats", stats)

        return json.dumps(stats, indent=2, default=str)
