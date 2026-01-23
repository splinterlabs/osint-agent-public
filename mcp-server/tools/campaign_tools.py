"""Campaign tracking MCP tools."""

from __future__ import annotations

import sys
from pathlib import Path

# Add parent paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from osint_agent.campaigns import (
    CampaignManager,
    CampaignStatus,
    ConfidenceLevel,
)
from osint_agent.correlation import CorrelationEngine


def get_campaign_manager() -> CampaignManager:
    """Get campaign manager instance."""
    data_dir = Path(__file__).parent.parent.parent / "data" / "campaigns"
    return CampaignManager(data_dir=data_dir)


def get_correlation_engine() -> CorrelationEngine:
    """Get correlation engine with campaign manager."""
    manager = get_campaign_manager()
    return CorrelationEngine(campaign_manager=manager)


def register_tools(mcp):
    """Register campaign tools with MCP server."""

    @mcp.tool()
    def campaign_create(
        name: str,
        description: str,
        threat_actor: str = "",
        tags: str = "",
    ) -> str:
        """Create a new threat campaign for tracking.

        Args:
            name: Campaign name (e.g., "Operation Cobalt Strike")
            description: Campaign description
            threat_actor: Attributed threat actor (if known)
            tags: Comma-separated tags

        Returns:
            Created campaign details
        """
        try:
            manager = get_campaign_manager()

            # Check if campaign with same name exists
            existing = manager.get_by_name(name)
            if existing:
                return f"Campaign '{name}' already exists (ID: {existing.id})"

            tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

            campaign = manager.create(
                name=name,
                description=description,
                threat_actor=threat_actor if threat_actor else None,
                tags=tag_list,
            )

            return f"""## Campaign Created

**ID:** {campaign.id}
**Name:** {campaign.name}
**Status:** {campaign.status.value}
**Created:** {campaign.created_at}

{f"**Threat Actor:** {campaign.threat_actor}" if campaign.threat_actor else ""}
{f"**Tags:** {', '.join(campaign.tags)}" if campaign.tags else ""}

**Description:**
{campaign.description}

Use `campaign_add_ioc` to add indicators to this campaign."""

        except Exception as e:
            return f"Failed to create campaign: {e}"

    @mcp.tool()
    def campaign_list(status: str = "", tag: str = "") -> str:
        """List all tracked campaigns.

        Args:
            status: Filter by status (active, monitoring, contained, resolved, archived)
            tag: Filter by tag

        Returns:
            List of campaigns
        """
        try:
            manager = get_campaign_manager()

            status_filter = None
            if status:
                try:
                    status_filter = CampaignStatus(status.lower())
                except ValueError:
                    return f"Invalid status '{status}'. Valid: active, monitoring, contained, resolved, archived"

            campaigns = manager.list(
                status=status_filter,
                tag=tag if tag else None,
            )

            if not campaigns:
                return "No campaigns found."

            lines = [
                "## Tracked Campaigns",
                "",
                f"Total: {len(campaigns)}",
                "",
            ]

            for c in campaigns[:20]:
                status_emoji = {
                    "active": "🔴",
                    "monitoring": "🟡",
                    "contained": "🟢",
                    "resolved": "✅",
                    "archived": "📦",
                }.get(c.status.value, "⚪")

                lines.append(f"### {status_emoji} {c.name} ({c.id})")
                lines.append(f"**Status:** {c.status.value} | **Updated:** {c.updated_at[:10]}")
                if c.threat_actor:
                    lines.append(f"**Threat Actor:** {c.threat_actor}")
                lines.append(f"**IOCs:** {len(c.iocs)} | **TTPs:** {len(c.ttps)} | **CVEs:** {len(c.cves)}")
                lines.append("")

            return "\n".join(lines)

        except Exception as e:
            return f"Failed to list campaigns: {e}"

    @mcp.tool()
    def campaign_get(campaign_id: str) -> str:
        """Get detailed information about a campaign.

        Args:
            campaign_id: Campaign ID

        Returns:
            Full campaign details
        """
        try:
            manager = get_campaign_manager()
            campaign = manager.get(campaign_id)

            if not campaign:
                # Try by name
                campaign = manager.get_by_name(campaign_id)

            if not campaign:
                return f"Campaign '{campaign_id}' not found."

            lines = [
                f"## {campaign.name}",
                "",
                f"**ID:** {campaign.id}",
                f"**Status:** {campaign.status.value}",
                f"**Created:** {campaign.created_at}",
                f"**Updated:** {campaign.updated_at}",
            ]

            if campaign.threat_actor:
                lines.append(f"**Threat Actor:** {campaign.threat_actor}")
                if campaign.threat_actor_aliases:
                    lines.append(f"**Aliases:** {', '.join(campaign.threat_actor_aliases)}")

            if campaign.tags:
                lines.append(f"**Tags:** {', '.join(campaign.tags)}")

            lines.append("")
            lines.append("### Description")
            lines.append(campaign.description)

            if campaign.targeted_sectors:
                lines.append("")
                lines.append(f"**Targeted Sectors:** {', '.join(campaign.targeted_sectors)}")

            if campaign.targeted_regions:
                lines.append(f"**Targeted Regions:** {', '.join(campaign.targeted_regions)}")

            if campaign.malware_families:
                lines.append(f"**Malware Families:** {', '.join(campaign.malware_families)}")

            if campaign.cves:
                lines.append("")
                lines.append(f"### CVEs Exploited ({len(campaign.cves)})")
                for cve in campaign.cves[:10]:
                    lines.append(f"- {cve}")

            if campaign.ttps:
                lines.append("")
                lines.append(f"### TTPs ({len(campaign.ttps)})")
                for ttp in campaign.ttps[:15]:
                    lines.append(f"- **{ttp.technique_id}** - {ttp.technique_name} ({ttp.tactic})")

            if campaign.iocs:
                lines.append("")
                lines.append(f"### IOCs ({len(campaign.iocs)})")

                # Group by type
                by_type: dict = {}
                for ioc in campaign.iocs:
                    if ioc.ioc_type not in by_type:
                        by_type[ioc.ioc_type] = []
                    by_type[ioc.ioc_type].append(ioc)

                for ioc_type, iocs in by_type.items():
                    lines.append(f"**{ioc_type}** ({len(iocs)}):")
                    for ioc in iocs[:5]:
                        lines.append(f"  - `{ioc.value}`")
                    if len(iocs) > 5:
                        lines.append(f"  - ... and {len(iocs) - 5} more")

            if campaign.references:
                lines.append("")
                lines.append("### References")
                for ref in campaign.references[:10]:
                    lines.append(f"- {ref}")

            if campaign.notes:
                lines.append("")
                lines.append("### Notes")
                lines.append(campaign.notes)

            return "\n".join(lines)

        except Exception as e:
            return f"Failed to get campaign: {e}"

    @mcp.tool()
    def campaign_add_ioc(
        campaign_id: str,
        ioc_type: str,
        value: str,
        source: str = "manual",
        confidence: str = "medium",
        notes: str = "",
    ) -> str:
        """Add an IOC to a campaign.

        Args:
            campaign_id: Campaign ID
            ioc_type: Type of IOC (ipv4, ipv6, domain, md5, sha1, sha256, url, email)
            value: IOC value
            source: Source of the IOC
            confidence: Confidence level (low, medium, high, confirmed)
            notes: Additional notes

        Returns:
            Confirmation
        """
        try:
            manager = get_campaign_manager()
            campaign = manager.get(campaign_id)

            if not campaign:
                campaign = manager.get_by_name(campaign_id)

            if not campaign:
                return f"Campaign '{campaign_id}' not found."

            try:
                conf_level = ConfidenceLevel(confidence.lower())
            except ValueError:
                conf_level = ConfidenceLevel.MEDIUM

            ioc = campaign.add_ioc(
                ioc_type=ioc_type,
                value=value,
                source=source,
                confidence=conf_level,
                notes=notes,
            )
            manager.update(campaign)

            return f"Added {ioc_type} `{value}` to campaign '{campaign.name}' (confidence: {conf_level.value})"

        except Exception as e:
            return f"Failed to add IOC: {e}"

    @mcp.tool()
    def campaign_add_ttp(
        campaign_id: str,
        technique_id: str,
        technique_name: str,
        tactic: str,
        evidence: str,
        confidence: str = "medium",
    ) -> str:
        """Add a TTP (ATT&CK technique) to a campaign.

        Args:
            campaign_id: Campaign ID
            technique_id: ATT&CK technique ID (e.g., T1059.001)
            technique_name: Technique name
            tactic: ATT&CK tactic (e.g., execution, persistence)
            evidence: Description of observed evidence
            confidence: Confidence level (low, medium, high, confirmed)

        Returns:
            Confirmation
        """
        try:
            manager = get_campaign_manager()
            campaign = manager.get(campaign_id)

            if not campaign:
                campaign = manager.get_by_name(campaign_id)

            if not campaign:
                return f"Campaign '{campaign_id}' not found."

            try:
                conf_level = ConfidenceLevel(confidence.lower())
            except ValueError:
                conf_level = ConfidenceLevel.MEDIUM

            ttp = campaign.add_ttp(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                evidence=evidence,
                confidence=conf_level,
            )
            manager.update(campaign)

            return f"Added TTP {technique_id} ({technique_name}) to campaign '{campaign.name}'"

        except Exception as e:
            return f"Failed to add TTP: {e}"

    @mcp.tool()
    def campaign_add_cve(campaign_id: str, cve_id: str) -> str:
        """Add a CVE to a campaign.

        Args:
            campaign_id: Campaign ID
            cve_id: CVE identifier (e.g., CVE-2024-3400)

        Returns:
            Confirmation
        """
        try:
            manager = get_campaign_manager()
            campaign = manager.get(campaign_id)

            if not campaign:
                campaign = manager.get_by_name(campaign_id)

            if not campaign:
                return f"Campaign '{campaign_id}' not found."

            campaign.add_cve(cve_id)
            manager.update(campaign)

            return f"Added {cve_id} to campaign '{campaign.name}'"

        except Exception as e:
            return f"Failed to add CVE: {e}"

    @mcp.tool()
    def campaign_update_status(campaign_id: str, status: str) -> str:
        """Update campaign status.

        Args:
            campaign_id: Campaign ID
            status: New status (active, monitoring, contained, resolved, archived)

        Returns:
            Confirmation
        """
        try:
            manager = get_campaign_manager()
            campaign = manager.get(campaign_id)

            if not campaign:
                campaign = manager.get_by_name(campaign_id)

            if not campaign:
                return f"Campaign '{campaign_id}' not found."

            try:
                new_status = CampaignStatus(status.lower())
            except ValueError:
                return f"Invalid status '{status}'. Valid: active, monitoring, contained, resolved, archived"

            old_status = campaign.status.value
            campaign.update_status(new_status)
            manager.update(campaign)

            return f"Updated campaign '{campaign.name}' status: {old_status} → {new_status.value}"

        except Exception as e:
            return f"Failed to update status: {e}"

    @mcp.tool()
    def campaign_find_by_ioc(ioc_type: str, value: str) -> str:
        """Find campaigns containing an IOC.

        Args:
            ioc_type: Type of IOC
            value: IOC value

        Returns:
            Matching campaigns
        """
        try:
            manager = get_campaign_manager()
            campaigns = manager.find_by_ioc(ioc_type, value)

            if not campaigns:
                return f"No campaigns found containing {ioc_type}: `{value}`"

            lines = [
                f"## Campaigns with {ioc_type}: `{value}`",
                "",
            ]

            for c in campaigns:
                lines.append(f"- **{c.name}** ({c.id}) - {c.status.value}")
                if c.threat_actor:
                    lines.append(f"  - Threat Actor: {c.threat_actor}")

            return "\n".join(lines)

        except Exception as e:
            return f"Failed to find campaigns: {e}"

    @mcp.tool()
    def campaign_correlate(campaign_id: str) -> str:
        """Perform correlation analysis on a campaign.

        Args:
            campaign_id: Campaign ID

        Returns:
            Correlation analysis results
        """
        try:
            engine = get_correlation_engine()
            results = engine.correlate_campaign_iocs(campaign_id)

            if "error" in results:
                return results["error"]

            lines = [
                f"## Correlation Analysis: {results['campaign_name']}",
                "",
                f"**Total IOCs:** {results['total_iocs']}",
                "",
            ]

            if results["ioc_types"]:
                lines.append("### IOC Distribution")
                for ioc_type, count in results["ioc_types"].items():
                    lines.append(f"- {ioc_type}: {count}")
                lines.append("")

            if results["infrastructure_patterns"]:
                lines.append("### Infrastructure Patterns")
                for pattern, domains in results["infrastructure_patterns"].items():
                    lines.append(f"**{pattern}:** {len(domains)} domains")
                    for d in domains[:3]:
                        lines.append(f"  - {d}")
                lines.append("")

            if results["related_campaigns"]:
                lines.append("### Related Campaigns")
                lines.append(f"Found {len(results['related_campaigns'])} campaigns with shared IOCs:")
                for cid in results["related_campaigns"][:5]:
                    lines.append(f"- {cid}")
                lines.append("")

            if results["technique_coverage"]:
                lines.append("### Technique Coverage by Tactic")
                for tactic, techniques in results["technique_coverage"].items():
                    lines.append(f"**{tactic}:** {', '.join(techniques)}")

            return "\n".join(lines)

        except Exception as e:
            return f"Correlation analysis failed: {e}"

    @mcp.tool()
    def campaign_statistics() -> str:
        """Get overall campaign statistics.

        Returns:
            Campaign statistics
        """
        try:
            manager = get_campaign_manager()
            stats = manager.get_statistics()

            lines = [
                "## Campaign Statistics",
                "",
                f"**Total Campaigns:** {stats['total_campaigns']}",
                f"**Total IOCs:** {stats['total_iocs']}",
                f"**Total TTPs:** {stats['total_ttps']}",
                "",
                "### By Status",
            ]

            for status, count in stats["by_status"].items():
                emoji = {
                    "active": "🔴",
                    "monitoring": "🟡",
                    "contained": "🟢",
                    "resolved": "✅",
                    "archived": "📦",
                }.get(status, "⚪")
                lines.append(f"- {emoji} {status}: {count}")

            return "\n".join(lines)

        except Exception as e:
            return f"Failed to get statistics: {e}"
