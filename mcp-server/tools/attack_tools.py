"""MITRE ATT&CK MCP tools."""

import sys
from pathlib import Path

# Add parent paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from osint_agent.clients.attack import ATTACKClient


def get_attack_client() -> ATTACKClient:
    """Get configured ATT&CK client."""
    cache_dir = Path(__file__).parent.parent.parent / "data" / "cache" / "attack"
    return ATTACKClient(cache_dir=cache_dir)


def register_tools(mcp):
    """Register ATT&CK tools with MCP server."""

    @mcp.tool()
    def attack_technique_lookup(technique_id: str) -> str:
        """Look up a MITRE ATT&CK technique by ID or name.

        Args:
            technique_id: ATT&CK ID (e.g., T1059.001) or technique name

        Returns:
            Technique details including tactics, platforms, and detection info
        """
        try:
            client = get_attack_client()
            technique = client.get_technique(technique_id)

            if not technique:
                return f"Technique '{technique_id}' not found in ATT&CK framework."

            lines = [
                f"## {technique['id']} - {technique['name']}",
                "",
                f"**URL:** {technique['url']}",
                f"**Tactics:** {', '.join(technique['tactics'])}",
                f"**Platforms:** {', '.join(technique['platforms'])}",
                "",
            ]

            if technique["is_subtechnique"]:
                lines.append("*This is a sub-technique*")
                lines.append("")

            if technique["deprecated"]:
                lines.append("**Warning:** This technique is deprecated")
                lines.append("")

            lines.append("### Description")
            # Truncate long descriptions
            desc = technique["description"]
            if len(desc) > 1000:
                desc = desc[:1000] + "..."
            lines.append(desc)
            lines.append("")

            if technique["permissions_required"]:
                lines.append(f"**Permissions Required:** {', '.join(technique['permissions_required'])}")

            if technique["data_sources"]:
                lines.append("")
                lines.append("### Data Sources")
                for ds in technique["data_sources"][:10]:
                    lines.append(f"- {ds}")

            if technique["detection"]:
                lines.append("")
                lines.append("### Detection")
                det = technique["detection"]
                if len(det) > 500:
                    det = det[:500] + "..."
                lines.append(det)

            return "\n".join(lines)

        except Exception as e:
            return f"ATT&CK lookup failed: {e}"

    @mcp.tool()
    def attack_search_techniques(
        query: str,
        tactic: str = "",
        platform: str = "",
    ) -> str:
        """Search ATT&CK techniques by keyword.

        Args:
            query: Search query (matches technique names and descriptions)
            tactic: Filter by tactic (e.g., "initial-access", "execution")
            platform: Filter by platform (e.g., "Windows", "Linux", "macOS")

        Returns:
            Matching techniques
        """
        try:
            client = get_attack_client()
            results = client.search_techniques(
                query,
                tactic=tactic if tactic else None,
                platform=platform if platform else None,
                limit=20,
            )

            if not results:
                return f"No techniques found matching '{query}'"

            lines = [
                f"## ATT&CK Techniques: '{query}'",
                "",
                f"Found {len(results)} techniques",
                "",
            ]

            for tech in results:
                tactics = ", ".join(tech["tactics"]) if tech["tactics"] else "N/A"
                lines.append(f"- **{tech['id']}** - {tech['name']}")
                lines.append(f"  - Tactics: {tactics}")

            return "\n".join(lines)

        except Exception as e:
            return f"ATT&CK search failed: {e}"

    @mcp.tool()
    def attack_list_tactics() -> str:
        """List all ATT&CK tactics in kill chain order.

        Returns:
            All tactics with IDs
        """
        try:
            client = get_attack_client()
            tactics = client.list_tactics()

            lines = [
                "## MITRE ATT&CK Tactics",
                "",
                "Listed in kill chain order:",
                "",
            ]

            for i, tactic in enumerate(tactics, 1):
                lines.append(f"{i}. **{tactic['id']}** - {tactic['name']} (`{tactic['shortname']}`)")

            return "\n".join(lines)

        except Exception as e:
            return f"Failed to list tactics: {e}"

    @mcp.tool()
    def attack_group_lookup(group_id: str) -> str:
        """Look up a threat actor/group in ATT&CK.

        Args:
            group_id: ATT&CK group ID (e.g., G0016) or name/alias

        Returns:
            Group details and aliases
        """
        try:
            client = get_attack_client()
            group = client.get_group(group_id)

            if not group:
                return f"Group '{group_id}' not found in ATT&CK framework."

            lines = [
                f"## {group['id']} - {group['name']}",
                "",
                f"**URL:** {group['url']}",
            ]

            if group["aliases"]:
                lines.append(f"**Aliases:** {', '.join(group['aliases'])}")

            lines.append("")
            lines.append("### Description")
            desc = group["description"]
            if len(desc) > 1500:
                desc = desc[:1500] + "..."
            lines.append(desc)

            return "\n".join(lines)

        except Exception as e:
            return f"Group lookup failed: {e}"

    @mcp.tool()
    def attack_software_lookup(software_id: str) -> str:
        """Look up malware or tool in ATT&CK.

        Args:
            software_id: ATT&CK software ID (e.g., S0154) or name

        Returns:
            Software details
        """
        try:
            client = get_attack_client()
            software = client.get_software(software_id)

            if not software:
                return f"Software '{software_id}' not found in ATT&CK framework."

            lines = [
                f"## {software['id']} - {software['name']}",
                "",
                f"**Type:** {software['type']}",
                f"**URL:** {software['url']}",
            ]

            if software["platforms"]:
                lines.append(f"**Platforms:** {', '.join(software['platforms'])}")

            if software["aliases"]:
                lines.append(f"**Aliases:** {', '.join(software['aliases'])}")

            lines.append("")
            lines.append("### Description")
            desc = software["description"]
            if len(desc) > 1000:
                desc = desc[:1000] + "..."
            lines.append(desc)

            return "\n".join(lines)

        except Exception as e:
            return f"Software lookup failed: {e}"

    @mcp.tool()
    def attack_map_behavior(behavior: str) -> str:
        """Map observed behavior to likely ATT&CK techniques.

        Args:
            behavior: Description of observed behavior (e.g., "executed PowerShell commands to download malware")

        Returns:
            Matching techniques with confidence
        """
        try:
            client = get_attack_client()
            results = client.map_behavior_to_techniques(behavior, limit=5)

            if not results:
                return f"No techniques found for: '{behavior}'"

            lines = [
                f"## Behavior Mapping",
                "",
                f"**Input:** {behavior}",
                "",
                "### Likely Techniques",
                "",
            ]

            for tech in results:
                confidence_pct = int(tech["confidence"] * 100)
                name = tech.get("name", "Unknown")
                tactics = ", ".join(tech.get("tactics", [])) if tech.get("tactics") else "N/A"
                lines.append(f"- **{tech['id']}** - {name} ({confidence_pct}% confidence)")
                lines.append(f"  - Tactics: {tactics}")

            lines.append("")
            lines.append("*Note: This is keyword-based matching. Review techniques for accuracy.*")

            return "\n".join(lines)

        except Exception as e:
            return f"Behavior mapping failed: {e}"
