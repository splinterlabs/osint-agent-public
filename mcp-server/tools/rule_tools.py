"""Detection rule generation tools (YARA, Sigma)."""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from osint_agent.rules import (
    generate_yara_rule,
    generate_sigma_rule,
    generate_sigma_dns_rule,
    generate_sigma_firewall_rule,
)

logger = logging.getLogger("osint-mcp.rules")


def register_tools(mcp: FastMCP) -> None:
    """Register rule generation tools with the MCP server."""

    @mcp.tool()
    def generate_yara_from_hashes(
        rule_name: str,
        hashes_json: str,
        description: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> str:
        """Generate a YARA rule from file hashes.

        Args:
            rule_name: Name for the YARA rule
            hashes_json: JSON array of hash objects with 'type' (md5/sha1/sha256) and 'value'
                Example: [{"type": "sha256", "value": "abc123..."}, {"type": "md5", "value": "def456..."}]
            description: Optional rule description
            tags: Optional comma-separated tags (e.g., "malware,trojan,apt")

        Returns:
            YARA rule as string, ready to save to a .yar file.
        """
        logger.info(f"Generating YARA rule: {rule_name}")

        try:
            hashes = json.loads(hashes_json)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid JSON: {e}"})

        tag_list = None
        if tags:
            tag_list = [t.strip() for t in tags.split(",")]

        rule = generate_yara_rule(
            name=rule_name,
            hashes=hashes,
            description=description,
            tags=tag_list,
        )

        return json.dumps(
            {
                "rule_type": "YARA",
                "rule_name": rule_name,
                "hash_count": len(hashes),
                "rule": rule,
            },
            indent=2,
        )

    @mcp.tool()
    def generate_sigma_network(
        title: str,
        iocs_json: str,
        description: Optional[str] = None,
        level: str = "high",
        tags: Optional[str] = None,
    ) -> str:
        """Generate a Sigma rule for network IOCs (proxy/web logs).

        Args:
            title: Rule title
            iocs_json: JSON object with IOC types as keys (ipv4, ipv6, domain, url)
                Example: {"ipv4": ["1.2.3.4"], "domain": ["evil.com"]}
            description: Optional rule description
            level: Detection level (low/medium/high/critical)
            tags: Optional comma-separated MITRE ATT&CK tags

        Returns:
            Sigma rule as YAML string.
        """
        logger.info(f"Generating Sigma network rule: {title}")

        try:
            iocs = json.loads(iocs_json)
            # Handle nested structure from extract_iocs
            if "iocs" in iocs:
                iocs = iocs["iocs"]
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid JSON: {e}"})

        tag_list = None
        if tags:
            tag_list = [t.strip() for t in tags.split(",")]

        rule = generate_sigma_rule(
            title=title,
            iocs=iocs,
            description=description,
            level=level,
            tags=tag_list,
        )

        return json.dumps(
            {
                "rule_type": "Sigma",
                "logsource": "proxy",
                "title": title,
                "rule": rule,
            },
            indent=2,
        )

    @mcp.tool()
    def generate_sigma_dns(
        title: str,
        domains_json: str,
        description: Optional[str] = None,
        level: str = "high",
        tags: Optional[str] = None,
    ) -> str:
        """Generate a Sigma rule for DNS query detection.

        Args:
            title: Rule title
            domains_json: JSON array of malicious domains
                Example: ["evil.com", "malware.net"]
            description: Optional rule description
            level: Detection level (low/medium/high/critical)
            tags: Optional comma-separated MITRE ATT&CK tags

        Returns:
            Sigma rule as YAML string.
        """
        logger.info(f"Generating Sigma DNS rule: {title}")

        try:
            domains = json.loads(domains_json)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid JSON: {e}"})

        tag_list = None
        if tags:
            tag_list = [t.strip() for t in tags.split(",")]

        rule = generate_sigma_dns_rule(
            title=title,
            domains=domains,
            description=description,
            level=level,
            tags=tag_list,
        )

        return json.dumps(
            {
                "rule_type": "Sigma",
                "logsource": "dns",
                "title": title,
                "domain_count": len(domains),
                "rule": rule,
            },
            indent=2,
        )

    @mcp.tool()
    def generate_sigma_firewall(
        title: str,
        ips_json: str,
        description: Optional[str] = None,
        level: str = "high",
        direction: str = "both",
        tags: Optional[str] = None,
    ) -> str:
        """Generate a Sigma rule for firewall log detection.

        Args:
            title: Rule title
            ips_json: JSON array of malicious IPs
                Example: ["1.2.3.4", "5.6.7.8"]
            description: Optional rule description
            level: Detection level (low/medium/high/critical)
            direction: Traffic direction - "inbound", "outbound", or "both"
            tags: Optional comma-separated MITRE ATT&CK tags

        Returns:
            Sigma rule as YAML string.
        """
        logger.info(f"Generating Sigma firewall rule: {title}")

        try:
            ips = json.loads(ips_json)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid JSON: {e}"})

        tag_list = None
        if tags:
            tag_list = [t.strip() for t in tags.split(",")]

        rule = generate_sigma_firewall_rule(
            title=title,
            ips=ips,
            description=description,
            level=level,
            direction=direction,
            tags=tag_list,
        )

        return json.dumps(
            {
                "rule_type": "Sigma",
                "logsource": "firewall",
                "title": title,
                "ip_count": len(ips),
                "direction": direction,
                "rule": rule,
            },
            indent=2,
        )
