"""Shodan MCP tools for host and service enumeration."""

from __future__ import annotations

import sys
from pathlib import Path

# Add parent paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from osint_agent.clients.shodan import ShodanClient
from osint_agent.keymanager import get_api_key


def get_shodan_client() -> ShodanClient:
    """Get configured Shodan client."""
    api_key = get_api_key("SHODAN_API_KEY")
    if not api_key:
        raise ValueError(
            "Shodan API key not configured. "
            "Run: python -m osint_agent.cli keys set SHODAN_API_KEY"
        )
    return ShodanClient(api_key=api_key)


def register_tools(mcp):
    """Register Shodan tools with MCP server."""

    @mcp.tool()
    def shodan_host_lookup(ip: str, include_history: bool = False) -> str:
        """Look up detailed information about an IP address using Shodan.

        Returns open ports, services, vulnerabilities, organization info,
        and geolocation data.

        Args:
            ip: IP address to look up
            include_history: Include historical service banners

        Returns:
            Formatted host information
        """
        try:
            client = get_shodan_client()
            result = client.host(ip, history=include_history)

            lines = [
                f"## Shodan Host: {result['ip']}",
                "",
                f"**Organization:** {result['org']}",
                f"**ISP:** {result['isp']}",
                f"**ASN:** {result['asn']}",
                f"**Location:** {result['city']}, {result['country']} ({result['country_code']})",
                f"**Last Updated:** {result['last_update']}",
                "",
            ]

            if result["hostnames"]:
                lines.append(f"**Hostnames:** {', '.join(result['hostnames'])}")
            if result["domains"]:
                lines.append(f"**Domains:** {', '.join(result['domains'])}")
            if result["tags"]:
                lines.append(f"**Tags:** {', '.join(result['tags'])}")

            lines.append("")
            lines.append(f"### Open Ports ({len(result['ports'])})")
            lines.append(f"`{', '.join(map(str, result['ports']))}`")
            lines.append("")

            if result["vulns"]:
                lines.append(f"### Vulnerabilities ({len(result['vulns'])})")
                for vuln in result["vulns"][:20]:
                    lines.append(f"- {vuln}")
                if len(result["vulns"]) > 20:
                    lines.append(f"- ... and {len(result['vulns']) - 20} more")
                lines.append("")

            if result["services"]:
                lines.append("### Services")
                for svc in result["services"][:10]:
                    port_info = f"{svc['port']}/{svc['transport']}"
                    product = svc["product"] or "unknown"
                    version = f" {svc['version']}" if svc["version"] else ""
                    lines.append(f"- **{port_info}**: {product}{version}")
                    if svc["cpe"]:
                        lines.append(f"  - CPE: `{svc['cpe'][0]}`")

            return "\n".join(lines)

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Shodan lookup failed: {e}"

    @mcp.tool()
    def shodan_search(
        query: str,
        page: int = 1,
        facets: str = "",
    ) -> str:
        """Search Shodan for hosts matching a query.

        Example queries:
        - "apache country:US" - Apache servers in US
        - "port:22 org:Amazon" - SSH servers at Amazon
        - "ssl.cert.subject.cn:example.com" - SSL certs for domain
        - "product:nginx vuln:CVE-2021-23017" - Vulnerable nginx servers

        Args:
            query: Shodan search query
            page: Page number (1-indexed)
            facets: Comma-separated facets (e.g., "country,port,org")

        Returns:
            Search results summary
        """
        try:
            client = get_shodan_client()
            facet_list = [f.strip() for f in facets.split(",") if f.strip()] if facets else None
            result = client.search(query, page=page, facets=facet_list)

            lines = [
                f"## Shodan Search: `{query}`",
                "",
                f"**Total Results:** {result['total']:,}",
                f"**Page:** {page}",
                "",
            ]

            if result["facets"]:
                lines.append("### Facets")
                for facet_name, facet_data in result["facets"].items():
                    lines.append(f"**{facet_name}:**")
                    for item in facet_data[:5]:
                        lines.append(f"  - {item['value']}: {item['count']:,}")
                lines.append("")

            if result["matches"]:
                lines.append(f"### Results ({len(result['matches'])})")
                for match in result["matches"][:15]:
                    ip = match["ip"]
                    port = match["port"]
                    product = match["product"] or "unknown"
                    org = match["org"] or "N/A"
                    country = match["country"] or "N/A"
                    lines.append(f"- **{ip}:{port}** - {product} ({org}, {country})")
                    if match["vulns"]:
                        lines.append(f"  - Vulns: {', '.join(match['vulns'][:5])}")

            return "\n".join(lines)

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Shodan search failed: {e}"

    @mcp.tool()
    def shodan_dns_lookup(domain: str) -> str:
        """Get DNS information and subdomains for a domain.

        Args:
            domain: Domain name to look up

        Returns:
            DNS records and subdomains
        """
        try:
            client = get_shodan_client()
            result = client.domain(domain)

            lines = [
                f"## Shodan DNS: {result['domain']}",
                "",
            ]

            if result["tags"]:
                lines.append(f"**Tags:** {', '.join(result['tags'])}")
                lines.append("")

            if result["subdomains"]:
                lines.append(f"### Subdomains ({len(result['subdomains'])})")
                for sub in result["subdomains"][:30]:
                    lines.append(f"- {sub}.{domain}")
                if len(result["subdomains"]) > 30:
                    lines.append(f"- ... and {len(result['subdomains']) - 30} more")
                lines.append("")

            if result["records"]:
                lines.append(f"### DNS Records ({len(result['records'])})")
                # Group by type
                by_type: dict = {}
                for record in result["records"]:
                    rtype = record["type"]
                    if rtype not in by_type:
                        by_type[rtype] = []
                    by_type[rtype].append(record)

                for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]:
                    if rtype in by_type:
                        lines.append(f"**{rtype} Records:**")
                        for r in by_type[rtype][:10]:
                            sub = r["subdomain"] or "@"
                            lines.append(f"  - {sub}: {r['value']}")

            return "\n".join(lines)

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Shodan DNS lookup failed: {e}"

    @mcp.tool()
    def shodan_vuln_lookup(cve_id: str) -> str:
        """Look up vulnerability details from Shodan.

        Includes EPSS score, KEV status, and ransomware campaign info.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            Vulnerability details
        """
        try:
            client = get_shodan_client()
            result = client.vulnerabilities(cve_id)

            lines = [
                f"## {result['cve_id']}",
                "",
                f"**Summary:** {result['summary']}",
                "",
            ]

            if result["cvss"]:
                lines.append(f"**CVSS v2:** {result['cvss']}")
            if result["cvss_v3"]:
                lines.append(f"**CVSS v3:** {result['cvss_v3']}")
            if result["epss"]:
                lines.append(f"**EPSS Score:** {result['epss']:.2%}")
            if result["kev"]:
                lines.append("**CISA KEV:** Yes - Known Exploited")
            if result["ransomware_campaign"]:
                lines.append(f"**Ransomware:** {result['ransomware_campaign']}")
            if result["proposed_action"]:
                lines.append(f"**Proposed Action:** {result['proposed_action']}")
            if result["published"]:
                lines.append(f"**Published:** {result['published']}")

            if result["cpe"]:
                lines.append("")
                lines.append("### Affected Products")
                for cpe in result["cpe"][:10]:
                    lines.append(f"- `{cpe}`")

            if result["references"]:
                lines.append("")
                lines.append("### References")
                for ref in result["references"][:10]:
                    lines.append(f"- {ref}")

            return "\n".join(lines)

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Shodan vulnerability lookup failed: {e}"

    @mcp.tool()
    def shodan_exploit_search(query: str) -> str:
        """Search for exploits related to a vulnerability or product.

        Args:
            query: Search query (e.g., CVE ID, product name)

        Returns:
            Matching exploits from various sources
        """
        try:
            client = get_shodan_client()
            result = client.exploits_search(query)

            lines = [
                f"## Exploit Search: `{query}`",
                "",
                f"**Total Results:** {result['total']}",
                "",
            ]

            if result["exploits"]:
                lines.append("### Exploits")
                for exp in result["exploits"][:15]:
                    source = exp["source"]
                    desc = exp["description"][:100] + "..." if len(exp["description"]) > 100 else exp["description"]
                    lines.append(f"- **[{source}]** {desc}")
                    if exp["cve"]:
                        lines.append(f"  - CVEs: {', '.join(exp['cve'][:5])}")
                    if exp["platform"]:
                        lines.append(f"  - Platform: {exp['platform']}")
            else:
                lines.append("No exploits found.")

            return "\n".join(lines)

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Exploit search failed: {e}"
