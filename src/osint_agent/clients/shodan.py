"""Shodan API client for host and service enumeration."""

from __future__ import annotations

import logging
from typing import Any, Optional

from .base import BaseClient, ProxyConfig

logger = logging.getLogger(__name__)


class ShodanClient(BaseClient):
    """Client for Shodan API.

    Shodan is a search engine for internet-connected devices. This client
    provides access to host information, service banners, and vulnerability data.

    API Documentation: https://developer.shodan.io/api
    """

    BASE_URL = "https://api.shodan.io"

    def __init__(
        self,
        api_key: str,
        timeout: Optional[int] = None,
        proxy: Optional[ProxyConfig] = None,
    ):
        """Initialize Shodan client.

        Args:
            api_key: Shodan API key (required)
            timeout: Request timeout in seconds
            proxy: Proxy configuration
        """
        if not api_key:
            raise ValueError("Shodan API key is required")
        super().__init__(api_key=api_key, timeout=timeout, proxy=proxy)

    def _get_headers(self) -> dict[str, str]:
        """Get headers for Shodan API requests."""
        return {}

    def _add_key(self, params: Optional[dict] = None) -> dict:
        """Add API key to request parameters."""
        params = params or {}
        params["key"] = self.api_key
        return params

    def host(self, ip: str, history: bool = False, minify: bool = False) -> dict[str, Any]:
        """Get all available information for an IP address.

        Args:
            ip: IP address to look up
            history: Include historical banners
            minify: Return only basic host information

        Returns:
            Host information including:
            - ip_str: IP address
            - hostnames: List of hostnames
            - ports: List of open ports
            - vulns: List of CVE IDs (if available)
            - data: List of service banners
            - org: Organization name
            - isp: ISP name
            - asn: ASN
            - country_code: Country code
            - city: City name
        """
        params = self._add_key()
        if history:
            params["history"] = "true"
        if minify:
            params["minify"] = "true"

        result = self.get(f"/shodan/host/{ip}", params=params)
        return self._parse_host(result)

    def _parse_host(self, data: dict) -> dict[str, Any]:
        """Parse host response into standardized format."""
        # Extract vulnerabilities from service data
        vulns = set()
        for service in data.get("data", []):
            if "vulns" in service:
                vulns.update(service["vulns"].keys())

        return {
            "ip": data.get("ip_str", ""),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "asn": data.get("asn", ""),
            "country": data.get("country_name", ""),
            "country_code": data.get("country_code", ""),
            "city": data.get("city", ""),
            "ports": data.get("ports", []),
            "vulns": list(vulns),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update", ""),
            "services": [
                {
                    "port": svc.get("port"),
                    "transport": svc.get("transport", "tcp"),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "cpe": svc.get("cpe", []),
                    "banner": svc.get("data", "")[:500],  # Truncate large banners
                }
                for svc in data.get("data", [])[:20]  # Limit services
            ],
        }

    def search(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
        facets: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Search Shodan for hosts matching a query.

        Args:
            query: Shodan search query (e.g., "apache country:US")
            page: Page number for pagination
            limit: Maximum results (up to 100 per page)
            facets: List of facets to include (e.g., ["country", "port"])

        Returns:
            Search results including:
            - total: Total number of results
            - matches: List of matching hosts
            - facets: Aggregated data (if requested)
        """
        params = self._add_key({"query": query, "page": page})
        if facets:
            params["facets"] = ",".join(facets)

        result = self.get("/shodan/host/search", params=params)

        return {
            "total": result.get("total", 0),
            "matches": [
                {
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port"),
                    "transport": match.get("transport", "tcp"),
                    "hostnames": match.get("hostnames", []),
                    "domains": match.get("domains", []),
                    "org": match.get("org", ""),
                    "product": match.get("product", ""),
                    "version": match.get("version", ""),
                    "cpe": match.get("cpe", []),
                    "vulns": list(match.get("vulns", {}).keys()),
                    "country": match.get("location", {}).get("country_name", ""),
                    "city": match.get("location", {}).get("city", ""),
                }
                for match in result.get("matches", [])[:limit]
            ],
            "facets": result.get("facets", {}),
        }

    def search_count(self, query: str, facets: Optional[list[str]] = None) -> dict[str, Any]:
        """Get the number of results for a search query (without results).

        This is faster and doesn't consume query credits.

        Args:
            query: Shodan search query
            facets: List of facets to include

        Returns:
            Count and facet data
        """
        params = self._add_key({"query": query})
        if facets:
            params["facets"] = ",".join(facets)

        result = self.get("/shodan/host/count", params=params)
        return {
            "total": result.get("total", 0),
            "facets": result.get("facets", {}),
        }

    def resolve(self, hostnames: list[str]) -> dict[str, Optional[str]]:
        """Resolve hostnames to IP addresses.

        Args:
            hostnames: List of hostnames to resolve

        Returns:
            Dictionary mapping hostnames to IP addresses
        """
        params = self._add_key({"hostnames": ",".join(hostnames[:100])})
        return self.get("/dns/resolve", params=params)

    def reverse(self, ips: list[str]) -> dict[str, list[str]]:
        """Reverse DNS lookup for IP addresses.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary mapping IPs to lists of hostnames
        """
        params = self._add_key({"ips": ",".join(ips[:100])})
        return self.get("/dns/reverse", params=params)

    def domain(self, domain: str) -> dict[str, Any]:
        """Get DNS information for a domain.

        Args:
            domain: Domain name to look up

        Returns:
            DNS records and subdomains
        """
        params = self._add_key()
        result = self.get(f"/dns/domain/{domain}", params=params)

        return {
            "domain": result.get("domain", domain),
            "tags": result.get("tags", []),
            "subdomains": result.get("subdomains", []),
            "records": [
                {
                    "subdomain": record.get("subdomain", ""),
                    "type": record.get("type", ""),
                    "value": record.get("value", ""),
                    "last_seen": record.get("last_seen", ""),
                }
                for record in result.get("data", [])
            ],
        }

    def exploits_search(self, query: str, page: int = 1) -> dict[str, Any]:
        """Search for exploits matching a query.

        Args:
            query: Search query (e.g., CVE ID or product name)
            page: Page number

        Returns:
            Matching exploits from various sources
        """
        params = self._add_key({"query": query, "page": page})
        result = self.get("/api-ms/exploits", params=params)

        return {
            "total": result.get("total", 0),
            "exploits": [
                {
                    "id": exp.get("_id", ""),
                    "source": exp.get("source", ""),
                    "description": exp.get("description", ""),
                    "cve": exp.get("cve", []),
                    "type": exp.get("type", ""),
                    "platform": exp.get("platform", ""),
                    "author": exp.get("author", ""),
                }
                for exp in result.get("matches", [])
            ],
        }

    def api_info(self) -> dict[str, Any]:
        """Get information about the current API plan.

        Returns:
            API plan details including credits remaining
        """
        params = self._add_key()
        return self.get("/api-info", params=params)

    def vulnerabilities(self, cve_id: str) -> dict[str, Any]:
        """Get detailed vulnerability information.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            Vulnerability details including references and affected products
        """
        params = self._add_key()
        result = self.get(f"/shodan/cve/{cve_id}", params=params)

        return {
            "cve_id": result.get("cve_id", cve_id),
            "summary": result.get("summary", ""),
            "cvss": result.get("cvss", None),
            "cvss_v3": result.get("cvss_v3", None),
            "epss": result.get("epss", None),
            "kev": result.get("kev", False),
            "proposed_action": result.get("proposed_action", ""),
            "ransomware_campaign": result.get("ransomware_campaign", ""),
            "references": result.get("references", []),
            "cpe": result.get("cpe", []),
            "published": result.get("published_time", ""),
        }
