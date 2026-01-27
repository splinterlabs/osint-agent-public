"""Abuse.ch threat intelligence tools (URLhaus, MalwareBazaar, ThreatFox)."""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from osint_agent.clients.abusech import (
    URLhausClient,
    MalwareBazaarClient,
    ThreatFoxClient,
)
from osint_agent.keymanager import get_api_key

logger = logging.getLogger("osint-mcp.abusech")

# Lazy singletons
_urlhaus: Optional[URLhausClient] = None
_bazaar: Optional[MalwareBazaarClient] = None
_threatfox: Optional[ThreatFoxClient] = None


def _get_auth_key() -> Optional[str]:
    return get_api_key("ABUSECH_AUTH_KEY")


def get_urlhaus() -> URLhausClient:
    global _urlhaus
    if _urlhaus is None:
        _urlhaus = URLhausClient(api_key=_get_auth_key())
    return _urlhaus


def get_bazaar() -> MalwareBazaarClient:
    global _bazaar
    if _bazaar is None:
        _bazaar = MalwareBazaarClient(api_key=_get_auth_key())
    return _bazaar


def get_threatfox() -> ThreatFoxClient:
    global _threatfox
    if _threatfox is None:
        _threatfox = ThreatFoxClient(api_key=_get_auth_key())
    return _threatfox


def register_tools(mcp: FastMCP) -> None:
    """Register Abuse.ch tools with the MCP server."""

    # ============ URLhaus Tools ============

    @mcp.tool()
    def lookup_url_urlhaus(url: str) -> str:
        """Look up a URL in URLhaus malicious URL database.

        Args:
            url: URL to check for malicious activity

        Returns:
            JSON with URL status, threat type, tags, and associated payloads.
        """
        logger.info(f"Looking up URL in URLhaus: {url[:50]}...")

        client = get_urlhaus()
        result = client.lookup_url(url)

        return json.dumps(
            {"source": "URLhaus", "query": url, "data": result},
            indent=2,
            default=str,
        )

    @mcp.tool()
    def lookup_host_urlhaus(host: str) -> str:
        """Look up a host (domain/IP) in URLhaus.

        Args:
            host: Domain or IP address to check

        Returns:
            JSON with host reputation and associated malicious URLs.
        """
        logger.info(f"Looking up host in URLhaus: {host}")

        client = get_urlhaus()
        result = client.lookup_host(host)

        return json.dumps(
            {"source": "URLhaus", "query": host, "data": result},
            indent=2,
            default=str,
        )

    @mcp.tool()
    def get_recent_urls_urlhaus(limit: int = 100) -> str:
        """Get recently reported malicious URLs from URLhaus.

        Args:
            limit: Maximum number of URLs to return (max 1000)

        Returns:
            JSON with list of recent malicious URLs and their details.
        """
        logger.info(f"Getting recent URLhaus URLs (limit: {limit})")

        client = get_urlhaus()
        urls = client.get_recent(limit=limit)

        return json.dumps(
            {"source": "URLhaus", "count": len(urls), "urls": urls},
            indent=2,
            default=str,
        )

    # ============ MalwareBazaar Tools ============

    @mcp.tool()
    def lookup_hash_malwarebazaar(hash_value: str) -> str:
        """Look up a malware sample by hash in MalwareBazaar.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash of the sample

        Returns:
            JSON with sample details, tags, signatures, and intelligence.
        """
        logger.info(f"Looking up hash in MalwareBazaar: {hash_value[:16]}...")

        client = get_bazaar()
        result = client.lookup_hash(hash_value)

        return json.dumps(
            {"source": "MalwareBazaar", "query": hash_value, "data": result},
            indent=2,
            default=str,
        )

    @mcp.tool()
    def search_malware_bazaar(
        query: str,
        query_type: str = "tag",
        limit: int = 50,
    ) -> str:
        """Search MalwareBazaar for malware samples.

        Args:
            query: Search term (malware name or tag)
            query_type: Type of search - "tag" or "signature"
            limit: Maximum number of results

        Returns:
            JSON with list of matching malware samples.
        """
        logger.info(f"Searching MalwareBazaar: {query_type}={query}")

        client = get_bazaar()

        if query_type == "signature":
            samples = client.lookup_signature(query, limit=limit)
        else:
            samples = client.lookup_tag(query, limit=limit)

        return json.dumps(
            {
                "source": "MalwareBazaar",
                "query": query,
                "query_type": query_type,
                "count": len(samples),
                "samples": samples,
            },
            indent=2,
            default=str,
        )

    @mcp.tool()
    def get_recent_malware_bazaar(limit: int = 100) -> str:
        """Get recently submitted malware samples from MalwareBazaar.

        Args:
            limit: Maximum number of samples to return

        Returns:
            JSON with list of recent malware samples.
        """
        logger.info(f"Getting recent MalwareBazaar samples (limit: {limit})")

        client = get_bazaar()
        samples = client.get_recent(limit=limit)

        return json.dumps(
            {"source": "MalwareBazaar", "count": len(samples), "samples": samples},
            indent=2,
            default=str,
        )

    # ============ ThreatFox Tools ============

    @mcp.tool()
    def lookup_ioc_threatfox(ioc: str) -> str:
        """Look up an IOC in ThreatFox database.

        Args:
            ioc: IOC value (IP, domain, URL, or hash)

        Returns:
            JSON with IOC details, malware association, and confidence level.
        """
        logger.info(f"Looking up IOC in ThreatFox: {ioc[:50]}...")

        client = get_threatfox()
        result = client.lookup_ioc(ioc)

        return json.dumps(
            {"source": "ThreatFox", "query": ioc, "data": result},
            indent=2,
            default=str,
        )

    @mcp.tool()
    def search_threatfox(
        query: str,
        query_type: str = "malware",
        limit: int = 50,
    ) -> str:
        """Search ThreatFox for IOCs by malware family or tag.

        Args:
            query: Search term (malware name or tag)
            query_type: Type of search - "malware" or "tag"
            limit: Maximum number of results

        Returns:
            JSON with list of matching IOCs.
        """
        logger.info(f"Searching ThreatFox: {query_type}={query}")

        client = get_threatfox()

        if query_type == "tag":
            iocs = client.lookup_tag(query, limit=limit)
        else:
            iocs = client.lookup_malware(query, limit=limit)

        return json.dumps(
            {
                "source": "ThreatFox",
                "query": query,
                "query_type": query_type,
                "count": len(iocs),
                "iocs": iocs,
            },
            indent=2,
            default=str,
        )

    @mcp.tool()
    def get_recent_iocs_threatfox(days: int = 3) -> str:
        """Get recently reported IOCs from ThreatFox.

        Args:
            days: Number of days to look back (max 7)

        Returns:
            JSON with list of recent IOCs and their threat context.
        """
        logger.info(f"Getting recent ThreatFox IOCs (days: {days})")

        client = get_threatfox()
        iocs = client.get_recent(days=days)

        return json.dumps(
            {"source": "ThreatFox", "days": days, "count": len(iocs), "iocs": iocs},
            indent=2,
            default=str,
        )
