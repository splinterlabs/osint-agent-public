"""AlienVault OTX (Open Threat Exchange) API client."""

from __future__ import annotations

import logging
from typing import Any

from ..keymanager import get_api_key
from .base import BaseClient

logger = logging.getLogger(__name__)


class OTXClient(BaseClient):
    """Client for the AlienVault OTX DirectConnect API.

    OTX provides threat intelligence pulses containing IOCs, malware samples,
    and context from the security community.

    API docs: https://otx.alienvault.com/api
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"
    DEFAULT_TIMEOUT = 30
    CACHE_TTL_HOURS = 4

    def __init__(self, api_key: str | None = None):
        key = api_key or get_api_key("OTX_API_KEY")
        super().__init__(api_key=key)

    def _get_headers(self) -> dict[str, str]:
        headers = {}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        return headers

    def get_indicator(
        self,
        indicator_type: str,
        indicator: str,
        section: str = "general",
    ) -> dict[str, Any]:
        """Get details about an indicator (IOC).

        Args:
            indicator_type: Type of indicator (ipv4, domain, md5, sha256, url, cve)
            indicator: The indicator value
            section: Data section to retrieve:
                - general: Basic info and pulse references
                - reputation: Reputation data (IP only)
                - geo: Geolocation (IP only)
                - malware: Associated malware (hash only)
                - passive_dns: DNS history (IP/domain)
                - url_list: Associated URLs

        Returns:
            Indicator details from OTX
        """
        # Map indicator type to OTX type
        otx_type = self._map_indicator_type(indicator_type)

        endpoint = f"/indicators/{otx_type}/{indicator}/{section}"
        response = self.get(endpoint)

        return self._parse_indicator(response, indicator_type, indicator)

    def get_indicator_full(
        self,
        indicator_type: str,
        indicator: str,
    ) -> dict[str, Any]:
        """Get comprehensive details about an indicator.

        Fetches general info plus type-specific sections.

        Args:
            indicator_type: Type of indicator
            indicator: The indicator value

        Returns:
            Full indicator details with all relevant sections
        """
        result = self.get_indicator(indicator_type, indicator, "general")

        # Add type-specific sections
        if indicator_type in ("ipv4", "ipv6"):
            try:
                result["geo"] = self.get_indicator(indicator_type, indicator, "geo")
                result["reputation"] = self.get_indicator(indicator_type, indicator, "reputation")
                result["passive_dns"] = self.get_indicator(indicator_type, indicator, "passive_dns")
            except Exception as e:
                logger.warning("Failed to fetch IP enrichment for %s: %s", indicator, e)

        elif indicator_type == "domain":
            try:
                result["passive_dns"] = self.get_indicator(indicator_type, indicator, "passive_dns")
                result["url_list"] = self.get_indicator(indicator_type, indicator, "url_list")
            except Exception as e:
                logger.warning("Failed to fetch domain enrichment for %s: %s", indicator, e)

        elif indicator_type in ("md5", "sha1", "sha256"):
            try:
                result["malware"] = self.get_indicator(indicator_type, indicator, "analysis")
            except Exception as e:
                logger.warning("Failed to fetch file analysis for %s: %s", indicator, e)

        return result

    def get_pulse(self, pulse_id: str) -> dict[str, Any]:
        """Get details about a specific pulse.

        Args:
            pulse_id: OTX pulse ID

        Returns:
            Pulse details including IOCs
        """
        endpoint = f"/pulses/{pulse_id}"
        response = self.get(endpoint)

        return self._parse_pulse(response)

    def search_pulses(
        self,
        query: str,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """Search for pulses by keyword.

        Args:
            query: Search query (e.g., malware name, CVE, threat actor)
            max_results: Maximum number of results

        Returns:
            List of matching pulses
        """
        endpoint = "/search/pulses"
        params = {"q": query, "limit": max_results}

        response = self.get(endpoint, params=params)

        pulses = []
        for result in response.get("results", []):
            pulses.append(self._parse_pulse(result))

        return pulses

    def get_subscribed_pulses(
        self,
        modified_since: str | None = None,
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        """Get pulses from subscribed feeds.

        Args:
            modified_since: ISO timestamp to filter by modification date
            max_results: Maximum number of results

        Returns:
            List of pulses from subscriptions
        """
        endpoint = "/pulses/subscribed"
        params = {"limit": max_results}
        if modified_since:
            params["modified_since"] = modified_since

        response = self.get(endpoint, params=params)

        pulses = []
        for result in response.get("results", []):
            pulses.append(self._parse_pulse(result))

        return pulses

    def _map_indicator_type(self, indicator_type: str) -> str:
        """Map our indicator type to OTX API type."""
        mapping = {
            "ipv4": "IPv4",
            "ipv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
            "url": "url",
            "md5": "file",
            "sha1": "file",
            "sha256": "file",
            "cve": "cve",
        }
        return mapping.get(indicator_type.lower(), indicator_type)

    def _parse_indicator(
        self,
        response: dict,
        indicator_type: str,
        indicator: str,
    ) -> dict[str, Any]:
        """Parse indicator response into standardized format."""
        pulse_info = response.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        return {
            "indicator": indicator,
            "type": indicator_type,
            "pulse_count": pulse_info.get("count", 0),
            "pulses": [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "author": p.get("author_name"),
                    "created": p.get("created"),
                    "tags": p.get("tags", []),
                    "targeted_countries": p.get("targeted_countries", []),
                    "malware_families": p.get("malware_families", []),
                    "attack_ids": p.get("attack_ids", []),
                }
                for p in pulses[:10]  # Limit to first 10 pulses
            ],
            "validation": response.get("validation", []),
            "asn": response.get("asn"),
            "country_code": response.get("country_code"),
            "country_name": response.get("country_name"),
        }

    def _parse_pulse(self, pulse: dict) -> dict[str, Any]:
        """Parse pulse data into standardized format."""
        indicators = pulse.get("indicators", [])

        # Group indicators by type
        iocs_by_type: dict[str, list[str]] = {}
        for ind in indicators:
            ind_type = ind.get("type", "unknown").lower()
            ind_value = ind.get("indicator", "")
            if ind_type not in iocs_by_type:
                iocs_by_type[ind_type] = []
            iocs_by_type[ind_type].append(ind_value)

        return {
            "id": pulse.get("id"),
            "name": pulse.get("name"),
            "description": pulse.get("description", ""),
            "author": pulse.get("author_name"),
            "created": pulse.get("created"),
            "modified": pulse.get("modified"),
            "tags": pulse.get("tags", []),
            "targeted_countries": pulse.get("targeted_countries", []),
            "malware_families": pulse.get("malware_families", []),
            "attack_ids": pulse.get("attack_ids", []),
            "references": pulse.get("references", []),
            "indicator_count": len(indicators),
            "indicators_by_type": iocs_by_type,
            "tlp": pulse.get("TLP", "white"),
        }
