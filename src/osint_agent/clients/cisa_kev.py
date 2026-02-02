"""CISA Known Exploited Vulnerabilities (KEV) Catalog client."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .base import BaseClient


class CISAKEVClient(BaseClient):
    """Client for CISA Known Exploited Vulnerabilities catalog."""

    BASE_URL = "https://www.cisa.gov/sites/default/files/feeds"
    DEFAULT_TIMEOUT = 30

    def __init__(self) -> None:
        super().__init__()
        self._cache: dict[str, Any] | None = None
        self._cache_time: datetime | None = None
        self._cache_ttl = timedelta(hours=1)
        self._cve_index: dict[str, dict[str, Any]] = {}

    def _get_catalog(self) -> dict[str, Any]:
        """Fetch the full KEV catalog (cached)."""
        now = datetime.now(UTC)

        # Return cached if fresh
        if (
            self._cache is not None
            and self._cache_time is not None
            and now - self._cache_time < self._cache_ttl
        ):
            return self._cache

        # Fetch fresh catalog
        response: dict[str, Any] = self.get("/known_exploited_vulnerabilities.json")
        self._cache = response
        self._cache_time = now
        # Build CVE index for O(1) lookups
        self._cve_index = {
            vuln.get("cveID", "").upper(): vuln
            for vuln in response.get("vulnerabilities", [])
        }
        return response

    def lookup(self, cve_id: str) -> dict[str, Any] | None:
        """Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            KEV entry if found, None otherwise
        """
        self._get_catalog()
        vuln = self._cve_index.get(cve_id.upper())
        if vuln:
            return self._parse_kev_entry(vuln)
        return None

    def is_exploited(self, cve_id: str) -> bool:
        """Check if a CVE is known to be actively exploited."""
        return self.lookup(cve_id) is not None

    def get_recent(self, days: int = 7) -> list[dict[str, Any]]:
        """Get recently added KEV entries.

        Args:
            days: Number of days to look back

        Returns:
            List of KEV entries added within the time period
        """
        catalog = self._get_catalog()
        cutoff = datetime.now(UTC) - timedelta(days=days)

        recent = []
        for vuln in catalog.get("vulnerabilities", []):
            date_added_str = vuln.get("dateAdded", "")
            if date_added_str:
                try:
                    date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
                        tzinfo=UTC
                    )
                    if date_added >= cutoff:
                        recent.append(self._parse_kev_entry(vuln))
                except ValueError:
                    continue

        # Sort by date added (most recent first)
        recent.sort(key=lambda x: x.get("date_added", ""), reverse=True)
        return recent

    def get_by_vendor(self, vendor: str) -> list[dict[str, Any]]:
        """Get KEV entries for a specific vendor.

        Args:
            vendor: Vendor name (case-insensitive partial match)

        Returns:
            List of KEV entries matching the vendor
        """
        catalog = self._get_catalog()
        vendor_lower = vendor.lower()

        matches = []
        for vuln in catalog.get("vulnerabilities", []):
            if vendor_lower in vuln.get("vendorProject", "").lower():
                matches.append(self._parse_kev_entry(vuln))

        return matches

    def _parse_kev_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Parse raw KEV entry into standardized format."""
        return {
            "cve_id": entry.get("cveID", ""),
            "vendor": entry.get("vendorProject", ""),
            "product": entry.get("product", ""),
            "vulnerability_name": entry.get("vulnerabilityName", ""),
            "date_added": entry.get("dateAdded", ""),
            "short_description": entry.get("shortDescription", ""),
            "required_action": entry.get("requiredAction", ""),
            "due_date": entry.get("dueDate", ""),
            "known_ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
            "notes": entry.get("notes", ""),
        }

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the KEV catalog."""
        catalog = self._get_catalog()
        vulnerabilities = catalog.get("vulnerabilities", [])

        # Count by vendor
        vendors: dict[str, int] = {}
        ransomware_count = 0

        for vuln in vulnerabilities:
            vendor = vuln.get("vendorProject", "Unknown")
            vendors[vendor] = vendors.get(vendor, 0) + 1

            if vuln.get("knownRansomwareCampaignUse", "").lower() == "known":
                ransomware_count += 1

        # Sort vendors by count
        top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "catalog_version": catalog.get("catalogVersion", ""),
            "date_released": catalog.get("dateReleased", ""),
            "ransomware_associated": ransomware_count,
            "top_vendors": dict(top_vendors),
        }
