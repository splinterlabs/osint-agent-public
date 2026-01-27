"""NVD (National Vulnerability Database) API client."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ..keymanager import get_api_key
from .base import BaseClient


class NVDClient(BaseClient):
    """Client for the NVD CVE API 2.0."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    DEFAULT_TIMEOUT = 30
    CACHE_TTL_HOURS = 24

    def __init__(self, api_key: Optional[str] = None):
        key = api_key or get_api_key("NVD_API_KEY")
        super().__init__(api_key=key)

    def _get_headers(self) -> dict[str, str]:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def lookup(self, cve_id: str) -> dict[str, Any]:
        """Look up a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            CVE details including CVSS, description, affected products
        """
        response = self.get("", params={"cveId": cve_id})

        vulnerabilities = response.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"error": f"CVE {cve_id} not found"}

        cve_data = vulnerabilities[0].get("cve", {})
        return self._parse_cve(cve_data)

    def get_critical(
        self,
        cvss_min: float = 8.0,
        days: int = 7,
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        """Get recent critical CVEs.

        Args:
            cvss_min: Minimum CVSS v3 score
            days: Number of days to look back
            max_results: Maximum number of results

        Returns:
            List of CVE details
        """
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        params = {
            "cvssV3Severity": "CRITICAL" if cvss_min >= 9.0 else "HIGH",
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": max_results,
        }

        response = self.get("", params=params)

        cves = []
        for vuln in response.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            parsed = self._parse_cve(cve_data)

            # Filter by exact CVSS score
            cvss_score = parsed.get("cvss_v3_score", 0)
            if cvss_score >= cvss_min:
                cves.append(parsed)

        return cves

    def _parse_cve(self, cve_data: dict) -> dict[str, Any]:
        """Parse raw CVE data into standardized format."""
        cve_id = cve_data.get("id", "")

        # Get description (prefer English)
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Get CVSS v3 metrics
        cvss_v3 = {}
        cvss_v3_score = 0.0
        cvss_v3_vector = ""

        metrics = cve_data.get("metrics", {})
        cvss_v3_data = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if cvss_v3_data:
            primary = cvss_v3_data[0].get("cvssData", {})
            cvss_v3_score = primary.get("baseScore", 0.0)
            cvss_v3_vector = primary.get("vectorString", "")
            cvss_v3 = {
                "score": cvss_v3_score,
                "vector": cvss_v3_vector,
                "severity": primary.get("baseSeverity", ""),
                "attack_vector": primary.get("attackVector", ""),
                "attack_complexity": primary.get("attackComplexity", ""),
                "privileges_required": primary.get("privilegesRequired", ""),
                "user_interaction": primary.get("userInteraction", ""),
            }

        # Get CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_ids.append(desc.get("value", ""))

        # Get affected products (CPE)
        affected_products = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if criteria:
                        # Parse CPE to human-readable
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            version = parts[5] if len(parts) > 5 else "*"
                            affected_products.append(
                                {
                                    "cpe": criteria,
                                    "vendor": vendor,
                                    "product": product,
                                    "version": version,
                                }
                            )

        # Get references
        references = []
        for ref in cve_data.get("references", []):
            references.append(
                {
                    "url": ref.get("url", ""),
                    "source": ref.get("source", ""),
                    "tags": ref.get("tags", []),
                }
            )

        return {
            "id": cve_id,
            "description": description,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v3": cvss_v3,
            "cwe_ids": cwe_ids,
            "affected_products": affected_products,
            "references": references,
            "published": cve_data.get("published", ""),
            "last_modified": cve_data.get("lastModified", ""),
        }
