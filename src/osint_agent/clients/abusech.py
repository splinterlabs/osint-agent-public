"""Abuse.ch API clients for URLhaus, MalwareBazaar, and ThreatFox."""

from __future__ import annotations

from typing import Any

from .base import BaseClient


class AbuseCHClient(BaseClient):
    """Base client for abuse.ch services that require Auth-Key header."""

    def _get_headers(self) -> dict[str, str]:
        """Add Auth-Key header if API key is configured."""
        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers


# Maximum related URLs/items returned in list responses
MAX_RELATED_ITEMS = 20


def _check_query_status(response: dict) -> dict[str, Any] | None:
    """Check abuse.ch query_status field. Returns error dict if not ok, None if ok."""
    if response.get("query_status") != "ok":
        return {"found": False, "status": response.get("query_status")}
    return None


class URLhausClient(AbuseCHClient):
    """Client for URLhaus - malicious URL database.

    URLhaus is a project from abuse.ch that collects and shares malicious URLs
    used for malware distribution.

    API docs: https://urlhaus-api.abuse.ch/
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"
    DEFAULT_TIMEOUT = 30
    CACHE_TTL_HOURS = 4

    def _should_cache(self, method, endpoint, params=None, json_data=None, form_data=None):
        return "/recent" not in endpoint

    def lookup_url(self, url: str) -> dict[str, Any]:
        """Look up a URL in URLhaus.

        Args:
            url: The URL to look up

        Returns:
            URL details including threat type, tags, and payloads
        """
        response = self.post("/url/", form_data={"url": url})
        return self._parse_url_response(response)

    def lookup_host(self, host: str) -> dict[str, Any]:
        """Look up a host (domain/IP) in URLhaus.

        Args:
            host: Domain or IP address

        Returns:
            Host details with associated malicious URLs
        """
        response = self.post("/host/", form_data={"host": host})
        return self._parse_host_response(response)

    def lookup_payload(self, hash_value: str, hash_type: str = "sha256") -> dict[str, Any]:
        """Look up a payload by hash.

        Args:
            hash_value: MD5 or SHA256 hash
            hash_type: Hash type ("md5" or "sha256")

        Returns:
            Payload details including URLs serving it
        """
        if hash_type.lower() == "md5":
            response = self.post("/payload/", form_data={"md5_hash": hash_value})
        else:
            response = self.post("/payload/", form_data={"sha256_hash": hash_value})

        return self._parse_payload_response(response)

    def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recently added malicious URLs.

        Args:
            limit: Maximum number of URLs (max 1000)

        Returns:
            List of recent malicious URLs
        """
        response = self.get("/urls/recent/", params={"limit": min(limit, 1000)})

        urls = []
        for entry in response.get("urls", []):
            urls.append(self._parse_url_entry(entry))

        return urls

    def _parse_url_response(self, response: dict) -> dict[str, Any]:
        """Parse URL lookup response."""
        if error := _check_query_status(response):
            return error

        return {
            "found": True,
            "url": response.get("url"),
            "url_status": response.get("url_status"),
            "host": response.get("host"),
            "date_added": response.get("date_added"),
            "threat": response.get("threat"),
            "blacklists": response.get("blacklists", {}),
            "reporter": response.get("reporter"),
            "tags": response.get("tags", []),
            "payloads": [
                {
                    "filename": p.get("filename"),
                    "file_type": p.get("file_type"),
                    "signature": p.get("signature"),
                    "md5": p.get("response_md5"),
                    "sha256": p.get("response_sha256"),
                }
                for p in response.get("payloads", [])
            ],
        }

    def _parse_host_response(self, response: dict) -> dict[str, Any]:
        """Parse host lookup response."""
        if error := _check_query_status(response):
            return error

        return {
            "found": True,
            "host": response.get("host"),
            "url_count": response.get("url_count", 0),
            "blacklists": response.get("blacklists", {}),
            "urls": [
                self._parse_url_entry(u) for u in response.get("urls", [])[:MAX_RELATED_ITEMS]
            ],
        }

    def _parse_payload_response(self, response: dict) -> dict[str, Any]:
        """Parse payload lookup response."""
        if error := _check_query_status(response):
            return error

        return {
            "found": True,
            "md5": response.get("md5_hash"),
            "sha256": response.get("sha256_hash"),
            "file_type": response.get("file_type"),
            "file_size": response.get("file_size"),
            "signature": response.get("signature"),
            "first_seen": response.get("firstseen"),
            "last_seen": response.get("lastseen"),
            "url_count": response.get("url_count", 0),
            "urls": [
                {
                    "url": u.get("url"),
                    "url_status": u.get("url_status"),
                    "filename": u.get("filename"),
                }
                for u in response.get("urls", [])[:MAX_RELATED_ITEMS]
            ],
        }

    def _parse_url_entry(self, entry: dict) -> dict[str, Any]:
        """Parse a single URL entry."""
        return {
            "url": entry.get("url"),
            "url_status": entry.get("url_status"),
            "date_added": entry.get("date_added"),
            "threat": entry.get("threat"),
            "tags": entry.get("tags", []),
            "reporter": entry.get("reporter"),
        }


class MalwareBazaarClient(AbuseCHClient):
    """Client for MalwareBazaar - malware sample database.

    MalwareBazaar is a project from abuse.ch for sharing malware samples
    with the security community.

    API docs: https://bazaar.abuse.ch/api/
    """

    BASE_URL = "https://mb-api.abuse.ch/api/v1"
    DEFAULT_TIMEOUT = 30
    CACHE_TTL_HOURS = 4

    def _should_cache(self, method, endpoint, params=None, json_data=None, form_data=None):
        return not (form_data and form_data.get("query") == "get_recent")

    def lookup_hash(self, hash_value: str) -> dict[str, Any]:
        """Look up a malware sample by hash.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash

        Returns:
            Sample details including tags, signatures, and intelligence
        """
        response = self.post("/", form_data={"query": "get_info", "hash": hash_value})
        return self._parse_sample_response(response)

    def lookup_tag(self, tag: str, limit: int = 50) -> list[dict[str, Any]]:
        """Get samples with a specific tag.

        Args:
            tag: Tag to search (e.g., "Emotet", "Cobalt Strike")
            limit: Maximum number of results

        Returns:
            List of matching samples
        """
        response = self.post(
            "/",
            form_data={"query": "get_taginfo", "tag": tag, "limit": limit},
        )
        return self._parse_sample_list(response)

    def lookup_signature(self, signature: str, limit: int = 50) -> list[dict[str, Any]]:
        """Get samples with a specific signature.

        Args:
            signature: AV signature name
            limit: Maximum number of results

        Returns:
            List of matching samples
        """
        response = self.post(
            "/",
            form_data={"query": "get_siginfo", "signature": signature, "limit": limit},
        )
        return self._parse_sample_list(response)

    def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recently added samples.

        Args:
            limit: Maximum number of samples

        Returns:
            List of recent malware samples
        """
        response = self.post(
            "/",
            form_data={"query": "get_recent", "selector": "time", "limit": limit},
        )
        return self._parse_sample_list(response)

    def _parse_sample_response(self, response: dict) -> dict[str, Any]:
        """Parse single sample lookup response."""
        if error := _check_query_status(response):
            return error

        data = response.get("data", [{}])[0] if response.get("data") else {}

        return {
            "found": True,
            "sha256": data.get("sha256_hash"),
            "sha1": data.get("sha1_hash"),
            "md5": data.get("md5_hash"),
            "file_name": data.get("file_name"),
            "file_type": data.get("file_type"),
            "file_type_mime": data.get("file_type_mime"),
            "file_size": data.get("file_size"),
            "signature": data.get("signature"),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "reporter": data.get("reporter"),
            "tags": data.get("tags", []),
            "intelligence": {
                "downloads": data.get("intelligence", {}).get("downloads"),
                "uploads": data.get("intelligence", {}).get("uploads"),
                "mail": data.get("intelligence", {}).get("mail"),
            },
            "delivery_method": data.get("delivery_method"),
            "comment": data.get("comment"),
        }

    def _parse_sample_list(self, response: dict) -> list[dict[str, Any]]:
        """Parse sample list response."""
        if _check_query_status(response):
            return []

        samples = []
        for data in response.get("data", []):
            samples.append(
                {
                    "sha256": data.get("sha256_hash"),
                    "md5": data.get("md5_hash"),
                    "file_name": data.get("file_name"),
                    "file_type": data.get("file_type"),
                    "file_size": data.get("file_size"),
                    "signature": data.get("signature"),
                    "first_seen": data.get("first_seen"),
                    "tags": data.get("tags", []),
                }
            )

        return samples


class ThreatFoxClient(AbuseCHClient):
    """Client for ThreatFox - IOC database.

    ThreatFox is a project from abuse.ch for sharing IOCs associated
    with malware.

    API docs: https://threatfox-api.abuse.ch/
    """

    BASE_URL = "https://threatfox-api.abuse.ch/api/v1"
    DEFAULT_TIMEOUT = 30
    CACHE_TTL_HOURS = 4

    def _should_cache(self, method, endpoint, params=None, json_data=None, form_data=None):
        return not (json_data and json_data.get("query") == "get_iocs")

    def lookup_ioc(self, ioc: str) -> dict[str, Any]:
        """Look up an IOC in ThreatFox.

        Args:
            ioc: IOC value (IP, domain, URL, hash)

        Returns:
            IOC details including malware association and tags
        """
        response = self.post("/", json_data={"query": "search_ioc", "search_term": ioc})
        return self._parse_ioc_response(response)

    def lookup_malware(self, malware: str, limit: int = 50) -> list[dict[str, Any]]:
        """Get IOCs for a specific malware family.

        Args:
            malware: Malware name (e.g., "Emotet", "Cobalt Strike")
            limit: Maximum number of results

        Returns:
            List of IOCs associated with the malware
        """
        response = self.post(
            "/",
            json_data={"query": "malwareinfo", "malware": malware, "limit": limit},
        )
        return self._parse_ioc_list(response)

    def lookup_tag(self, tag: str, limit: int = 50) -> list[dict[str, Any]]:
        """Get IOCs with a specific tag.

        Args:
            tag: Tag to search
            limit: Maximum number of results

        Returns:
            List of matching IOCs
        """
        response = self.post(
            "/",
            json_data={"query": "taginfo", "tag": tag, "limit": limit},
        )
        return self._parse_ioc_list(response)

    def get_recent(self, days: int = 3) -> list[dict[str, Any]]:
        """Get recently added IOCs.

        Args:
            days: Number of days to look back (max 7)

        Returns:
            List of recent IOCs
        """
        response = self.post(
            "/",
            json_data={"query": "get_iocs", "days": min(days, 7)},
        )
        return self._parse_ioc_list(response)

    def _parse_ioc_response(self, response: dict) -> dict[str, Any]:
        """Parse single IOC lookup response."""
        if error := _check_query_status(response):
            return error

        data = response.get("data", [{}])[0] if response.get("data") else {}

        return {
            "found": True,
            "id": data.get("id"),
            "ioc": data.get("ioc"),
            "ioc_type": data.get("ioc_type"),
            "threat_type": data.get("threat_type"),
            "malware": data.get("malware"),
            "malware_alias": data.get("malware_alias"),
            "malware_printable": data.get("malware_printable"),
            "confidence_level": data.get("confidence_level"),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "reporter": data.get("reporter"),
            "tags": data.get("tags", []),
            "reference": data.get("reference"),
        }

    def _parse_ioc_list(self, response: dict) -> list[dict[str, Any]]:
        """Parse IOC list response."""
        if _check_query_status(response):
            return []

        iocs = []
        for data in response.get("data", []):
            iocs.append(
                {
                    "id": data.get("id"),
                    "ioc": data.get("ioc"),
                    "ioc_type": data.get("ioc_type"),
                    "threat_type": data.get("threat_type"),
                    "malware": data.get("malware"),
                    "malware_printable": data.get("malware_printable"),
                    "confidence_level": data.get("confidence_level"),
                    "first_seen": data.get("first_seen"),
                    "tags": data.get("tags", []),
                }
            )

        return iocs
