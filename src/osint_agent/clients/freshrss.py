"""FreshRSS client using Google Reader-compatible API."""

from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urljoin

from .base import APIError, BaseClient

logger = logging.getLogger(__name__)


class FreshRSSClient(BaseClient):
    """Client for FreshRSS using Google Reader-compatible API.

    FreshRSS exposes a Google Reader-compatible API that allows:
    - Listing subscriptions
    - Fetching feed entries
    - Marking entries as read
    - Searching entries
    """

    DEFAULT_TIMEOUT = 30
    MAX_RETRIES = 3
    BACKOFF_BASE = 1.0

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: Optional[int] = None,
    ):
        """Initialize FreshRSS client.

        Args:
            base_url: Base URL of FreshRSS instance (e.g., https://rss.example.com)
            username: FreshRSS username
            password: FreshRSS password
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.BASE_URL = self.base_url
        self.username = username
        self.password = password
        self._auth_token: Optional[str] = None
        super().__init__(timeout=timeout)

    def _get_headers(self) -> dict[str, str]:
        """Get headers with auth token if authenticated."""
        headers = {}
        if self._auth_token:
            headers["Authorization"] = f"GoogleLogin auth={self._auth_token}"
        return headers

    def authenticate(self) -> str:
        """Authenticate with FreshRSS and get auth token.

        Returns:
            Auth token string

        Raises:
            APIError: If authentication fails
        """
        logger.info(f"Authenticating to FreshRSS at {self.base_url}")

        url = urljoin(self.base_url, "/accounts/ClientLogin")

        try:
            response = self.session.post(
                url,
                data={
                    "Email": self.username,
                    "Passwd": self.password,
                },
                timeout=self.timeout,
                proxies=self.proxy.get_proxies() if not self.proxy.should_bypass(url) else {},
            )
            response.raise_for_status()
        except Exception as e:
            raise APIError(f"FreshRSS authentication failed: {e}")

        # Parse response - format is key=value pairs
        auth_data = {}
        for line in response.text.strip().split("\n"):
            if "=" in line:
                key, value = line.split("=", 1)
                auth_data[key] = value

        if "Auth" not in auth_data:
            raise APIError("FreshRSS authentication response missing Auth token")

        self._auth_token = auth_data["Auth"]
        logger.info("Successfully authenticated to FreshRSS")
        return self._auth_token

    def _ensure_authenticated(self) -> None:
        """Ensure we have a valid auth token."""
        if not self._auth_token:
            self.authenticate()

    def get_subscriptions(self) -> list[dict[str, Any]]:
        """Get list of all subscribed feeds.

        Returns:
            List of subscription dicts with id, title, url, categories
        """
        self._ensure_authenticated()

        response = self.get("/reader/api/0/subscription/list", params={"output": "json"})

        subscriptions = []
        for sub in response.get("subscriptions", []):
            subscriptions.append({
                "id": sub.get("id", ""),
                "title": sub.get("title", ""),
                "url": sub.get("url", ""),
                "html_url": sub.get("htmlUrl", ""),
                "icon_url": sub.get("iconUrl", ""),
                "categories": [
                    {"id": cat.get("id", ""), "label": cat.get("label", "")}
                    for cat in sub.get("categories", [])
                ],
            })

        return subscriptions

    def get_entries(
        self,
        feed_id: Optional[str] = None,
        count: int = 20,
        unread_only: bool = False,
        continuation: Optional[str] = None,
    ) -> dict[str, Any]:
        """Fetch entries from a feed or all feeds.

        Args:
            feed_id: Specific feed ID (stream ID) or None for all feeds
            count: Maximum number of entries to return
            unread_only: If True, only return unread entries
            continuation: Continuation token for pagination

        Returns:
            Dict with entries list and optional continuation token
        """
        self._ensure_authenticated()

        # Determine stream ID
        if feed_id:
            stream_id = feed_id
        else:
            stream_id = "user/-/state/com.google/reading-list"

        params: dict[str, Any] = {
            "output": "json",
            "n": count,
        }

        if unread_only:
            params["xt"] = "user/-/state/com.google/read"

        if continuation:
            params["c"] = continuation

        # URL encode the stream ID in the path
        from urllib.parse import quote
        endpoint = f"/reader/api/0/stream/contents/{quote(stream_id, safe='')}"

        response = self.get(endpoint, params=params)

        entries = []
        for item in response.get("items", []):
            entry = self._parse_entry(item)
            entries.append(entry)

        return {
            "entries": entries,
            "continuation": response.get("continuation"),
        }

    def get_unread_entries(self, count: int = 50) -> list[dict[str, Any]]:
        """Get all unread entries across all feeds.

        Args:
            count: Maximum number of entries to return

        Returns:
            List of unread entry dicts
        """
        result = self.get_entries(feed_id=None, count=count, unread_only=True)
        return result["entries"]

    def mark_read(self, entry_ids: list[str]) -> bool:
        """Mark entries as read.

        Args:
            entry_ids: List of entry IDs to mark as read

        Returns:
            True if successful
        """
        if not entry_ids:
            return True

        self._ensure_authenticated()

        url = urljoin(self.base_url, "/reader/api/0/edit-tag")

        try:
            response = self.session.post(
                url,
                headers=self._get_headers(),
                data={
                    "a": "user/-/state/com.google/read",
                    "i": entry_ids,
                },
                timeout=self.timeout,
                proxies=self.proxy.get_proxies() if not self.proxy.should_bypass(url) else {},
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to mark entries as read: {e}")
            return False

    def search(self, query: str, count: int = 20) -> list[dict[str, Any]]:
        """Search entries by keyword.

        Note: FreshRSS search requires the search extension to be enabled.

        Args:
            query: Search query string
            count: Maximum number of results

        Returns:
            List of matching entry dicts
        """
        self._ensure_authenticated()

        # FreshRSS uses a special search stream
        from urllib.parse import quote
        search_stream = f"user/-/state/com.google/label/{quote(query, safe='')}"

        # Try the standard search endpoint first
        params = {
            "output": "json",
            "n": count,
            "s": "user/-/state/com.google/reading-list",
            "q": query,
        }

        try:
            response = self.get("/reader/api/0/stream/contents", params=params)
            entries = [self._parse_entry(item) for item in response.get("items", [])]
            return entries
        except APIError:
            # Fallback: search by fetching all and filtering client-side
            logger.warning("Server-side search failed, falling back to client-side filtering")
            all_entries = self.get_entries(count=count * 5)
            query_lower = query.lower()
            filtered = []
            for entry in all_entries["entries"]:
                if (query_lower in entry.get("title", "").lower() or
                    query_lower in entry.get("summary", "").lower()):
                    filtered.append(entry)
                    if len(filtered) >= count:
                        break
            return filtered

    def _parse_entry(self, item: dict) -> dict[str, Any]:
        """Parse a raw entry item into standardized format.

        Args:
            item: Raw entry dict from API

        Returns:
            Standardized entry dict
        """
        # Extract canonical URL
        url = ""
        canonical = item.get("canonical", [])
        if canonical and isinstance(canonical, list):
            url = canonical[0].get("href", "")
        if not url:
            alternate = item.get("alternate", [])
            if alternate and isinstance(alternate, list):
                url = alternate[0].get("href", "")

        # Extract summary/content
        summary = ""
        if "summary" in item:
            summary = item["summary"].get("content", "")
        elif "content" in item:
            summary = item["content"].get("content", "")

        # Extract origin (feed info)
        origin = item.get("origin", {})

        return {
            "id": item.get("id", ""),
            "title": item.get("title", ""),
            "url": url,
            "published": item.get("published", 0),
            "updated": item.get("updated", item.get("published", 0)),
            "author": item.get("author", ""),
            "summary": summary,
            "feed_id": origin.get("streamId", ""),
            "feed_title": origin.get("title", ""),
            "categories": [cat.get("label", "") for cat in item.get("categories", []) if isinstance(cat, dict)],
        }
