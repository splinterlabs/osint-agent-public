"""FreshRSS threat intelligence feed tools."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from typing import Optional

from mcp.server.fastmcp import FastMCP

from osint_agent.clients.freshrss import FreshRSSClient
from osint_agent.extractors import extract_iocs
from osint_agent.keymanager import get_api_key
from osint_agent.parallel import get_workers, parallel_filter_map
from osint_agent.usage import track_tool

logger = logging.getLogger("osint-mcp.freshrss")


@lru_cache(maxsize=1)
def get_client() -> FreshRSSClient:
    """Get or create FreshRSS client singleton (thread-safe via lru_cache)."""
    url = get_api_key("FRESHRSS_URL")
    username = get_api_key("FRESHRSS_USERNAME")
    password = get_api_key("FRESHRSS_PASSWORD")

    if not url:
        raise ValueError(
            "FreshRSS URL not configured. "
            "Run: python -m osint_agent.cli keys set FRESHRSS_URL"
        )
    if not username:
        raise ValueError(
            "FreshRSS username not configured. "
            "Run: python -m osint_agent.cli keys set FRESHRSS_USERNAME"
        )
    if not password:
        raise ValueError(
            "FreshRSS password not configured. "
            "Run: python -m osint_agent.cli keys set FRESHRSS_PASSWORD"
        )

    return FreshRSSClient(base_url=url, username=username, password=password)


def register_tools(mcp: FastMCP) -> None:
    """Register FreshRSS tools with the MCP server."""

    @mcp.tool()
    @track_tool("freshrss_list_feeds")
    def freshrss_list_feeds() -> str:
        """List all subscribed feeds from FreshRSS.

        Returns:
            JSON string with list of subscribed feeds including id, title, and URL.
        """
        logger.info("Listing FreshRSS feeds")

        try:
            client = get_client()
            subscriptions = client.get_subscriptions()

            return json.dumps(
                {
                    "feed_count": len(subscriptions),
                    "feeds": subscriptions,
                },
                indent=2,
            )
        except ValueError as e:
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.error(f"Failed to list FreshRSS feeds: {e}")
            return json.dumps({"error": f"Failed to list feeds: {e}"})

    @mcp.tool()
    @track_tool("freshrss_get_entries")
    def freshrss_get_entries(
        feed_id: Optional[str] = None,
        count: int = 20,
        unread_only: bool = False,
    ) -> str:
        """Get entries from a specific feed or all feeds.

        Args:
            feed_id: Specific feed ID (stream ID) or None for all feeds.
                     Feed IDs can be obtained from freshrss_list_feeds.
            count: Maximum number of entries to return (default: 20)
            unread_only: If True, only return unread entries (default: False)

        Returns:
            JSON string with list of feed entries including title, URL, and content.
        """
        logger.info(f"Getting FreshRSS entries: feed_id={feed_id}, count={count}, unread_only={unread_only}")

        try:
            client = get_client()
            result = client.get_entries(feed_id=feed_id, count=count, unread_only=unread_only)

            return json.dumps(
                {
                    "entry_count": len(result["entries"]),
                    "has_more": result.get("continuation") is not None,
                    "entries": result["entries"],
                },
                indent=2,
            )
        except ValueError as e:
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.error(f"Failed to get FreshRSS entries: {e}")
            return json.dumps({"error": f"Failed to get entries: {e}"})

    @mcp.tool()
    @track_tool("freshrss_get_unread")
    def freshrss_get_unread(count: int = 50) -> str:
        """Get all unread entries across all subscribed feeds.

        Args:
            count: Maximum number of unread entries to return (default: 50)

        Returns:
            JSON string with list of unread entries.
        """
        logger.info(f"Getting FreshRSS unread entries: count={count}")

        try:
            client = get_client()
            entries = client.get_unread_entries(count=count)

            return json.dumps(
                {
                    "unread_count": len(entries),
                    "entries": entries,
                },
                indent=2,
            )
        except ValueError as e:
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.error(f"Failed to get FreshRSS unread entries: {e}")
            return json.dumps({"error": f"Failed to get unread entries: {e}"})

    @mcp.tool()
    @track_tool("freshrss_extract_iocs")
    def freshrss_extract_iocs(feed_id: Optional[str] = None, count: int = 20) -> str:
        """Get feed entries and extract IOCs (Indicators of Compromise) from them.

        Useful for monitoring security feeds (vendor advisories, threat reports,
        CVE feeds) and automatically extracting actionable IOCs.

        Args:
            feed_id: Specific feed ID or None for all feeds.
                     Feed IDs can be obtained from freshrss_list_feeds.
            count: Maximum number of entries to process (default: 20)

        Returns:
            JSON string with entries that contain IOCs, including extracted
            IPs, domains, hashes, URLs, and CVEs.
        """
        logger.info(f"Extracting IOCs from FreshRSS entries: feed_id={feed_id}, count={count}")

        try:
            client = get_client()
            result = client.get_entries(feed_id=feed_id, count=count)

            def _process_entry(entry: dict) -> dict | None:
                """Extract IOCs from a single feed entry."""
                content = f"{entry.get('title', '')}\n{entry.get('summary', '')}"
                iocs = extract_iocs(content)
                if any(iocs.values()):
                    ioc_count = sum(len(v) for v in iocs.values())
                    return {
                        "entry_id": entry["id"],
                        "title": entry.get("title", ""),
                        "url": entry.get("url", ""),
                        "feed_title": entry.get("feed_title", ""),
                        "published": entry.get("published", 0),
                        "ioc_count": ioc_count,
                        "iocs": iocs,
                    }
                return None

            workers = get_workers("feed_processing_workers", 10)
            entries_with_iocs = parallel_filter_map(
                _process_entry,
                result["entries"],
                max_workers=workers,
                label="freshrss_ioc_extraction",
            )
            total_iocs = sum(e["ioc_count"] for e in entries_with_iocs)

            return json.dumps(
                {
                    "entries_processed": len(result["entries"]),
                    "entries_with_iocs": len(entries_with_iocs),
                    "total_iocs": total_iocs,
                    "results": entries_with_iocs,
                },
                indent=2,
            )
        except ValueError as e:
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.error(f"Failed to extract IOCs from FreshRSS: {e}")
            return json.dumps({"error": f"Failed to extract IOCs: {e}"})

    @mcp.tool()
    @track_tool("freshrss_search")
    def freshrss_search(query: str, count: int = 20) -> str:
        """Search entries by keyword across all subscribed feeds.

        Args:
            query: Search query string
            count: Maximum number of results to return (default: 20)

        Returns:
            JSON string with matching entries.
        """
        logger.info(f"Searching FreshRSS entries: query={query}, count={count}")

        try:
            client = get_client()
            entries = client.search(query=query, count=count)

            return json.dumps(
                {
                    "query": query,
                    "result_count": len(entries),
                    "entries": entries,
                },
                indent=2,
            )
        except ValueError as e:
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.error(f"Failed to search FreshRSS: {e}")
            return json.dumps({"error": f"Failed to search: {e}"})

    @mcp.tool()
    @track_tool("freshrss_mark_read")
    def freshrss_mark_read(entry_ids: str) -> str:
        """Mark entries as read.

        Args:
            entry_ids: Comma-separated list of entry IDs to mark as read

        Returns:
            JSON string with success status.
        """
        logger.info(f"Marking FreshRSS entries as read: {entry_ids}")

        try:
            client = get_client()
            ids = [id.strip() for id in entry_ids.split(",") if id.strip()]

            if not ids:
                return json.dumps({"error": "No entry IDs provided"})

            success = client.mark_read(ids)

            return json.dumps(
                {
                    "success": success,
                    "marked_count": len(ids) if success else 0,
                    "entry_ids": ids,
                },
                indent=2,
            )
        except ValueError as e:
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.error(f"Failed to mark FreshRSS entries as read: {e}")
            return json.dumps({"error": f"Failed to mark as read: {e}"})
