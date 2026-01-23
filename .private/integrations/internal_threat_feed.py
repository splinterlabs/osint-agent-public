"""Internal threat feed client - PROPRIETARY.

This file should NEVER appear in the public repo.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class InternalThreatFeed:
    """Client for internal threat intelligence feed.

    This is proprietary code that connects to internal systems.
    """

    BASE_URL = "https://internal.example.com/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def get_indicators(self, days: int = 7) -> list[dict[str, Any]]:
        """Fetch recent indicators from internal feed."""
        # Proprietary implementation
        logger.info(f"Fetching indicators from internal feed (last {days} days)")
        return []

    def submit_indicator(self, ioc_type: str, value: str) -> bool:
        """Submit new indicator to internal system."""
        # Proprietary implementation
        return True


SECRET_INTERNAL_KEY = "this-should-never-be-public"
