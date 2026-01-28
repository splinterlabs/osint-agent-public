"""Base client with common functionality for all API clients."""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# Matches sensitive query parameters/header values that may appear in exception messages.
# Covers: key=, apiKey=, api_key=, Auth-Key:, Authorization:, Passwd=, password=
_SENSITIVE_PARAM_RE = re.compile(
    r"((?:key|apiKey|api_key|Auth-Key|Authorization|Passwd|password|token|secret)"
    r"[=:]\s*)[^\s&,;\"']+",
    re.IGNORECASE,
)


def _sanitize_message(msg: str) -> str:
    """Redact sensitive parameter values from a string."""
    return _SENSITIVE_PARAM_RE.sub(r"\1[REDACTED]", msg)


class ProxyConfig:
    """Proxy configuration with environment variable and explicit support."""

    def __init__(
        self,
        http_proxy: Optional[str] = None,
        https_proxy: Optional[str] = None,
        no_proxy: Optional[list[str]] = None,
        enabled: bool = True,
    ):
        """Initialize proxy configuration.

        Args:
            http_proxy: HTTP proxy URL (e.g., http://proxy:8080 or socks5://proxy:1080)
            https_proxy: HTTPS proxy URL
            no_proxy: List of domains to bypass proxy
            enabled: Whether proxy is enabled
        """
        self.enabled = enabled
        self._http_proxy = http_proxy
        self._https_proxy = https_proxy
        self._no_proxy = no_proxy or []

    @property
    def http_proxy(self) -> Optional[str]:
        """Get HTTP proxy from config or environment."""
        if not self.enabled:
            return None
        return self._http_proxy or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")

    @property
    def https_proxy(self) -> Optional[str]:
        """Get HTTPS proxy from config or environment."""
        if not self.enabled:
            return None
        return self._https_proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")

    @property
    def no_proxy(self) -> list[str]:
        """Get no-proxy list from config or environment."""
        if self._no_proxy:
            return self._no_proxy
        env_no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
        if env_no_proxy:
            return [d.strip() for d in env_no_proxy.split(",")]
        return []

    def get_proxies(self) -> dict[str, str]:
        """Get proxies dict for requests library."""
        if not self.enabled:
            return {}
        proxies = {}
        if self.http_proxy:
            proxies["http"] = self.http_proxy
        if self.https_proxy:
            proxies["https"] = self.https_proxy
        return proxies

    def should_bypass(self, url: str) -> bool:
        """Check if URL should bypass proxy."""
        if not self.no_proxy:
            return False
        from urllib.parse import urlparse

        hostname = urlparse(url).hostname or ""
        for pattern in self.no_proxy:
            if pattern.startswith("."):
                # Suffix match: .example.com matches foo.example.com
                if hostname.endswith(pattern) or hostname == pattern[1:]:
                    return True
            elif hostname == pattern or hostname.endswith(f".{pattern}"):
                return True
        return False

    @classmethod
    def from_dict(cls, config: dict) -> "ProxyConfig":
        """Create ProxyConfig from dictionary."""
        return cls(
            http_proxy=config.get("http_proxy"),
            https_proxy=config.get("https_proxy"),
            no_proxy=config.get("no_proxy"),
            enabled=config.get("enabled", True),
        )


class APIError(Exception):
    """Base exception for API errors."""

    pass


class RateLimitError(APIError):
    """Raised when API rate limit is exceeded."""

    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after


class APITimeoutError(APIError):
    """Raised when API request times out."""

    pass


class BaseClient:
    """Base class for API clients with retry and error handling."""

    BASE_URL: str = ""
    DEFAULT_TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    BACKOFF_BASE: float = 1.0
    DEFAULT_USER_AGENT: str = "OSINT-Agent/0.1.0"
    CACHE_TTL_HOURS: int = 0  # 0 = caching disabled; override in subclasses

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: Optional[int] = None,
        proxy: Optional[ProxyConfig] = None,
        user_agent: Optional[str] = None,
    ):
        self.api_key = api_key
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.proxy = proxy or ProxyConfig()
        self.user_agent = user_agent or os.environ.get("OSINT_USER_AGENT") or self.DEFAULT_USER_AGENT
        self.session = requests.Session()
        self._setup_session()

        # Initialize response cache if TTL is configured
        # Set OSINT_NO_CACHE=1 to disable, OSINT_CACHE_DIR to override location
        self._response_cache = None
        if self.CACHE_TTL_HOURS > 0 and not os.environ.get("OSINT_NO_CACHE"):
            from pathlib import Path

            from osint_agent.cache import ThreatContextCache

            cache_dir = Path(os.environ.get("OSINT_CACHE_DIR", "data/cache/api"))
            self._response_cache = ThreatContextCache(
                cache_dir=cache_dir,
                ttl_hours=self.CACHE_TTL_HOURS,
            )

    def _setup_session(self) -> None:
        """Configure session with default headers."""
        self.session.headers.update(
            {
                "User-Agent": self.user_agent,
                "Accept": "application/json",
            }
        )

    def _get_headers(self) -> dict[str, str]:
        """Get headers for request. Override in subclasses for auth."""
        return {}

    def _should_cache(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
        form_data: Optional[dict] = None,
    ) -> bool:
        """Whether this request should use the response cache.

        Override in subclasses to exclude volatile endpoints (e.g. "recent" feeds).
        Only called when ``_response_cache`` is not None.
        """
        return True

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
        form_data: Optional[dict] = None,
        **kwargs,
    ) -> Any:
        """Make HTTP request with retry logic and error handling."""
        from urllib.parse import urlparse

        from osint_agent.usage import get_usage_tracker

        url = f"{self.BASE_URL}{endpoint}"
        service = urlparse(url).hostname or "unknown"

        # --- response cache check ---
        cache_key: Optional[str] = None
        if self._response_cache is not None and self._should_cache(
            method, endpoint, params, json_data, form_data
        ):
            from osint_agent.cache import make_request_cache_key

            cache_key = make_request_cache_key(method, url, params, json_data, form_data)
            if not self._response_cache.is_stale(cache_key):
                cached = self._response_cache.get(cache_key)
                if cached is not None:
                    logger.debug("Cache hit: %s %s", method, url)
                    return cached

        headers = {**self._get_headers(), **kwargs.pop("headers", {})}

        # Configure proxy unless bypassed for this URL
        proxies = {}
        if self.proxy and not self.proxy.should_bypass(url):
            proxies = self.proxy.get_proxies()

        last_exception: Optional[Exception] = None

        for attempt in range(self.MAX_RETRIES):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_data,
                    data=form_data,
                    headers=headers,
                    timeout=self.timeout,
                    proxies=proxies,
                    **kwargs,
                )

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after_raw = response.headers.get("Retry-After", "60")
                    try:
                        retry_after = int(retry_after_raw)
                    except (ValueError, TypeError):
                        # Retry-After may be a date string per HTTP spec
                        retry_after = 60
                    raise RateLimitError(
                        f"Rate limit exceeded for {url}", retry_after=retry_after
                    )

                # Handle other errors
                if response.status_code >= 400:
                    response.raise_for_status()

                data = response.json()
                get_usage_tracker().record_api_request(service)

                # --- cache successful response ---
                if cache_key is not None:
                    try:
                        self._response_cache.set(cache_key, data)
                    except Exception:
                        logger.debug("Failed to cache response for %s %s", method, url)

                return data

            except requests.Timeout as e:
                last_exception = APITimeoutError(f"Request to {url} timed out")
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.MAX_RETRIES}: {url}")

            except RateLimitError:
                raise

            except requests.RequestException as e:
                sanitized = _sanitize_message(str(e))
                last_exception = APIError(f"Request failed: {sanitized}")
                logger.warning(
                    f"Request failed on attempt {attempt + 1}/{self.MAX_RETRIES}: {sanitized}"
                )

            # Exponential backoff
            if attempt < self.MAX_RETRIES - 1:
                sleep_time = self.BACKOFF_BASE * (2**attempt)
                logger.debug(f"Retrying in {sleep_time}s...")
                time.sleep(sleep_time)

        get_usage_tracker().record_api_request(service, error=True)
        raise last_exception or APIError("Request failed after all retries")

    def get(self, endpoint: str, params: Optional[dict] = None, **kwargs) -> Any:
        """Make GET request."""
        return self._request("GET", endpoint, params=params, **kwargs)

    def post(
        self, endpoint: str, json_data: Optional[dict] = None, form_data: Optional[dict] = None, **kwargs
    ) -> Any:
        """Make POST request."""
        return self._request("POST", endpoint, json_data=json_data, form_data=form_data, **kwargs)
