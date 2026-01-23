"""Base client with common functionality for all API clients."""

import logging
import time
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


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

    def __init__(self, api_key: Optional[str] = None, timeout: Optional[int] = None):
        self.api_key = api_key
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.session = requests.Session()
        self._setup_session()

    def _setup_session(self) -> None:
        """Configure session with default headers."""
        self.session.headers.update(
            {
                "User-Agent": "OSINT-Agent/0.1.0",
                "Accept": "application/json",
            }
        )

    def _get_headers(self) -> dict[str, str]:
        """Get headers for request. Override in subclasses for auth."""
        return {}

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
        **kwargs,
    ) -> Any:
        """Make HTTP request with retry logic and error handling."""
        url = f"{self.BASE_URL}{endpoint}"
        headers = {**self._get_headers(), **kwargs.pop("headers", {})}

        last_exception: Optional[Exception] = None

        for attempt in range(self.MAX_RETRIES):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_data,
                    headers=headers,
                    timeout=self.timeout,
                    **kwargs,
                )

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    raise RateLimitError(
                        f"Rate limit exceeded for {url}", retry_after=retry_after
                    )

                # Handle other errors
                if response.status_code >= 400:
                    response.raise_for_status()

                return response.json()

            except requests.Timeout as e:
                last_exception = APITimeoutError(f"Request to {url} timed out")
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.MAX_RETRIES}: {url}")

            except RateLimitError:
                raise

            except requests.RequestException as e:
                last_exception = APIError(f"Request failed: {e}")
                logger.warning(
                    f"Request failed on attempt {attempt + 1}/{self.MAX_RETRIES}: {e}"
                )

            # Exponential backoff
            if attempt < self.MAX_RETRIES - 1:
                sleep_time = self.BACKOFF_BASE * (2**attempt)
                logger.debug(f"Retrying in {sleep_time}s...")
                time.sleep(sleep_time)

        raise last_exception or APIError("Request failed after all retries")

    def get(self, endpoint: str, params: Optional[dict] = None, **kwargs) -> Any:
        """Make GET request."""
        return self._request("GET", endpoint, params=params, **kwargs)

    def post(
        self, endpoint: str, json_data: Optional[dict] = None, **kwargs
    ) -> Any:
        """Make POST request."""
        return self._request("POST", endpoint, json_data=json_data, **kwargs)
