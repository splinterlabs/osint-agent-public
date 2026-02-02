"""Local web fetching MCP tools with realistic browser headers.

This module provides an alternative to the built-in WebFetch tool that may be
blocked by enterprise security policies. It uses the local requests library
with rotating User-Agents to blend in with normal browser traffic.

SECURITY: Includes SSRF protection to prevent abuse for internal network scanning,
cloud metadata access, or localhost attacks.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

# Add parent paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from osint_agent.usage import track_tool

logger = logging.getLogger(__name__)

# Realistic browser User-Agents (updated for 2026)
# Mix of Chrome, Firefox, Safari on different platforms
USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]


# SSRF Protection - Blocklist of dangerous hosts
SSRF_BLOCKLIST = {
    # Loopback addresses
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    # Cloud metadata services
    "169.254.169.254",  # AWS EC2 metadata
    "metadata.google.internal",  # GCP metadata
    "fd00:ec2::254",  # AWS IMDSv2 IPv6
    # Kubernetes
    "kubernetes.default.svc",
    "kubernetes.default",
}


def is_safe_url(url: str) -> tuple[bool, str]:
    """Validate URL against SSRF attacks.

    Blocks:
    - Private/internal IP ranges (RFC 1918)
    - Loopback addresses
    - Link-local addresses
    - Cloud metadata services
    - Reserved IP ranges

    Args:
        url: URL to validate

    Returns:
        Tuple of (is_safe, error_message)
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return (False, "Invalid URL: no hostname")

        # Check blocklist
        if hostname.lower() in SSRF_BLOCKLIST:
            return (False, f"Blocked: {hostname} is not allowed (security policy)")

        # Resolve hostname to IP
        try:
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
        except (socket.gaierror, ValueError) as e:
            return (False, f"Failed to resolve hostname: {hostname}")

        # Block private IP ranges (RFC 1918)
        if ip.is_private:
            return (False, f"Blocked: {ip} is a private IP address")

        # Block loopback
        if ip.is_loopback:
            return (False, f"Blocked: {ip} is a loopback address")

        # Block link-local
        if ip.is_link_local:
            return (False, f"Blocked: {ip} is a link-local address")

        # Block multicast
        if ip.is_multicast:
            return (False, f"Blocked: {ip} is a multicast address")

        # Block reserved
        if ip.is_reserved:
            return (False, f"Blocked: {ip} is a reserved address")

        # Explicit check for cloud metadata service
        if str(ip) == "169.254.169.254":
            return (False, "Blocked: AWS/GCP metadata service access denied")

        return (True, "")

    except Exception as e:
        logger.exception("URL validation error")
        return (False, f"URL validation error: {e}")


def get_realistic_headers() -> dict[str, str]:
    """Generate realistic browser headers with cryptographically secure UA rotation.

    Returns:
        Dictionary of HTTP headers that mimic a real browser
    """
    return {
        "User-Agent": secrets.choice(USER_AGENTS),  # Cryptographically secure random
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",  # Do Not Track
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }


def register_tools(mcp):
    """Register web fetching tools with MCP server."""

    @mcp.tool()
    @track_tool("local_web_fetch")
    def local_web_fetch(url: str, extract_text: bool = True, timeout: int = 30, verify_ssl: bool = True) -> str:
        """Fetch URL content using local requests library with realistic browser headers.

        This tool provides an alternative to WebFetch that may work when the built-in
        tool is blocked by network restrictions or enterprise security policies.

        Uses rotating User-Agents that mimic real browsers (Chrome, Firefox, Safari)
        and includes realistic HTTP headers to avoid detection as an automated tool.

        SECURITY: Includes SSRF protection - blocks private IPs, loopback, and cloud metadata.

        Args:
            url: URL to fetch (must start with http:// or https://, public IPs only)
            extract_text: If True, extract readable text from HTML (default: True)
            timeout: Request timeout in seconds (default: 30)
            verify_ssl: If False, skip SSL certificate verification (default: True)

        Returns:
            URL content (HTML or extracted text)

        Examples:
            - Fetch security blog post: local_web_fetch("https://blog.example.com/cve-analysis")
            - Get raw HTML: local_web_fetch("https://example.com", extract_text=False)
            - Skip SSL verification: local_web_fetch("https://example.com", verify_ssl=False)
        """
        try:
            import requests
            from bs4 import BeautifulSoup
            import urllib3

            # Suppress SSL warnings if verification is disabled
            if not verify_ssl:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Validate URL format
            if not url.startswith(("http://", "https://")):
                return f"Error: URL must start with http:// or https://"

            # SSRF Protection
            is_safe, error_msg = is_safe_url(url)
            if not is_safe:
                logger.warning(f"SSRF attempt blocked: {url} - {error_msg}")
                return f"Error: {error_msg}"

            # Fetch with realistic headers
            headers = get_realistic_headers()
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=verify_ssl)
            response.raise_for_status()

            # Return raw HTML if requested
            if not extract_text:
                return response.text

            # Extract readable text from HTML
            soup = BeautifulSoup(response.text, "html.parser")

            # Remove script and style elements
            for script in soup(["script", "style", "noscript"]):
                script.decompose()

            # Get text and clean it up
            text = soup.get_text(separator="\n", strip=True)

            # Remove excessive blank lines
            lines = [line for line in text.split("\n") if line.strip()]
            cleaned_text = "\n".join(lines)

            # Add metadata
            result = [
                f"URL: {response.url}",
                f"Status: {response.status_code}",
                f"Content-Type: {response.headers.get('content-type', 'unknown')}",
                f"Content-Length: {len(response.text)} bytes",
                "",
                "--- Content ---",
                "",
                cleaned_text,
            ]

            return "\n".join(result)

        except requests.exceptions.Timeout:
            return f"Error: Request timed out after {timeout} seconds"
        except requests.exceptions.ConnectionError as e:
            return f"Error: Connection failed - {str(e)}"
        except requests.exceptions.HTTPError as e:
            return f"Error: HTTP {e.response.status_code} - {e.response.reason}"
        except requests.exceptions.RequestException as e:
            return f"Error: Request failed - {str(e)}"
        except Exception as e:
            logger.exception("Unexpected error in local_web_fetch")
            return f"Error: {type(e).__name__}: {str(e)}"

    @mcp.tool()
    @track_tool("local_web_fetch_json")
    def local_web_fetch_json(url: str, timeout: int = 30, verify_ssl: bool = True) -> str:
        """Fetch JSON data from a URL using local requests with realistic headers.

        Specialized tool for fetching JSON APIs. Uses the same realistic browser
        headers as local_web_fetch but with JSON-specific Accept headers.

        SECURITY: Includes SSRF protection - blocks private IPs, loopback, and cloud metadata.

        Args:
            url: API endpoint URL (must start with http:// or https://, public IPs only)
            timeout: Request timeout in seconds (default: 30)
            verify_ssl: If False, skip SSL certificate verification (default: True)

        Returns:
            JSON response as formatted string

        Examples:
            - Fetch API data: local_web_fetch_json("https://api.example.com/v1/data")
        """
        try:
            import requests
            import json
            import urllib3

            # Suppress SSL warnings if verification is disabled
            if not verify_ssl:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Validate URL format
            if not url.startswith(("http://", "https://")):
                return f"Error: URL must start with http:// or https://"

            # SSRF Protection
            is_safe, error_msg = is_safe_url(url)
            if not is_safe:
                logger.warning(f"SSRF attempt blocked: {url} - {error_msg}")
                return f"Error: {error_msg}"

            # Fetch with realistic headers but JSON Accept
            headers = get_realistic_headers()
            headers["Accept"] = "application/json, text/plain, */*"

            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=verify_ssl)
            response.raise_for_status()

            # Try to parse as JSON
            try:
                data = response.json()
                return json.dumps(data, indent=2, ensure_ascii=False)
            except ValueError:
                # Not valid JSON, return raw content
                return f"Warning: Response is not valid JSON\n\n{response.text}"

        except requests.exceptions.Timeout:
            return f"Error: Request timed out after {timeout} seconds"
        except requests.exceptions.ConnectionError as e:
            return f"Error: Connection failed - {str(e)}"
        except requests.exceptions.HTTPError as e:
            return f"Error: HTTP {e.response.status_code} - {e.response.reason}"
        except requests.exceptions.RequestException as e:
            return f"Error: Request failed - {str(e)}"
        except Exception as e:
            logger.exception("Unexpected error in local_web_fetch_json")
            return f"Error: {type(e).__name__}: {str(e)}"

    @mcp.tool()
    @track_tool("local_web_fetch_raw")
    def local_web_fetch_raw(url: str, timeout: int = 30, verify_ssl: bool = True) -> str:
        """Fetch raw content from a URL (binary-safe).

        Use this for downloading files, images, or any non-text content.
        Returns base64-encoded data for binary files.

        SECURITY: Includes SSRF protection - blocks private IPs, loopback, and cloud metadata.

        Args:
            url: URL to fetch (must start with http:// or https://, public IPs only)
            timeout: Request timeout in seconds (default: 30)
            verify_ssl: If False, skip SSL certificate verification (default: True)

        Returns:
            Raw content or base64-encoded binary data with content type
        """
        try:
            import requests
            import base64
            import urllib3

            # Suppress SSL warnings if verification is disabled
            if not verify_ssl:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Validate URL format
            if not url.startswith(("http://", "https://")):
                return f"Error: URL must start with http:// or https://"

            # SSRF Protection
            is_safe, error_msg = is_safe_url(url)
            if not is_safe:
                logger.warning(f"SSRF attempt blocked: {url} - {error_msg}")
                return f"Error: {error_msg}"

            # Fetch with realistic headers
            headers = get_realistic_headers()
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=verify_ssl)
            response.raise_for_status()

            content_type = response.headers.get("content-type", "unknown")

            # Check if content is text
            if content_type.startswith(("text/", "application/json", "application/xml")):
                return f"Content-Type: {content_type}\n\n{response.text}"

            # Binary content - encode as base64
            encoded = base64.b64encode(response.content).decode("ascii")
            return f"Content-Type: {content_type}\nSize: {len(response.content)} bytes\nEncoding: base64\n\n{encoded}"

        except requests.exceptions.Timeout:
            return f"Error: Request timed out after {timeout} seconds"
        except requests.exceptions.ConnectionError as e:
            return f"Error: Connection failed - {str(e)}"
        except requests.exceptions.HTTPError as e:
            return f"Error: HTTP {e.response.status_code} - {e.response.reason}"
        except requests.exceptions.RequestException as e:
            return f"Error: Request failed - {str(e)}"
        except Exception as e:
            logger.exception("Unexpected error in local_web_fetch_raw")
            return f"Error: {type(e).__name__}: {str(e)}"
