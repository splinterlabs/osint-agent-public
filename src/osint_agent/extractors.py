"""IOC extraction with validation, defang support, and false positive filtering."""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration
EXTRACTION_TIMEOUT_SECONDS = 2
MAX_CONTENT_LENGTH = 500_000  # 500KB max

# Module-level executor to avoid per-call creation overhead
_timeout_executor = ThreadPoolExecutor(max_workers=1)

# Valid TLDs for domain validation (common + security-relevant)
VALID_TLDS = {
    # Generic
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "me",
    "info", "biz", "xyz", "online", "site", "top", "app", "dev",
    # Country codes (common)
    "ru", "cn", "de", "uk", "fr", "jp", "br", "in", "it", "nl", "au",
    "es", "ca", "kr", "pl", "ua", "ir", "kp",
    # Commonly abused
    "su", "cc", "tk", "ml", "ga", "cf", "gq", "pw", "top", "buzz",
    # Special
    "onion", "bit", "i2p",
}

# Known false positive domains
FALSE_POSITIVE_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "localhost.localdomain",
    "schema.org", "w3.org", "xmlns.com",
    "purl.org", "rdfs.org",
}


class IOCPatterns:
    """Compiled regex patterns for IOC extraction."""

    # IPv4 with octet range validation (0-255)
    IPV4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    # IPv6 (simplified - common forms)
    IPV6 = re.compile(
        r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|"
        r"\b(?:[a-fA-F0-9]{1,4}:){1,7}:|"
        r"\b::(?:[a-fA-F0-9]{1,4}:){0,6}[a-fA-F0-9]{1,4}\b"
    )

    # Domain - supports defanged formats like example[.]com
    DOMAIN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b|"
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"(?:\[\.\]|\[dot\]|\(dot\)|\(\.\)))+[a-zA-Z]{2,}\b",
        re.IGNORECASE,
    )

    # Hashes - exact lengths with word boundaries
    MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
    SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
    SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

    # CVE - standard format
    CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    # URL - supports defanged hxxp(s) and [.] notation
    URL = re.compile(
        r"(?:https?|hxxps?|ftp|ftps)://[^\s<>\"']+",
        re.IGNORECASE,
    )

    # Email addresses
    EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def refang(text: str) -> str:
    """Convert defanged IOCs back to normal form.

    Handles common defanging patterns:
    - [.] or [dot] -> .
    - hxxp -> http
    - [://] -> ://
    - [@] -> @
    """
    return (
        text.replace("[.]", ".")
        .replace("[dot]", ".")
        .replace("(dot)", ".")
        .replace("(.)", ".")
        .replace("hxxp", "http")
        .replace("hXXp", "http")
        .replace("HXXP", "HTTP")
        .replace("[://]", "://")
        .replace("[:]", ":")
        .replace("[@]", "@")
        .replace("[at]", "@")
    )


def validate_domain(domain: str) -> bool:
    """Validate domain has known TLD and isn't a false positive."""
    domain = refang(domain).lower()

    parts = domain.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]

    # Check against known TLDs
    if tld not in VALID_TLDS:
        return False

    # Filter known false positives
    if domain in FALSE_POSITIVE_DOMAINS:
        return False

    # Filter version strings that look like domains (v1.2.3)
    if re.match(r"^v?\d+\.\d+", domain):
        return False

    # Filter file extensions that match domain pattern
    if len(parts) == 2 and parts[0] in ("file", "image", "document", "report"):
        return False

    return True


def validate_ip(ip: str) -> bool:
    """Filter private/reserved IPs that are usually false positives."""
    try:
        octets = [int(x) for x in ip.split(".")]
    except ValueError:
        return False

    if len(octets) != 4:
        return False

    # Private ranges (RFC 1918)
    if octets[0] == 10:
        return False
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    if octets[0] == 192 and octets[1] == 168:
        return False

    # Loopback
    if octets[0] == 127:
        return False

    # Link-local
    if octets[0] == 169 and octets[1] == 254:
        return False

    # Invalid/reserved
    if octets[0] == 0:
        return False
    if octets[0] >= 224:  # Multicast and reserved
        return False

    return True


def validate_hash(hash_value: str, hash_type: str) -> bool:
    """Validate hash isn't a known false positive pattern."""
    h = hash_value.lower()

    # All zeros or all same character
    if len(set(h)) == 1:
        return False

    # Sequential patterns
    if h in ("0123456789abcdef" * 4)[:len(h)]:
        return False

    # Common test values
    test_patterns = {
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty string
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty
    }
    if h in test_patterns:
        return False

    return True


def _run_with_timeout(func, timeout_seconds: int):
    """Run a function with timeout protection (cross-platform).

    Uses ThreadPoolExecutor for cross-platform timeout support.
    Works on Windows, Linux, and macOS.

    Args:
        func: Callable to execute
        timeout_seconds: Maximum execution time

    Returns:
        Result of func()

    Raises:
        TimeoutError: If execution exceeds timeout
    """
    future = _timeout_executor.submit(func)
    try:
        return future.result(timeout=timeout_seconds)
    except FuturesTimeoutError:
        raise TimeoutError(f"Operation timed out after {timeout_seconds}s")


def _extract_iocs_internal(content: str) -> dict[str, list[str]]:
    """Internal IOC extraction logic (called with timeout protection)."""
    extracted: dict[str, list[str]] = {}

    # IPv4
    ipv4_matches = IOCPatterns.IPV4.findall(content)
    valid_ips = [ip for ip in set(ipv4_matches) if validate_ip(ip)]
    if valid_ips:
        extracted["ipv4"] = sorted(valid_ips)

    # IPv6
    ipv6_matches = IOCPatterns.IPV6.findall(content)
    if ipv6_matches:
        extracted["ipv6"] = sorted(set(ipv6_matches))

    # Domains (with TLD validation)
    domain_matches = IOCPatterns.DOMAIN.findall(content)
    valid_domains = [
        refang(d).lower() for d in set(domain_matches) if validate_domain(d)
    ]
    if valid_domains:
        extracted["domain"] = sorted(set(valid_domains))

    # Hashes
    for hash_type, pattern in [
        ("md5", IOCPatterns.MD5),
        ("sha1", IOCPatterns.SHA1),
        ("sha256", IOCPatterns.SHA256),
    ]:
        matches = pattern.findall(content)
        valid_hashes = [
            h.lower() for h in set(matches) if validate_hash(h, hash_type)
        ]
        if valid_hashes:
            extracted[hash_type] = sorted(valid_hashes)

    # CVEs
    cve_matches = IOCPatterns.CVE.findall(content)
    if cve_matches:
        extracted["cve"] = sorted(set(c.upper() for c in cve_matches))

    # URLs
    url_matches = IOCPatterns.URL.findall(content)
    if url_matches:
        extracted["url"] = sorted(set(refang(u) for u in url_matches))

    # Emails
    email_matches = IOCPatterns.EMAIL.findall(content)
    if email_matches:
        # Filter out common false positives
        valid_emails = [
            e.lower()
            for e in set(email_matches)
            if not e.lower().endswith(("@example.com", "@test.com"))
        ]
        if valid_emails:
            extracted["email"] = sorted(valid_emails)

    return extracted


def extract_iocs(content: str) -> dict[str, list[str]]:
    """Extract IOCs from content with validation and timeout protection.

    Uses cross-platform timeout protection via ThreadPoolExecutor.
    Works on Windows, Linux, and macOS.

    Args:
        content: Text content to search for IOCs

    Returns:
        Dictionary mapping IOC type to list of extracted values
    """
    # Truncate oversized content
    if len(content) > MAX_CONTENT_LENGTH:
        logger.warning(f"Content truncated from {len(content)} to {MAX_CONTENT_LENGTH}")
        content = content[:MAX_CONTENT_LENGTH]

    try:
        return _run_with_timeout(
            lambda: _extract_iocs_internal(content),
            EXTRACTION_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        logger.error("IOC extraction timed out - possible ReDoS attempt")
        return {}
    except Exception as e:
        logger.error(f"IOC extraction failed: {e}")
        return {}
