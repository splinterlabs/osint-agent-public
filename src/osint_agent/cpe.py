"""CPE (Common Platform Enumeration) matching utilities.

Provides pattern matching for CPE strings against watchlist patterns,
with support for wildcards and version ranges.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class CPEMatch:
    """Result of a CPE pattern match."""

    matched: bool
    pattern: str
    cpe: str
    vendor: str | None = None
    product: str | None = None
    version: str | None = None


def parse_cpe23(cpe: str) -> dict[str, str]:
    """Parse a CPE 2.3 formatted string.

    CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

    Args:
        cpe: CPE 2.3 string

    Returns:
        Dictionary with parsed components
    """
    # Handle both CPE 2.2 and 2.3 formats
    if cpe.startswith("cpe:/"):
        return parse_cpe22(cpe)

    if not cpe.startswith("cpe:2.3:"):
        return {}

    parts = cpe.split(":")
    if len(parts) < 5:
        return {}

    # CPE 2.3 has 13 components after "cpe:2.3:"
    component_names = [
        "part",
        "vendor",
        "product",
        "version",
        "update",
        "edition",
        "language",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other",
    ]

    result = {}
    for i, name in enumerate(component_names):
        idx = i + 2  # Skip "cpe" and "2.3"
        if idx < len(parts):
            value = parts[idx]
            # Handle escaped characters and wildcards
            value = value.replace("\\:", ":")
            if value not in ("*", "-"):
                result[name] = value
            elif value == "*":
                result[name] = "*"

    return result


def parse_cpe22(cpe: str) -> dict[str, str]:
    """Parse a CPE 2.2 formatted string.

    CPE 2.2 format: cpe:/part:vendor:product:version:update:edition:language

    Args:
        cpe: CPE 2.2 string

    Returns:
        Dictionary with parsed components
    """
    if not cpe.startswith("cpe:/"):
        return {}

    # Remove cpe:/ prefix
    remainder = cpe[5:]
    parts = remainder.split(":")

    if len(parts) < 1:
        return {}

    # First character is the part (a=application, o=os, h=hardware)
    part = parts[0][0] if parts[0] else ""
    vendor = parts[0][1:] if len(parts[0]) > 1 else (parts[1] if len(parts) > 1 else "")

    component_names = ["vendor", "product", "version", "update", "edition", "language"]
    result = {"part": part}

    # Adjust parts list - vendor might be in first part or second
    if len(parts[0]) > 1:
        # Vendor is in first part after the type character
        values = [parts[0][1:]] + parts[1:]
    else:
        values = parts[1:]

    for i, name in enumerate(component_names):
        if i < len(values) and values[i]:
            result[name] = values[i]

    return result


def match_cpe_pattern(cpe: str, pattern: str) -> CPEMatch:
    """Match a CPE string against a pattern.

    Supports wildcards (*) in pattern components.

    Args:
        cpe: CPE string to check
        pattern: CPE pattern (may contain * wildcards)

    Returns:
        CPEMatch with match result and details
    """
    cpe_parts = parse_cpe23(cpe)
    pattern_parts = parse_cpe23(pattern)

    if not cpe_parts or not pattern_parts:
        return CPEMatch(
            matched=False,
            pattern=pattern,
            cpe=cpe,
        )

    # Check each component
    for key, pattern_value in pattern_parts.items():
        if pattern_value == "*":
            continue  # Wildcard matches anything

        cpe_value = cpe_parts.get(key, "")

        # Handle version wildcards like "7.*"
        if "*" in pattern_value:
            regex = pattern_value.replace(".", r"\.").replace("*", ".*")
            if not re.match(f"^{regex}$", cpe_value, re.IGNORECASE):
                return CPEMatch(
                    matched=False,
                    pattern=pattern,
                    cpe=cpe,
                    vendor=cpe_parts.get("vendor"),
                    product=cpe_parts.get("product"),
                    version=cpe_parts.get("version"),
                )
        elif pattern_value.lower() != cpe_value.lower():
            return CPEMatch(
                matched=False,
                pattern=pattern,
                cpe=cpe,
                vendor=cpe_parts.get("vendor"),
                product=cpe_parts.get("product"),
                version=cpe_parts.get("version"),
            )

    return CPEMatch(
        matched=True,
        pattern=pattern,
        cpe=cpe,
        vendor=cpe_parts.get("vendor"),
        product=cpe_parts.get("product"),
        version=cpe_parts.get("version"),
    )


def match_vendor_product(
    cpe: str, vendors: list[str], products: list[str]
) -> tuple[bool, str | None, str | None]:
    """Check if CPE matches any vendor or product in lists.

    Args:
        cpe: CPE string to check
        vendors: List of vendor names to match
        products: List of product names to match

    Returns:
        Tuple of (matched, matched_vendor, matched_product)
    """
    parts = parse_cpe23(cpe)
    if not parts:
        return False, None, None

    cpe_vendor = parts.get("vendor", "").lower().replace("_", " ")
    cpe_product = parts.get("product", "").lower().replace("_", " ")

    matched_vendor = None
    matched_product = None

    # Check vendors
    for vendor in vendors:
        vendor_lower = vendor.lower()
        if vendor_lower in cpe_vendor or cpe_vendor in vendor_lower:
            matched_vendor = vendor
            break

    # Check products
    for product in products:
        product_lower = product.lower()
        if product_lower in cpe_product or cpe_product in product_lower:
            matched_product = product
            break

    matched = matched_vendor is not None or matched_product is not None
    return matched, matched_vendor, matched_product


class WatchlistMatcher:
    """Matches CVE data against watchlist configuration."""

    def __init__(self, watchlist: dict[str, Any]):
        """Initialize matcher with watchlist config.

        Args:
            watchlist: Dictionary with vendors, products, cpe_patterns, keywords
        """
        self.vendors = [v.lower() for v in watchlist.get("vendors", [])]
        self.products = [p.lower() for p in watchlist.get("products", [])]
        self.cpe_patterns = watchlist.get("cpe_patterns", [])
        self.keywords = [k.lower() for k in watchlist.get("keywords", [])]

    def match_cve(self, cve_data: dict[str, Any]) -> dict[str, Any]:
        """Check if CVE matches watchlist criteria.

        Args:
            cve_data: CVE data with description, affected_products, etc.

        Returns:
            Match result with details
        """
        matches: dict[str, Any] = {
            "matched": False,
            "vendor_matches": [],
            "product_matches": [],
            "cpe_matches": [],
            "keyword_matches": [],
        }

        # Check description for keywords
        description = cve_data.get("description", "").lower()
        for keyword in self.keywords:
            if keyword in description:
                matches["keyword_matches"].append(keyword)
                matches["matched"] = True

        # Check affected products
        affected = cve_data.get("affected_products", [])
        for product_info in affected:
            cpe = product_info.get("cpe", "")

            # Check CPE patterns
            for pattern in self.cpe_patterns:
                result = match_cpe_pattern(cpe, pattern)
                if result.matched:
                    matches["cpe_matches"].append(
                        {
                            "pattern": pattern,
                            "cpe": cpe,
                            "vendor": result.vendor,
                            "product": result.product,
                        }
                    )
                    matches["matched"] = True

            # Check vendor/product names
            vendor = product_info.get("vendor", "").lower()
            product = product_info.get("product", "").lower()

            for v in self.vendors:
                if v in vendor or vendor in v:
                    if v not in matches["vendor_matches"]:
                        matches["vendor_matches"].append(v)
                        matches["matched"] = True

            for p in self.products:
                if p in product or product in p:
                    if p not in matches["product_matches"]:
                        matches["product_matches"].append(p)
                        matches["matched"] = True

        return matches

    def match_cpe_list(self, cpes: list[str]) -> list[CPEMatch]:
        """Match a list of CPEs against all patterns.

        Args:
            cpes: List of CPE strings

        Returns:
            List of successful matches
        """
        results = []
        for cpe in cpes:
            for pattern in self.cpe_patterns:
                match = match_cpe_pattern(cpe, pattern)
                if match.matched:
                    results.append(match)

            # Also check vendor/product lists
            matched, vendor, product = match_vendor_product(
                cpe, self.vendors, self.products
            )
            if matched:
                parts = parse_cpe23(cpe)
                results.append(
                    CPEMatch(
                        matched=True,
                        pattern=f"vendor:{vendor}" if vendor else f"product:{product}",
                        cpe=cpe,
                        vendor=parts.get("vendor"),
                        product=parts.get("product"),
                        version=parts.get("version"),
                    )
                )

        return results
