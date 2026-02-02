"""STIX 2.1 export for OpenCTI compatibility.

OpenCTI uses the STIX 2.1 standard for its data model:
- STIX Domain Objects (SDOs): Attack Patterns, Malware, Threat Actors, Vulnerabilities
- STIX Cyber Observables (SCOs): IP Addresses, Domains, Hashes, URLs
- STIX Relationship Objects (SROs): Relationships between entities

Reference: https://docs.opencti.io/latest/usage/data-model/
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# STIX 2.1 namespace for deterministic UUIDs
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def generate_stix_id(type_name: str, value: str) -> str:
    """Generate deterministic STIX ID based on type and value."""
    # Use UUIDv5 for deterministic IDs (same input = same ID)
    name = f"{type_name}--{value}"
    generated_uuid = uuid.uuid5(STIX_NAMESPACE, name)
    return f"{type_name}--{generated_uuid}"


def now_iso() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class STIXBundle:
    """Builder for STIX 2.1 bundles."""

    def __init__(self) -> None:
        self.objects: list[dict[str, Any]] = []
        self._seen_ids: set[str] = set()

    def add(self, obj: dict[str, Any]) -> str:
        """Add object to bundle, deduplicating by ID."""
        obj_id: str = obj.get("id", "")
        if obj_id not in self._seen_ids:
            self.objects.append(obj)
            self._seen_ids.add(obj_id)
        return obj_id

    def to_dict(self) -> dict[str, Any]:
        """Export bundle as dictionary."""
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": self.objects,
        }

    def to_json(self, indent: int = 2) -> str:
        """Export bundle as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str | Path) -> None:
        """Save bundle to file (atomic write)."""
        import tempfile
        import os
        target = Path(path)
        fd, tmp_path = tempfile.mkstemp(
            dir=target.parent,
            prefix=".stix_",
            suffix=".json.tmp",
        )
        try:
            with open(fd, "w") as f:
                f.write(self.to_json())
            os.replace(tmp_path, path)
        except Exception:
            Path(tmp_path).unlink(missing_ok=True)
            raise


# =============================================================================
# STIX Cyber Observables (SCOs) - Technical Indicators
# =============================================================================


def create_ipv4_observable(ip: str, labels: Optional[list[str]] = None) -> dict[str, Any]:
    """Create STIX IPv4 Address observable."""
    return {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": generate_stix_id("ipv4-addr", ip),
        "value": ip,
        "x_opencti_labels": labels or [],
    }


def create_ipv6_observable(ip: str, labels: Optional[list[str]] = None) -> dict[str, Any]:
    """Create STIX IPv6 Address observable."""
    return {
        "type": "ipv6-addr",
        "spec_version": "2.1",
        "id": generate_stix_id("ipv6-addr", ip),
        "value": ip,
        "x_opencti_labels": labels or [],
    }


def create_domain_observable(
    domain: str, labels: Optional[list[str]] = None
) -> dict[str, Any]:
    """Create STIX Domain Name observable."""
    return {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": generate_stix_id("domain-name", domain),
        "value": domain,
        "x_opencti_labels": labels or [],
    }


def create_url_observable(url: str, labels: Optional[list[str]] = None) -> dict[str, Any]:
    """Create STIX URL observable."""
    return {
        "type": "url",
        "spec_version": "2.1",
        "id": generate_stix_id("url", url),
        "value": url,
        "x_opencti_labels": labels or [],
    }


def create_file_hash_observable(
    hash_value: str,
    hash_type: str,  # "MD5", "SHA-1", "SHA-256"
    labels: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create STIX File observable with hash."""
    # Normalize hash type to STIX format
    stix_hash_type = {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha-1": "SHA-1",
        "sha256": "SHA-256",
        "sha-256": "SHA-256",
    }.get(hash_type.lower(), hash_type.upper())

    return {
        "type": "file",
        "spec_version": "2.1",
        "id": generate_stix_id("file", hash_value),
        "hashes": {stix_hash_type: hash_value},
        "x_opencti_labels": labels or [],
    }


def create_email_observable(
    email: str, labels: Optional[list[str]] = None
) -> dict[str, Any]:
    """Create STIX Email Address observable."""
    return {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": generate_stix_id("email-addr", email),
        "value": email,
        "x_opencti_labels": labels or [],
    }


# =============================================================================
# STIX Domain Objects (SDOs) - High-level Intelligence
# =============================================================================


def create_vulnerability(
    cve_id: str,
    name: str,
    description: str,
    cvss_score: Optional[float] = None,
    external_references: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Create STIX Vulnerability object for CVE."""
    vuln: dict[str, Any] = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": generate_stix_id("vulnerability", cve_id),
        "created": now_iso(),
        "modified": now_iso(),
        "name": cve_id,
        "description": description,
        "external_references": [
            {
                "source_name": "cve",
                "external_id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        ],
    }

    if cvss_score is not None:
        vuln["x_opencti_cvss_base_score"] = cvss_score

    if external_references:
        vuln["external_references"].extend(external_references)

    return vuln


def create_indicator(
    pattern: str,
    pattern_type: str = "stix",
    name: Optional[str] = None,
    description: Optional[str] = None,
    labels: Optional[list[str]] = None,
    valid_from: Optional[str] = None,
    confidence: Optional[int] = None,
) -> dict[str, Any]:
    """Create STIX Indicator object.

    Args:
        pattern: STIX pattern (e.g., "[ipv4-addr:value = '1.2.3.4']")
        pattern_type: Pattern language ("stix", "yara", "sigma", etc.)
        name: Human-readable name
        description: Detailed description
        labels: Classification labels
        valid_from: When indicator becomes valid (ISO timestamp)
        confidence: Confidence level (0-100)
    """
    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": generate_stix_id("indicator", pattern),
        "created": now_iso(),
        "modified": now_iso(),
        "pattern": pattern,
        "pattern_type": pattern_type,
        "valid_from": valid_from or now_iso(),
    }

    if name:
        indicator["name"] = name
    if description:
        indicator["description"] = description
    if labels:
        indicator["labels"] = labels
    if confidence is not None:
        indicator["confidence"] = confidence

    return indicator


def create_report(
    name: str,
    description: str,
    published: Optional[str] = None,
    report_types: Optional[list[str]] = None,
    object_refs: Optional[list[str]] = None,
    labels: Optional[list[str]] = None,
    confidence: Optional[int] = None,
    external_references: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Create STIX Report object.

    Args:
        name: Report title
        description: Report content/summary
        published: Publication date (ISO timestamp)
        report_types: Types like "threat-report", "attack-pattern", "campaign"
        object_refs: List of STIX IDs referenced in this report
        labels: Classification labels
        confidence: Confidence level (0-100)
        external_references: External links and sources
    """
    report: dict[str, Any] = {
        "type": "report",
        "spec_version": "2.1",
        "id": generate_stix_id("report", f"{name}-{now_iso()}"),
        "created": now_iso(),
        "modified": now_iso(),
        "name": name,
        "description": description,
        "published": published or now_iso(),
        "report_types": report_types or ["threat-report"],
        "object_refs": object_refs or [],
    }

    if labels:
        report["labels"] = labels
    if confidence is not None:
        report["confidence"] = confidence
    if external_references:
        report["external_references"] = external_references

    return report


def create_threat_actor(
    name: str,
    description: Optional[str] = None,
    aliases: Optional[list[str]] = None,
    threat_actor_types: Optional[list[str]] = None,
    labels: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create STIX Threat Actor object."""
    actor: dict[str, Any] = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": generate_stix_id("threat-actor", name),
        "created": now_iso(),
        "modified": now_iso(),
        "name": name,
    }

    if description:
        actor["description"] = description
    if aliases:
        actor["aliases"] = aliases
    if threat_actor_types:
        actor["threat_actor_types"] = threat_actor_types
    if labels:
        actor["labels"] = labels

    return actor


def create_malware(
    name: str,
    description: Optional[str] = None,
    malware_types: Optional[list[str]] = None,
    is_family: bool = True,
    labels: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create STIX Malware object."""
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": generate_stix_id("malware", name),
        "created": now_iso(),
        "modified": now_iso(),
        "name": name,
        "is_family": is_family,
    }

    if description:
        malware["description"] = description
    if malware_types:
        malware["malware_types"] = malware_types
    if labels:
        malware["labels"] = labels

    return malware


# =============================================================================
# STIX Relationship Objects (SROs)
# =============================================================================


def create_relationship(
    source_ref: str,
    target_ref: str,
    relationship_type: str,
    description: Optional[str] = None,
    confidence: Optional[int] = None,
) -> dict[str, Any]:
    """Create STIX Relationship object.

    Common relationship types:
    - "indicates": Indicator indicates Threat Actor/Malware
    - "uses": Threat Actor uses Malware/Tool
    - "targets": Threat Actor/Malware targets Identity/Vulnerability
    - "attributed-to": Incident attributed to Threat Actor
    - "related-to": General relationship
    """
    rel: dict[str, Any] = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": generate_stix_id("relationship", f"{source_ref}-{relationship_type}-{target_ref}"),
        "created": now_iso(),
        "modified": now_iso(),
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }

    if description:
        rel["description"] = description
    if confidence is not None:
        rel["confidence"] = confidence

    return rel


# =============================================================================
# Conversion Helpers
# =============================================================================


def escape_stix_pattern_value(value: str) -> str:
    """Escape special characters in STIX pattern values.

    STIX patterns use single quotes for string values. Characters that need
    escaping: backslash (\\), single quote ('), and other special chars.

    Reference: STIX 2.1 Pattern Grammar
    """
    # Escape backslashes first (before other escapes add more)
    value = value.replace("\\", "\\\\")
    # Escape single quotes
    value = value.replace("'", "\\'")
    return value


def iocs_to_stix_bundle(
    iocs: dict[str, list[str]],
    labels: Optional[list[str]] = None,
    create_indicators: bool = True,
) -> STIXBundle:
    """Convert extracted IOCs to a STIX bundle.

    Args:
        iocs: Dictionary of IOC type -> list of values
        labels: Labels to apply to all observables
        create_indicators: Also create Indicator objects with STIX patterns

    Returns:
        STIXBundle containing observables and optionally indicators
    """
    bundle = STIXBundle()
    labels = labels or []

    for ipv4 in iocs.get("ipv4", []):
        obs = create_ipv4_observable(ipv4, labels)
        bundle.add(obs)
        if create_indicators:
            escaped_ip = escape_stix_pattern_value(ipv4)
            indicator = create_indicator(
                pattern=f"[ipv4-addr:value = '{escaped_ip}']",
                name=f"IP: {ipv4}",
                labels=labels,
            )
            bundle.add(indicator)
            bundle.add(create_relationship(indicator["id"], obs["id"], "based-on"))

    for ipv6 in iocs.get("ipv6", []):
        obs = create_ipv6_observable(ipv6, labels)
        bundle.add(obs)
        if create_indicators:
            escaped_ip = escape_stix_pattern_value(ipv6)
            indicator = create_indicator(
                pattern=f"[ipv6-addr:value = '{escaped_ip}']",
                name=f"IPv6: {ipv6}",
                labels=labels,
            )
            bundle.add(indicator)
            bundle.add(create_relationship(indicator["id"], obs["id"], "based-on"))

    for domain in iocs.get("domain", []):
        obs = create_domain_observable(domain, labels)
        bundle.add(obs)
        if create_indicators:
            escaped_domain = escape_stix_pattern_value(domain)
            indicator = create_indicator(
                pattern=f"[domain-name:value = '{escaped_domain}']",
                name=f"Domain: {domain}",
                labels=labels,
            )
            bundle.add(indicator)
            bundle.add(create_relationship(indicator["id"], obs["id"], "based-on"))

    for url in iocs.get("url", []):
        obs = create_url_observable(url, labels)
        bundle.add(obs)
        if create_indicators:
            escaped_url = escape_stix_pattern_value(url)
            indicator = create_indicator(
                pattern=f"[url:value = '{escaped_url}']",
                name=f"URL: {url[:50]}{'...' if len(url) > 50 else ''}",
                labels=labels,
            )
            bundle.add(indicator)
            bundle.add(create_relationship(indicator["id"], obs["id"], "based-on"))

    for hash_type in ["md5", "sha1", "sha256"]:
        for hash_value in iocs.get(hash_type, []):
            obs = create_file_hash_observable(hash_value, hash_type, labels)
            bundle.add(obs)
            if create_indicators:
                stix_hash_type = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[hash_type]
                escaped_hash = escape_stix_pattern_value(hash_value)
                indicator = create_indicator(
                    pattern=f"[file:hashes.'{stix_hash_type}' = '{escaped_hash}']",
                    name=f"{hash_type.upper()}: {hash_value[:16]}...",
                    labels=labels,
                )
                bundle.add(indicator)
                bundle.add(create_relationship(indicator["id"], obs["id"], "based-on"))

    for email in iocs.get("email", []):
        obs = create_email_observable(email, labels)
        bundle.add(obs)

    return bundle


def cve_to_stix(cve_data: dict[str, Any]) -> dict[str, Any]:
    """Convert CVE data to STIX Vulnerability object."""
    external_refs = []

    # Add references from CVE data
    for ref in cve_data.get("references", []):
        external_refs.append(
            {
                "source_name": ref.get("source", "unknown"),
                "url": ref.get("url", ""),
            }
        )

    return create_vulnerability(
        cve_id=cve_data.get("id", ""),
        name=cve_data.get("id", ""),
        description=cve_data.get("description", ""),
        cvss_score=cve_data.get("cvss_v3_score"),
        external_references=external_refs if external_refs else None,
    )
