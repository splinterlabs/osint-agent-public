"""YARA and Sigma rule generation from IOCs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import re

# Maximum IOCs per field/direction in generated rules
MAX_IOCS_PER_FIELD = 20
MAX_IOCS_PER_RULE = 50


def generate_yara_rule(
    name: str,
    hashes: list[dict[str, str]],
    description: Optional[str] = None,
    author: str = "OSINT Agent",
    tags: Optional[list[str]] = None,
    strings: Optional[list[str]] = None,
) -> str:
    """Generate a YARA rule from file hashes.

    Args:
        name: Rule name (will be sanitized)
        hashes: List of hash dicts with 'type' (md5/sha1/sha256) and 'value' keys
        description: Rule description
        author: Rule author
        tags: Optional tags for the rule
        strings: Optional additional string patterns to match

    Returns:
        YARA rule as string
    """
    # Sanitize rule name
    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if safe_name[0].isdigit():
        safe_name = "rule_" + safe_name

    # Build meta section
    meta_lines = []
    if description:
        meta_lines.append(f'        description = "{_escape_yara_string(description)}"')
    meta_lines.append(f'        author = "{_escape_yara_string(author)}"')
    meta_lines.append(f'        date = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"')

    if tags:
        meta_lines.append(f'        tags = "{", ".join(tags)}"')

    # Build hash conditions
    hash_conditions = []
    for h in hashes:
        hash_type = h.get("type", "").lower()
        hash_value = h.get("value", "").lower()

        if hash_type == "md5" and len(hash_value) == 32:
            hash_conditions.append(f'hash.md5(0, filesize) == "{hash_value}"')
        elif hash_type == "sha1" and len(hash_value) == 40:
            hash_conditions.append(f'hash.sha1(0, filesize) == "{hash_value}"')
        elif hash_type == "sha256" and len(hash_value) == 64:
            hash_conditions.append(f'hash.sha256(0, filesize) == "{hash_value}"')

    # Build strings section
    string_lines = []
    if strings:
        for i, s in enumerate(strings):
            string_lines.append(f'        $s{i} = "{_escape_yara_string(s)}"')

    # Build condition
    conditions = []
    if hash_conditions:
        conditions.append("(" + " or ".join(hash_conditions) + ")")
    if strings:
        conditions.append("any of ($s*)")

    condition_str = " or ".join(conditions) if conditions else "false"

    # Assemble rule
    tags_str = " : " + " ".join(tags) if tags else ""

    rule = f"""import "hash"

rule {safe_name}{tags_str}
{{
    meta:
{chr(10).join(meta_lines)}

"""

    if string_lines:
        rule += f"""    strings:
{chr(10).join(string_lines)}

"""

    rule += f"""    condition:
        {condition_str}
}}
"""

    return rule


def generate_sigma_rule(
    title: str,
    iocs: dict[str, list[str]],
    description: Optional[str] = None,
    author: str = "OSINT Agent",
    level: str = "high",
    status: str = "experimental",
    tags: Optional[list[str]] = None,
    logsource_category: str = "proxy",
    logsource_product: Optional[str] = None,
) -> str:
    """Generate a Sigma rule from network IOCs.

    Args:
        title: Rule title
        iocs: Dict with IOC types (ipv4, domain, url) as keys
        description: Rule description
        author: Rule author
        level: Detection level (low/medium/high/critical)
        status: Rule status (experimental/test/stable)
        tags: MITRE ATT&CK tags
        logsource_category: Log source category (proxy, firewall, dns, etc.)
        logsource_product: Optional specific product

    Returns:
        Sigma rule as YAML string
    """
    # Build detection section based on IOC types
    detection_fields = []

    if iocs.get("ipv4") or iocs.get("ipv6"):
        ips = (iocs.get("ipv4", []) + iocs.get("ipv6", []))[:MAX_IOCS_PER_RULE]
        if ips:
            detection_fields.append(("dst_ip", ips))
            detection_fields.append(("src_ip", ips))

    if iocs.get("domain"):
        domains = iocs["domain"][:MAX_IOCS_PER_RULE]
        detection_fields.append(("cs-host", domains))
        detection_fields.append(("query", domains))

    if iocs.get("url"):
        urls = iocs["url"][:MAX_IOCS_PER_RULE]
        detection_fields.append(("cs-uri", urls))

    # Build YAML
    lines = []
    lines.append(f"title: {title}")
    lines.append(f"id: {_generate_uuid_from_title(title)}")
    lines.append(f"status: {status}")

    if description:
        lines.append(f"description: {description}")

    lines.append(f"author: {author}")
    lines.append(f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}")

    if tags:
        lines.append("tags:")
        for tag in tags:
            lines.append(f"    - {tag}")

    lines.append("logsource:")
    lines.append(f"    category: {logsource_category}")
    if logsource_product:
        lines.append(f"    product: {logsource_product}")

    lines.append("detection:")

    # Add selection conditions
    for i, (field, values) in enumerate(detection_fields):
        selection_name = f"selection_{i}"
        lines.append(f"    {selection_name}:")
        lines.append(f"        {field}|contains:")
        for val in values[:MAX_IOCS_PER_FIELD]:
            lines.append(f"            - '{val}'")

    # Condition
    if detection_fields:
        selection_names = [f"selection_{i}" for i in range(len(detection_fields))]
        lines.append(f"    condition: {' or '.join(selection_names)}")
    else:
        lines.append("    condition: false")

    lines.append(f"level: {level}")
    lines.append("falsepositives:")
    lines.append("    - Legitimate traffic to these destinations")

    return "\n".join(lines)


def generate_sigma_dns_rule(
    title: str,
    domains: list[str],
    description: Optional[str] = None,
    author: str = "OSINT Agent",
    level: str = "high",
    tags: Optional[list[str]] = None,
) -> str:
    """Generate a Sigma rule for DNS queries.

    Args:
        title: Rule title
        domains: List of malicious domains
        description: Rule description
        author: Rule author
        level: Detection level
        tags: MITRE ATT&CK tags

    Returns:
        Sigma rule as YAML string
    """
    lines = []
    lines.append(f"title: {title}")
    lines.append(f"id: {_generate_uuid_from_title(title)}")
    lines.append("status: experimental")

    if description:
        lines.append(f"description: {description}")

    lines.append(f"author: {author}")
    lines.append(f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}")

    if tags:
        lines.append("tags:")
        for tag in tags:
            lines.append(f"    - {tag}")

    lines.append("logsource:")
    lines.append("    category: dns")

    lines.append("detection:")
    lines.append("    selection:")
    lines.append("        query|endswith:")
    for domain in domains[:MAX_IOCS_PER_RULE]:
        lines.append(f"            - '.{domain}'")
        lines.append(f"            - '{domain}'")

    lines.append("    condition: selection")
    lines.append(f"level: {level}")
    lines.append("falsepositives:")
    lines.append("    - Legitimate access to these domains")

    return "\n".join(lines)


def generate_sigma_firewall_rule(
    title: str,
    ips: list[str],
    description: Optional[str] = None,
    author: str = "OSINT Agent",
    level: str = "high",
    direction: str = "both",
    tags: Optional[list[str]] = None,
) -> str:
    """Generate a Sigma rule for firewall logs.

    Args:
        title: Rule title
        ips: List of malicious IPs
        description: Rule description
        author: Rule author
        level: Detection level
        direction: Traffic direction (inbound/outbound/both)
        tags: MITRE ATT&CK tags

    Returns:
        Sigma rule as YAML string
    """
    lines = []
    lines.append(f"title: {title}")
    lines.append(f"id: {_generate_uuid_from_title(title)}")
    lines.append("status: experimental")

    if description:
        lines.append(f"description: {description}")

    lines.append(f"author: {author}")
    lines.append(f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}")

    if tags:
        lines.append("tags:")
        for tag in tags:
            lines.append(f"    - {tag}")

    lines.append("logsource:")
    lines.append("    category: firewall")

    lines.append("detection:")

    if direction in ("both", "outbound"):
        lines.append("    selection_dst:")
        lines.append("        dst_ip:")
        for ip in ips[:MAX_IOCS_PER_RULE]:
            lines.append(f"            - '{ip}'")

    if direction in ("both", "inbound"):
        lines.append("    selection_src:")
        lines.append("        src_ip:")
        for ip in ips[:MAX_IOCS_PER_RULE]:
            lines.append(f"            - '{ip}'")

    if direction == "both":
        lines.append("    condition: selection_dst or selection_src")
    elif direction == "outbound":
        lines.append("    condition: selection_dst")
    else:
        lines.append("    condition: selection_src")

    lines.append(f"level: {level}")
    lines.append("falsepositives:")
    lines.append("    - Legitimate traffic from/to these IPs")

    return "\n".join(lines)


def _escape_yara_string(s: str) -> str:
    """Escape special characters for YARA strings."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _generate_uuid_from_title(title: str) -> str:
    """Generate a deterministic UUID-like ID from title."""
    import hashlib

    hash_obj = hashlib.sha256(title.encode())
    hex_dig = hash_obj.hexdigest()
    return f"{hex_dig[:8]}-{hex_dig[8:12]}-{hex_dig[12:16]}-{hex_dig[16:20]}-{hex_dig[20:32]}"
