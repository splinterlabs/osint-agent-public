---
name: extract-iocs
description: Extract IOCs from a file, URL, or text
argument-hint: "[file|url]"
---

# Extract IOCs

Extract Indicators of Compromise (IOCs) from a file, URL, or text content.

## Arguments

- `$ARGUMENTS` - File path, URL, or leave empty to be prompted for content

## Instructions

### If a file path is provided:

```bash
cd $PROJECT_ROOT && python -m osint_agent.cli extract -f "$ARGUMENTS" --format text
```

Or read the file and use the extractor directly:

```python
from src.osint_agent.extractors import extract_iocs
content = open("$ARGUMENTS").read()
iocs = extract_iocs(content)
```

### If a URL is provided:

1. Use WebFetch to retrieve the content
2. Pass the content through the IOC extractor

### If no argument provided:

Ask the user what content they want to extract IOCs from.

## Supported IOC Types

- **IPv4/IPv6** - IP addresses (filters private/reserved ranges)
- **Domains** - With TLD validation and defang support (`[.]` -> `.`)
- **Hashes** - MD5, SHA1, SHA256 (filters empty/test hashes)
- **URLs** - Including defanged `hxxp://` format
- **Emails** - Email addresses
- **CVEs** - CVE identifiers

## Output Format

Present extracted IOCs grouped by type:

```
## Extracted IOCs

### IPv4 (3 found)
- 192.0.2.1
- 198.51.100.5
- 203.0.113.10

### Domains (2 found)
- malicious-domain.com
- evil.example.net

### SHA256 (1 found)
- a1b2c3d4...
```

Also offer to:
1. Save IOCs to the database (`data/iocs.db`)
2. Export as STIX format (save to `reports/`)
3. Export as JSON (save to `reports/`)
