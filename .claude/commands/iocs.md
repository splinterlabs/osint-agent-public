---
name: iocs
description: Query the local IOC database
argument-hint: "[query|type|stats]"
---

# IOC Database

Query and manage the local Indicators of Compromise database.

## Arguments

- `$ARGUMENTS` - Optional: search query, IOC type filter, or "stats"

## Instructions

Use the CLI to query the IOC database:

```bash
cd $PROJECT_ROOT && .venv/bin/python -m osint_agent.cli iocs <action> [query] --format text
```

### Actions

Determine the appropriate action from `$ARGUMENTS`:

- **stats** (default when no arguments): `iocs stats` — Show counts by type, total, and recent 24h additions
- **search**: `iocs search "<query>"` — Match a query against IOC values and sources. Use this when `$ARGUMENTS` looks like a CVE ID, IP address, domain, hash, or other IOC value
- **filter**: `iocs filter <type>` — List recent entries of a given type. Use when `$ARGUMENTS` is one of: ipv4, ipv6, domain, md5, sha1, sha256, url, email, cve
- **recent**: `iocs recent` — Show 20 most recent IOCs. Use when `$ARGUMENTS` is "recent"

Use `--format json` when you need to process results programmatically.

Present results in a readable table format.
