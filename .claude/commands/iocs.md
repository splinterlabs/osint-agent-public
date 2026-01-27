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

The IOC database is at `data/iocs.db` (SQLite). Columns: `id`, `type`, `value`, `source`, `first_seen`, `last_seen`, `hit_count`. Types: ipv4, ipv6, domain, md5, sha1, sha256, url, email, cve.

### Operations

Run SQL queries against the database:
- **stats** (default): Count by type, total, and recent 24h additions
- **search**: Match `$ARGUMENTS` against the `value` column
- **filter by type**: If `$ARGUMENTS` is a type name, list recent entries of that type
- **recent**: Show 20 most recent IOCs

Present results in a readable table format.
