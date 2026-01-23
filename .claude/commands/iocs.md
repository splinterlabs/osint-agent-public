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

The IOC database is located at `data/iocs.db` (SQLite).

### Schema

```sql
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,        -- ipv4, ipv6, domain, md5, sha1, sha256, url, email, cve
    value TEXT NOT NULL,
    source TEXT,               -- Where the IOC was found
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hit_count INTEGER DEFAULT 1,
    UNIQUE(type, value)
);
```

### Operations

**Show statistics (default or "stats"):**
```sql
SELECT type, COUNT(*) as count FROM iocs GROUP BY type ORDER BY count DESC;
SELECT COUNT(*) as total FROM iocs;
SELECT COUNT(*) FROM iocs WHERE first_seen > datetime('now', '-24 hours');
```

**Search for specific IOC:**
```sql
SELECT * FROM iocs WHERE value LIKE '%$ARGUMENTS%';
```

**Filter by type (if argument is a type name):**
```sql
SELECT value, source, first_seen, hit_count FROM iocs WHERE type = '$ARGUMENTS' ORDER BY last_seen DESC LIMIT 20;
```

**Recent IOCs:**
```sql
SELECT type, value, source, first_seen FROM iocs ORDER BY first_seen DESC LIMIT 20;
```

## Output Format

Present results in a readable table format. For statistics, show:
- Total IOCs tracked
- Breakdown by type
- IOCs added in last 24 hours
- Most frequently seen IOCs (highest hit_count)

## Examples

- `/iocs` - Show database statistics
- `/iocs stats` - Show database statistics
- `/iocs ipv4` - List recent IPv4 addresses
- `/iocs 192.168` - Search for IOCs containing "192.168"
- `/iocs sha256` - List recent SHA256 hashes
