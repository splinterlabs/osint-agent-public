---
name: watchlist
description: View or manage the vulnerability watchlist
argument-hint: "[add|remove] [type] [value]"
---

# Watchlist Management

View and manage the vulnerability watchlist for vendors, products, and CVEs.

## Arguments

- `$ARGUMENTS` - Optional: "add <type> <value>", "remove <type> <value>", or empty to view

## Instructions

The watchlist is stored at `config/watchlist.json`.

### Schema

```json
{
  "vendors": ["Microsoft", "Cisco", ...],
  "products": ["Windows Server", "FortiOS", ...],
  "cpe_patterns": ["cpe:2.3:o:microsoft:windows_server:*", ...],
  "keywords": ["remote code execution", "zero-day", ...]
}
```

### Operations

**View watchlist (no arguments):**
Read and display `config/watchlist.json` in a formatted list.

**Add to watchlist:**
Parse `$ARGUMENTS` for pattern: `add <type> <value>`
- Types: `vendor`, `product`, `cpe`, `keyword`
- Update the JSON file with the new entry

**Remove from watchlist:**
Parse `$ARGUMENTS` for pattern: `remove <type> <value>`
- Remove the entry from the appropriate array

### Validation

- Vendor names should be proper case (e.g., "Microsoft" not "microsoft")
- CPE patterns should follow CPE 2.3 format
- Warn if adding a duplicate entry

## Output Format

**When viewing:**
```
## Current Watchlist

### Vendors (8)
- Microsoft
- Cisco
- Fortinet
...

### Products (9)
- Windows Server
- Exchange Server
...

### Keywords (5)
- remote code execution
- authentication bypass
...
```

**When modifying:**
Confirm the change and show the updated section.

## Examples

- `/watchlist` - View current watchlist
- `/watchlist add vendor Sophos` - Add Sophos to watched vendors
- `/watchlist add product GitLab` - Add GitLab to watched products
- `/watchlist remove vendor Juniper` - Remove Juniper from watched vendors
- `/watchlist add keyword supply chain` - Add keyword to watch for

### Usage Footnote

Call the `get_investigation_usage` MCP tool and display a compact footnote at the very end:

```
---
> usage: {total_tool_calls} tool calls | {total_api_requests} API requests | {total_api_errors} errors
```

Always display this as the last line of output.
