---
name: intel
description: Get current threat intelligence summary
---

# Threat Intelligence Summary

Get current threat intelligence including recent critical CVEs, CISA KEV additions, and watchlist alerts.

## Instructions

Run the session start hook to fetch current threat intelligence:

```bash
cd $PROJECT_ROOT && python .claude/hooks/session_start.py
```

If the hook fails or for more detailed data, use the MCP tools directly:

1. **Recent Critical CVEs** - Query NVD for CVEs with CVSS >= 8.0 from the last 7 days
2. **CISA KEV Additions** - Check for recent additions to the Known Exploited Vulnerabilities catalog
3. **IOC Summary** - Query the local IOC database for statistics
4. **Watchlist Alerts** - Check if any watched vendors/products have new vulnerabilities

## Output Format

Present the results as a structured summary:

- Watchlist alerts (if any) at the top with high visibility
- Summary statistics (critical CVEs, KEV additions, IOCs tracked)
- Top 5 recent critical CVEs with ID and CVSS score
- Top 5 recent KEV additions with vendor, product, and due date

## Arguments

This command takes no arguments.
