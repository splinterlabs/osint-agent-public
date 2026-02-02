---
name: intel
description: Get current threat intelligence summary
---

# Threat Intelligence Summary

Get current threat intelligence including recent critical CVEs, CISA KEV additions, and watchlist alerts.

## Instructions

Run the session start hook with `--full` to fetch current threat intelligence:

```bash
cd $PROJECT_ROOT && .venv/bin/python3 .claude/hooks/session_start.py --full
```

Present the results as a structured summary with watchlist alerts at the top, summary statistics, top 5 critical CVEs, and top 5 KEV additions.

After displaying the summary, offer to save the full report to `reports/`.

### Report Formatting Requirements

When generating markdown reports, **ALWAYS** include reference links:

1. **CVE Links** - For every CVE mentioned:
   ```markdown
   **Affected Products**: See [NVD CVE-YYYY-NNNNN](https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN) for specific product details
   ```

2. **CISA KEV Links** - For actively exploited vulnerabilities:
   ```markdown
   **Type**: See [CISA KEV CVE-YYYY-NNNNN](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for vulnerability type details
   ```

3. **General KEV Catalog Link** - In KEV sections:
   ```markdown
   Check [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for full details
   ```

4. **Reference Template** - Use `config/templates/intel_report_template.md` as the canonical format reference.

**Critical**: Do not use placeholder text like "(Check NVD for details)" without hyperlinks. Every CVE reference must be clickable.

### Usage Footnote

Call the `get_investigation_usage` MCP tool and display a compact footnote at the very end:

```
---
> usage: {total_tool_calls} tool calls | {total_api_requests} API requests | {total_api_errors} errors
```

Always display this as the last line of output.
