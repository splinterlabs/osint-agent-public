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

### Usage Footnote

Call the `get_investigation_usage` MCP tool and display a compact footnote at the very end:

```
---
> usage: {total_tool_calls} tool calls | {total_api_requests} API requests | {total_api_errors} errors
```

Always display this as the last line of output.
