# OSINT Agent MCP Server

MCP server that exposes OSINT agent capabilities to Claude Code.

## Tools

| Tool | Description |
|------|-------------|
| `lookup_cve` | Look up CVE details with active exploitation status |
| `get_critical_cves` | Get recent high-severity vulnerabilities |
| `extract_iocs_from_text` | Extract IOCs from text content |
| `check_kev` | Check if CVE is actively exploited |
| `search_kev_vendor` | Find KEV entries by vendor |
| `get_kev_stats` | Get KEV catalog statistics |
| `iocs_to_stix` | Convert IOCs to STIX 2.1 bundle |

## Installation

1. Install dependencies:
```bash
cd mcp-server
uv sync
```

2. Verify server starts:
```bash
uv run server.py
```

The server should start without errors and wait for input on stdin.

## Claude Code Configuration

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "osint-agent": {
      "command": "uv",
      "args": ["--directory", "/path/to/SecurityResearch/mcp-server", "run", "server.py"]
    }
  }
}
```

Replace `/path/to/SecurityResearch` with the actual path to your SecurityResearch directory.

After updating settings, restart Claude Code to load the MCP server.

## Usage Examples

Once configured, these tools are available in Claude Code:

### Look up a CVE
```
lookup_cve CVE-2024-3400
```

### Get recent critical vulnerabilities
```
get_critical_cves
get_critical_cves cvss_min=9.0 days=30
```

### Extract IOCs from text
```
extract_iocs_from_text "The malware connects to 192.168.1.1 and evil[.]com"
```

### Check if CVE is in KEV
```
check_kev CVE-2024-3400
```

### Search KEV by vendor
```
search_kev_vendor Microsoft
search_kev_vendor Palo Alto
```

### Get KEV statistics
```
get_kev_stats
```

### Convert IOCs to STIX
```
iocs_to_stix '{"ipv4": ["1.2.3.4"], "domain": ["evil.com"]}'
```

## Adding New Data Sources

The server uses a modular architecture. Each data source has its own module in `tools/`.

### Structure

```
mcp-server/
├── server.py              # Main server, registers all tools
├── tools/
│   ├── __init__.py
│   ├── nvd_tools.py       # NVD vulnerability tools
│   ├── kev_tools.py       # CISA KEV tools
│   ├── extractor_tools.py # IOC extraction tools
│   ├── stix_tools.py      # STIX export tools
│   └── your_source.py     # Add new sources here
└── pyproject.toml
```

### Creating a New Tool Module

1. Create `tools/your_source_tools.py`:

```python
"""Your data source tools."""

import json
import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Import your client from osint_agent or create inline
from osint_agent.clients.your_client import YourClient

logger = logging.getLogger("osint-mcp.your_source")

# Lazy singleton for client
_client: Optional[YourClient] = None


def get_client() -> YourClient:
    """Get or create client singleton."""
    global _client
    if _client is None:
        _client = YourClient()
    return _client


def register_tools(mcp: FastMCP) -> None:
    """Register your tools with the MCP server."""

    @mcp.tool()
    def your_tool(param: str) -> str:
        """Tool description shown to Claude.

        Args:
            param: Parameter description

        Returns:
            JSON string with results.
        """
        logger.info(f"Your tool called with: {param}")

        client = get_client()
        result = client.do_something(param)

        return json.dumps(result, indent=2)
```

2. Register in `server.py`:

```python
# Add import
from tools import your_source_tools

# Add registration
your_source_tools.register_tools(mcp)
```

### Best Practices

- **Return JSON strings**: All tools should return JSON for easy parsing
- **Use logging**: Never use `print()` - it breaks STDIO transport
- **Lazy singletons**: Initialize clients only when first used
- **Docstrings**: Write clear docstrings - they're shown to Claude as tool descriptions
- **Error handling**: Return errors as JSON with an `"error"` key

## Development

Run tests:
```bash
uv run pytest
```

Check logs (logs go to stderr):
```bash
uv run server.py 2>&1 | tee server.log
```
