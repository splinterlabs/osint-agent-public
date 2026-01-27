# OSINT Agent MCP Server

MCP server that exposes OSINT agent capabilities to Claude Code. Provides 15 tool modules with 60+ tools for threat intelligence, vulnerability analysis, and investigation workflows.

## Tools

### CVE & Vulnerability (5 tools)

| Tool | Description |
|------|-------------|
| `lookup_cve` | Look up CVE details from NVD with exploitation status from CISA KEV |
| `get_critical_cves` | Get recent high-severity vulnerabilities from NVD |
| `check_kev` | Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog |
| `search_kev_vendor` | Find KEV entries for a specific vendor |
| `get_kev_stats` | Get KEV catalog statistics |

### IOC Extraction & STIX Export (2 tools)

| Tool | Description |
|------|-------------|
| `extract_iocs_from_text` | Extract IOCs (IPs, domains, hashes, URLs, emails, CVEs) from text |
| `iocs_to_stix` | Convert extracted IOCs to a STIX 2.1 bundle |

### AlienVault OTX (4 tools)

| Tool | Description |
|------|-------------|
| `lookup_ioc_otx` | Look up an IOC in OTX (IP, domain, hash, URL, CVE) |
| `search_otx_pulses` | Search OTX threat intelligence pulses |
| `get_otx_pulse` | Get details of a specific OTX pulse |
| `get_otx_subscribed` | Get recent pulses from OTX subscriptions |

### Abuse.ch (9 tools)

| Tool | Description |
|------|-------------|
| `lookup_url_urlhaus` | Look up a URL in URLhaus |
| `lookup_host_urlhaus` | Look up a host (domain/IP) in URLhaus |
| `get_recent_urls_urlhaus` | Get recently reported malicious URLs |
| `lookup_hash_malwarebazaar` | Look up a malware sample by hash |
| `search_malware_bazaar` | Search MalwareBazaar by tag or signature |
| `get_recent_malware_bazaar` | Get recently submitted malware samples |
| `lookup_ioc_threatfox` | Look up an IOC in ThreatFox |
| `search_threatfox` | Search ThreatFox by malware family or tag |
| `get_recent_iocs_threatfox` | Get recently reported IOCs from ThreatFox |

### Shodan (5 tools)

| Tool | Description |
|------|-------------|
| `shodan_host_lookup` | Detailed IP address info (ports, services, vulns, geolocation) |
| `shodan_search` | Search Shodan for hosts matching a query |
| `shodan_dns_lookup` | DNS records and subdomains for a domain |
| `shodan_vuln_lookup` | Vulnerability details with EPSS and KEV status |
| `shodan_exploit_search` | Search for exploits by CVE or product |

### MITRE ATT&CK (6 tools)

| Tool | Description |
|------|-------------|
| `attack_technique_lookup` | Look up a technique by ID or name |
| `attack_search_techniques` | Search techniques by keyword, tactic, or platform |
| `attack_list_tactics` | List all tactics in kill chain order |
| `attack_group_lookup` | Look up a threat actor/group |
| `attack_software_lookup` | Look up malware or tool |
| `attack_map_behavior` | Map observed behavior to likely techniques |

### Campaign Tracking (10 tools)

| Tool | Description |
|------|-------------|
| `campaign_create` | Create a new threat campaign |
| `campaign_list` | List all tracked campaigns |
| `campaign_get` | Get detailed campaign information |
| `campaign_add_ioc` | Add an IOC to a campaign |
| `campaign_add_ttp` | Add a TTP (ATT&CK technique) to a campaign |
| `campaign_add_cve` | Add a CVE to a campaign |
| `campaign_update_status` | Update campaign status |
| `campaign_find_by_ioc` | Find campaigns containing an IOC |
| `campaign_correlate` | Perform correlation analysis on a campaign |
| `campaign_statistics` | Get overall campaign statistics |

### Detection Rules (4 tools)

| Tool | Description |
|------|-------------|
| `generate_yara_from_hashes` | Generate a YARA rule from file hashes |
| `generate_sigma_network` | Generate a Sigma rule for proxy/web logs |
| `generate_sigma_dns` | Generate a Sigma rule for DNS query detection |
| `generate_sigma_firewall` | Generate a Sigma rule for firewall log detection |

### Context & Investigation Management (9 tools)

| Tool | Description |
|------|-------------|
| `start_investigation` | Start a new investigation (resets context, creates log) |
| `get_context_summary` | Get a summary of all context tiers |
| `get_context` | Get context data from a specific tier |
| `set_context` | Set a context value |
| `add_ioc_to_context` | Add an IOC to the tactical context |
| `add_finding` | Add a finding to the tactical context |
| `get_active_iocs` | Get all active IOCs from tactical context |
| `get_findings` | Get all findings from tactical context |
| `get_investigation_usage` | Get per-investigation usage statistics |

### Investigation Logging (3 tools)

| Tool | Description |
|------|-------------|
| `log_investigation_step` | Log an enrichment step with raw result to JSONL file |
| `log_investigation_conclusion` | Log the verdict and coverage to JSONL file |
| `get_investigation_log` | Read back all entries from an investigation log |

### FreshRSS Feed Integration (6 tools)

| Tool | Description |
|------|-------------|
| `freshrss_list_feeds` | List all subscribed feeds |
| `freshrss_get_entries` | Get entries from a specific feed or all feeds |
| `freshrss_get_unread` | Get all unread entries |
| `freshrss_extract_iocs` | Get feed entries and extract IOCs from them |
| `freshrss_search` | Search entries by keyword |
| `freshrss_mark_read` | Mark entries as read |

### Web Fetch (3 tools)

| Tool | Description |
|------|-------------|
| `local_web_fetch` | Fetch URL content with realistic browser headers |
| `local_web_fetch_json` | Fetch JSON data from a URL |
| `local_web_fetch_raw` | Fetch raw/binary content (base64-encoded) |

### Health & Configuration (2 tools)

| Tool | Description |
|------|-------------|
| `health_check` | Check server health and external API connectivity |
| `list_api_keys` | List which API keys are configured |

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
      "args": ["--directory", "/path/to/osint-agent/mcp-server", "run", "server.py"]
    }
  }
}
```

Replace `/path/to/osint-agent` with the actual path to your project directory.

After updating settings, restart Claude Code to load the MCP server.

## Adding New Data Sources

The server uses a modular architecture. Each data source has its own module in `tools/`.

### Structure

```
mcp-server/
├── server.py                        # Main server, registers all tool modules
├── tools/
│   ├── __init__.py
│   ├── nvd_tools.py                 # NVD vulnerability lookups
│   ├── kev_tools.py                 # CISA KEV tools
│   ├── extractor_tools.py           # IOC extraction
│   ├── stix_tools.py                # STIX 2.1 export
│   ├── otx_tools.py                 # AlienVault OTX
│   ├── abusech_tools.py             # URLhaus, MalwareBazaar, ThreatFox
│   ├── shodan_tools.py              # Shodan host/DNS/vuln lookups
│   ├── attack_tools.py              # MITRE ATT&CK framework
│   ├── campaign_tools.py            # Campaign tracking and correlation
│   ├── rule_tools.py                # YARA/Sigma rule generation
│   ├── context_tools.py             # Investigation context management
│   ├── investigation_log_tools.py   # Per-investigation JSONL step logging
│   ├── freshrss_tools.py            # FreshRSS feed integration
│   ├── web_fetch_tools.py           # Local web fetch with browser headers
│   └── health_tools.py              # Health checks and API key status
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

from osint_agent.clients.your_client import YourClient
from osint_agent.usage import track_tool

logger = logging.getLogger("osint-mcp.your_source")

_client: Optional[YourClient] = None


def get_client() -> YourClient:
    global _client
    if _client is None:
        _client = YourClient()
    return _client


def register_tools(mcp: FastMCP) -> None:
    """Register your tools with the MCP server."""

    @mcp.tool()
    @track_tool("your_tool")
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
from tools import your_source_tools
your_source_tools.register_tools(mcp)
```

### Best Practices

- **Return JSON strings**: All tools should return JSON for easy parsing
- **Use logging**: Never use `print()` - it breaks STDIO transport
- **Lazy singletons**: Initialize clients only when first used
- **Docstrings**: Write clear docstrings - they're shown to Claude as tool descriptions
- **Error handling**: Return errors as JSON with an `"error"` key
- **Usage tracking**: Wrap tools with `@track_tool("name")` for per-investigation statistics

## Development

Run tests:
```bash
uv run pytest
```

Check logs (logs go to stderr):
```bash
uv run server.py 2>&1 | tee server.log
```
