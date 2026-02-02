# OSINT Agent - Developer Context

A threat intelligence assistant for Claude Code with CVE lookups, IOC extraction, structured investigations, and automated security monitoring.

## Architecture Quick Map

```
osint-agent/
├── src/osint_agent/              # Main Python package
│   ├── clients/                  # API clients for threat intelligence sources
│   │   ├── nvd.py               # National Vulnerability Database
│   │   ├── cisa_kev.py          # CISA Known Exploited Vulnerabilities
│   │   ├── otx.py               # AlienVault Open Threat Exchange
│   │   ├── abuse_ch.py          # Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
│   │   ├── shodan_client.py     # Shodan Internet intelligence
│   │   ├── freshrss.py          # FreshRSS threat feed aggregation
│   │   └── attack.py            # MITRE ATT&CK framework
│   ├── extractors.py            # IOC extraction (IPs, domains, hashes, etc.)
│   ├── rules.py                 # YARA and Sigma rule generation
│   ├── stix_export.py           # STIX 2.1 format export
│   ├── campaigns.py             # Threat campaign tracking
│   ├── correlation.py           # Campaign IOC correlation
│   ├── context.py               # Investigation context management (5-tier)
│   ├── investigation_log.py     # Per-investigation JSONL logging
│   ├── usage.py                 # Per-investigation usage tracking
│   ├── cache.py                 # Transparent API response caching
│   ├── parallel.py              # Concurrent execution utilities
│   ├── keymanager.py            # Secure API key storage (keyring)
│   ├── watchlist.py             # Vendor/product monitoring
│   └── cli.py                   # Command-line interface
│
├── mcp-server/                   # Claude Code MCP server
│   ├── server.py                # MCP server entry point
│   ├── tools/                   # 60+ tool modules organized by domain
│   │   ├── cve.py              # CVE and KEV lookups
│   │   ├── ioc.py              # IOC extraction and lookup
│   │   ├── otx.py              # OTX threat intelligence
│   │   ├── abuse.py            # Abuse.ch integrations
│   │   ├── shodan.py           # Shodan reconnaissance
│   │   ├── attack.py           # MITRE ATT&CK
│   │   ├── campaigns.py        # Campaign management
│   │   ├── rules.py            # Detection rule generation
│   │   ├── context.py          # Investigation context
│   │   ├── freshrss.py         # Feed aggregation
│   │   ├── web.py              # Local web fetching
│   │   └── investigation.py    # Investigation logging
│   └── README.md               # MCP tool reference
│
├── .claude/                      # Claude Code integration
│   ├── commands/                # Slash commands (7 commands)
│   │   ├── investigate/        # /investigate - Structured investigation
│   │   ├── review/             # /review - Independent judge layer
│   │   ├── cve/                # /cve - CVE lookup
│   │   ├── intel/              # /intel - Threat intelligence summary
│   │   ├── extract-iocs/       # /extract-iocs - IOC extraction
│   │   ├── iocs/               # /iocs - IOC database query
│   │   └── watchlist/          # /watchlist - Vendor monitoring
│   ├── hooks/                  # Automation hooks
│   │   ├── session_start.py   # Startup briefing (watchlist + intel)
│   │   ├── pre_tool_use.py    # Pre-tool validation
│   │   ├── post_tool_use.py   # Post-tool logging
│   │   └── notification.py    # Notification handling
│   ├── settings.local.json     # Project-specific Claude settings
│   └── prompts/                # Prompt templates
│       └── install.md          # Installation wizard prompt
│
├── config/                       # Configuration files
│   ├── watchlist.json          # Monitored vendors/products (user-specific)
│   ├── watchlist.example.json  # Watchlist template
│   └── source_reliability.json # Source confidence scoring
│
├── data/                         # Runtime data (gitignored)
│   ├── cache/                  # API response cache (TTL-based)
│   ├── context/                # Investigation context state (5 tiers)
│   ├── campaigns/              # Campaign tracking data
│   ├── logs/                   # JSONL logs
│   │   ├── alerts.jsonl       # Watchlist alerts
│   │   └── investigations/    # Per-investigation logs
│   ├── iocs.db                 # SQLite IOC database
│   └── rate_limits.db          # Rate limiting state
│
├── tests/                        # Unit and integration tests
│   ├── unit/                   # Unit tests
│   ├── integration/            # Integration tests
│   └── cassettes/              # VCR.py HTTP fixtures
│
├── reports/                      # Generated output (gitignored)
│   ├── *.json                  # STIX exports, IOC extractions
│   ├── *.md                    # Investigation reports
│   └── *.yar / *.yml           # Detection rules
│
└── logs/                         # Makefile operation logs (gitignored)
    └── validation.log          # Installation validation output
```

## Core Concepts

**Multi-Source Enrichment**: OSINT Agent aggregates data from 8+ threat intelligence sources (NVD, CISA KEV, OTX, Abuse.ch, Shodan, ATT&CK, RIRs, Maigret) to provide comprehensive context on indicators.

**Investigation Context (5-Tier)**: Investigations maintain state across strategic, operational, tactical, technical, and security tiers. See `src/osint_agent/context.py:10-50`.

**Transparent Caching**: API responses are cached with TTLs to reduce redundant requests and respect rate limits. See `src/osint_agent/cache.py:1-100`.

**Campaign Tracking**: Create campaigns to group IOCs, TTPs (ATT&CK techniques), and CVEs. Includes correlation analysis for discovering relationships. See `src/osint_agent/campaigns.py:1-200`.

**JSONL Logging**: Each investigation step is logged to `data/logs/investigations/<id>.jsonl` with full enrichment data. Console output is compact; logs contain everything. See `src/osint_agent/investigation_log.py:1-150`.

**Watchlist Alerting**: Monitor vendors/products for new CVEs. Alerts appear on Claude Code startup with severity indicators. See `src/osint_agent/watchlist.py:1-200`.

## File Navigation Guide

### Core Functionality

**CVE Lookups**
- Client: `src/osint_agent/clients/nvd.py:1-150` and `src/osint_agent/clients/cisa_kev.py:1-100`
- MCP tool: `mcp-server/tools/cve.py:1-200`
- Slash command: `.claude/commands/cve/command.md`

**IOC Extraction**
- Extractor: `src/osint_agent/extractors.py:1-300` (regex patterns, validation, defanging)
- MCP tool: `mcp-server/tools/ioc.py:50-150`
- Slash command: `.claude/commands/extract-iocs/command.md`

**Structured Investigations**
- Workflow: `.claude/commands/investigate/command.md:1-100` (multi-source enrichment)
- Logging: `src/osint_agent/investigation_log.py:1-150`
- Context: `src/osint_agent/context.py:1-200`
- MCP tools: `mcp-server/tools/investigation.py:1-100`

**Independent Review**
- Judge layer: `.claude/commands/review/command.md:1-100` (evaluates findings)
- Loads investigation log and provides second opinion

**Threat Intelligence**
- OTX: `src/osint_agent/clients/otx.py:1-250` (pulses, subscriptions)
- Abuse.ch: `src/osint_agent/clients/abuse_ch.py:1-300` (URLhaus, MalwareBazaar, ThreatFox)
- Shodan: `src/osint_agent/clients/shodan_client.py:1-200`
- Intel summary: `.claude/commands/intel/command.md`

**Campaign Tracking**
- Management: `src/osint_agent/campaigns.py:1-400` (create, add IOCs/TTPs/CVEs)
- Correlation: `src/osint_agent/correlation.py:1-200` (find relationships)
- MCP tools: `mcp-server/tools/campaigns.py:1-300`

### Configuration

**API Keys**
- Keyring storage: `src/osint_agent/keymanager.py:1-150` (secure, cross-platform)
- Environment fallback: `.env` (optional, use `.env.example` as template)
- Configuration: All clients check keyring first, then env vars

**Watchlist**
- Config file: `config/watchlist.json` (user-specific, gitignored)
- Template: `config/watchlist.example.json`
- Implementation: `src/osint_agent/watchlist.py:1-200`
- Hook: `.claude/hooks/session_start.py:50-150` (startup alerts)

**Source Reliability**
- Scoring: `config/source_reliability.json` (confidence levels for each source)
- Used in context management and reporting

### Testing

**Unit Tests**
- Location: `tests/unit/`
- Run: `make test`
- Coverage: `make test-cov` (target: 80%+)
- Pattern: `tests/unit/test_<module>.py`

**Integration Tests**
- Location: `tests/integration/`
- HTTP fixtures: `tests/cassettes/` (VCR.py cassettes)
- Run: `make test` (includes both unit and integration)

**Test Scenarios**
- CVE lookup: `tests/unit/test_nvd.py` and `tests/unit/test_cisa_kev.py`
- IOC extraction: `tests/unit/test_extractors.py`
- Caching: `tests/unit/test_cache.py`
- Campaigns: `tests/unit/test_campaigns.py`

## Development Patterns

### Python Code Style

```python
# Type hints are used throughout
from typing import Optional, List, Dict, Any

def lookup_cve(cve_id: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
    """
    Look up CVE details from NVD.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-3400")
        use_cache: Whether to use cached responses

    Returns:
        CVE details dict or None if not found
    """
    # Implementation
    pass

# Async for concurrent operations
import asyncio
from src.osint_agent.parallel import run_parallel

async def enrich_indicator(indicator: str) -> List[Dict[str, Any]]:
    """Run multiple enrichment sources concurrently."""
    tasks = [
        lookup_otx(indicator),
        lookup_shodan(indicator),
        lookup_abuse_ch(indicator),
    ]
    return await run_parallel(tasks)
```

### Testing Pattern

```python
# tests/unit/test_example.py
import pytest
from unittest.mock import Mock, patch

def test_cve_lookup():
    """Test CVE lookup with mocked API response."""
    # Arrange
    mock_response = {"cve_id": "CVE-2024-3400", "cvss": 10.0}

    # Act
    with patch("src.osint_agent.clients.nvd.requests.get") as mock_get:
        mock_get.return_value.json.return_value = mock_response
        result = lookup_cve("CVE-2024-3400")

    # Assert
    assert result["cve_id"] == "CVE-2024-3400"
    assert result["cvss"] == 10.0
```

### MCP Tool Pattern

```python
# mcp-server/tools/example.py
from typing import Dict, Any

def tool_name(param: str) -> str:
    """
    Tool description shown in Claude Code.

    Args:
        param: Parameter description

    Returns:
        Human-readable result (Claude reads this)
    """
    # Validate input
    if not param:
        raise ValueError("param is required")

    # Call client or perform operation
    result = client.do_something(param)

    # Format output for Claude
    return f"Found {result['count']} items for {param}"
```

### Slash Command Pattern

```markdown
<!-- .claude/commands/example/command.md -->
# Example Command

You are a specialized assistant for [task].

## Process

1. Validate input
2. Call appropriate MCP tools
3. Synthesize results
4. Provide actionable output

## Tools to Use

- mcp__osint-agent__tool_name
- mcp__osint-agent__another_tool

## Output Format

Present results in a structured way:
- Key findings
- Recommendations
- Next steps
```

## Common Workflows

### Start Development

```bash
# One-time setup
make init

# Activate virtual environment
source .venv/bin/activate

# Run in development mode (make code changes while running)
python -m osint_agent.cli --help
```

### Run Tests

```bash
make test          # All tests
make test-cov      # With coverage report (opens htmlcov/index.html)
pytest tests/unit/test_nvd.py -v  # Specific test file
```

### Add New Threat Intelligence Source

1. **Create client**: `src/osint_agent/clients/newsource.py`
   - Implement API calls
   - Add caching with `@cache_response` decorator
   - Handle rate limiting
   - Add error handling

2. **Create MCP tool**: `mcp-server/tools/newsource.py`
   - Define tool functions
   - Add docstrings (shown in Claude Code)
   - Format output for readability

3. **Update server**: `mcp-server/server.py`
   - Import tool module
   - Register tools with MCP server

4. **Add tests**: `tests/unit/test_newsource.py`
   - Unit tests for client
   - Integration tests with cassettes

5. **Update docs**:
   - Add to `README.md` data sources table
   - Document in `mcp-server/README.md` tool reference
   - Update `AGENTS.md` (this file)

### Add New Slash Command

1. **Create directory**: `.claude/commands/mycommand/`

2. **Create prompt**: `.claude/commands/mycommand/command.md`
   - Define role and process
   - List tools to use
   - Specify output format

3. **Add metadata**: `.claude/commands/mycommand/metadata.json`
   ```json
   {
     "name": "mycommand",
     "description": "Short description shown in /help"
   }
   ```

4. **Test**: Start Claude Code and type `/mycommand`

## Project Status

**Phase:** Production Ready | **Version:** 1.0

✅ Complete:
- CVE lookup (NVD + CISA KEV)
- IOC extraction and database
- AlienVault OTX integration
- Abuse.ch integrations (URLhaus, MalwareBazaar, ThreatFox)
- Shodan reconnaissance
- MITRE ATT&CK integration
- Campaign tracking with correlation
- Watchlist alerting
- Rule generation (YARA, Sigma)
- STIX 2.1 export
- WHOIS/RIR lookups (RIPE, ARIN, APNIC, AfriNIC, LACNIC)
- Username OSINT (Maigret)
- Structured investigation workflow
- Independent review layer
- Investigation logging (JSONL)
- Usage tracking
- API response caching
- Claude Code integration (hooks + slash commands + MCP)

⏳ In Progress:
- Additional threat feeds
- Advanced correlation algorithms
- Reporting templates

📋 Planned:
- GraphQL query interface
- Web dashboard (optional)
- Additional detection rule formats
- Machine learning for IOC scoring

---

**Philosophy**: Provide comprehensive, multi-source threat intelligence in a format that's immediately actionable. Automate the tedious parts (data gathering, correlation) so analysts can focus on decision-making.

## Quick Reference

### Key Commands
```bash
make init          # First-time setup
make status        # Quick health check
make validate      # Full validation with logs
make test          # Run all tests
make check         # Pre-commit checks (lint + type + test)
```

### Key Files to Know
- `src/osint_agent/cli.py` - CLI entry point
- `src/osint_agent/clients/` - All API clients
- `.claude/commands/investigate/` - Main investigation workflow
- `.claude/hooks/session_start.py` - Startup briefing
- `mcp-server/server.py` - MCP tool registration

### Common Tasks
- **Add API key**: `.venv/bin/python -m osint_agent.cli keys set KEY_NAME`
- **Monitor vendor**: Edit `config/watchlist.json`
- **Extract IOCs**: `/extract-iocs <file>` or CLI: `python -m osint_agent.cli extract -f <file>`
- **Investigate**: `/investigate <indicator>` or CLI: `python -m osint_agent.cli investigate <indicator>`
- **Get intel**: `/intel` or CLI: `python -m osint_agent.cli intel`
