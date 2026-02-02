# Contributing to OSINT Agent

Thank you for your interest in contributing to OSINT Agent! This guide will help you get started with development, testing, and best practices.

## Table of Contents

- [Quick Start for Contributors](#quick-start-for-contributors)
- [Repository Structure](#repository-structure)
- [Architecture Overview](#architecture-overview)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Code Style](#code-style)
- [Adding Features](#adding-features)
- [Private/Public Repository Model](#privatepublic-repository-model)

---

## Quick Start for Contributors

```bash
# Clone the repository
git clone https://github.com/splinterlabs/osint-agent-public.git
cd osint-agent

# Run initial setup
make init

# Activate virtual environment
source .venv/bin/activate

# Run tests to verify everything works
make test

# Run all pre-commit checks
make check
```

---

## Repository Structure

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
│   └── settings.local.json     # Project-specific Claude settings
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
└── docs/                         # Documentation
    ├── README.md                # Documentation index
    ├── local-web-fetch.md      # Local web fetch tools
    ├── local-models.md         # Running with local LLMs
    └── archive/                 # Historical documentation
```

---

## Architecture Overview

### Core Concepts

**Multi-Source Enrichment**: OSINT Agent aggregates data from 8+ threat intelligence sources (NVD, CISA KEV, OTX, Abuse.ch, Shodan, ATT&CK, RIRs, Maigret) to provide comprehensive context on indicators.

**Investigation Context (5-Tier)**: Investigations maintain state across strategic, operational, tactical, technical, and security tiers. See `src/osint_agent/context.py:10-50`.

**Transparent Caching**: API responses are cached with TTLs to reduce redundant requests and respect rate limits. See `src/osint_agent/cache.py:1-100`.

**Campaign Tracking**: Create campaigns to group IOCs, TTPs (ATT&CK techniques), and CVEs. Includes correlation analysis for discovering relationships. See `src/osint_agent/campaigns.py:1-200`.

**JSONL Logging**: Each investigation step is logged to `data/logs/investigations/<id>.jsonl` with full enrichment data. Console output is compact; logs contain everything. See `src/osint_agent/investigation_log.py:1-150`.

**Watchlist Alerting**: Monitor vendors/products for new CVEs. Alerts appear on Claude Code startup with severity indicators. See `src/osint_agent/watchlist.py:1-200`.

---

## Development Setup

### Prerequisites

- Python 3.11+
- uv (recommended) or pip
- Claude Code CLI (for full integration)
- macOS or Linux

### Initial Setup

```bash
# Install uv (recommended)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and set up
git clone https://github.com/splinterlabs/osint-agent-public.git
cd osint-agent
make init

# Verify installation
make validate
```

### Development Workflow

```bash
# Activate virtual environment
source .venv/bin/activate

# Run CLI in development mode
python -m osint_agent.cli --help

# Make code changes and test immediately
python -m osint_agent.cli lookup CVE-2024-3400
```

### Key Commands

```bash
make init          # First-time setup
make status        # Quick health check
make validate      # Full validation with logs
make test          # Run all tests
make test-cov      # Tests with coverage report
make check         # Pre-commit checks (lint + type + test)
make format        # Auto-format code with ruff
make clean         # Clean build artifacts
```

---

## Testing

### Test Organization

```
tests/
├── unit/                    # Unit tests (fast, no external calls)
│   ├── test_nvd.py         # CVE client tests
│   ├── test_extractors.py  # IOC extraction tests
│   ├── test_cache.py       # Caching tests
│   └── test_campaigns.py   # Campaign tracking tests
├── integration/             # Integration tests (with mocks/cassettes)
└── cassettes/              # VCR.py HTTP fixtures
```

### Running Tests

```bash
# All tests
make test

# With coverage report (opens htmlcov/index.html)
make test-cov

# Specific test file
pytest tests/unit/test_nvd.py -v

# Specific test function
pytest tests/unit/test_nvd.py::test_cve_lookup -v

# Run tests with verbose output
pytest -vv
```

### Writing Tests

**Unit Test Pattern:**

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

**Integration Test Pattern:**

```python
# tests/integration/test_nvd_integration.py
import pytest
import vcr

@vcr.use_cassette('tests/cassettes/nvd_cve_lookup.yaml')
def test_nvd_api_call():
    """Test actual NVD API call with recorded response."""
    result = lookup_cve("CVE-2024-3400")
    assert result is not None
    assert "cvss" in result
```

### Coverage Targets

- **Overall**: 80%+
- **Core modules** (clients, extractors, campaigns): 90%+
- **MCP tools**: 70%+

---

## Code Style

### Python Style Guide

We use **Ruff** for linting and formatting:

```bash
# Auto-format code
make format

# Check for issues
ruff check src/ tests/

# Fix auto-fixable issues
ruff check --fix src/ tests/
```

### Type Hints

Type hints are required for all functions:

```python
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
```

### Async Patterns

Use async for concurrent operations:

```python
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

### Docstring Format

Use Google-style docstrings:

```python
def function_name(param1: str, param2: int = 0) -> bool:
    """
    Brief description of what the function does.

    Longer description with more details if needed.

    Args:
        param1: Description of param1
        param2: Description of param2 (default: 0)

    Returns:
        Description of return value

    Raises:
        ValueError: If param1 is invalid
    """
    pass
```

---

## Adding Features

### Adding a New Threat Intelligence Source

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
   - Update this file (CONTRIBUTING.md)

### Adding a New Slash Command

1. **Create directory**: `.claude/commands/mycommand/`

2. **Create prompt**: `.claude/commands/mycommand/command.md`
   ```markdown
   # My Command

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

3. **Add metadata**: `.claude/commands/mycommand/metadata.json`
   ```json
   {
     "name": "mycommand",
     "description": "Short description shown in /help"
   }
   ```

4. **Test**: Start Claude Code and type `/mycommand`

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

---

## Private/Public Repository Model

This repository uses a **private upstream + public fork** model for development.

### Repository Structure

```
Private: osint-agent-private (upstream)
    ↓ sync script
Public: osint-agent (GitHub public)
```

### Directory Layout

```
osint-agent-private/
├── .private/              # NEVER synced to public
│   ├── integrations/      # Proprietary API clients
│   ├── intel/             # Internal threat intelligence
│   ├── enterprise/        # Enterprise-only features
│   └── docs/              # Internal documentation
├── src/osint_agent/       # Core package (synced)
├── mcp-server/            # MCP tools (synced)
├── scripts/
│   └── sync-to-public.sh  # Sync script (not synced)
└── ...
```

### What Stays Private

The following are **never** synced to public:

| Pattern | Purpose |
|---------|---------|
| `.private/` | All private code and data |
| `*.private.*` | Any file with `.private.` in name |
| `INTERNAL_*.md` | Internal documentation |
| `.sync-config` | Sync configuration |
| `scripts/sync-to-public.sh` | The sync script itself |
| `data/campaigns/*.json` | Campaign data |
| `data/context/*.json` | Investigation context |

### Workflow for Maintainers

**Daily Development:**
1. Work in the private repo normally
2. All features start here
3. Use `.private/` for proprietary code

**Syncing to Public:**
```bash
# 1. Set up sync config (first time only)
cp .sync-config.example .sync-config
# Edit .sync-config with public repo URL

# 2. Preview what will be synced
./scripts/sync-to-public.sh --dry-run

# 3. Sync to public
./scripts/sync-to-public.sh
```

### Naming Conventions for Private Code

- `*.private.py` - Private Python modules
- `*.private.json` - Private config files
- `INTERNAL_*.md` - Internal docs
- `.private/` - Private directory

### Conditional Imports for Optional Features

```python
# In public code
try:
    from osint_agent.private.enterprise import EnterpriseFeature
    HAS_ENTERPRISE = True
except ImportError:
    HAS_ENTERPRISE = False

def some_function():
    if HAS_ENTERPRISE:
        return EnterpriseFeature().run()
    return basic_implementation()
```

---

## Pull Request Process

1. **Fork the repository** (for external contributors)
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Run checks**: `make check`
5. **Run tests**: `make test`
6. **Commit**: `git commit -m 'Add amazing feature'`
7. **Push**: `git push origin feature/amazing-feature`
8. **Open a Pull Request**

### PR Checklist

- [ ] Tests pass (`make test`)
- [ ] Linting passes (`make check`)
- [ ] Type hints added for new functions
- [ ] Docstrings added for new functions
- [ ] Documentation updated (if needed)
- [ ] No sensitive data (API keys, internal URLs)

---

## Common Tasks Quick Reference

```bash
# Add API key
.venv/bin/python -m osint_agent.cli keys set KEY_NAME

# Monitor vendor
# Edit config/watchlist.json

# Extract IOCs
/extract-iocs <file>
# or CLI:
python -m osint_agent.cli extract -f <file>

# Investigate indicator
/investigate <indicator>
# or CLI:
python -m osint_agent.cli investigate <indicator>

# Get threat intel summary
/intel
# or CLI:
python -m osint_agent.cli intel
```

---

## Getting Help

- **Issues**: https://github.com/splinterlabs/osint-agent-public/issues
- **Discussions**: https://github.com/splinterlabs/osint-agent-public/discussions
- **Documentation**: See `docs/` directory

---

## License

MIT License - see [LICENSE](LICENSE) for details.
