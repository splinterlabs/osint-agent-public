# OSINT Agent

[![CI](https://github.com/splinterlabs/osint-agent-public/actions/workflows/ci.yml/badge.svg)](https://github.com/splinterlabs/osint-agent-public/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/splinterlabs/osint-agent-public/branch/main/graph/badge.svg)](https://codecov.io/gh/splinterlabs/osint-agent-public)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

A threat intelligence assistant for [Claude Code](https://claude.ai/code) with CVE lookups, IOC extraction, and automated security monitoring.

## Features

- **CVE Lookup** - Query NVD and CISA KEV for vulnerability details
- **IOC Extraction** - Automatically extract IPs, domains, hashes, URLs from text/files
- **Threat Feeds** - Integration with AlienVault OTX, Abuse.ch
- **Watchlist Alerts** - Monitor vendors/products for new vulnerabilities
- **Rule Generation** - Create YARA and Sigma rules from IOCs
- **STIX Export** - Export IOCs in STIX 2.1 format
- **Claude Code Integration** - Slash commands, hooks, and MCP server

## Quick Start

```bash
# Clone the repository
git clone https://github.com/splinterlabs/osint-agent-public.git
cd osint-agent

# Run setup
./setup.sh

# Verify installation
make verify
```

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

## Usage

### CLI

```bash
# Look up a CVE
python -m osint_agent.cli lookup CVE-2024-3400

# Extract IOCs from a file
python -m osint_agent.cli extract -f report.txt

# Get threat intel summary
python -m osint_agent.cli intel
```

### Claude Code

Start Claude Code in the project directory to enable slash commands:

```bash
cd osint-agent
claude
```

| Command | Description | Example |
|---------|-------------|---------|
| `/cve` | Look up CVE details | `/cve CVE-2024-3400` |
| `/intel` | Daily threat summary | `/intel` |
| `/extract-iocs` | Extract IOCs from text/file | `/extract-iocs report.pdf` |
| `/iocs` | Query IOC database | `/iocs sha256` |
| `/watchlist` | Manage monitored vendors | `/watchlist add vendor Fortinet` |

### Session Start Hook

When you start Claude Code, you'll automatically receive:
- Recent critical CVEs (CVSS 8.0+)
- New CISA KEV additions
- Watchlist alerts for monitored vendors
- IOC database statistics

## Configuration

### API Keys (Optional)

API keys enhance functionality but are not required:

```bash
# Store securely in system keyring
python -m osint_agent.cli keys set NVD_API_KEY
python -m osint_agent.cli keys set OTX_API_KEY
```

Or copy `.env.example` to `.env` and fill in values.

| Key | Source | Benefits |
|-----|--------|----------|
| `NVD_API_KEY` | [NVD](https://nvd.nist.gov/developers/request-an-api-key) | Higher rate limits |
| `OTX_API_KEY` | [AlienVault](https://otx.alienvault.com/) | Threat pulse access |

### Watchlist

Edit `config/watchlist.json` to monitor specific vendors, products, or keywords:

```json
{
  "vendors": ["Microsoft", "Cisco", "Fortinet"],
  "products": ["Exchange", "FortiGate", "PAN-OS"],
  "keywords": ["RCE", "zero-day", "actively exploited"]
}
```

## Architecture

```
osint-agent/
├── src/osint_agent/     # Main Python package
│   ├── clients/         # API clients (NVD, CISA, OTX, Abuse.ch)
│   ├── extractors.py    # IOC extraction
│   ├── rules.py         # YARA/Sigma generation
│   └── stix_export.py   # STIX 2.1 export
├── mcp-server/          # Claude Code MCP server (optional)
├── .claude/
│   ├── commands/        # Slash commands
│   └── hooks/           # Automation hooks
├── config/              # Configuration files
└── data/                # Databases and cache
```

## MCP Server (Optional)

For additional Claude Code integration via MCP:

```bash
./setup.sh --with-mcp
```

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

## Development

```bash
# Install dev dependencies
make install-dev

# Run tests
make test

# Run all checks
make check

# Format code
make format
```

## Use Cases

See [USE_CASES.md](USE_CASES.md) for detailed workflows:

1. **Daily Threat Brief** - Start your day with `/intel`
2. **Incident Investigation** - Extract and correlate IOCs
3. **Vulnerability Triage** - Prioritize patching with `/cve`
4. **Threat Actor Research** - Track campaigns and TTPs

## Data Sources

| Source | Type | Auth Required |
|--------|------|---------------|
| [NVD](https://nvd.nist.gov/) | CVE details | Optional |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited vulns | No |
| [AlienVault OTX](https://otx.alienvault.com/) | Threat intel | Yes (free) |
| [Abuse.ch](https://abuse.ch/) | Malware/URLs | No |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run checks (`make check`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [NVD](https://nvd.nist.gov/) for vulnerability data
- [CISA](https://www.cisa.gov/) for KEV catalog
- [AlienVault](https://otx.alienvault.com/) for OTX platform
- [Abuse.ch](https://abuse.ch/) for threat feeds
