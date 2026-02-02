# OSINT Agent

[![CI](https://github.com/splinterlabs/osint-agent-public/actions/workflows/ci.yml/badge.svg)](https://github.com/splinterlabs/osint-agent-public/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/splinterlabs/osint-agent-public/branch/main/graph/badge.svg)](https://codecov.io/gh/splinterlabs/osint-agent-public)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

A threat intelligence assistant for [Claude Code](https://claude.ai/code) with CVE lookups, IOC extraction, structured investigations, and automated security monitoring.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/splinterlabs/osint-agent-public.git
cd osint-agent

# Run one-command setup
make init

# Verify installation
make status
```

**That's it!** Start using:
- **Claude Code:** `claude` (then use `/intel`, `/investigate`, `/cve`, etc.)
- **CLI:** `.venv/bin/python -m osint_agent.cli --help`

See [QUICKSTART.md](QUICKSTART.md) for detailed setup guide or run `/install` in Claude Code for interactive wizard.

## Features

- **Structured Investigations** - `/investigate` runs multi-source enrichment with compact console output and full JSONL logging; `/review` provides an independent judge layer
- **CVE Lookup** - Query NVD and CISA KEV for vulnerability details, CVSS scores, and exploitation status
- **IOC Extraction** - Extract IPs, domains, hashes, URLs, emails, and CVE IDs from text and files
- **Threat Feeds** - Integration with AlienVault OTX, Abuse.ch (URLhaus, MalwareBazaar, ThreatFox), and FreshRSS
- **Shodan Reconnaissance** - Host lookups, DNS resolution, vulnerability exposure, and exploit search
- **MITRE ATT&CK** - Technique lookups, tactic mapping, threat group profiles, and behavior-to-technique mapping
- **Campaign Tracking** - Create and manage threat campaigns with IOCs, TTPs, CVEs, and correlation analysis
- **Watchlist Alerts** - Monitor vendors/products for new vulnerabilities with session-start briefings
- **Rule Generation** - Create YARA and Sigma (network, DNS, firewall) detection rules from IOCs
- **STIX Export** - Export IOCs and CVEs in STIX 2.1 format
- **WHOIS / RIR Lookups** - Query RIPE, ARIN, APNIC, AfriNIC, and LACNIC for IP/ASN/contact data
- **Username OSINT** - Search for usernames across social networks via Maigret
- **Claude Code Integration** - Slash commands, hooks, MCP server, and per-investigation usage tracking


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
| `/investigate` | Structured multi-source investigation | `/investigate CVE-2026-24061` |
| `/review` | Independent judge layer for findings | `/review` |
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
python -m osint_agent.cli keys set SHODAN_API_KEY
```

Or copy `.env.example` to `.env` and fill in values.

| Key | Source | Benefits |
|-----|--------|----------|
| `NVD_API_KEY` | [NVD](https://nvd.nist.gov/developers/request-an-api-key) | Higher rate limits |
| `OTX_API_KEY` | [AlienVault](https://otx.alienvault.com/) | Threat pulse access |
| `SHODAN_API_KEY` | [Shodan](https://account.shodan.io/) | Host/DNS/vuln lookups |
| `FRESHRSS_URL` | Self-hosted | Threat feed monitoring |
| `FRESHRSS_USER` | Self-hosted | FreshRSS credentials |
| `FRESHRSS_PASSWORD` | Self-hosted | FreshRSS credentials |

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
├── src/osint_agent/          # Main Python package
│   ├── clients/              # API clients (NVD, CISA, OTX, Abuse.ch, Shodan, FreshRSS, ATT&CK)
│   ├── extractors.py         # IOC extraction
│   ├── rules.py              # YARA/Sigma generation
│   ├── stix_export.py        # STIX 2.1 export
│   ├── campaigns.py          # Campaign tracking
│   ├── correlation.py        # Campaign IOC correlation
│   ├── context.py            # Investigation context management
│   ├── investigation_log.py  # Per-investigation JSONL step logging
│   ├── usage.py              # Per-investigation usage tracking
│   ├── cache.py              # Transparent API response caching
│   └── parallel.py           # Concurrent execution utilities
├── mcp-server/               # Claude Code MCP server
│   ├── server.py             # Server entry point (15 tool modules)
│   └── tools/                # MCP tool modules (60+ tools)
├── .claude/
│   ├── commands/             # Slash commands (7 commands)
│   └── hooks/                # Automation hooks
├── config/                   # Configuration files
├── data/                     # Databases, cache, and logs
│   ├── cache/                # API response cache
│   ├── context/              # Investigation context state
│   ├── campaigns/            # Campaign data
│   └── logs/                 # JSONL logs (alerts, investigations)
└── tests/                    # Unit and integration tests
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

See [mcp-server/README.md](mcp-server/README.md) for the full tool reference.

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

1. **Structured Investigation** - Run `/investigate` on any indicator for multi-source enrichment
2. **Independent Review** - Run `/review` to get a second-opinion judge layer on findings
3. **Daily Threat Brief** - Start your day with `/intel`
4. **Incident Investigation** - Extract and correlate IOCs across campaigns
5. **Vulnerability Triage** - Prioritize patching with `/cve`
6. **Threat Actor Research** - Track campaigns and TTPs with ATT&CK mapping

## Data Sources

| Source | Type | Auth Required |
|--------|------|---------------|
| [NVD](https://nvd.nist.gov/) | CVE details | Optional |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited vulns | No |
| [AlienVault OTX](https://otx.alienvault.com/) | Threat intel pulses | Yes (free) |
| [Abuse.ch](https://abuse.ch/) (URLhaus, MalwareBazaar, ThreatFox) | Malware/URLs/IOCs | No |
| [Shodan](https://www.shodan.io/) | Internet-facing assets | Yes (free tier) |
| [MITRE ATT&CK](https://attack.mitre.org/) | TTPs and threat groups | No (bundled) |
| [FreshRSS](https://freshrss.org/) | Threat feed aggregation | Self-hosted |
| WHOIS/RIR (RIPE, ARIN, APNIC, AfriNIC, LACNIC) | IP/ASN ownership | No |
| [Maigret](https://github.com/soxoj/maigret) | Username OSINT | No |

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
- [Abuse.ch](https://abuse.ch/) for URLhaus, MalwareBazaar, and ThreatFox
- [Shodan](https://www.shodan.io/) for internet intelligence
- [MITRE](https://attack.mitre.org/) for ATT&CK framework
- [Maigret](https://github.com/soxoj/maigret) for username OSINT
