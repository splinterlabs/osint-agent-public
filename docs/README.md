# OSINT Agent Documentation

Comprehensive documentation for OSINT Agent threat intelligence platform.

## 📚 Documentation Index

### Getting Started

- **[Installation Guide](../INSTALL.md)** - Setup instructions, prerequisites, and troubleshooting
- **[Quick Start (README)](../README.md)** - Get running in under 5 minutes

### User Guides

- **[Use Cases](../USE_CASES.md)** - Six primary workflows with examples:
  - Structured Investigation (`/investigate`)
  - Independent Review (`/review`)
  - Daily Threat Brief (`/intel`)
  - Incident Investigation (IOC extraction and correlation)
  - Vulnerability Triage (`/cve`)
  - Threat Actor Research (campaign tracking)

### Developer Documentation

- **[Contributing Guide](../CONTRIBUTING.md)** - Development setup, testing, code style, and repository structure
- **[AI Agent Instructions](../AGENTS.md)** - Project instructions for AI coding assistants (Claude Code, Cursor, Aider, etc.)
- **[MCP Server Reference](../mcp-server/README.md)** - Complete tool reference for 60+ MCP tools
- **[Security Policy](../SECURITY.md)** - Security practices and vulnerability reporting

### Advanced Topics

- **[Local Models Guide](local-models.md)** - Running OSINT Agent with local LLMs or without LLM
  - Architecture overview (LLM-free data layer)
  - MCP server with Ollama/Open WebUI
  - Model size recommendations (7B vs 14B vs 70B+)
  - What works without a frontier model

- **[Local Web Fetch Tools](local-web-fetch.md)** - Alternative web fetching for restricted networks
  - Bypass network restrictions
  - Realistic browser headers and User-Agent rotation
  - SSL flexibility for corporate proxies
  - Tools: `local_web_fetch`, `local_web_fetch_json`, `local_web_fetch_raw`

### Historical Documentation

- **[archive/OSINT_AGENT_PROPOSAL.md](archive/OSINT_AGENT_PROPOSAL.md)** - Original implementation proposal (archived)
- **[archive/SSL_FIX_SUMMARY.md](archive/SSL_FIX_SUMMARY.md)** - Zscaler SSL certificate troubleshooting (archived)

---

## Quick Reference

### Key Features

- **CVE Lookup** - NVD + CISA KEV integration
- **IOC Extraction** - Extract IPs, domains, hashes, URLs, CVEs from text
- **Threat Intelligence** - OTX, Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
- **Reconnaissance** - Shodan host/DNS/vulnerability lookups
- **ATT&CK Mapping** - MITRE ATT&CK techniques and threat groups
- **Campaign Tracking** - Group IOCs, TTPs, CVEs with correlation
- **Watchlist Alerts** - Monitor vendors/products for new CVEs
- **Detection Rules** - Generate YARA and Sigma rules
- **STIX Export** - Export IOCs in STIX 2.1 format

### Architecture Highlights

```
osint-agent/
├── src/osint_agent/          # Main Python package (zero LLM dependencies)
│   ├── clients/              # API clients for 8+ threat intel sources
│   ├── extractors.py         # IOC extraction (regex-based)
│   ├── campaigns.py          # Campaign tracking and correlation
│   ├── investigation_log.py  # Per-investigation JSONL logging
│   └── cache.py              # Transparent API response caching
├── mcp-server/               # MCP server with 60+ tools
├── .claude/                  # Claude Code integration
│   ├── commands/             # 7 slash commands
│   └── hooks/                # Automation hooks (startup briefing, etc.)
├── data/                     # Databases, cache, logs (gitignored)
└── docs/                     # Documentation (you are here)
```

### Data Sources

| Source | Type | Auth Required |
|--------|------|---------------|
| [NVD](https://nvd.nist.gov/) | CVE details | Optional |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited vulns | No |
| [AlienVault OTX](https://otx.alienvault.com/) | Threat intel pulses | Yes (free) |
| [Abuse.ch](https://abuse.ch/) | Malware/URLs/IOCs | No |
| [Shodan](https://www.shodan.io/) | Internet-facing assets | Yes (free tier) |
| [MITRE ATT&CK](https://attack.mitre.org/) | TTPs and threat groups | No (bundled) |
| WHOIS/RIR | IP/ASN ownership | No |
| [Maigret](https://github.com/soxoj/maigret) | Username OSINT | No |

---

## Common Tasks

### Investigation Workflow

```bash
# In Claude Code
/investigate <indicator>    # Multi-source enrichment
/review                      # Independent judge layer
```

### CLI Usage

```bash
# Activate environment
source .venv/bin/activate

# Look up CVE
python -m osint_agent.cli lookup CVE-2024-3400

# Extract IOCs
python -m osint_agent.cli extract -f report.txt

# Get threat intel summary
python -m osint_agent.cli intel

# Search IOC database
python -m osint_agent.cli iocs --type sha256
```

### Development Commands

```bash
make init          # First-time setup
make test          # Run tests
make test-cov      # Tests with coverage
make check         # Pre-commit checks (lint + type + test)
make format        # Auto-format code
```

---

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/splinterlabs/osint-agent-public/issues)
- **Discussions**: [GitHub Discussions](https://github.com/splinterlabs/osint-agent-public/discussions)
- **Security**: See [SECURITY.md](../SECURITY.md) for vulnerability reporting

---

## License

MIT License - see [LICENSE](../LICENSE) for details.
