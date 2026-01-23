# OSINT Agent

Cyber security threat intelligence toolkit with Claude Code integration.

## Features

- CVE lookup via NVD and CISA KEV
- IOC extraction and tracking
- Threat intelligence feeds (AlienVault OTX, Abuse.ch)
- YARA/Sigma rule generation
- STIX export

## Installation

```bash
uv pip install -e .
```

## Usage

```bash
# CLI
osint lookup CVE-2024-3400
osint extract -f report.txt

# Claude Code slash commands
/cve CVE-2024-3400
/extract-iocs path/to/file
/intel
/iocs
/watchlist
```
