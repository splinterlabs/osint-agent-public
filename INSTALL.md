# OSINT Agent Installation Guide

A threat intelligence assistant for Claude Code with CVE lookups, IOC extraction, and automated security monitoring.

## Prerequisites

- **Python 3.11+**
- **uv** (recommended) or pip
- **Claude Code** CLI
- **macOS or Linux**

### Install uv (Recommended)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Quick Install

```bash
git clone <repository-url> osint-agent
cd osint-agent
./setup.sh
```

For MCP server support:
```bash
./setup.sh --with-mcp
```

## Manual Installation

### 1. Clone and Install

```bash
git clone <repository-url> osint-agent
cd osint-agent

# Using uv (recommended)
uv pip install -e .

# Or using pip
pip install -e .
```

### 2. Create Data Directories

```bash
mkdir -p data/{cache,context,logs}
mkdir -p .claude/data/{cache,logs}
```

### 3. Initialize Databases

Databases auto-create on first use, or run:

```bash
python -c "
import sqlite3
conn = sqlite3.connect('data/iocs.db')
conn.execute('''CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hit_count INTEGER DEFAULT 1,
    UNIQUE(type, value)
)''')
conn.close()
"
```

### 4. Configure API Keys (Optional)

API keys enhance functionality but are not required:

```bash
# NVD API key (higher rate limits)
python -m osint_agent.cli keys set NVD_API_KEY

# AlienVault OTX (threat intelligence)
python -m osint_agent.cli keys set OTX_API_KEY
```

Get keys from:
- **NVD**: https://nvd.nist.gov/developers/request-an-api-key
- **OTX**: https://otx.alienvault.com/ (free account)

## Claude Code Integration

### Using with Claude Code

Start Claude Code from the project directory:

```bash
cd osint-agent
claude
```

The `.claude/` directory provides:
- **Slash commands**: `/cve`, `/intel`, `/extract-iocs`, `/iocs`, `/watchlist`
- **Hooks**: Automated threat briefing on session start
- **Settings**: Project-specific permissions

### Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `/cve <id>` | Look up CVE details | `/cve CVE-2024-3400` |
| `/intel` | Daily threat summary | `/intel` |
| `/extract-iocs` | Extract IOCs from text/file | `/extract-iocs report.txt` |
| `/iocs` | Query IOC database | `/iocs sha256` |
| `/watchlist` | Manage monitored vendors | `/watchlist add vendor Fortinet` |

### MCP Server (Optional)

The MCP server provides additional tools for Claude Code.

1. Install the MCP server:
   ```bash
   cd mcp-server
   uv sync
   ```

2. Add to `~/.claude/settings.json`:
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

3. Restart Claude Code

## Configuration

### Watchlist (`config/watchlist.json`)

Monitor specific vendors, products, or keywords:

```json
{
  "vendors": ["Microsoft", "Cisco", "Fortinet"],
  "products": ["Exchange", "FortiGate", "PAN-OS"],
  "keywords": ["RCE", "zero-day", "actively exploited"]
}
```

### Allowed Domains (`config/allowed_domains.json`)

Whitelist of OSINT sources with rate limits. Pre-configured with common sources.

## Verification

Test the installation:

```bash
# CLI test
python -m osint_agent.cli lookup CVE-2024-3400

# Module import test
python -c "import osint_agent; print('OK')"
```

## Troubleshooting

### "Module not found" errors

Ensure you installed in editable mode:
```bash
uv pip install -e .
```

### Hook errors in Claude Code

Check hook logs:
```bash
cat .claude/data/logs/alerts.jsonl
```

### Rate limiting issues

The system enforces rate limits per domain. If blocked:
```bash
cat data/logs/blocked_requests.jsonl
```

### Database locked

SQLite concurrent access issue. Restart Claude Code or:
```bash
rm data/rate_limits.db  # Will be recreated
```

## Updating

```bash
git pull
uv pip install -e .
```

## Uninstalling

```bash
uv pip uninstall osint-agent
rm -rf data/  # Remove databases (optional)
```

## Project Structure

```
osint-agent/
├── src/osint_agent/     # Main Python package
├── mcp-server/          # Optional MCP server
├── .claude/             # Claude Code integration
│   ├── commands/        # Slash commands
│   ├── hooks/           # Automation hooks
│   └── settings.local.json
├── config/              # Configuration files
├── data/                # Databases and cache
└── setup.sh             # Installation script
```

## Support

- Check existing issues or open a new one
- Review USE_CASES.md for workflow examples
