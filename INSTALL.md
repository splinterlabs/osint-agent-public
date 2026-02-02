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

## Quick Install (< 5 Minutes)

```bash
# Clone the repository
git clone https://github.com/splinterlabs/osint-agent-public.git
cd osint-agent

# One-command setup
make init
```

**What `make init` does:**
1. ✅ Verifies Python 3.11+ and dependencies
2. ✅ Creates virtual environment with uv
3. ✅ Installs OSINT Agent and all dependencies
4. ✅ Creates configuration files from examples
5. ✅ Initializes databases (IOCs and rate limits)
6. ✅ Creates required directories (data/, reports/, logs/)
7. ✅ Runs validation checks

**Total time:** 2-3 minutes

### Verify Installation

```bash
make validate  # Full validation with detailed log
make status    # Quick status summary
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
mkdir -p data/{cache,context,logs,campaigns}
mkdir -p data/logs/investigations
mkdir -p data/cache/attack
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

# Shodan (host/DNS/vuln lookups)
python -m osint_agent.cli keys set SHODAN_API_KEY
```

Get keys from:
- **NVD**: https://nvd.nist.gov/developers/request-an-api-key
- **OTX**: https://otx.alienvault.com/ (free account)
- **Shodan**: https://account.shodan.io/ (free tier available)

For FreshRSS integration, set these in `.env`:
- `FRESHRSS_URL` — Your FreshRSS instance URL
- `FRESHRSS_USER` — FreshRSS username
- `FRESHRSS_PASSWORD` — FreshRSS password

## Claude Code Integration

### Using with Claude Code

Start Claude Code from the project directory:

```bash
cd osint-agent
claude
```

The `.claude/` directory provides:
- **Slash commands**: `/investigate`, `/review`, `/cve`, `/intel`, `/extract-iocs`, `/iocs`, `/watchlist`
- **Hooks**: Automated threat briefing on session start
- **Settings**: Project-specific permissions

### Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `/investigate` | Structured multi-source investigation | `/investigate CVE-2026-24061` |
| `/review` | Independent judge layer for findings | `/review` |
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

### Python Version Error

**Problem:** `❌ Python 3.11+ required. You have: Python 3.10.x`

**Solution:** Install Python 3.11 or higher:
```bash
# macOS (via Homebrew)
brew install python@3.11

# Ubuntu/Debian
sudo apt install python3.11

# Then retry
make init
```

### Virtual Environment Issues

**Problem:** `❌ Virtual environment missing`

**Solution:**
```bash
make setup-venv
make validate
```

### Database Not Initialized

**Problem:** `❌ IOC database missing`

**Solution:**
```bash
make init-db
make validate
```

### "Module not found" errors

**Problem:** Import errors when running CLI

**Solution:** Ensure you installed in editable mode:
```bash
uv pip install -e .
# or
make install
```

### Hook errors in Claude Code

**Problem:** Errors in Claude Code hooks

**Solution:** Check hook logs:
```bash
cat .claude/data/logs/alerts.jsonl
```

### API Key Errors

**Problem:** Rate limits or "API key not found" errors

**Solution:** API keys are optional. Without them, you'll use public access with lower rate limits. To add keys:
```bash
.venv/bin/python -m osint_agent.cli keys set NVD_API_KEY
# Enter your key when prompted
```

### Rate Limiting Issues

**Problem:** "Rate limit exceeded" errors

**Solution:** The system enforces rate limits per domain. If blocked, check logs:
```bash
cat data/logs/blocked_requests.jsonl
```

Wait for rate limit reset or add API keys for higher limits.

### Database Locked

**Problem:** SQLite concurrent access issue

**Solution:** Restart Claude Code or recreate the database:
```bash
rm data/rate_limits.db  # Will be recreated automatically
```

### Permission Denied Errors

**Problem:** Permission errors when creating directories or databases

**Solution:** Ensure you have write permissions in the project directory:
```bash
# Check ownership
ls -la

# If needed, fix permissions
chmod -R u+w .
```

### SSL Certificate Errors

**Problem:** SSL verification failures on corporate networks

**Solution:** If you're behind Zscaler or similar SSL inspection:

See `docs/archive/SSL_FIX_SUMMARY.md` for details on configuring SSL certificates.

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
│   ├── clients/         # API clients (NVD, OTX, Abuse.ch, Shodan, FreshRSS, ATT&CK)
│   └── ...              # Extractors, rules, STIX, campaigns, context, caching
├── mcp-server/          # MCP server (15 tool modules, 60+ tools)
│   └── tools/           # Tool modules
├── .claude/
│   ├── commands/        # Slash commands (7 commands)
│   ├── hooks/           # Automation hooks
│   └── settings.local.json
├── config/              # Configuration files
├── data/                # Databases, cache, and logs
│   ├── cache/           # API response cache
│   ├── context/         # Investigation context state
│   ├── campaigns/       # Campaign tracking data
│   └── logs/            # JSONL logs (alerts, investigations)
├── tests/               # Unit and integration tests
└── setup.sh             # Installation script
```

## Support

- Check existing issues or open a new one
- Review USE_CASES.md for workflow examples
