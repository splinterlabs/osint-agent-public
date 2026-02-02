# Quickstart Guide - Get Running in < 5 Minutes

Get OSINT Agent running on your machine in under 5 minutes.

## Prerequisites

- **Python 3.11+** - Required for running the agent
- **uv** - Fast Python package installer (recommended)
- **API Keys** - Optional but recommended for full functionality

Check your Python version:
```bash
python3 --version  # Should be 3.11 or higher
```

Install uv (if not already installed):
```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or via pip
pip install uv
```

## One-Command Setup

```bash
make init
```

This command will:
1. ✅ Verify Python version and dependencies
2. ✅ Create virtual environment
3. ✅ Install OSINT Agent and all dependencies
4. ✅ Create configuration files from examples
5. ✅ Initialize databases (IOCs and rate limits)
6. ✅ Create required directories
7. ✅ Run validation checks

**Total time:** 2-3 minutes

## Configure (Optional)

API keys enhance functionality but are **not required**. The agent works with public data sources by default.

### Option 1: Secure Keyring Storage (Recommended)
```bash
# Store API keys securely in your system keyring
.venv/bin/python -m osint_agent.cli keys set NVD_API_KEY
.venv/bin/python -m osint_agent.cli keys set OTX_API_KEY
.venv/bin/python -m osint_agent.cli keys set SHODAN_API_KEY
```

### Option 2: Environment File
If `.env` file was created, edit it to add your API keys:
```bash
# Edit .env and add your keys
NVD_API_KEY=your-nvd-key-here
OTX_API_KEY=your-otx-key-here
SHODAN_API_KEY=your-shodan-key-here
```

### Customize Watchlist
Edit `config/watchlist.json` to monitor specific vendors, products, or keywords:
```bash
# config/watchlist.json
{
  "vendors": ["Microsoft", "Cisco", "Fortinet"],
  "products": ["Exchange", "Windows", "FortiGate"],
  "keywords": ["RCE", "zero-day", "authentication bypass"]
}
```

## Start Using

### Claude Code (Primary Interface)

Start Claude Code in the project directory:
```bash
cd osint-agent
claude
```

You'll automatically receive a threat intelligence briefing on startup. Then use slash commands:

| Command | Description | Example |
|---------|-------------|---------|
| `/investigate` | Structured multi-source investigation | `/investigate CVE-2024-3400` |
| `/review` | Independent judge layer for findings | `/review` |
| `/cve` | Look up CVE details | `/cve CVE-2024-3400` |
| `/intel` | Daily threat summary | `/intel` |
| `/extract-iocs` | Extract IOCs from text/file | `/extract-iocs report.pdf` |
| `/iocs` | Query IOC database | `/iocs sha256` |
| `/watchlist` | Manage monitored vendors | `/watchlist add vendor Fortinet` |

### Command Line Interface

```bash
# Activate virtual environment
source .venv/bin/activate

# Look up a CVE
python -m osint_agent.cli lookup CVE-2024-3400

# Extract IOCs from a file
python -m osint_agent.cli extract -f threat_report.txt

# Get threat intelligence summary
python -m osint_agent.cli intel

# Search IOC database
python -m osint_agent.cli iocs --type sha256

# See all CLI commands
python -m osint_agent.cli --help
```

### MCP Server (Optional Advanced Feature)

For additional Claude Code integration via MCP:

```bash
# Install MCP server
make setup-mcp
```

Then add to `~/.claude/settings.json`:
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

## Verify Installation

```bash
make validate  # Full validation with detailed log
make status    # Quick status summary
```

Both commands check:
- System dependencies (Python, uv)
- Virtual environment
- Installed packages
- Databases
- Configuration files
- Claude Code integration

## Common Commands

| Command | Description |
|---------|-------------|
| `make help` | Show all available commands |
| `make init` | Initialize project (first time) |
| `make status` | Quick status check |
| `make validate` | Full validation with logging |
| `make test` | Run tests |
| `make check` | Run all quality checks |
| `make update` | Update dependencies |
| `make clean` | Clean build artifacts |
| `make backup` | Backup databases and config |

## Troubleshooting

### Python Version Error
**Problem:** `❌ Python 3.11+ required. You have: Python 3.10.x`
**Solution:** Install Python 3.11 or higher:
```bash
# macOS (via Homebrew)
brew install python@3.11

# Ubuntu/Debian
sudo apt install python3.11

# Then retry: make init
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

### Claude Commands Not Found
**Problem:** `⚠️  Claude commands missing`
**Solution:** This is normal if you haven't cloned the full repository with `.claude/` directory. The agent will still work via CLI.

### API Key Errors
**Problem:** Rate limits or "API key not found" errors
**Solution:** API keys are optional. Without them, you'll use public access with lower rate limits. To add keys:
```bash
.venv/bin/python -m osint_agent.cli keys set NVD_API_KEY
# Enter your key when prompted
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

## What's Next?

After successful installation:

1. **Try the CLI:**
   ```bash
   .venv/bin/python -m osint_agent.cli intel
   ```

2. **Use Claude Code:**
   ```bash
   claude
   # Then type: /intel
   ```

3. **Run your first investigation:**
   ```bash
   # In Claude Code
   /investigate CVE-2024-3400
   ```

4. **Set up watchlist alerts:**
   - Edit `config/watchlist.json`
   - Add vendors/products you want to monitor
   - Restart Claude Code to see alerts

5. **Explore the documentation:**
   - [README.md](README.md) - Full feature overview
   - [AGENTS.md](AGENTS.md) - Architecture and developer guide
   - [USE_CASES.md](USE_CASES.md) - Detailed workflows
   - [INSTALL.md](INSTALL.md) - Advanced installation options

## Interactive Installation Wizard

Using Claude Code? Get interactive help:

```bash
claude
# Then type: /install
```

The wizard will:
- Read validation logs to diagnose issues
- Guide you through fixing each problem
- Prompt for API keys if needed
- Re-validate after changes
- Provide next steps when complete

---

**Time to first run:** < 5 minutes ⚡

**Need help?** Check the troubleshooting section above or open an issue on GitHub.
