#!/usr/bin/env bash
set -euo pipefail

# OSINT Agent Setup Script
# Usage: ./setup.sh [--with-mcp]

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_MCP=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --with-mcp)
            INSTALL_MCP=true
            shift
            ;;
    esac
done

echo -e "${GREEN}=== OSINT Agent Setup ===${NC}"
echo "Project root: $PROJECT_ROOT"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
REQUIRED_VERSION="3.11"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python $REQUIRED_VERSION+ is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Python $PYTHON_VERSION"

# Check for uv (preferred) or pip
if command -v uv &> /dev/null; then
    PKG_MANAGER="uv"
    echo -e "  ${GREEN}✓${NC} uv package manager"
elif command -v pip3 &> /dev/null; then
    PKG_MANAGER="pip"
    echo -e "  ${YELLOW}!${NC} Using pip (uv recommended: https://docs.astral.sh/uv/)"
else
    echo -e "${RED}Error: uv or pip is required${NC}"
    exit 1
fi

echo ""

# Create data directories
echo -e "${YELLOW}Creating data directories...${NC}"
mkdir -p "$PROJECT_ROOT/data/cache"
mkdir -p "$PROJECT_ROOT/data/context"
mkdir -p "$PROJECT_ROOT/data/logs"
mkdir -p "$PROJECT_ROOT/.claude/data/cache"
mkdir -p "$PROJECT_ROOT/.claude/data/logs"
echo -e "  ${GREEN}✓${NC} Data directories created"

# Copy config templates
if [ ! -f "$PROJECT_ROOT/config/watchlist.json" ]; then
    cp "$PROJECT_ROOT/config/watchlist.example.json" "$PROJECT_ROOT/config/watchlist.json"
    echo -e "  ${GREEN}✓${NC} Created config/watchlist.json from template"
else
    echo -e "  ${GREEN}✓${NC} config/watchlist.json already exists"
fi

# Install main package
echo ""
echo -e "${YELLOW}Installing OSINT Agent...${NC}"
cd "$PROJECT_ROOT"

if [ "$PKG_MANAGER" = "uv" ]; then
    uv pip install -e .
else
    pip3 install -e .
fi
echo -e "  ${GREEN}✓${NC} Main package installed"

# Install MCP server if requested
if [ "$INSTALL_MCP" = true ]; then
    echo ""
    echo -e "${YELLOW}Installing MCP server...${NC}"
    cd "$PROJECT_ROOT/mcp-server"
    if [ "$PKG_MANAGER" = "uv" ]; then
        uv sync
    else
        pip3 install -e .
    fi
    echo -e "  ${GREEN}✓${NC} MCP server installed"
fi

# Initialize databases
echo ""
echo -e "${YELLOW}Initializing databases...${NC}"
cd "$PROJECT_ROOT"

python3 -c "
import sqlite3
import os

# IOC database
ioc_db = '$PROJECT_ROOT/data/iocs.db'
if not os.path.exists(ioc_db):
    conn = sqlite3.connect(ioc_db)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            hit_count INTEGER DEFAULT 1,
            UNIQUE(type, value)
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_type ON iocs(type)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_value ON iocs(value)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_first_seen ON iocs(first_seen)')
    conn.commit()
    conn.close()
    print('  Created iocs.db')
else:
    print('  iocs.db exists')

# Rate limit database
rate_db = '$PROJECT_ROOT/data/rate_limits.db'
if not os.path.exists(rate_db):
    conn = sqlite3.connect(rate_db)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_domain ON requests(domain)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON requests(timestamp)')
    conn.commit()
    conn.close()
    print('  Created rate_limits.db')
else:
    print('  rate_limits.db exists')
"
echo -e "  ${GREEN}✓${NC} Databases initialized"

# Claude Code integration info
echo ""
echo -e "${YELLOW}Claude Code Integration${NC}"
echo ""
echo "To use with Claude Code, add this project to your allowed directories:"
echo ""
echo "  1. Open Claude Code settings (~/.claude.json or via /config)"
echo "  2. Add this project path to 'projects' or start Claude Code from this directory"
echo ""
echo "The .claude/ directory contains:"
echo "  - commands/  : Slash commands (/cve, /intel, /extract-iocs, /iocs, /watchlist)"
echo "  - hooks/     : Automated threat intelligence on session start"
echo "  - settings.local.json : Project-specific permissions"
echo ""

if [ "$INSTALL_MCP" = true ]; then
    echo "To enable the MCP server, add to ~/.claude/settings.json:"
    echo ""
    echo '  "mcpServers": {'
    echo '    "osint-agent": {'
    echo '      "command": "uv",'
    echo "      \"args\": [\"--directory\", \"$PROJECT_ROOT/mcp-server\", \"run\", \"server.py\"]"
    echo '    }'
    echo '  }'
    echo ""
fi

# API keys
echo -e "${YELLOW}API Keys (Optional)${NC}"
echo ""
echo "For enhanced functionality, configure API keys:"
echo ""
echo "  python -m osint_agent.cli keys set NVD_API_KEY"
echo "  python -m osint_agent.cli keys set OTX_API_KEY"
echo ""
echo "Get keys from:"
echo "  - NVD: https://nvd.nist.gov/developers/request-an-api-key"
echo "  - OTX: https://otx.alienvault.com/ (free account)"
echo ""

# Verify installation
echo -e "${YELLOW}Verifying installation...${NC}"
if [ "$PKG_MANAGER" = "uv" ]; then
    PYTHON_CMD="uv run python"
else
    PYTHON_CMD="python3"
fi

if $PYTHON_CMD -c "import osint_agent" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} osint_agent module importable"
else
    echo -e "  ${RED}✗${NC} Failed to import osint_agent"
    exit 1
fi

if $PYTHON_CMD -m osint_agent.cli --help &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} CLI working"
else
    echo -e "  ${YELLOW}!${NC} CLI may need additional setup"
fi

echo ""
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo ""
echo "Quick start:"
echo "  python -m osint_agent.cli lookup CVE-2024-3400"
echo ""
echo "Or use Claude Code slash commands:"
echo "  /cve CVE-2024-3400"
echo "  /intel"
echo "  /watchlist"
