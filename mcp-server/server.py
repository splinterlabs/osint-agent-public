#!/usr/bin/env python3
"""MCP server exposing OSINT agent capabilities to Claude Code.

This server uses a modular architecture that supports adding new data sources.
New tools can be added by:
1. Creating a new module in tools/
2. Importing and registering it in this file
"""

import logging
import sys
from pathlib import Path

# Add parent src/ to path for osint_agent imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mcp.server.fastmcp import FastMCP

# Configure logging (never use print - breaks STDIO transport)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("osint-mcp")

# Initialize FastMCP server
mcp = FastMCP("osint-agent")

# Import and register tool modules
# Each module calls register_tools(mcp) to add its tools
from tools import nvd_tools
from tools import kev_tools
from tools import extractor_tools
from tools import stix_tools
from tools import otx_tools
from tools import abusech_tools
from tools import rule_tools
from tools import context_tools
from tools import shodan_tools
from tools import attack_tools
from tools import campaign_tools

nvd_tools.register_tools(mcp)
kev_tools.register_tools(mcp)
extractor_tools.register_tools(mcp)
stix_tools.register_tools(mcp)
otx_tools.register_tools(mcp)
abusech_tools.register_tools(mcp)
rule_tools.register_tools(mcp)
context_tools.register_tools(mcp)
shodan_tools.register_tools(mcp)
attack_tools.register_tools(mcp)
campaign_tools.register_tools(mcp)

# To add a new source:
# 1. Create tools/new_source_tools.py with register_tools(mcp) function
# 2. Import and call register_tools here


def main():
    """Run the MCP server with stdio transport."""
    logger.info("Starting OSINT MCP server")
    mcp.run()


if __name__ == "__main__":
    main()
