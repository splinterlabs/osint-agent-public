# Running OSINT Agent with Local Models

This document explains how to run the OSINT Agent stack without Claude Code, using local LLMs or no LLM at all.

## Architecture Overview

The OSINT Agent has a clean two-layer architecture:

```
┌─────────────────────────────────────────────────────────┐
│  Intelligence Layer (LLM)                               │
│  Workflow orchestration, synthesis, reporting            │
│  Currently: Claude Code + slash commands                 │
│  Replaceable: Any MCP-compatible LLM client              │
├─────────────────────────────────────────────────────────┤
│  Data Layer (Python)                                     │
│  60+ MCP tools, CLI, IOC database, rule generation,     │
│  STIX export, campaign tracking, caching, hooks          │
│  Zero LLM dependencies — fully standalone                │
└─────────────────────────────────────────────────────────┘
         │                          │
    stdio (JSON-RPC)           Direct CLI
         │                          │
    ┌────┴────┐               ┌─────┴─────┐
    │ MCP     │               │ REST APIs │
    │ Server  │───────────────│ NVD, OTX, │
    │         │               │ Shodan,   │
    └─────────┘               │ Abuse.ch  │
                              └───────────┘
```

**Key insight:** The Python backend has zero LLM dependencies. No `openai`, `anthropic`, `langchain`, or `ollama` imports exist in the source code. All intelligence synthesis currently happens in Claude Code's slash commands (`.claude/commands/*.md`), which are portable prompt templates.

## What Works Without Any LLM

The CLI and MCP server are fully functional standalone:

```bash
# CVE lookup
python -m osint_agent.cli lookup CVE-2024-3400 --format text

# IOC database operations
python -m osint_agent.cli iocs search "8.8.8.8" --format text
python -m osint_agent.cli iocs stats

# IOC extraction (regex-based, no LLM)
python -m osint_agent.cli extract -f report.txt
python -m osint_agent.cli extract -t "Check 192.168.1.1 and evil.com"

# API key management
python -m osint_agent.cli keys list
python -m osint_agent.cli keys set SHODAN_API_KEY
```

These features require no LLM:

| Feature | How It Works |
|---------|-------------|
| CVE/KEV lookups | REST API calls to NVD and CISA |
| IOC extraction | Regex pattern matching |
| IOC database | SQLite queries |
| YARA rule generation | Template-based construction |
| Sigma rule generation | Template-based construction |
| STIX export | Schema builder (deterministic) |
| Campaign tracking | SQLite CRUD operations |
| API response caching | SQLite with TTL |
| Rate limiting | Token bucket in SQLite |
| Watchlist matching | String/CPE comparison |
| Investigation logging | JSONL file writes |

## Running the MCP Server with a Local Model

The MCP server uses **stdio transport** (JSON-RPC over stdin/stdout). It doesn't know or care what LLM is calling it. Any MCP-compatible client can connect.

### Option 1: Ollama + Open WebUI with MCP Support

If your Open WebUI instance supports MCP tool calling, point it at the same server:

```json
{
  "mcpServers": {
    "osint-agent": {
      "command": "/path/to/osint-agent/.venv/bin/python",
      "args": ["/path/to/osint-agent/mcp-server/server.py"]
    }
  }
}
```

### Option 2: Custom Python Orchestrator

Build a lightweight wrapper that connects to the MCP server and drives workflows programmatically:

```python
"""
Example: Minimal investigation orchestrator using a local LLM.
Calls MCP tools directly, sends results to a local model for synthesis.
"""

import subprocess
import json

# Start the MCP server as a subprocess
proc = subprocess.Popen(
    [".venv/bin/python", "mcp-server/server.py"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

def call_mcp_tool(name: str, arguments: dict) -> dict:
    """Send a JSON-RPC tool call to the MCP server via stdio."""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
        },
    }
    proc.stdin.write(json.dumps(request).encode() + b"\n")
    proc.stdin.flush()
    response = proc.stdout.readline()
    return json.loads(response)

# Example: look up a CVE
result = call_mcp_tool("lookup_cve", {"cve_id": "CVE-2024-3400"})

# Example: Shodan host lookup
result = call_mcp_tool("shodan_host_lookup", {"ip": "192.42.116.211"})

# Feed results to your local LLM for synthesis
# (using ollama, llama-cpp-python, vllm, etc.)
```

> **Note:** The above is a simplified example. A production implementation would need to handle the full MCP initialization handshake (initialize → initialized → tool calls). See the [MCP specification](https://modelcontextprotocol.io/) for the complete protocol.

### Option 3: Script-Based Automation (No LLM)

For repeatable workflows, skip the LLM entirely and script the enrichment:

```bash
#!/bin/bash
# investigate-ip.sh — Automated IP investigation without LLM
IP="$1"
PROJECT_ROOT="/path/to/osint-agent"
cd "$PROJECT_ROOT"

echo "=== Investigating $IP ==="

echo "--- Local IOC DB ---"
.venv/bin/python -m osint_agent.cli iocs search "$IP" --format text

echo "--- CVE Lookup (if applicable) ---"
# Use the CLI for structured lookups

echo "--- Full enrichment via MCP tools ---"
# Call MCP tools via a Python script or mcp-cli
```

## Adapting Slash Commands for Local Models

The seven slash commands in `.claude/commands/` are markdown files containing step-by-step instructions. They are essentially prompt templates that tell the LLM:

1. What tools to call and in what order
2. How to interpret and present results
3. What format to use for output

| Command | Complexity | Local Model Feasibility |
|---------|-----------|------------------------|
| `/cve` | Low | Single tool call + formatting. Any model works. |
| `/iocs` | Low | Database query + display. Any model works. |
| `/intel` | Medium | Runs a script, cross-references watchlist. 14B+ recommended. |
| `/watchlist` | Low | JSON file read/write. Any model works. |
| `/extract-iocs` | Medium | Multi-step: extract → display → offer STIX. 14B+ recommended. |
| `/investigate` | High | 6+ sequential tool calls, conditional logic, synthesis. 70B+ recommended. |
| `/review` | Very High | 16-point analytical checklist, independent reasoning, verdict calibration. 70B+ strongly recommended. |

### Converting a Command

To adapt `/investigate` for a local model, extract the workflow logic from `.claude/commands/investigate.md` into a structured prompt:

```
You are a threat intelligence analyst. Investigate the indicator: {indicator}

Type: {classified_type}

Call these tools in order and report findings:
1. shodan_host_lookup(ip="{indicator}") — Get host details
2. lookup_ioc_otx(indicator="{indicator}", indicator_type="ipv4") — Check OTX
3. lookup_host_urlhaus(host="{indicator}") — Check URLhaus
4. lookup_ioc_threatfox(ioc="{indicator}") — Check ThreatFox

After collecting results, provide:
- Verdict: Malicious | Suspicious | Benign | Inconclusive
- Confidence: High | Medium | Low
- 2-3 sentence summary of findings
```

Simpler prompts work better with smaller models. The full `/investigate` command has nuanced instructions about context isolation, step logging, and coverage tracking that a 7B model will struggle with — simplify for your model's capability.

## Model Size Recommendations

| Model Class | Examples | Capability |
|-------------|---------|------------|
| **70B+** | Llama 3.3 70B, Qwen 2.5 72B, Mixtral 8x22B | Full workflow orchestration. Can handle `/investigate` and `/review` with adapted prompts. May need 2-3 prompt iterations to match Claude's synthesis quality. |
| **14B–32B** | Qwen 2.5 32B, Mistral Small 24B, Gemma 2 27B | Good for single-tool lookups, `/intel`, `/watchlist`, `/extract-iocs`. Multi-step investigations will need a simplified orchestration script rather than freeform reasoning. |
| **7B–8B** | Llama 3.1 8B, Gemma 2 9B, Phi-3 | Basic tool calling and summarization. Best paired with script-based automation where the model only handles the final synthesis step. |

## What You Lose Without a Frontier Model

The highest-value capabilities that degrade with smaller models:

1. **The `/review` judge layer** — The 16-point checklist requires genuine analytical reasoning about false positives, circular reporting, and proportionality. This is the hardest capability to replicate.

2. **Adaptive investigation flow** — Claude decides on the fly which findings warrant deeper investigation and offers context-aware follow-ups. Smaller models tend to follow scripts rigidly.

3. **Nuanced synthesis** — Distinguishing "this IP is suspicious" from "this IP is a legitimate Tor exit node that *looks* suspicious due to inflated OTX pulse counts from circular honeypot reporting" requires calibrated judgment.

4. **Multi-tool orchestration** — Calling 6+ tools sequentially, maintaining context across all results, and producing a coherent report is where context window size and instruction-following quality matter most.

## What You Keep Fully Intact

Everything data-driven works identically regardless of which model (or no model) drives it:

- All 60+ MCP tools and external API integrations
- IOC database (SQLite) — search, add, stats
- Campaign tracking and correlation
- YARA/Sigma rule generation
- STIX 2.1 bundle export
- Watchlist matching against NVD CVEs
- Investigation JSONL logging with full raw results
- API response caching (reduces redundant requests)
- Rate limiting (pre-tool hook)
- Passive IOC extraction from tool output (post-tool hook)
- Session start threat briefing

## Recommended Approach for Local Deployment

1. **Start with the CLI** — Get comfortable with `python -m osint_agent.cli` for direct lookups and IOC management. No LLM needed.

2. **Connect a local model via MCP** — Use a 70B+ model with MCP tool-calling support. Start with simple single-tool lookups before attempting full investigations.

3. **Simplify the slash commands** — Convert the markdown command files into shorter, more directive prompts suited to your model's capability. Remove nuances like context isolation and step logging if your model can't reliably follow them.

4. **Script what you can** — For repeatable workflows (daily intel summary, batch IOC lookups), write shell scripts that call the CLI directly. Reserve the LLM for synthesis and ad-hoc investigation.

5. **Use the data layer as your foundation** — The MCP tools, databases, and caching work the same regardless of frontend. Your local model only needs to be good enough to decide *which* tools to call and *how* to interpret results.
