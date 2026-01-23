"""Tool modules for the OSINT MCP server.

Each module should expose a register_tools(mcp) function that registers
its tools with the FastMCP server instance.

Example module structure:
```python
from mcp.server.fastmcp import FastMCP

def register_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def my_tool(param: str) -> str:
        '''Tool description.'''
        return result
```
"""
