"""
CTF Solver MCP Server
Exposes tools for Reversing/Pwn, Crypto, Web, and Forensics challenges.
"""

import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from tools.reversing import reversing_tools, handle_reversing
from tools.crypto import crypto_tools, handle_crypto
from tools.web import web_tools, handle_web
from tools.forensics import forensics_tools, handle_forensics

server = Server("ctf-solver")

ALL_TOOLS = reversing_tools + crypto_tools + web_tools + forensics_tools

TOOL_HANDLERS = {}
for tool in reversing_tools:
    TOOL_HANDLERS[tool.name] = handle_reversing
for tool in crypto_tools:
    TOOL_HANDLERS[tool.name] = handle_crypto
for tool in web_tools:
    TOOL_HANDLERS[tool.name] = handle_web
for tool in forensics_tools:
    TOOL_HANDLERS[tool.name] = handle_forensics


@server.list_tools()
async def list_tools() -> list[Tool]:
    return ALL_TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    result = await handler(name, arguments)
    return [TextContent(type="text", text=result)]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
