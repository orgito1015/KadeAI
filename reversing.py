"""
Reversing / Pwn tools:
  - disassemble     : objdump disassembly of a binary
  - strings_extract : run `strings` on a file
  - ltrace_strace   : run ltrace or strace on a binary with args
  - checksec        : check binary protections (via checksec)
  - run_pwnscript   : execute a pwntools Python script
  - run_binary      : run a binary with optional stdin and capture output
"""

import os
import base64
from mcp.types import Tool
from tools.utils import run_cmd, run_python, write_tempfile, decode_input

reversing_tools = [
    Tool(
        name="disassemble",
        description=(
            "Disassemble a binary using objdump. "
            "Pass the binary as base64 in `binary_b64`, or provide a `filepath`. "
            "Optional: `arch` (default: auto), `section` (e.g. .text)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "binary_b64": {"type": "string", "description": "Base64-encoded binary bytes"},
                "filepath": {"type": "string", "description": "Absolute path to binary on disk"},
                "section": {"type": "string", "description": "ELF section to disassemble (default: .text)"},
            },
        },
    ),
    Tool(
        name="strings_extract",
        description="Run `strings` on a binary or file to find printable strings. Accepts base64 or filepath.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_b64": {"type": "string"},
                "filepath": {"type": "string"},
                "min_length": {"type": "integer", "description": "Minimum string length (default: 4)"},
            },
        },
    ),
    Tool(
        name="checksec",
        description="Check binary security protections (NX, PIE, RELRO, stack canary) using checksec.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_b64": {"type": "string"},
                "filepath": {"type": "string"},
            },
        },
    ),
    Tool(
        name="run_binary",
        description="Execute a binary with optional stdin input and capture stdout/stderr. 20s timeout.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_b64": {"type": "string"},
                "filepath": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}, "description": "CLI arguments"},
                "stdin": {"type": "string", "description": "Data to send on stdin"},
            },
        },
    ),
    Tool(
        name="run_pwnscript",
        description=(
            "Execute a Python pwntools script. "
            "Write your full exploit in `code`. "
            "Use process('/path/to/binary') or remote('host', port). "
            "The script runs as a subprocess; print() output is returned."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Full Python pwntools script"},
            },
            "required": ["code"],
        },
    ),
]


def _resolve_binary(args: dict) -> tuple[str | None, str | None]:
    """Return (filepath, error_msg). Writes temp file if b64 supplied."""
    if "filepath" in args and args["filepath"]:
        return args["filepath"], None
    if "binary_b64" in args and args["binary_b64"]:
        data = base64.b64decode(args["binary_b64"])
        path = write_tempfile(data, suffix=".bin")
        os.chmod(path, 0o755)
        return path, None
    return None, "[error] provide binary_b64 or filepath"


async def handle_reversing(name: str, args: dict) -> str:
    if name == "disassemble":
        path, err = _resolve_binary(args)
        if err:
            return err
        section = args.get("section", ".text")
        return await run_cmd("objdump", "-d", "-M", "intel", "--section", section, path)

    if name == "strings_extract":
        path, err = _resolve_binary(args)
        if err:
            return err
        min_len = str(args.get("min_length", 4))
        return await run_cmd("strings", "-n", min_len, path)

    if name == "checksec":
        path, err = _resolve_binary(args)
        if err:
            return err
        return await run_cmd("checksec", "--file", path)

    if name == "run_binary":
        path, err = _resolve_binary(args)
        if err:
            return err
        cli_args = args.get("args", [])
        stdin_data = args.get("stdin", "").encode() if args.get("stdin") else None
        return await run_cmd(path, *cli_args, input_data=stdin_data)

    if name == "run_pwnscript":
        return await run_python(args["code"])

    return f"[error] unknown reversing tool: {name}"
