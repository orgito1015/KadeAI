"""
Shared utilities: sandboxed command runner and file helpers.
"""

import asyncio
import os
import tempfile

TIMEOUT = 20  # seconds per tool call


async def run_cmd(*args: str, input_data: bytes | None = None, timeout: int = TIMEOUT) -> str:
    """
    Run a command as a subprocess, capturing stdout + stderr.
    Returns combined output as a string, or an error message on failure.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if input_data else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=input_data), timeout=timeout
        )
        out = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        combined = out
        if err.strip():
            combined += f"\n[stderr]\n{err}"
        return combined.strip() or "(no output)"
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return f"[error] command timed out after {timeout}s"
    except FileNotFoundError as e:
        return f"[error] tool not found: {e}. Is it installed?"
    except Exception as e:
        return f"[error] {e}"


async def run_python(code: str, timeout: int = TIMEOUT) -> str:
    """Execute arbitrary Python code in a subprocess and return output."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        fname = f.name
    try:
        result = await run_cmd("python3", fname, timeout=timeout)
    finally:
        os.unlink(fname)
    return result


def write_tempfile(data: bytes, suffix: str = "") -> str:
    """Write bytes to a temp file and return the path."""
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(data)
        return f.name


def decode_input(raw: str) -> bytes:
    """
    Accept hex-encoded (0x... or plain hex) or raw string input.
    Returns bytes.
    """
    raw = raw.strip()
    if raw.startswith("0x") or raw.startswith("0X"):
        return bytes.fromhex(raw[2:])
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode()
