"""
Forensics / Stego tools:
  - file_info       : file type, magic bytes, metadata (file + exiftool)
  - binwalk_scan    : scan for embedded files and extract them
  - hex_dump        : hexdump with ASCII sidebar
  - stego_extract   : steghide / zsteg / outguess extraction
  - metadata_strip  : dump full EXIF/metadata from images
  - pcap_analyze    : basic pcap analysis (tshark summary)
  - carve_strings   : strings with offset info
"""

import base64
import os
from mcp.types import Tool
from tools.utils import run_cmd, run_python, write_tempfile, decode_input

forensics_tools = [
    Tool(
        name="file_info",
        description="Identify a file's type, magic bytes, and basic metadata. Accepts base64 or filepath.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_b64": {"type": "string", "description": "Base64-encoded file bytes"},
                "filepath": {"type": "string"},
            },
        },
    ),
    Tool(
        name="binwalk_scan",
        description=(
            "Scan a file for embedded content using binwalk. "
            "Set extract=true to extract detected files into a temp directory."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "file_b64": {"type": "string"},
                "filepath": {"type": "string"},
                "extract": {"type": "boolean", "default": False},
            },
        },
    ),
    Tool(
        name="hex_dump",
        description="Produce a hex dump of a file or bytes. Limit bytes shown with `length`.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_b64": {"type": "string"},
                "filepath": {"type": "string"},
                "length": {"type": "integer", "description": "Max bytes to dump (default: 512)"},
                "offset": {"type": "integer", "description": "Start offset (default: 0)"},
            },
        },
    ),
    Tool(
        name="stego_extract",
        description=(
            "Attempt steganography extraction using steghide, zsteg (PNG/BMP), and outguess. "
            "Optionally provide a passphrase."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "file_b64": {"type": "string"},
                "filepath": {"type": "string"},
                "passphrase": {"type": "string", "description": "Steghide passphrase (try empty if unknown)"},
            },
        },
    ),
    Tool(
        name="metadata_dump",
        description="Dump full EXIF and metadata from an image or document using exiftool.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_b64": {"type": "string"},
                "filepath": {"type": "string"},
            },
        },
    ),
    Tool(
        name="pcap_analyze",
        description=(
            "Analyze a PCAP file. "
            "Modes: summary (default), http_objects, dns, credentials, follow_tcp."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "file_b64": {"type": "string"},
                "filepath": {"type": "string"},
                "mode": {
                    "type": "string",
                    "enum": ["summary", "http_objects", "dns", "credentials", "follow_tcp"],
                    "default": "summary",
                },
                "stream_index": {"type": "integer", "description": "TCP stream index for follow_tcp mode"},
            },
        },
    ),
    Tool(
        name="carve_strings",
        description="Extract printable strings with file offsets. Useful for finding hidden flags.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_b64": {"type": "string"},
                "filepath": {"type": "string"},
                "min_length": {"type": "integer", "default": 6},
                "filter_pattern": {"type": "string", "description": "Only show strings matching this substring"},
            },
        },
    ),
]


def _resolve_file(args: dict, suffix: str = "") -> tuple[str | None, str | None]:
    if "filepath" in args and args["filepath"]:
        return args["filepath"], None
    if "file_b64" in args and args["file_b64"]:
        data = base64.b64decode(args["file_b64"])
        path = write_tempfile(data, suffix=suffix)
        return path, None
    return None, "[error] provide file_b64 or filepath"


async def handle_forensics(name: str, args: dict) -> str:
    if name == "file_info":
        path, err = _resolve_file(args)
        if err:
            return err
        file_out = await run_cmd("file", path)
        exif_out = await run_cmd("exiftool", "-s", "-s", path)
        return f"=== file ===\n{file_out}\n\n=== exiftool (short) ===\n{exif_out}"

    if name == "binwalk_scan":
        path, err = _resolve_file(args)
        if err:
            return err
        if args.get("extract"):
            import tempfile
            outdir = tempfile.mkdtemp()
            result = await run_cmd("binwalk", "--extract", "--directory", outdir, path)
            listing = await run_cmd("find", outdir, "-type", "f")
            return f"{result}\n\nExtracted files:\n{listing}"
        return await run_cmd("binwalk", path)

    if name == "hex_dump":
        path, err = _resolve_file(args)
        if err:
            return err
        length = args.get("length", 512)
        offset = args.get("offset", 0)
        return await run_cmd("xxd", "-l", str(length), "-s", str(offset), path)

    if name == "stego_extract":
        path, err = _resolve_file(args)
        if err:
            return err
        passphrase = args.get("passphrase", "")
        results = []

        # steghide
        sh_result = await run_cmd(
            "steghide", "extract", "-sf", path, "-p", passphrase, "-f"
        )
        results.append(f"=== steghide ===\n{sh_result}")

        # zsteg (PNG/BMP)
        zs_result = await run_cmd("zsteg", "-a", path)
        results.append(f"\n=== zsteg ===\n{zs_result}")

        # outguess
        import tempfile
        out_path = tempfile.mktemp(suffix=".txt")
        og_result = await run_cmd("outguess", "-r", path, out_path)
        if os.path.exists(out_path):
            with open(out_path, "rb") as f:
                og_data = f.read()
            og_result += f"\nExtracted: {og_data[:500]}"
        results.append(f"\n=== outguess ===\n{og_result}")

        return "\n".join(results)

    if name == "metadata_dump":
        path, err = _resolve_file(args)
        if err:
            return err
        return await run_cmd("exiftool", path)

    if name == "pcap_analyze":
        path, err = _resolve_file(args, suffix=".pcap")
        if err:
            return err
        mode = args.get("mode", "summary")

        if mode == "summary":
            return await run_cmd(
                "tshark", "-r", path, "-q", "-z", "conv,tcp", "-z", "io,stat,0"
            )
        if mode == "http_objects":
            import tempfile
            outdir = tempfile.mkdtemp()
            await run_cmd("tshark", "-r", path, "--export-objects", f"http,{outdir}")
            listing = await run_cmd("ls", "-la", outdir)
            return f"HTTP objects exported to {outdir}:\n{listing}"
        if mode == "dns":
            return await run_cmd(
                "tshark", "-r", path, "-Y", "dns", "-T", "fields",
                "-e", "dns.qry.name", "-e", "dns.a"
            )
        if mode == "credentials":
            return await run_cmd(
                "tshark", "-r", path, "-Y",
                "ftp.request.command==PASS || http.authbasic || telnet",
                "-T", "fields", "-e", "ftp.request.arg", "-e", "http.authbasic"
            )
        if mode == "follow_tcp":
            idx = args.get("stream_index", 0)
            return await run_cmd(
                "tshark", "-r", path, "-q", "-z", f"follow,tcp,ascii,{idx}"
            )
        return "[error] unknown pcap mode"

    if name == "carve_strings":
        path, err = _resolve_file(args)
        if err:
            return err
        min_len = str(args.get("min_length", 6))
        out = await run_cmd("strings", "-t", "x", "-n", min_len, path)
        pattern = args.get("filter_pattern", "")
        if pattern:
            lines = [ln for ln in out.splitlines() if pattern.lower() in ln.lower()]
            return "\n".join(lines) or f"(no strings matching '{pattern}')"
        return out

    return f"[error] unknown forensics tool: {name}"
