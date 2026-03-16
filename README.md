# KadeMCP — CTF Solver MCP Server

> A [Model Context Protocol](https://modelcontextprotocol.io) server that turns Claude into a hands-on CTF solver.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/MCP-1.0%2B-purple.svg)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)
[![CI](https://github.com/orgito1015/KadeMCP/actions/workflows/ci.yml/badge.svg)](https://github.com/orgito1015/KadeMCP/actions/workflows/ci.yml)

Connect this server to Claude Desktop and Claude can **disassemble binaries, crack hashes, fuzz web apps, extract steganography, and run full pwntools exploits** — all from natural language prompts.

---

## Categories

| Category | Tools |
|---|---|
| 🔩 **Reversing / Pwn** | `disassemble`, `strings_extract`, `checksec`, `run_binary`, `run_pwnscript` |
| 🔐 **Crypto** | `decode_encode`, `hash_identify`, `hash_crack`, `xor_bruteforce`, `frequency_analysis`, `run_crypto` |
| 🌐 **Web** | `http_request`, `fuzz_params`, `sqli_test`, `lfi_test`, `run_webscript` |
| 🔍 **Forensics / Stego** | `file_info`, `binwalk_scan`, `hex_dump`, `stego_extract`, `metadata_dump`, `pcap_analyze`, `carve_strings` |

---

## Quick start

### Option A — Local (Python)

```bash
git clone https://github.com/orgito1015/KadeMCP
cd KadeMCP
pip install -r requirements.txt

# System tools (Debian / Ubuntu)
sudo apt install binutils gdb binwalk tshark exiftool steghide hashcat
```

Add to Claude Desktop config:

- **macOS** — `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows** — `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ctf-solver": {
      "command": "python3",
      "args": ["/absolute/path/to/KadeMCP/server.py"]
    }
  }
}
```

### Option B — Docker (recommended for pwn/reversing)

```bash
git clone https://github.com/orgito1015/KadeMCP
cd KadeMCP
docker build -t kademcp .
```

```json
{
  "mcpServers": {
    "ctf-solver": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--network", "host",
        "-v", "/path/to/challenges:/challenges",
        "kademcp"
      ]
    }
  }
}
```

---

## Tool reference

### 🔩 Reversing / Pwn

| Tool | Description |
|---|---|
| `disassemble` | objdump disassembly — pass `binary_b64` (base64) or `filepath` |
| `strings_extract` | `strings` on a binary to surface printable content and flags |
| `checksec` | Check NX, PIE, RELRO, stack canary |
| `run_binary` | Execute binary with optional stdin, capture output |
| `run_pwnscript` | Run a full Python pwntools exploit — Claude writes it, this runs it |

### 🔐 Crypto

| Tool | Description |
|---|---|
| `decode_encode` | base64, hex, rot13, url, binary, morse, ascii — encode or decode |
| `hash_identify` | Guess hash type from length and pattern |
| `hash_crack` | hashcat + rockyou for md5/sha1/sha256/sha512/ntlm |
| `xor_bruteforce` | Single-byte XOR brute-force ranked by English frequency, or known-key XOR |
| `frequency_analysis` | Letter frequency for classical cipher cracking |
| `run_crypto` | Arbitrary Python — pycryptodome, gmpy2, sympy available |

### 🌐 Web

| Tool | Description |
|---|---|
| `http_request` | HTTP GET/POST/PUT/DELETE with headers, cookies, JSON body |
| `fuzz_params` | Fuzz a `FUZZ`-marked URL/body — presets: sqli, xss, lfi, ssti, xxe |
| `sqli_test` | Automated SQLi detection (error, boolean, time-based) |
| `lfi_test` | Path traversal / LFI payload testing |
| `run_webscript` | Arbitrary Python — requests, BeautifulSoup4, httpx available |

### 🔍 Forensics / Stego

| Tool | Description |
|---|---|
| `file_info` | `file` + `exiftool` type and metadata identification |
| `binwalk_scan` | Scan and optionally extract embedded files |
| `hex_dump` | `xxd` with offset and length control |
| `stego_extract` | Tries steghide, zsteg (PNG/BMP), outguess in sequence |
| `metadata_dump` | Full exiftool dump — flags often hide in EXIF fields |
| `pcap_analyze` | tshark modes: summary, http_objects, dns, credentials, follow_tcp |
| `carve_strings` | `strings` with offsets + optional filter pattern |

---

## Example prompts

```
"Here's a binary (base64): <...> — find the flag. Start with checksec and strings."

"Crack this hash: 5f4dcc3b5aa765d61d8327deb882cf99"

"The site at http://ctf.local/search?q=FUZZ is probably injectable. Run sqli_test."

"This JPEG might have a hidden message. Try all stego methods."

"Analyze challenge.pcap — look for credentials in HTTP and FTP streams."

"The ciphertext looks like single-byte XOR: 1a3f2b0e... brute-force it."
```

---

## Project structure

```
KadeMCP/
├── server.py                   # MCP entry point — registers all tools
├── tools/
│   ├── __init__.py
│   ├── utils.py                # Shared: run_cmd, run_python, helpers
│   ├── reversing.py            # Reversing + pwn tools
│   ├── crypto.py               # Crypto tools
│   ├── web.py                  # Web exploitation tools
│   └── forensics.py            # Forensics + stego tools
├── .github/
│   └── workflows/
│       └── ci.yml              # Lint + import check on push/PR
├── Dockerfile
├── requirements.txt
├── pyproject.toml
├── LICENSE
└── README.md
```

## Extending

Each category is self-contained. To add a tool:

1. Open `tools/<category>.py`
2. Add a `Tool(name=..., description=..., inputSchema=...)` to the list
3. Add an `if name == "..."` branch in the `handle_*` function

No changes to `server.py` needed — it auto-registers everything.

---

## Security

- Use Docker when running untrusted binaries (pwn/reversing)
- Never expose the server on a network port — it runs shell commands
- The Dockerfile runs as a non-root `ctf` user

---

## License

[MIT](LICENSE)
