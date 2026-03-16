"""
Crypto tools:
  - decode_encode   : base64, hex, rot13, url, binary, morse
  - hash_identify   : guess hash type from its length/pattern
  - hash_crack      : crack hash with rockyou wordlist via hashcat/john
  - run_crypto      : run arbitrary Python crypto code (pycryptodome available)
  - xor_bruteforce  : single-byte and multi-byte XOR brute-force
  - frequency_analysis : letter frequency analysis for classical ciphers
"""

import base64
import urllib.parse
import string
from mcp.types import Tool
from tools.utils import run_cmd, run_python, decode_input

crypto_tools = [
    Tool(
        name="decode_encode",
        description=(
            "Encode or decode data using a named scheme. "
            "Schemes: base64, base64url, hex, rot13, url, binary, morse, ascii. "
            "Direction: encode | decode (default: decode)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Input data (string or hex prefixed with 0x)"},
                "scheme": {"type": "string", "description": "Encoding scheme"},
                "direction": {"type": "string", "enum": ["encode", "decode"], "default": "decode"},
            },
            "required": ["data", "scheme"],
        },
    ),
    Tool(
        name="hash_identify",
        description="Identify a hash type by its length and character set.",
        inputSchema={
            "type": "object",
            "properties": {
                "hash_value": {"type": "string"},
            },
            "required": ["hash_value"],
        },
    ),
    Tool(
        name="hash_crack",
        description=(
            "Attempt to crack a hash using hashcat with rockyou. "
            "Provide the hash string. Common modes: md5, sha1, sha256, sha512, ntlm."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hash_value": {"type": "string"},
                "mode": {
                    "type": "string",
                    "description": "Hash mode: md5, sha1, sha256, sha512, ntlm (default: auto-detect)",
                },
            },
            "required": ["hash_value"],
        },
    ),
    Tool(
        name="xor_bruteforce",
        description=(
            "XOR brute-force. For single-byte XOR, tries all 256 keys and ranks by English frequency. "
            "For known key, XORs data with that key (repeating). "
            "Input as hex (0x...) or raw string."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Ciphertext as hex (0x...) or raw"},
                "key": {"type": "string", "description": "Known key (leave empty to brute-force single-byte)"},
                "top_n": {"type": "integer", "description": "Show top N single-byte results (default: 5)"},
            },
            "required": ["data"],
        },
    ),
    Tool(
        name="frequency_analysis",
        description="Letter frequency analysis for classical cipher cracking (Caesar, Vigenère, etc.).",
        inputSchema={
            "type": "object",
            "properties": {
                "ciphertext": {"type": "string"},
                "top_n": {"type": "integer", "description": "How many top letters to show (default: 10)"},
            },
            "required": ["ciphertext"],
        },
    ),
    Tool(
        name="run_crypto",
        description=(
            "Run arbitrary Python crypto code. pycryptodome (Crypto.*), gmpy2, sympy are available. "
            "Print results; they are returned as output."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "code": {"type": "string"},
            },
            "required": ["code"],
        },
    ),
]

# Morse code table
MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9",
}
MORSE_ENC = {v: k for k, v in MORSE.items()}

HASH_SIGNATURES = [
    (32,  "MD5"),
    (40,  "SHA1"),
    (56,  "SHA224"),
    (64,  "SHA256 or NTLM(partial)"),
    (96,  "SHA384"),
    (128, "SHA512"),
]

HASHCAT_MODES = {
    "md5": "0", "sha1": "100", "sha256": "1400",
    "sha512": "1700", "ntlm": "1000",
}

ENGLISH_FREQ = "etaoinshrdlcumwfgypbvkjxqz"


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def _score_english(text: bytes) -> float:
    try:
        s = text.decode(errors="replace").lower()
    except Exception:
        return 0.0
    score = 0.0
    for ch in s:
        pos = ENGLISH_FREQ.find(ch)
        if pos != -1:
            score += len(ENGLISH_FREQ) - pos
    return score


async def handle_crypto(name: str, args: dict) -> str:
    if name == "decode_encode":
        data = args["data"]
        scheme = args["scheme"].lower()
        direction = args.get("direction", "decode")

        try:
            if scheme == "base64":
                if direction == "decode":
                    return base64.b64decode(data).decode(errors="replace")
                return base64.b64encode(data.encode()).decode()

            if scheme == "base64url":
                if direction == "decode":
                    return base64.urlsafe_b64decode(data + "==").decode(errors="replace")
                return base64.urlsafe_b64encode(data.encode()).decode()

            if scheme == "hex":
                raw = data.replace(" ", "").replace("0x", "")
                if direction == "decode":
                    return bytes.fromhex(raw).decode(errors="replace")
                return data.encode().hex()

            if scheme == "rot13":
                return data.translate(str.maketrans(
                    string.ascii_uppercase + string.ascii_lowercase,
                    string.ascii_uppercase[13:] + string.ascii_uppercase[:13] +
                    string.ascii_lowercase[13:] + string.ascii_lowercase[:13],
                ))

            if scheme == "url":
                if direction == "decode":
                    return urllib.parse.unquote(data)
                return urllib.parse.quote(data)

            if scheme == "binary":
                if direction == "decode":
                    groups = data.split()
                    return "".join(chr(int(g, 2)) for g in groups)
                return " ".join(f"{ord(c):08b}" for c in data)

            if scheme == "morse":
                if direction == "decode":
                    return "".join(MORSE.get(tok, "?") for tok in data.strip().split())
                return " ".join(MORSE_ENC.get(c.upper(), "?") for c in data)

            if scheme == "ascii":
                if direction == "decode":
                    nums = [int(x) for x in data.replace(",", " ").split()]
                    return "".join(chr(n) for n in nums)
                return " ".join(str(ord(c)) for c in data)

            return f"[error] unknown scheme: {scheme}"
        except Exception as e:
            return f"[error] {e}"

    if name == "hash_identify":
        h = args["hash_value"].strip()
        length = len(h)
        candidates = [sig for ln, sig in HASH_SIGNATURES if ln == length]
        colon = h.find(":")
        hints = []
        if colon != -1:
            hints.append("Contains ':' — may be salted or username:hash format")
        if h.startswith("$"):
            hints.append("Starts with '$' — likely crypt / bcrypt / scrypt format")
        result = f"Hash: {h}\nLength: {length}\n"
        result += f"Likely type: {', '.join(candidates) if candidates else 'unknown'}\n"
        if hints:
            result += "\n".join(hints)
        return result

    if name == "hash_crack":
        h = args["hash_value"].strip()
        mode_name = args.get("mode", "")
        if mode_name:
            hc_mode = HASHCAT_MODES.get(mode_name.lower(), "0")
        else:
            # auto-detect
            ln = len(h)
            hc_mode = {"32": "0", "40": "100", "64": "1400", "128": "1700"}.get(str(ln), "0")

        wordlist = "/usr/share/wordlists/rockyou.txt"
        result = await run_cmd(
            "hashcat", "-m", hc_mode, "-a", "0", "--quiet",
            "--potfile-disable", h, wordlist,
        )
        if "[error] tool not found" in result:
            # fallback to john
            result = await run_cmd("john", "--wordlist=" + wordlist, "--stdin")
        return result or "[no crack found]"

    if name == "xor_bruteforce":
        raw = decode_input(args["data"])
        key_str = args.get("key", "")

        if key_str:
            key = decode_input(key_str)
            decrypted = _xor_bytes(raw, key)
            return decrypted.decode(errors="replace")

        # single-byte brute-force
        top_n = args.get("top_n", 5)
        results = []
        for k in range(256):
            decrypted = _xor_bytes(raw, bytes([k]))
            score = _score_english(decrypted)
            results.append((score, k, decrypted))
        results.sort(reverse=True)
        lines = [f"Top {top_n} single-byte XOR keys by English frequency score:\n"]
        for score, k, dec in results[:top_n]:
            preview = dec.decode(errors="replace")[:80].replace("\n", " ")
            lines.append(f"  key=0x{k:02x} ({k:3d})  score={score:.0f}  {preview}")
        return "\n".join(lines)

    if name == "frequency_analysis":
        text = args["ciphertext"].upper()
        counts: dict[str, int] = {}
        total = 0
        for ch in text:
            if ch.isalpha():
                counts[ch] = counts.get(ch, 0) + 1
                total += 1
        if total == 0:
            return "[error] no alphabetic characters found"
        sorted_chars = sorted(counts.items(), key=lambda x: -x[1])
        top_n = args.get("top_n", 10)
        lines = [f"Frequency analysis (total letters: {total})\n",
                 f"{'Letter':<8} {'Count':<8} {'%':<8} {'Likely plaintext (if sub cipher)'}"]
        for i, (ch, cnt) in enumerate(sorted_chars[:top_n]):
            pct = cnt / total * 100
            hint = ENGLISH_FREQ[i].upper() if i < len(ENGLISH_FREQ) else "?"
            lines.append(f"  {ch:<8} {cnt:<8} {pct:<8.1f} → possibly '{hint}'")
        return "\n".join(lines)

    if name == "run_crypto":
        return await run_python(args["code"])

    return f"[error] unknown crypto tool: {name}"
