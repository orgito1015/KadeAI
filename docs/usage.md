# KadeAI Usage Guide

## Starting KadeAI

```bash
python main.py
```

You'll see the KadeAI banner and a `kade>` prompt.

---

## Example Commands

### Threat Intelligence

```
kade> What are the latest CVEs for nginx?
kade> Check if IP 1.2.3.4 is malicious
kade> Is this hash dangerous: d41d8cd98f00b204e9800998ecf8427e
```

### Vulnerability Scanning

```
kade> Scan 192.168.1.1 for open ports
kade> Run a full service scan on 10.0.0.5
kade> Quick scan my.target.com
```

> **Note:** Nmap must be installed. You must have permission to scan the target.

### OSINT / Recon

```
kade> Recon example.com
kade> Get WHOIS info for google.com
kade> Search Shodan for Apache servers in Albania
```

### Incident Response

```
kade> Analyze this log: "Failed login for admin from 1.2.3.4 x50"
kade> Triage this alert: ransomware detected on fileserver
kade> How do I respond to a SQL injection attack?
```

### Report Generation

```
kade> Generate a pentest report for 192.168.1.1
kade> Create an executive summary: 2 critical, 3 high, 1 medium
```

---

## Tips

- You can chain tasks: "Scan 10.0.0.1 and then generate a report"
- KadeAI remembers context within a session
- All reports are saved to the `reports/` directory as Markdown files

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `Invalid API key` | Check `OPENAI_API_KEY` in `.env` |
| `Nmap not found` | `sudo apt install nmap` |
| `Shodan returns nothing` | Add `SHODAN_API_KEY` to `.env` |
| Module not responding | Check `LOG_LEVEL=DEBUG` for details |
