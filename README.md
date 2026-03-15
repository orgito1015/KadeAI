#  KadeAI — AI Powered Cybersecurity Agent

> An intelligent cybersecurity agent that uses AI to automate threat intelligence, vulnerability scanning, OSINT recon, incident response, and professional report generation — all through a natural language interface.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

---

##  Features

| Module | Description |
|---|---|
|  **Threat Intel** | Fetch CVEs, scan VirusTotal, monitor threat feeds |
|  **Vuln Scanner** | AI-driven Nmap/Nuclei wrapper with plain-English results |
|  **Incident Response** | Auto-triage alerts, suggest and execute remediation |
|  **OSINT / Recon** | Footprint targets via WHOIS, Shodan, certificate transparency |
|  **Report Generator** | Auto-generate pentest reports with severity ratings |
|  **Chat Interface** | Natural language commands — no CLI flags needed |

---

##  Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/KadeAI.git
cd KadeAI
```

### 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
# Edit .env and add your API keys
```

### 5. Run KadeAI

```bash
python main.py
```

---

##  Project Structure

```
KadeAI/
├── main.py                  # Entry point
├── requirements.txt         # Python dependencies
├── .env.example             # Environment variable template
├── kadeai/
│   ├── agent.py             # Core AI agent orchestrator
│   ├── config.py            # Config loader
│   ├── modules/
│   │   ├── threat_intel.py      # Threat intelligence module
│   │   ├── vuln_scanner.py      # Vulnerability scanner
│   │   ├── incident_response.py # Incident response module
│   │   ├── osint.py             # OSINT & recon module
│   │   └── report_generator.py  # Report generation module
│   └── utils/
│       ├── logger.py        # Logging utilities
│       └── formatter.py     # Output formatting
├── tests/
│   └── test_modules.py      # Unit tests
├── docs/
│   ├── architecture.md      # Architecture overview
│   └── usage.md             # Usage guide
└── scripts/
    └── setup.sh             # Setup helper script
```

---

##  How It Works

KadeAI uses a central AI agent (powered by an LLM) that routes your natural language commands to the appropriate security module. Each module is a self-contained tool that the agent can call.

```
User: "Scan 192.168.1.1 for open ports and explain what you find"
  └─> KadeAI Agent
        └─> Vuln Scanner Module (runs Nmap)
              └─> AI formats results in plain English
                    └─> Logs + optional report generation
```

---

##  Required API Keys

Set these in your `.env` file:

| Key | Service | Free Tier? |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI (LLM backbone) | ✅ Trial |
| `VIRUSTOTAL_API_KEY` | Virus/malware scanning | ✅ Free |
| `SHODAN_API_KEY` | Internet-facing device intel | ✅ Free |
| `NVD_API_KEY` | NIST CVE database | ✅ Free |

---

##  Legal Disclaimer

> KadeAI is intended for **authorized security testing, research, and educational purposes only**.  
> Do not use this tool against systems you do not own or have explicit permission to test.  
> The authors take no responsibility for misuse.

---

##  Contributing

Pull requests are welcome! Please read [`docs/contributing.md`](docs/contributing.md) before submitting.

---

##  License

MIT License — see [LICENSE](LICENSE) for details.
