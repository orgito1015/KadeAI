# KadeAI Architecture

## Overview

KadeAI is built as a modular AI agent. A central orchestrator (powered by GPT-4o) receives natural language input, decides which security module to invoke, dispatches the task, and returns a formatted result.

```
User Input (natural language)
        │
        ▼
┌───────────────────┐
│   KadeAI Agent    │  ← GPT-4o backbone
│  (agent.py)       │  ← Maintains conversation history
└────────┬──────────┘
         │ dispatches to
    ┌────┴─────────────────────────────────┐
    │                                      │
    ▼                ▼                     ▼
Threat Intel    Vuln Scanner          OSINT / Recon
(NVD, VT)       (Nmap wrapper)        (WHOIS, Shodan)

    ▼                                      ▼
Incident                          Report Generator
Response                          (Markdown output)
(log analysis)
```

## Module Design

Each module follows the same interface:

```python
class SomeModule:
    def __init__(self, config: dict): ...
    async def execute(self, action: str, params: dict) -> str: ...
```

The agent calls `module.execute(action, params)` after parsing the LLM's JSON response. This makes modules easy to add, remove, or swap out.

## Adding a New Module

1. Create `kadeai/modules/your_module.py`
2. Implement `__init__(self, config)` and `async execute(self, action, params)`
3. Register it in `kadeai/agent.py` under `self.modules`
4. The agent will automatically route to it when the LLM selects it

## Data Flow

```
1. User types: "Scan 10.0.0.1 for open ports"
2. Agent sends to GPT-4o with system prompt
3. GPT-4o returns JSON: {"module": "vuln_scanner", "action": "port_scan", "params": {"target": "10.0.0.1"}}
4. Agent dispatches to VulnScannerModule.execute("port_scan", {"target": "10.0.0.1"})
5. Module runs Nmap, returns raw output
6. Agent returns result to user
```
