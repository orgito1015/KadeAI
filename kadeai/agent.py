"""
KadeAI Core Agent — routes natural language commands to security modules.
"""

import openai
import json
from kadeai.modules.threat_intel import ThreatIntelModule
from kadeai.modules.vuln_scanner import VulnScannerModule
from kadeai.modules.incident_response import IncidentResponseModule
from kadeai.modules.osint import OSINTModule
from kadeai.modules.report_generator import ReportGeneratorModule
from kadeai.utils.logger import setup_logger

logger = setup_logger("kadeai.agent")

SYSTEM_PROMPT = """You are KadeAI, an expert AI cybersecurity agent.

You help security professionals by:
- Scanning for vulnerabilities
- Gathering threat intelligence
- Performing OSINT and recon
- Responding to incidents
- Generating professional reports

When a user gives you a task, decide which module to call and respond with a JSON action like:
{
  "module": "vuln_scanner" | "threat_intel" | "osint" | "incident_response" | "report_generator",
  "action": "<specific action>",
  "params": { ... }
}

Or respond directly in plain text if no module is needed.
Always be precise, professional, and security-focused.
"""


class KadeAgent:
    def __init__(self, config: dict):
        self.config = config
        self.client = openai.AsyncOpenAI(api_key=config.get("OPENAI_API_KEY"))
        self.modules = {
            "threat_intel": ThreatIntelModule(config),
            "vuln_scanner": VulnScannerModule(config),
            "incident_response": IncidentResponseModule(config),
            "osint": OSINTModule(config),
            "report_generator": ReportGeneratorModule(config),
        }
        self.history = []

    async def run(self, user_input: str) -> str:
        """Process a user command and return a response."""
        self.history.append({"role": "user", "content": user_input})
        logger.info(f"User input: {user_input}")

        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "system", "content": SYSTEM_PROMPT}] + self.history,
                temperature=0.2,
            )

            reply = response.choices[0].message.content
            self.history.append({"role": "assistant", "content": reply})

            # Try to parse as a module action
            try:
                action = json.loads(reply)
                if "module" in action:
                    return await self._dispatch(action)
            except (json.JSONDecodeError, KeyError):
                pass

            return reply

        except openai.AuthenticationError:
            return "[error] Invalid OpenAI API key. Check your .env file."
        except Exception as e:
            logger.error(f"Agent error: {e}")
            return f"[error] {e}"

    async def _dispatch(self, action: dict) -> str:
        """Dispatch an action to the appropriate module."""
        module_name = action.get("module")
        module = self.modules.get(module_name)

        if not module:
            return f"[error] Unknown module: {module_name}"

        logger.info(f"Dispatching to module: {module_name}, action: {action.get('action')}")
        return await module.execute(action.get("action"), action.get("params", {}))

    def print_help(self):
        print("""
Available commands (natural language examples):

  Threat Intel:
    "What are the latest CVEs for Apache?"
    "Check if this IP is malicious: 1.2.3.4"

  Vulnerability Scanner:
    "Scan 192.168.1.1 for open ports"
    "Run a vulnerability scan on example.com"

  OSINT / Recon:
    "Recon example.com"
    "Get WHOIS info for google.com"

  Incident Response:
    "Analyze this log for suspicious activity"
    "What should I do if I detect a brute force attack?"

  Report Generator:
    "Generate a pentest report for my last scan"
    "Create an executive summary of findings"

  General:
    "help"   - show this menu
    "exit"   - quit KadeAI
        """)
