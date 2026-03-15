"""
Incident Response Module
Analyzes logs, triages alerts, and suggests remediation steps.
"""

import re
from kadeai.utils.logger import setup_logger

logger = setup_logger("kadeai.incident_response")

# Common attack pattern signatures
PATTERNS = {
    "brute_force": re.compile(r"(failed (login|password|auth)|invalid (user|password)|authentication failure)", re.IGNORECASE),
    "sql_injection": re.compile(r"(union select|drop table|1=1|' or '|xp_cmdshell|information_schema)", re.IGNORECASE),
    "xss": re.compile(r"(<script|javascript:|onerror=|onload=|alert\()", re.IGNORECASE),
    "directory_traversal": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e)", re.IGNORECASE),
    "command_injection": re.compile(r"(;.*(ls|cat|whoami|id|uname|wget|curl|bash|sh)|`[^`]*`|\$\([^)]*\))", re.IGNORECASE),
    "port_scan": re.compile(r"(nmap|masscan|port scan|syn flood|connection refused.*\d{2,} times)", re.IGNORECASE),
}

REMEDIATION = {
    "brute_force": [
        "Block the source IP immediately",
        "Enable account lockout policies (e.g., 5 failed attempts)",
        "Enforce MFA on all accounts",
        "Review authentication logs for successful logins from the same source",
    ],
    "sql_injection": [
        "Sanitize and parameterize all database queries",
        "Review and patch the affected endpoint",
        "Check for data exfiltration in database logs",
        "Enable a WAF rule for SQL injection patterns",
    ],
    "xss": [
        "Encode all user-supplied output (HTML entities)",
        "Implement a strict Content Security Policy (CSP) header",
        "Sanitize input with an allowlist",
        "Review session tokens — a successful XSS may have stolen cookies",
    ],
    "directory_traversal": [
        "Validate file paths — reject input containing '../'",
        "Chroot or jail the web server process",
        "Audit files accessible via the web root",
        "Check for unauthorized file reads in access logs",
    ],
    "command_injection": [
        "Never pass unsanitized user input to shell commands",
        "Use allowlists for acceptable input characters",
        "Check for new files, cron jobs, or accounts created by the attacker",
        "Isolate the affected system immediately",
    ],
    "port_scan": [
        "Block the scanning source IP at the firewall",
        "Enable port scan detection (e.g., psad or fail2ban)",
        "Review what services are exposed — close unnecessary ports",
        "Check if the scan preceded further exploitation",
    ],
}


class IncidentResponseModule:
    def __init__(self, config: dict):
        self.config = config

    async def execute(self, action: str, params: dict) -> str:
        actions = {
            "analyze_log": self.analyze_log,
            "triage": self.triage,
            "remediate": self.remediate,
        }
        fn = actions.get(action)
        if not fn:
            return f"[incident_response] Unknown action: {action}"
        return await fn(params)

    async def analyze_log(self, params: dict) -> str:
        log_text = params.get("log", "")
        if not log_text:
            return "[incident_response] No log text provided."

        findings = []
        for attack_type, pattern in PATTERNS.items():
            matches = pattern.findall(log_text)
            if matches:
                findings.append((attack_type, len(matches), matches[:3]))

        if not findings:
            return "[incident_response] No known attack patterns detected in the provided log."

        result = [f"[Incident Response] Log Analysis — {len(findings)} threat type(s) detected:\n"]
        for attack_type, count, samples in findings:
            result.append(f"  🔴 {attack_type.replace('_', ' ').title()} ({count} match(es))")
            result.append(f"     Sample: {samples[0]}\n")

        result.append("\nRecommended next steps:")
        for attack_type, _, _ in findings:
            result.append(f"\n[{attack_type.replace('_', ' ').title()}]")
            for step in REMEDIATION.get(attack_type, []):
                result.append(f"  • {step}")

        return "\n".join(result)

    async def triage(self, params: dict) -> str:
        alert = params.get("alert", "")
        if not alert:
            return "[incident_response] No alert provided for triage."

        severity = "MEDIUM"
        if any(kw in alert.lower() for kw in ["ransomware", "data breach", "exfil", "root", "admin", "shell"]):
            severity = "CRITICAL"
        elif any(kw in alert.lower() for kw in ["injection", "traversal", "rce", "backdoor"]):
            severity = "HIGH"
        elif any(kw in alert.lower() for kw in ["scan", "brute", "failed login"]):
            severity = "MEDIUM"

        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

        return (
            f"[Incident Response] Triage Result:\n"
            f"  Severity: {icon} {severity}\n"
            f"  Alert:    {alert}\n\n"
            f"  Immediate action: {'Isolate affected systems NOW' if severity == 'CRITICAL' else 'Investigate and contain within 1 hour'}"
        )

    async def remediate(self, params: dict) -> str:
        attack_type = params.get("attack_type", "").lower().replace(" ", "_")
        steps = REMEDIATION.get(attack_type)

        if not steps:
            return f"[incident_response] No remediation steps found for: {attack_type}"

        result = [f"[Incident Response] Remediation for {attack_type.replace('_', ' ').title()}:\n"]
        for i, step in enumerate(steps, 1):
            result.append(f"  {i}. {step}")
        return "\n".join(result)
