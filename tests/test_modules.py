"""
KadeAI - Basic unit tests
Run with: pytest tests/
"""

import asyncio
import pytest
from kadeai.modules.incident_response import IncidentResponseModule
from kadeai.modules.report_generator import ReportGeneratorModule


@pytest.fixture
def config():
    return {
        "OPENAI_API_KEY": "",
        "VIRUSTOTAL_API_KEY": "",
        "SHODAN_API_KEY": "",
        "NVD_API_KEY": "",
        "REPORTS_DIR": "/tmp/kadeai_test_reports/",
    }


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestIncidentResponse:
    def test_detects_brute_force(self, config):
        module = IncidentResponseModule(config)
        log = "Failed login attempt for user admin from 192.168.1.10. Authentication failure."
        result = run(module.analyze_log({"log": log}))
        assert "Brute Force" in result or "brute_force" in result.lower()

    def test_detects_sql_injection(self, config):
        module = IncidentResponseModule(config)
        log = "GET /search?q=' UNION SELECT username,password FROM users--"
        result = run(module.analyze_log({"log": log}))
        assert "Sql Injection" in result or "sql_injection" in result.lower()

    def test_no_false_positives_clean_log(self, config):
        module = IncidentResponseModule(config)
        log = "User john logged in successfully from 10.0.0.1 at 09:23."
        result = run(module.analyze_log({"log": log}))
        assert "No known attack patterns" in result

    def test_triage_critical(self, config):
        module = IncidentResponseModule(config)
        result = run(module.triage({"alert": "Ransomware detected on file server"}))
        assert "CRITICAL" in result

    def test_triage_medium(self, config):
        module = IncidentResponseModule(config)
        result = run(module.triage({"alert": "Multiple failed login attempts detected"}))
        assert "MEDIUM" in result


class TestReportGenerator:
    def test_pentest_report_creates_file(self, config):
        import os
        module = ReportGeneratorModule(config)
        result = run(module.pentest_report({"target": "testhost.local", "findings": []}))
        assert "saved to" in result.lower()

    def test_executive_summary(self, config):
        module = ReportGeneratorModule(config)
        result = run(module.executive_summary({
            "target": "testhost.local",
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 1
        }))
        assert "Critical" in result
        assert "IMMEDIATE ACTION" in result
