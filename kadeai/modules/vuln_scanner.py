"""
Vulnerability Scanner Module
Wraps Nmap for port scanning. Results are explained in plain English via AI.
"""

import asyncio
import shutil
from kadeai.utils.logger import setup_logger

logger = setup_logger("kadeai.vuln_scanner")


class VulnScannerModule:
    def __init__(self, config: dict):
        self.config = config
        self.nmap_available = shutil.which("nmap") is not None

    async def execute(self, action: str, params: dict) -> str:
        actions = {
            "port_scan": self.port_scan,
            "service_scan": self.service_scan,
            "quick_scan": self.quick_scan,
        }
        fn = actions.get(action)
        if not fn:
            return f"[vuln_scanner] Unknown action: {action}"
        return await fn(params)

    async def port_scan(self, params: dict) -> str:
        target = params.get("target", "")
        if not target:
            return "[vuln_scanner] No target specified."
        if not self.nmap_available:
            return "[vuln_scanner] Nmap is not installed. Install it with: sudo apt install nmap"

        logger.info(f"Starting port scan on {target}")
        return await self._run_nmap(target, ["-sV", "--top-ports", "1000", "-T4"])

    async def service_scan(self, params: dict) -> str:
        target = params.get("target", "")
        ports = params.get("ports", "")
        if not target:
            return "[vuln_scanner] No target specified."
        if not self.nmap_available:
            return "[vuln_scanner] Nmap is not installed."

        args = ["-sV", "-sC", "-T4"]
        if ports:
            args += ["-p", ports]

        return await self._run_nmap(target, args)

    async def quick_scan(self, params: dict) -> str:
        target = params.get("target", "")
        if not target:
            return "[vuln_scanner] No target specified."
        if not self.nmap_available:
            return "[vuln_scanner] Nmap is not installed."

        return await self._run_nmap(target, ["-F", "-T4"])

    async def _run_nmap(self, target: str, args: list) -> str:
        cmd = ["nmap"] + args + [target]
        logger.info(f"Running: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            if proc.returncode != 0:
                return f"[vuln_scanner] Nmap error:\n{stderr.decode()}"

            output = stdout.decode()
            return f"[vuln_scanner] Scan results for {target}:\n\n{output}"

        except asyncio.TimeoutError:
            return f"[vuln_scanner] Scan timed out for {target}."
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return f"[vuln_scanner] Scan failed: {e}"
