"""
Threat Intelligence Module
Fetches CVEs from NVD, checks IPs/hashes via VirusTotal.
"""

import httpx
from kadeai.utils.logger import setup_logger

logger = setup_logger("kadeai.threat_intel")


class ThreatIntelModule:
    def __init__(self, config: dict):
        self.vt_key = config.get("VIRUSTOTAL_API_KEY", "")
        self.nvd_key = config.get("NVD_API_KEY", "")

    async def execute(self, action: str, params: dict) -> str:
        actions = {
            "cve_lookup": self.cve_lookup,
            "ip_check": self.ip_check,
            "hash_check": self.hash_check,
        }
        fn = actions.get(action)
        if not fn:
            return f"[threat_intel] Unknown action: {action}"
        return await fn(params)

    async def cve_lookup(self, params: dict) -> str:
        keyword = params.get("keyword", "")
        if not keyword:
            return "[threat_intel] No keyword provided for CVE lookup."

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"
        headers = {}
        if self.nvd_key:
            headers["apiKey"] = self.nvd_key

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return f"[threat_intel] No CVEs found for '{keyword}'."

            results = [f"Found {len(vulnerabilities)} CVE(s) for '{keyword}':\n"]
            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description.")
                metrics = cve.get("metrics", {})
                cvss = "N/A"
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                results.append(f"  [{cve_id}] CVSS: {cvss}\n  {desc[:200]}...\n")

            return "\n".join(results)

        except Exception as e:
            logger.error(f"CVE lookup failed: {e}")
            return f"[threat_intel] CVE lookup failed: {e}"

    async def ip_check(self, params: dict) -> str:
        ip = params.get("ip", "")
        if not ip:
            return "[threat_intel] No IP address provided."
        if not self.vt_key:
            return "[threat_intel] VIRUSTOTAL_API_KEY not configured."

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_key}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = sum(stats.values())

            verdict = "🔴 MALICIOUS" if malicious > 3 else "🟡 SUSPICIOUS" if malicious > 0 else "🟢 CLEAN"
            return (
                f"[VirusTotal] IP: {ip}\n"
                f"Verdict: {verdict}\n"
                f"Detections: {malicious} malicious, {suspicious} suspicious, {harmless} harmless "
                f"(out of {total} engines)"
            )

        except Exception as e:
            logger.error(f"IP check failed: {e}")
            return f"[threat_intel] IP check failed: {e}"

    async def hash_check(self, params: dict) -> str:
        file_hash = params.get("hash", "")
        if not file_hash:
            return "[threat_intel] No file hash provided."
        if not self.vt_key:
            return "[threat_intel] VIRUSTOTAL_API_KEY not configured."

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_key}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()

            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            name = attrs.get("meaningful_name", "Unknown")
            verdict = "🔴 MALICIOUS" if malicious > 3 else "🟡 SUSPICIOUS" if malicious > 0 else "🟢 CLEAN"

            return (
                f"[VirusTotal] Hash: {file_hash}\n"
                f"File name: {name}\n"
                f"Verdict: {verdict}\n"
                f"Malicious detections: {malicious}/{sum(stats.values())}"
            )

        except Exception as e:
            logger.error(f"Hash check failed: {e}")
            return f"[threat_intel] Hash check failed: {e}"
