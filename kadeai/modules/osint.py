"""
OSINT / Recon Module
Performs open-source intelligence gathering: WHOIS, DNS, Shodan.
"""

import httpx
import socket
from kadeai.utils.logger import setup_logger

logger = setup_logger("kadeai.osint")


class OSINTModule:
    def __init__(self, config: dict):
        self.shodan_key = config.get("SHODAN_API_KEY", "")

    async def execute(self, action: str, params: dict) -> str:
        actions = {
            "whois": self.whois_lookup,
            "dns_lookup": self.dns_lookup,
            "shodan_search": self.shodan_search,
            "full_recon": self.full_recon,
        }
        fn = actions.get(action)
        if not fn:
            return f"[osint] Unknown action: {action}"
        return await fn(params)

    async def whois_lookup(self, params: dict) -> str:
        domain = params.get("domain", "")
        if not domain:
            return "[osint] No domain provided."

        try:
            url = f"https://rdap.org/domain/{domain}"
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url)
                r.raise_for_status()
                data = r.json()

            registrar = next(
                (e.get("publicIds", [{}])[0].get("identifier", "N/A")
                 for e in data.get("entities", []) if "registrar" in e.get("roles", [])),
                "N/A"
            )
            status = ", ".join(data.get("status", ["N/A"]))
            events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}

            return (
                f"[OSINT] WHOIS for {domain}:\n"
                f"  Registrar:   {registrar}\n"
                f"  Status:      {status}\n"
                f"  Registered:  {events.get('registration', 'N/A')}\n"
                f"  Updated:     {events.get('last changed', 'N/A')}\n"
                f"  Expires:     {events.get('expiration', 'N/A')}"
            )
        except Exception as e:
            logger.error(f"WHOIS failed: {e}")
            return f"[osint] WHOIS lookup failed: {e}"

    async def dns_lookup(self, params: dict) -> str:
        domain = params.get("domain", "")
        if not domain:
            return "[osint] No domain provided."

        try:
            ip = socket.gethostbyname(domain)
            return f"[OSINT] DNS for {domain}:\n  A record: {ip}"
        except Exception as e:
            return f"[osint] DNS lookup failed: {e}"

    async def shodan_search(self, params: dict) -> str:
        query = params.get("query", "")
        if not query:
            return "[osint] No Shodan query provided."
        if not self.shodan_key:
            return "[osint] SHODAN_API_KEY not configured."

        try:
            url = "https://api.shodan.io/shodan/host/search"
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, params={"key": self.shodan_key, "query": query})
                r.raise_for_status()
                data = r.json()

            total = data.get("total", 0)
            matches = data.get("matches", [])[:5]

            result = [f"[OSINT] Shodan: {total} results for '{query}'\n"]
            for m in matches:
                result.append(
                    f"  {m.get('ip_str', '?')}:{m.get('port', '?')} "
                    f"({m.get('org', 'Unknown org')}) — {m.get('data', '')[:80]}"
                )
            return "\n".join(result)

        except Exception as e:
            logger.error(f"Shodan search failed: {e}")
            return f"[osint] Shodan search failed: {e}"

    async def full_recon(self, params: dict) -> str:
        domain = params.get("domain", "")
        if not domain:
            return "[osint] No domain provided for full recon."

        results = []
        results.append(await self.whois_lookup({"domain": domain}))
        results.append(await self.dns_lookup({"domain": domain}))

        if self.shodan_key:
            results.append(await self.shodan_search({"query": f"hostname:{domain}"}))

        return "\n\n".join(results)
