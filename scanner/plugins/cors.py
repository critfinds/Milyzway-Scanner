"""
CORS misconfiguration scanner plugin (passive/safe checks).

This plugin performs non-intrusive GET requests with crafted Origin
headers and inspects the response headers for Access-Control-* values.
It does not send credentials or perform authenticated requests.
"""
from .base import BasePlugin
from typing import List, Dict, Any


class Plugin(BasePlugin):
    name = "cors"

    TEST_ORIGINS: List[str] = [
        "https://evil.example",
        "http://localhost:3000",
    ]

    async def run(self, target: str, requester, oast_server: str = None) -> List[Dict[str, Any]] | None:
        findings = []
        for origin in self.TEST_ORIGINS:
            headers = {"Origin": origin}
            resp = await requester.get(target, headers=headers)
            if not resp or not isinstance(resp, dict):
                continue

            resp_headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            acao = resp_headers.get("access-control-allow-origin")
            acac = resp_headers.get("access-control-allow-credentials")

            # Report ACAO=* without credentials
            if acao == "*" and (not acac or acac.lower() != "true"):
                findings.append({
                    "type": "wildcard_no_credentials",
                    "origin_tested": origin,
                    "acao": acao,
                    "acac": acac,
                    "note": "Wildcard ACAO without credentials.",
                    "severity": "low",
                    "confidence": "firm",
                })
                continue

            # Report reflected origins or ACAO with credentials
            if acao:
                findings.append({
                    "type": "potentially_exploitable",
                    "origin_tested": origin,
                    "acao": acao,
                    "acac": acac,
                    "note": "Reflected ACAO or ACAO with credentials — review for possible CORS abuse.",
                    "severity": "medium",
                    "confidence": "tentative",
                })

        return findings
