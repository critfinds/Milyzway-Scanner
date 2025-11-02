"""CORS misconfiguration scanner plugin (passive/safe checks).

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

    async def run(self, target: str, requester, oast_server: str = None) -> Dict[str, Any] | None:
        findings = []
        for origin in self.TEST_ORIGINS:
            headers = {"Origin": origin}
            # Use requester.get which returns a dict {status,text,headers}
            resp = await requester.get(target, headers=headers)
            if not resp or not isinstance(resp, dict):
                continue
            resp_headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            acao = resp_headers.get("access-control-allow-origin")
            acac = resp_headers.get("access-control-allow-credentials")

            if acao:
                if acao == "*":
                    if acac and acac.lower() == "true":
                        findings.append({
                            "type": "wildcard_with_credentials",
                            "origin_tested": origin,
                            "acao": acao,
                            "acac": acac,
                            "note": "Access-Control-Allow-Origin is '*' and credentials are allowed.",
                        })
                    else:
                        findings.append({
                            "type": "wildcard_no_credentials",
                            "origin_tested": origin,
                            "acao": acao,
                            "note": "Access-Control-Allow-Origin is '*' (no credentials).",
                        })
                elif acao == origin:
                    findings.append({
                        "type": "reflected_origin_allowed",
                        "origin_tested": origin,
                        "acao": acao,
                        "acac": acac,
                        "note": "Server reflects the Origin header in Access-Control-Allow-Origin.",
                    })
                else:
                    findings.append({
                        "type": "specific_origin_allowed",
                        "origin_tested": origin,
                        "acao": acao,
                        "acac": acac,
                    })

        if findings:
            return {"cors_findings": findings}
        return None
