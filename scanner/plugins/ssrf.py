"""Passive SSRF surface discovery.

This plugin looks for candidate parameters and URLs in the target's
HTML/text and reports them for manual triage. It does NOT attempt to
trigger SSRF or make external requests to attacker-controlled hosts.
"""
from .base import BasePlugin
import re
from typing import Dict, Any, List


class Plugin(BasePlugin):
    name = "ssrf"

    PARAM_NAMES = ["url", "redirect", "endpoint", "callback", "target"]

    async def run(self, target: str, requester, oast_server: str = None) -> Dict[str, Any] | None:
        findings: List[Dict[str, Any]] = []
        # Get page content (passive)
        resp = await requester.get(target)
        if not resp or not isinstance(resp, dict):
            return None
        body = resp.get("text") or ""

        # find likely URL parameters in links/forms/text
        pattern = r"[?&](%s)=([^&\s'\"]+)" % "|".join(re.escape(p) for p in self.PARAM_NAMES)
        matches = re.findall(pattern, body, re.IGNORECASE)
        for name, val in matches:
            findings.append({"param": name, "value": val, "note": "Potential SSRF parameter found (passive)."})

        # Also look for form/input fields named like ssrf params
        form_pattern = r"<input[^>]+name=[\'\"]?(%s)[\'\"]?[^>]*>" % "|".join(self.PARAM_NAMES)
        form_matches = re.findall(form_pattern, body, re.IGNORECASE)
        for name in form_matches:
            findings.append({"param": name, "value": None, "note": "Form input with potential SSRF parameter name."})

        if findings:
            return {"ssrf_findings": findings}
        return None