"""A tiny OAuth misconfiguration detector plugin.

This plugin is intentionally conservative: it performs a GET on the
target and looks for the substring "oauth" in the response body as a
heuristic. Real exploit checks should be implemented carefully and
only used with permission.
"""
from .base import BasePlugin


class Plugin(BasePlugin):
    name = "oauth"

    async def run(self, target, requester, oast_server: str = None):
        try:
            resp = await requester.get(target)
            if not resp:
                return None
            text = resp.get("text") if isinstance(resp, dict) else resp
            if not text:
                return None
            if "oauth" in text.lower():
                return {"type": "oauth_indicator", "evidence": "oauth found in response body"}
            return None
        except Exception:
            return None