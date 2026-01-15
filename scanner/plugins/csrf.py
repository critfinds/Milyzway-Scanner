from scanner.plugins.base import BasePlugin
from bs4 import BeautifulSoup

class Plugin(BasePlugin):
    name = "csrf"

    async def run(self, target: str, requester, oast_server: str = None):
        if not target.startswith("http"):
            return []

        try:
            response = await requester.get(target)
            if not response or not isinstance(response, dict):
                return []
            soup = BeautifulSoup(response.get("text") or "", "html.parser")
            cookies = response.get("headers", {}).get("Set-Cookie", "")
        except Exception:
            return []

        results = []

        # Check for anti-CSRF tokens in forms
        for form in soup.find_all("form"):
            has_csrf_token = False
            for input_tag in form.find_all("input"):
                if input_tag.get("type") == "hidden" and "csrf" in input_tag.get("name", "").lower():
                    has_csrf_token = True
                    break
            if not has_csrf_token:
                results.append({
                    "type": "missing_csrf_token",
                    "message": f"Form without anti-CSRF token found on {target}",
                    "severity": "medium",
                    "confidence": "firm",
                })

        # Check for SameSite attribute on cookies
        # This is a simplified check; a real implementation would parse cookies properly
        if cookies and "samesite" not in cookies.lower():
            results.append({
                "type": "missing_samesite_cookie",
                "message": f"Cookie without SameSite attribute found on {target}",
                "severity": "low",
                "confidence": "firm",
            })

        return results
