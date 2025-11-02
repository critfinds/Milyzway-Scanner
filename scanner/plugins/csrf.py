from scanner.plugins.base import BasePlugin
from bs4 import BeautifulSoup

class CsrfPlugin(BasePlugin):
    name = "csrf"

    async def run(self, target: str, requester, oast_server: str = None):
        if not target.startswith("http"):
            return []

        try:
            response = await requester.get(target)
            response.raise_for_status()
            soup = BeautifulSoup(await response.text(), "html.parser")
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
                    "plugin": self.name,
                    "tool": "csrf",
                    "type": "form",
                    "target": target,
                    "message": f"Form without anti-CSRF token found on {target}",
                })

        # Check for SameSite attribute on cookies
        for cookie in response.cookies.values():
            if "samesite" not in cookie.keys():
                results.append({
                    "plugin": self.name,
                    "tool": "csrf",
                    "type": "cookie",
                    "target": target,
                    "message": f"Cookie without SameSite attribute found on {target}",
                })

        return results
