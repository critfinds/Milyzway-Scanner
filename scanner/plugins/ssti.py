"""
Server-Side Template Injection (SSTI) Plugin
"""
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin

# Payloads for SSTI detection
SSTI_PAYLOADS = {
    "{{7*7}}": "49",
    "${7*7}": "49",
    "<%= 7*7 %>": "49",
    "#{7*7}": "49",
}

class Plugin(BasePlugin):
    """
    Server-Side Template Injection (SSTI) plugin
    """
    def __init__(self):
        self.name = "ssti"
        self.description = "Detects Server-Side Template Injection (SSTI) vulnerabilities"

    async def run(self, target: str, requester, oast_server: str = None):
        vulnerabilities = []

        # Test URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        for param, values in query_params.items():
            for payload, expected_result in SSTI_PAYLOADS.items():
                new_query_params = query_params.copy()
                new_query_params[param] = payload
                new_url = parsed_url._replace(query=urlencode(new_query_params, doseq=True)).geturl()
                
                try:
                    response = await requester.get(new_url)
                    if not response or not isinstance(response, dict): continue
                    content = response.get("text") or ""
                    if expected_result in content:
                        vulnerabilities.append({
                            "type": "reflected_ssti",
                            "param": param,
                            "payload": payload,
                            "message": f"SSTI confirmed in URL parameter '{param}'.",
                            "severity": "high",
                            "confidence": "firm",
                        })
                except Exception:
                    pass

        # Test forms
        try:
            response = await requester.get(target)
            if not response or not isinstance(response, dict):
                raise ValueError("No response")
            soup = BeautifulSoup(response.get("text") or "", "html.parser")
            forms = soup.find_all("form")
        except Exception:
            forms = []

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all(["input", "textarea", "select"])
            form_url = urljoin(target, action)

            for payload, expected_result in SSTI_PAYLOADS.items():
                data = {i.get("name"): payload for i in inputs if i.get("name")}
                if not data: continue
                
                try:
                    if method == "post":
                        response = await requester.post(form_url, data=data)
                    else:
                        response = await requester.get(form_url, params=data)
                    
                    if not response or not isinstance(response, dict): continue
                    content = response.get("text") or ""
                    if expected_result in content:
                        vulnerabilities.append({
                            "type": "form_based_ssti",
                            "url": form_url,
                            "payload": payload,
                            "message": f"SSTI confirmed in form on page {target}.",
                            "severity": "high",
                            "confidence": "firm",
                        })
                except Exception:
                    pass
        return vulnerabilities