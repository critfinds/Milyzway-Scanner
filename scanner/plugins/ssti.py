"""
Server-Side Template Injection (SSTI) Plugin
"""
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin

# A simple SSTI payload
PAYLOADS = {
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
        """
        Run the Server-Side Template Injection (SSTI) plugin
        """
        vulnerabilities = []

        # 1. Test URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)
        for param, values in query_params.items():
            original_value = values[0]
            for payload, result in PAYLOADS.items():
                new_query_params = query_params.copy()
                new_query_params[param] = payload
                new_url = parsed_url._replace(query=urlencode(new_query_params, doseq=True)).geturl()
                try:
                    response = await requester.get(new_url)
                    content = await response.text()
                    if result in content:
                        vulnerabilities.append(f"SSTI vulnerability found in URL parameter '{param}' with payload '{payload}' at {new_url}")
                except Exception:
                    pass

        # 2. Test forms
        try:
            response = await requester.get(target)
            soup = BeautifulSoup(await response.text(), "html.parser")
            forms = soup.find_all("form")
        except Exception:
            forms = []

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all(["input", "textarea", "select"])
            form_url = urljoin(target, action)
            
            for payload, result in PAYLOADS.items():
                data = {}
                for i in inputs:
                    name = i.get("name")
                    if name:
                        data[name] = payload

                try:
                    if method == "post":
                        response = await requester.post(form_url, data=data)
                    else:
                        response = await requester.get(form_url, params=data)
                    
                    content = await response.text()
                    if result in content:
                        vulnerabilities.append(f"SSTI vulnerability found in form at {form_url} with payload '{payload}'")
                except Exception:
                    pass

        return vulnerabilities if vulnerabilities else None
