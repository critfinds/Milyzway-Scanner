"""
XPath Injection Plugin
"""
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin

# Payloads for different XPath injection techniques
ERROR_BASED_PAYLOADS = [
    "'",
    "' or 1=1",
    "' or ''='",
]

BOOLEAN_BASED_PAYLOADS = {
    "' or 1=1 or ''=''": "' and 1=2 and ''=''",
    "' or 'a'='a'": "' and 'a'='b'",
}

# Common XPath error messages
ERROR_MESSAGES = [
    "Invalid expression",
    "XPathException",
    "xsltproc",
    "msxml",
]

class Plugin(BasePlugin):
    """
    XPath Injection plugin
    """
    def __init__(self):
        self.name = "xpath"
        self.description = "Detects XPath injection vulnerabilities"

    async def _test_error_based(self, url, method, data, requester):
        for payload in ERROR_BASED_PAYLOADS:
            try:
                if method == "post":
                    response = await requester.post(url, data={k: payload for k in data.keys()})
                else:
                    response = await requester.get(url, params={k: payload for k in data.keys()})
                
                content = await response.text()
                for error in ERROR_MESSAGES:
                    if error in content:
                        return f"Error-based XPath injection found with payload '{payload}'"
            except Exception:
                pass
        return None

    async def _test_boolean_based(self, url, method, data, requester):
        for true_payload, false_payload in BOOLEAN_BASED_PAYLOADS.items():
            try:
                # Send true request
                if method == "post":
                    true_response = await requester.post(url, data={k: true_payload for k in data.keys()})
                else:
                    true_response = await requester.get(url, params={k: true_payload for k in data.keys()})
                true_content = await true_response.text()

                # Send false request
                if method == "post":
                    false_response = await requester.post(url, data={k: false_payload for k in data.keys()})
                else:
                    false_response = await requester.get(url, params={k: false_payload for k in data.keys()})
                false_content = await false_response.text()

                if true_content != false_content:
                    return f"Boolean-based XPath injection found with payload '{true_payload}'"
            except Exception:
                pass
        return None

    async def run(self, target: str, requester, oast_server: str = None):
        vulnerabilities = []

        # 1. Test URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)
        for param, values in query_params.items():
            original_value = values[0]
            
            # Error-based
            res = await self._test_error_based(target, "get", {param: original_value}, requester)
            if res:
                vulnerabilities.append(f"{res} in URL parameter '{param}' at {target}")

            # Boolean-based
            res = await self._test_boolean_based(target, "get", {param: original_value}, requester)
            if res:
                vulnerabilities.append(f"{res} in URL parameter '{param}' at {target}")

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
            
            data = {}
            for i in inputs:
                name = i.get("name")
                if name:
                    data[name] = "test"

            # Error-based
            res = await self._test_error_based(form_url, method, data, requester)
            if res:
                vulnerabilities.append(f"{res} in form at {form_url}")

            # Boolean-based
            res = await self._test_boolean_based(form_url, method, data, requester)
            if res:
                vulnerabilities.append(f"{res} in form at {form_url}")

        return vulnerabilities if vulnerabilities else None
