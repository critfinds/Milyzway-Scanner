import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin
from scanner.logger import get_logger

LOG = get_logger("vuln-scanner")

# Common RCE payloads for different OS and techniques
RCE_PAYLOADS = {
    "linux_command_injection": [
        "cat /etc/passwd",
        "sleep 5",
        "id",
        "whoami",
    ],
    "windows_command_injection": [
        "type C:\\Windows\\win.ini",
        "ping -n 1 127.0.0.1", # Simple ping to check for execution
        "whoami",
    ],
    # Add more sophisticated payloads later if needed, e.g., template injection, deserialization
}

class Plugin(BasePlugin):
    name = "rce"
    description = "Detects Remote Code Execution vulnerabilities"

    async def _test_rce_payload(self, url, method, data, payload, requester, oast_server=None):
        test_data = {}
        for k, v in data.items():
            # Inject payload into each parameter
            test_data[k] = f"{v}{payload}"

        try:
            start_time = asyncio.get_event_loop().time()
            if method == "post":
                response = await requester.post(url, data=test_data)
            else:
                response = await requester.get(url, params=test_data)
            
            if response is None:
                return None

            response_text = response.get("text", "") # Ensure response is fully received
            end_time = asyncio.get_event_loop().time()

            # Check for time-based RCE (if payload was sleep)
            if "sleep 5" in payload and (end_time - start_time) > 4: # Check for a delay of more than 4 seconds
                return f"Time-based RCE detected with payload: '{payload}'"

            # Check for OAST interaction (if payload was OAST-based)
            if oast_server and oast_server.split('//')[-1].split('/')[0] in payload:
                # Note: The current AioRequester does not automatically check the OAST server.
                # User needs to manually check their OAST server for interactions.
                return f"OAST-based RCE payload sent. Check your OAST server for interactions from payload: '{payload}'"

            # Add more sophisticated checks here, e.g., error messages, specific output patterns
            # For now, we'll rely on OAST or time-based for confirmation.

        except Exception as e:
            LOG.debug(f"RCE plugin request failed for {url} with payload '{payload}': {e}")
        return None

    async def run(self, target: str, requester, oast_server: str = None):
        if not target.startswith("http"):
            return []

        vulnerabilities = []

        # 1. Test URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)
        
        # Prepare data for testing (using original values as base)
        param_data = {k: v[0] for k, v in query_params.items()} if query_params else {"dummy_param": "test"}

        for os_type, payloads in RCE_PAYLOADS.items():
            for payload in payloads:
                # Add OAST payload if server is available
                current_payload = payload
                if oast_server:
                    oast_domain = oast_server.split('//')[-1].split('/')[0]
                    if os_type == "linux_command_injection":
                        current_payload = f"{payload}; ping -c 1 {oast_domain}"
                    elif os_type == "windows_command_injection":
                        current_payload = f"{payload} & ping -n 1 {oast_domain}"

                res = await self._test_rce_payload(target, "get", param_data, current_payload, requester, oast_server)
                if res:
                    vulnerabilities.append(f"{res} in URL parameters ({os_type}) at {target}")

        # 2. Test forms
        try:
            response = await requester.get(target)
            if response is None:
                forms = []
            else:
                soup = BeautifulSoup(response.get("text", ""), "html.parser")
                forms = soup.find_all("form")
        except Exception:
            forms = []

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all(["input", "textarea", "select"])
            form_url = urljoin(target, action)
            
            form_data = {}
            for i in inputs:
                name = i.get("name")
                if name:
                    form_data[name] = "test" # Use a dummy value as base

            if not form_data: # If no input fields, skip this form
                continue

            for os_type, payloads in RCE_PAYLOADS.items():
                for payload in payloads:
                    current_payload = payload
                    if oast_server:
                        oast_domain = oast_server.split('//')[-1].split('/')[0]
                        if os_type == "linux_command_injection":
                            current_payload = f"{payload}; ping -c 1 {oast_domain}"
                        elif os_type == "windows_command_injection":
                            current_payload = f"{payload} & ping -n 1 {oast_domain}"

                    res = await self._test_rce_payload(form_url, method, form_data, current_payload, requester, oast_server)
                    if res:
                        vulnerabilities.append(f"{res} in form ({os_type}) at {form_url}")

        return vulnerabilities if vulnerabilities else None
