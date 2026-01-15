"""
Professional-Grade Open Redirect Plugin
Detects open redirect vulnerabilities in web applications

Supports:
- URL parameter-based redirects
- Header-based redirects (Location, Refresh)
- JavaScript-based redirects (window.location, etc.)
- Meta refresh tag redirects
- Protocol handler bypasses (javascript:, data:)
- Domain bypass techniques (@, \\, //, etc.)
- OAuth redirect_uri vulnerabilities
- Path-based redirects
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urljoin, urlencode, quote
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin
from scanner.logger import get_logger

LOG = get_logger("vuln-scanner")


class OpenRedirectPayloads:
    """Comprehensive open redirect payload library"""

    # Test domains (use your own for real testing)
    TEST_DOMAINS = [
        "https://evil.com",
        "https://attacker.com",
        "http://redirect-test.com",
        "//evil.com",
        "///evil.com",
    ]

    # Common redirect parameter names
    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri", "redirectUrl",
        "next", "next_url", "nextUrl", "continue", "return", "returnTo",
        "return_to", "return_url", "returnUrl", "callback", "callback_url",
        "callbackUrl", "goto", "go", "target", "dest", "destination",
        "link", "view", "redir", "out", "path", "page", "navigation",
        "forward", "to", "uri", "load", "file", "domain", "site"
    ]

    # Bypass techniques for WAF/filter evasion
    @staticmethod
    def generate_bypass_payloads(domain: str) -> List[str]:
        """Generate bypass payloads for open redirect filters"""
        payloads = []

        # Basic payloads
        payloads.append(domain)
        payloads.append(f"//{domain}")
        payloads.append(f"///{domain}")
        payloads.append(f"////{domain}")

        # @ symbol bypass
        payloads.append(f"@{domain}")
        payloads.append(f"javascript:@{domain}")
        payloads.append(f"https://trusted.com@{domain}")

        # Backslash bypass
        payloads.append(f"https:\\\\{domain}")
        payloads.append(f"\\\\{domain}")

        # NULL byte bypass
        payloads.append(f"{domain}%00.trusted.com")
        payloads.append(f"https://trusted.com/%2f{domain}")

        # Protocol handler bypass
        payloads.append(f"javascript:window.location='{domain}'")
        payloads.append(f"data:text/html,<script>window.location='{domain}'</script>")

        # Encoded variations
        payloads.append(quote(domain, safe=''))
        payloads.append(f"//{quote(domain[2:], safe='')}")  # Skip protocol

        # Subdomain bypass attempts
        payloads.append(f"https://trusted.com.{domain}")
        payloads.append(f"https://{domain}.trusted.com")

        # Path traversal style
        payloads.append(f"https://trusted.com/../{domain}")
        payloads.append(f"https://trusted.com/..;/{domain}")

        # CRLF injection for header injection
        payloads.append(f"%0d%0aLocation: {domain}")

        return payloads

    # OAuth-specific redirect_uri bypasses
    OAUTH_BYPASS_PAYLOADS = [
        "redirect_uri=https://evil.com",
        "redirect_uri=https://trusted.com@evil.com",
        "redirect_uri=https://trusted.com.evil.com",
        "redirect_uri=https://trusted.com%252f@evil.com",
        "redirect_uri=https://trusted.com%2f%2fevil.com",
        "redirect_uri=//evil.com/callback",
    ]


class Plugin(BasePlugin):
    name = "open_redirect"
    description = "Detects Open Redirect vulnerabilities"

    def __init__(self):
        super().__init__()
        self.payloads = OpenRedirectPayloads()
        # Use a safe test domain (replace with your own OAST server for real testing)
        self.test_domain = "https://redirect-test.example.com"

    async def _check_redirect_in_response(self, response: dict, test_domain: str) -> Dict[str, Any]:
        """Check if response contains redirect to test domain"""

        if not response or not isinstance(response, dict):
            return None

        # 1. Check HTTP headers (Location, Refresh)
        headers = response.get("headers", {})

        # Location header
        location = headers.get("location", "") or headers.get("Location", "")
        if location and test_domain in location:
            return {
                "redirect_type": "header_location",
                "redirect_target": location,
                "method": "HTTP Location header"
            }

        # Refresh header
        refresh = headers.get("refresh", "") or headers.get("Refresh", "")
        if refresh and test_domain in refresh:
            return {
                "redirect_type": "header_refresh",
                "redirect_target": refresh,
                "method": "HTTP Refresh header"
            }

        # 2. Check response body for redirects
        content = response.get("text", "")

        if not content:
            return None

        # JavaScript redirects
        js_redirect_patterns = [
            r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.location\.replace\(['\"]([^'\"]+)['\"]\)",
            r"document\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\.href\s*=\s*['\"]([^'\"]+)['\"]",
        ]

        for pattern in js_redirect_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if test_domain in match:
                    return {
                        "redirect_type": "javascript",
                        "redirect_target": match,
                        "method": "JavaScript window.location"
                    }

        # Meta refresh tag
        soup = BeautifulSoup(content, "html.parser")
        meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
        if meta_refresh:
            meta_content = meta_refresh.get("content", "")
            if test_domain in meta_content:
                return {
                    "redirect_type": "meta_refresh",
                    "redirect_target": meta_content,
                    "method": "HTML Meta Refresh tag"
                }

        # Check for 3xx status codes
        status = response.get("status", 0)
        if 300 <= status < 400:
            return {
                "redirect_type": "http_redirect",
                "redirect_target": location or "unknown",
                "method": f"HTTP {status} redirect",
                "status_code": status
            }

        return None

    async def _test_parameter_redirect(self, url: str, param: str, requester):
        """Test a parameter for open redirect vulnerability"""
        vulnerabilities = []

        # Generate bypass payloads
        payloads = self.payloads.generate_bypass_payloads(self.test_domain)

        # Test each payload
        for payload in payloads[:15]:  # Test top 15 payloads
            test_params = {param: payload}

            try:
                # Follow redirects to see where we end up
                response = await requester.get(url, params=test_params, allow_redirects=True)

                if not response:
                    continue

                # Check if response contains redirect to our test domain
                redirect_info = await self._check_redirect_in_response(response, self.test_domain)

                if redirect_info:
                    vulnerabilities.append({
                        "type": "open_redirect",
                        "param": param,
                        "payload": payload,
                        "redirect_type": redirect_info["redirect_type"],
                        "redirect_target": redirect_info["redirect_target"],
                        "method": redirect_info["method"],
                        "message": f"Open Redirect detected via {redirect_info['method']}",
                        "severity": "medium",  # Can be high in OAuth contexts
                        "confidence": "firm",
                        "impact": "Attackers can redirect users to phishing sites, bypass authentication, or steal OAuth tokens",
                        "bounty_potential": "$500 - $10,000 (higher for OAuth contexts)",
                    })
                    return vulnerabilities  # Stop on first confirmed

                # Also check final URL after redirects
                final_url = response.get("url", "")
                if final_url and self.test_domain in final_url:
                    vulnerabilities.append({
                        "type": "open_redirect",
                        "param": param,
                        "payload": payload,
                        "redirect_type": "http_redirect_chain",
                        "redirect_target": final_url,
                        "method": "HTTP redirect chain",
                        "message": "Open Redirect detected via redirect chain",
                        "severity": "medium",
                        "confidence": "firm",
                        "impact": "Redirect chain leads to external domain",
                        "bounty_potential": "$500 - $10,000",
                    })
                    return vulnerabilities

            except Exception as e:
                LOG.debug(f"Open redirect test failed: {e}")

        return vulnerabilities

    async def _test_oauth_redirect_uri(self, url: str, requester):
        """Test OAuth redirect_uri parameter specifically"""
        vulnerabilities = []

        # Check if URL looks like OAuth endpoint
        oauth_indicators = ["oauth", "authorize", "login", "auth", "sso"]
        if not any(indicator in url.lower() for indicator in oauth_indicators):
            return vulnerabilities

        # Test OAuth-specific bypasses
        for payload in self.payloads.OAUTH_BYPASS_PAYLOADS[:5]:  # Test top 5
            try:
                # Parse existing params
                parsed = urlparse(url)

                # Add redirect_uri payload
                test_url = f"{url}&{payload}" if "?" in url else f"{url}?{payload}"

                response = await requester.get(test_url, allow_redirects=True)

                if not response:
                    continue

                # Check for redirect
                redirect_info = await self._check_redirect_in_response(response, "evil.com")

                if redirect_info:
                    vulnerabilities.append({
                        "type": "oauth_open_redirect",
                        "param": "redirect_uri",
                        "payload": payload,
                        "redirect_type": redirect_info["redirect_type"],
                        "redirect_target": redirect_info["redirect_target"],
                        "message": "OAuth Open Redirect detected in redirect_uri parameter",
                        "severity": "high",  # Higher severity for OAuth
                        "confidence": "firm",
                        "impact": "OAuth token theft, account takeover via malicious redirect_uri",
                        "bounty_potential": "$2,000 - $25,000",
                    })
                    return vulnerabilities

            except Exception as e:
                LOG.debug(f"OAuth redirect test failed: {e}")

        return vulnerabilities

    async def _find_redirect_parameters(self, target: str, requester):
        """Find potential redirect parameters in target"""
        params = []

        # Check URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        for param_name in query_params.keys():
            if any(redirect_param in param_name.lower() for redirect_param in self.payloads.REDIRECT_PARAMS):
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
                        if name and any(redirect_param in name.lower() for redirect_param in self.payloads.REDIRECT_PARAMS):
                            params.append(("form", name))
        except Exception:
            pass

        return params

    async def run(self, target: str, requester, oast_server: str = None):
        """Main entry point for open redirect scanning"""

        if not target.startswith("http"):
            return []

        vulnerabilities = []

        # 1. Test OAuth redirect_uri if applicable
        oauth_result = await self._test_oauth_redirect_uri(target, requester)
        if oauth_result:
            vulnerabilities.extend(oauth_result)

        # 2. Find potential redirect parameters
        params = await self._find_redirect_parameters(target, requester)

        if not params:
            return vulnerabilities  # Return any OAuth findings, or empty list

        # 3. Test each parameter
        for param_type, param_name in params[:5]:  # Test top 5 params
            LOG.info(f"Testing open redirect parameter: {param_name}")

            result = await self._test_parameter_redirect(target, param_name, requester)
            if result:
                vulnerabilities.extend(result)
                # Continue testing other params (multiple vulns possible)

        return vulnerabilities
