"""
IDOR (Insecure Direct Object Reference) Detection Plugin
Detects authorization bypass vulnerabilities in APIs and web applications

Common IDOR scenarios:
- Sequential ID enumeration (users, orders, documents)
- UUID/GUID manipulation
- File path traversal
- API endpoint enumeration
- User profile access control issues
"""

import re
import asyncio
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any
from scanner.plugins.base import BasePlugin


class Plugin(BasePlugin):
    """IDOR vulnerability detection plugin"""

    name = "idor"

    # Common parameter names that might contain object references
    IDOR_PARAM_NAMES = [
        "id", "user_id", "userid", "uid", "user",
        "doc_id", "document_id", "file_id", "fileid",
        "order_id", "orderid", "invoice_id",
        "account_id", "account", "profile_id",
        "message_id", "msg_id", "comment_id",
        "post_id", "article_id", "item_id",
        "transaction_id", "trans_id", "payment_id",
        "key", "ref", "reference", "uuid", "guid",
    ]

    # Endpoints commonly vulnerable to IDOR
    SENSITIVE_ENDPOINTS = [
        r'/api/user',
        r'/api/profile',
        r'/api/account',
        r'/api/order',
        r'/api/invoice',
        r'/api/document',
        r'/api/file',
        r'/api/message',
        r'/api/admin',
        r'/download',
        r'/view',
        r'/edit',
        r'/delete',
    ]

    def __init__(self):
        self.description = "Detects IDOR (Insecure Direct Object Reference) vulnerabilities"

    async def run(self, target: str, requester, oast_server: str = None) -> List[Dict[str, Any]]:
        """Main entry point"""
        findings = []

        # Check if this is a sensitive endpoint
        is_sensitive = any(re.search(pattern, target, re.IGNORECASE) for pattern in self.SENSITIVE_ENDPOINTS)

        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        # Test URL parameters for IDOR
        for param, values in query_params.items():
            if param.lower() in self.IDOR_PARAM_NAMES or is_sensitive:
                original_value = values[0]

                # Determine ID type and test accordingly
                id_type = self._detect_id_type(original_value)

                if id_type == "numeric":
                    result = await self._test_numeric_idor(target, param, original_value, requester)
                    if result:
                        findings.append(result)

                elif id_type == "uuid":
                    result = await self._test_uuid_idor(target, param, original_value, requester)
                    if result:
                        findings.append(result)

                elif id_type == "alphanumeric":
                    result = await self._test_alphanumeric_idor(target, param, original_value, requester)
                    if result:
                        findings.append(result)

        # Test path-based IDOR (e.g., /api/user/123)
        path_result = await self._test_path_idor(target, requester)
        if path_result:
            findings.extend(path_result)

        return findings

    def _detect_id_type(self, value: str) -> str:
        """Detect the type of ID for targeted testing"""
        # UUID/GUID pattern
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.IGNORECASE):
            return "uuid"

        # Numeric ID
        if value.isdigit():
            return "numeric"

        # Alphanumeric (base64, hash, etc.)
        if re.match(r'^[a-zA-Z0-9_-]+$', value):
            return "alphanumeric"

        return "unknown"

    async def _test_numeric_idor(self, url: str, param: str, original_value: str, requester) -> Dict[str, Any]:
        """Test numeric ID parameters for IDOR"""

        # Get baseline response with original ID
        baseline = await requester.get(url)
        if not baseline or not isinstance(baseline, dict):
            return None

        baseline_status = baseline.get("status", 0)
        baseline_content = baseline.get("text", "")
        baseline_len = len(baseline_content)

        # Only proceed if baseline is successful
        if baseline_status not in [200, 201]:
            return None

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        try:
            original_id = int(original_value)
        except ValueError:
            return None

        # Test multiple ID variations
        test_ids = [
            original_id - 1,  # Previous ID
            original_id + 1,  # Next ID
            1,  # First ID
            original_id * 10,  # Far away ID
            999999,  # High ID
        ]

        accessible_ids = []

        for test_id in test_ids:
            # Replace the parameter value
            query_params[param] = [str(test_id)]
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))

            # Test the modified URL
            response = await requester.get(test_url)
            if not response or not isinstance(response, dict):
                continue

            status = response.get("status", 0)
            content = response.get("text", "")
            content_len = len(content)

            # Vulnerability indicators:
            # 1. Returns 200 with different content (not empty)
            # 2. Content length is similar to baseline (actual data, not error page)
            if status == 200 and content_len > 100:
                # Check if content is sufficiently different (different user's data)
                if abs(content_len - baseline_len) < baseline_len * 0.5:  # Within 50% of original size
                    # Additional check: look for user-specific data patterns
                    if self._contains_user_data(content):
                        accessible_ids.append(test_id)

            # Also check for information disclosure in errors
            elif status in [403, 401]:
                # Forbidden/Unauthorized suggests the resource exists but access denied
                # This itself might be information disclosure
                pass

        if accessible_ids:
            return {
                "type": "idor_numeric",
                "param": param,
                "original_id": original_id,
                "accessible_ids": accessible_ids[:3],  # Report first 3
                "message": f"IDOR vulnerability: Can access other users' data via numeric ID enumeration",
                "location": url,
                "severity": "high",
                "confidence": "firm",
                "impact": "Attacker can enumerate and access other users' sensitive data",
                "bounty_potential": "$1,000 - $50,000+ (depending on data sensitivity)",
                "exploitation": f"Change {param}={original_id} to {param}={accessible_ids[0]}",
            }

        return None

    async def _test_uuid_idor(self, url: str, param: str, original_value: str, requester) -> Dict[str, Any]:
        """Test UUID/GUID parameters for IDOR"""

        # Get baseline
        baseline = await requester.get(url)
        if not baseline or not isinstance(baseline, dict):
            return None

        if baseline.get("status", 0) not in [200, 201]:
            return None

        # Generate test UUIDs (common patterns)
        test_uuids = [
            "00000000-0000-0000-0000-000000000000",  # Nil UUID
            "00000000-0000-0000-0000-000000000001",  # First UUID
            original_value.replace('-', '').lower(),  # Try without hyphens
            original_value.upper(),  # Try uppercase
        ]

        # Try incrementing the last segment
        try:
            parts = original_value.split('-')
            last_part = parts[-1]
            incremented = format(int(last_part, 16) + 1, '012x')
            test_uuid = '-'.join(parts[:-1] + [incremented])
            test_uuids.append(test_uuid)
        except Exception:
            pass

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for test_uuid in test_uuids:
            query_params[param] = [test_uuid]
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))

            response = await requester.get(test_url)
            if not response or not isinstance(response, dict):
                continue

            status = response.get("status", 0)
            content = response.get("text", "")

            if status == 200 and len(content) > 100:
                return {
                    "type": "idor_uuid",
                    "param": param,
                    "original_uuid": original_value,
                    "accessible_uuid": test_uuid,
                    "message": "IDOR vulnerability: UUID/GUID access control issue",
                    "location": url,
                    "severity": "high",
                    "confidence": "tentative",
                    "impact": "UUIDs are guessable or predictable, allowing unauthorized access",
                    "bounty_potential": "$1,000 - $25,000+",
                }

        return None

    async def _test_alphanumeric_idor(self, url: str, param: str, original_value: str, requester) -> Dict[str, Any]:
        """Test alphanumeric ID parameters"""

        # For base64-encoded IDs, try to decode and manipulate
        if len(original_value) > 10 and re.match(r'^[A-Za-z0-9+/=]+$', original_value):
            import base64
            try:
                decoded = base64.b64decode(original_value).decode('utf-8', errors='ignore')

                # If decoded value looks like a numeric ID, manipulate it
                if decoded.isdigit():
                    manipulated_id = str(int(decoded) + 1)
                    new_encoded = base64.b64encode(manipulated_id.encode()).decode()

                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [new_encoded]
                    new_query = urlencode(query_params, doseq=True)
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))

                    response = await requester.get(test_url)
                    if response and response.get("status") == 200:
                        return {
                            "type": "idor_encoded",
                            "param": param,
                            "message": "IDOR via base64-encoded ID manipulation",
                            "original_value": original_value,
                            "decoded_original": decoded,
                            "manipulated_value": new_encoded,
                            "location": url,
                            "severity": "high",
                            "confidence": "firm",
                            "bounty_potential": "$2,000 - $50,000+",
                        }

            except Exception:
                pass

        return None

    async def _test_path_idor(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test for IDOR in URL path (e.g., /api/user/123)"""
        findings = []

        # Extract numeric IDs from path
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.split('/')

        for i, part in enumerate(path_parts):
            if part.isdigit():
                original_id = int(part)

                # Get baseline
                baseline = await requester.get(url)
                if not baseline or baseline.get("status") not in [200, 201]:
                    continue

                baseline_len = len(baseline.get("text", ""))

                # Test adjacent IDs
                test_ids = [original_id - 1, original_id + 1]

                for test_id in test_ids:
                    # Replace the ID in path
                    new_path_parts = path_parts.copy()
                    new_path_parts[i] = str(test_id)
                    new_path = '/'.join(new_path_parts)

                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        new_path,
                        parsed_url.params,
                        parsed_url.query,
                        parsed_url.fragment
                    ))

                    response = await requester.get(test_url)
                    if not response:
                        continue

                    status = response.get("status", 0)
                    content_len = len(response.get("text", ""))

                    if status == 200 and content_len > 100:
                        if abs(content_len - baseline_len) < baseline_len * 0.5:
                            findings.append({
                                "type": "idor_path",
                                "message": "IDOR in URL path - sequential ID enumeration possible",
                                "original_url": url,
                                "vulnerable_url": test_url,
                                "original_id": original_id,
                                "accessible_id": test_id,
                                "severity": "high",
                                "confidence": "firm",
                                "impact": "Can enumerate and access other users' resources",
                                "bounty_potential": "$2,000 - $50,000+",
                            })
                            break  # Found one, no need to test more

        return findings

    def _contains_user_data(self, content: str) -> bool:
        """Check if response contains user-specific data patterns"""
        user_data_patterns = [
            r'email',
            r'user',
            r'name',
            r'profile',
            r'account',
            r'address',
            r'phone',
            r'balance',
            r'order',
            r'invoice',
        ]

        content_lower = content.lower()
        matches = sum(1 for pattern in user_data_patterns if re.search(pattern, content_lower))

        # If 3+ user data patterns found, likely contains user data
        return matches >= 3


# Plugin registration
Plugin = Plugin
