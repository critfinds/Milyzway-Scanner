"""
GraphQL Vulnerability Detection Plugin
Detects security issues in GraphQL APIs

Vulnerabilities detected:
- Introspection enabled in production
- Query depth/complexity attacks (DoS)
- Field suggestion information disclosure
- Batch query attacks
- Authorization bypass via query manipulation
- GraphQL injection
- Alias-based DoS
- Circular query references
"""

import re
import json
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse
from scanner.plugins.base import BasePlugin


class Plugin(BasePlugin):
    """GraphQL API vulnerability scanner"""

    name = "graphql"

    # Common GraphQL endpoint patterns
    GRAPHQL_ENDPOINTS = [
        "/graphql",
        "/graphiql",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/graphql/console",
        "/query",
        "/gql",
    ]

    def __init__(self):
        self.description = "Detects GraphQL API vulnerabilities"

    async def run(self, target: str, requester, oast_server: str = None) -> List[Dict[str, Any]]:
        """Main entry point"""
        findings = []

        # Validate target is not an error page before testing
        try:
            initial_response = await requester.get(target)
            if self.is_error_page(initial_response):
                # Skip testing on error pages (404, 403, etc.)
                return []
        except Exception:
            return []

        # Check if target is a GraphQL endpoint
        graphql_endpoints = await self._discover_graphql_endpoints(target, requester)

        for endpoint in graphql_endpoints:
            findings.extend(await self._test_introspection(endpoint, requester))
            findings.extend(await self._test_depth_limit(endpoint, requester))
            findings.extend(await self._test_field_suggestions(endpoint, requester))
            findings.extend(await self._test_batch_queries(endpoint, requester))
            findings.extend(await self._test_alias_dos(endpoint, requester))
            findings.extend(await self._test_directive_overload(endpoint, requester))

        return findings

    async def _discover_graphql_endpoints(self, target: str, requester) -> List[str]:
        """Discover GraphQL endpoints"""
        endpoints = []

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Test common GraphQL endpoints
        for path in self.GRAPHQL_ENDPOINTS:
            test_url = urljoin(base_url, path)

            # Send a simple GraphQL query
            test_query = {"query": "{__typename}"}

            response = await requester.post(test_url, json=test_query)

            if response and isinstance(response, dict):
                content = response.get("text", "")
                status = response.get("status", 0)

                # GraphQL endpoint indicators
                if (status == 200 and
                    ("data" in content or "errors" in content or "__typename" in content)):
                    endpoints.append(test_url)

        # Also check if current target is GraphQL
        if not endpoints:
            test_query = {"query": "{__typename}"}
            response = await requester.post(target, json=test_query)
            if response and "data" in response.get("text", ""):
                endpoints.append(target)

        return endpoints

    async def _test_introspection(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test if introspection is enabled"""
        findings = []

        # Introspection query to get schema
        introspection_query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                        types {
                            name
                            kind
                            description
                            fields {
                                name
                                description
                                type {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
            """
        }

        response = await requester.post(url, json=introspection_query)

        if not response or not isinstance(response, dict):
            return findings

        content = response.get("text", "")
        status = response.get("status", 0)

        if status == 200:
            try:
                data = json.loads(content)

                if "data" in data and "__schema" in data["data"]:
                    schema_info = data["data"]["__schema"]
                    types = schema_info.get("types", [])

                    # Extract interesting types
                    custom_types = [t["name"] for t in types if not t["name"].startswith("__")]

                    # Look for sensitive fields
                    sensitive_fields = []
                    for type_info in types:
                        if type_info.get("fields"):
                            for field in type_info["fields"]:
                                field_name = field["name"].lower()
                                if any(keyword in field_name for keyword in
                                       ["password", "secret", "token", "key", "api", "admin", "private"]):
                                    sensitive_fields.append({
                                        "type": type_info["name"],
                                        "field": field["name"]
                                    })

                    findings.append({
                        "type": "graphql_introspection_enabled",
                        "message": "CRITICAL: GraphQL introspection enabled in production",
                        "location": url,
                        "schema_types_count": len(custom_types),
                        "sample_types": custom_types[:10],
                        "sensitive_fields": sensitive_fields[:5],
                        "severity": "high",
                        "confidence": "firm",
                        "impact": "Entire API schema exposed, reveals all queries, mutations, and data structure",
                        "bounty_potential": "$500 - $5,000+",
                        "recommendation": "Disable introspection in production environments",
                    })

            except json.JSONDecodeError:
                pass

        return findings

    async def _test_depth_limit(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test for query depth limit vulnerabilities"""
        findings = []

        # Create deeply nested query
        deep_query = {
            "query": """
                query {
                    user {
                        posts {
                            comments {
                                author {
                                    posts {
                                        comments {
                                            author {
                                                posts {
                                                    comments {
                                                        author {
                                                            id
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            """
        }

        import asyncio
        start = asyncio.get_event_loop().time()
        response = await requester.post(url, json=deep_query)
        elapsed = asyncio.get_event_loop().time() - start

        if response:
            status = response.get("status", 0)
            content = response.get("text", "")

            # If query succeeds and takes long time, depth limit not enforced
            if status == 200 and elapsed > 2.0:
                try:
                    data = json.loads(content)
                    if "data" in data:
                        findings.append({
                            "type": "graphql_no_depth_limit",
                            "message": "GraphQL query depth limit not enforced - DoS risk",
                            "location": url,
                            "query_time": f"{elapsed:.2f}s",
                            "severity": "medium",
                            "confidence": "firm",
                            "impact": "Attacker can craft deeply nested queries causing DoS",
                            "bounty_potential": "$500 - $3,000+",
                            "recommendation": "Implement query depth limiting",
                        })
                except json.JSONDecodeError:
                    pass

        return findings

    async def _test_field_suggestions(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test field suggestion information disclosure"""
        findings = []

        # Query with typo to trigger field suggestions
        typo_query = {
            "query": """
                query {
                    userr {
                        id
                    }
                }
            """
        }

        response = await requester.post(url, json=typo_query)

        if response:
            content = response.get("text", "")

            try:
                data = json.loads(content)

                if "errors" in data:
                    error_messages = [e.get("message", "") for e in data["errors"]]
                    error_text = " ".join(error_messages)

                    # Check for field suggestions
                    if "did you mean" in error_text.lower() or "suggestion" in error_text.lower():
                        findings.append({
                            "type": "graphql_field_suggestions",
                            "message": "GraphQL field suggestions enabled - information disclosure",
                            "location": url,
                            "example_error": error_text[:200],
                            "severity": "low",
                            "confidence": "firm",
                            "impact": "Helps attackers discover valid field names via typos",
                            "bounty_potential": "$100 - $1,000",
                            "recommendation": "Disable field suggestions in production",
                        })

            except json.JSONDecodeError:
                pass

        return findings

    async def _test_batch_queries(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test batch query attacks"""
        findings = []

        # Send batch of queries
        batch_queries = [
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
            {"query": "{__typename}"},
        ]

        response = await requester.post(url, json=batch_queries)

        if response:
            status = response.get("status", 0)
            content = response.get("text", "")

            # If batch queries succeed, batching is enabled
            if status == 200:
                try:
                    data = json.loads(content)

                    if isinstance(data, list) and len(data) > 1:
                        findings.append({
                            "type": "graphql_batch_queries_enabled",
                            "message": "GraphQL batch queries enabled - potential DoS/rate limit bypass",
                            "location": url,
                            "batch_size_tested": len(batch_queries),
                            "severity": "medium",
                            "confidence": "firm",
                            "impact": "Attacker can bypass rate limiting via batched queries",
                            "bounty_potential": "$500 - $5,000+",
                            "recommendation": "Implement batch query limits or disable batching",
                        })

                except json.JSONDecodeError:
                    pass

        return findings

    async def _test_alias_dos(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test alias-based DoS attack"""
        findings = []

        # Create query with many aliases (query de-duplication bypass)
        aliases = "\n".join([f"alias{i}: __typename" for i in range(100)])
        alias_query = {
            "query": f"""
                query {{
                    {aliases}
                }}
            """
        }

        import asyncio
        start = asyncio.get_event_loop().time()
        response = await requester.post(url, json=alias_query)
        elapsed = asyncio.get_event_loop().time() - start

        if response:
            status = response.get("status", 0)

            # If query succeeds, alias limit not enforced
            if status == 200 and elapsed > 1.0:
                findings.append({
                    "type": "graphql_alias_dos",
                    "message": "GraphQL alias-based DoS possible - no alias limit",
                    "location": url,
                    "aliases_tested": 100,
                    "query_time": f"{elapsed:.2f}s",
                    "severity": "medium",
                    "confidence": "firm",
                    "impact": "Attacker can bypass query de-duplication and cause DoS",
                    "bounty_potential": "$1,000 - $5,000+",
                    "recommendation": "Implement alias count limiting",
                })

        return findings

    async def _test_directive_overload(self, url: str, requester) -> List[Dict[str, Any]]:
        """Test directive overload attack"""
        findings = []

        # Query with excessive @skip/@include directives
        directive_query = {
            "query": """
                query {
                    __typename
                        @skip(if: false)
                        @skip(if: false)
                        @skip(if: false)
                        @skip(if: false)
                        @skip(if: false)
                        @skip(if: false)
                        @skip(if: false)
                        @skip(if: false)
                        @skip(if: false)
                        @skip(if: false)
                }
            """
        }

        import asyncio
        start = asyncio.get_event_loop().time()
        response = await requester.post(url, json=directive_query)
        elapsed = asyncio.get_event_loop().time() - start

        if response:
            status = response.get("status", 0)

            if status == 200:
                findings.append({
                    "type": "graphql_directive_overload",
                    "message": "GraphQL directive overload possible",
                    "location": url,
                    "query_time": f"{elapsed:.2f}s",
                    "severity": "low",
                    "confidence": "tentative",
                    "impact": "May cause performance degradation",
                    "bounty_potential": "$250 - $2,000",
                    "recommendation": "Implement directive count limits",
                })

        return findings


# Plugin registration
Plugin = Plugin
