"""
Scope Management and Safety Controls
Ensures scanner only targets authorized assets
"""

import re
from urllib.parse import urlparse
from typing import List, Set
from pathlib import Path


class ScopeManager:
    """Manages scanning scope and enforces safety controls"""

    def __init__(self, config_path: str = None):
        self.in_scope_domains: Set[str] = set()
        self.in_scope_ips: Set[str] = set()
        self.in_scope_patterns: List[str] = []

        self.out_of_scope_domains: Set[str] = set()
        self.out_of_scope_paths: List[str] = []

        self.safe_mode: bool = True
        self.max_depth: int = 3
        self.respect_robots_txt: bool = True

        if config_path:
            self.load_scope(config_path)

    def load_scope(self, config_path: str):
        """Load scope from configuration file"""
        try:
            config_file = Path(config_path)
            if config_file.exists():
                import yaml
                with open(config_file) as f:
                    config = yaml.safe_load(f)

                # Load in-scope
                in_scope = config.get("scope", {}).get("in_scope", [])
                for item in in_scope:
                    if item.startswith("*."):
                        # Wildcard domain
                        self.in_scope_patterns.append(item.replace("*.", ""))
                    elif self._is_ip(item):
                        self.in_scope_ips.add(item)
                    else:
                        self.in_scope_domains.add(item)

                # Load out-of-scope
                out_of_scope = config.get("scope", {}).get("out_of_scope", [])
                for item in out_of_scope:
                    if "/" in item:
                        self.out_of_scope_paths.append(item)
                    else:
                        self.out_of_scope_domains.add(item)

                # Safety settings
                safety = config.get("safety", {})
                self.safe_mode = safety.get("safe_mode", True)
                self.max_depth = safety.get("max_depth", 3)
                self.respect_robots_txt = safety.get("respect_robots_txt", True)

        except Exception:
            pass

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]

            # Check if explicitly out of scope
            if domain in self.out_of_scope_domains:
                return False

            # Check if path is out of scope
            for path_pattern in self.out_of_scope_paths:
                if path_pattern in parsed.path:
                    return False

            # If no scope defined, allow everything (dangerous!)
            if not self.in_scope_domains and not self.in_scope_ips and not self.in_scope_patterns:
                return True

            # Check exact domain match
            if domain in self.in_scope_domains:
                return True

            # Check IP match
            if domain in self.in_scope_ips:
                return True

            # Check wildcard pattern match
            for pattern in self.in_scope_patterns:
                if domain.endswith(pattern):
                    return True

            return False

        except Exception:
            return False

    def add_to_scope(self, target: str):
        """Add a target to scope"""
        if target.startswith("*."):
            self.in_scope_patterns.append(target.replace("*.", ""))
        elif self._is_ip(target):
            self.in_scope_ips.add(target)
        else:
            # Parse as URL to extract domain
            try:
                parsed = urlparse(target if "://" in target else f"http://{target}")
                domain = parsed.netloc
                if ":" in domain:
                    domain = domain.split(":")[0]
                self.in_scope_domains.add(domain)
            except Exception:
                self.in_scope_domains.add(target)

    def remove_from_scope(self, target: str):
        """Remove a target from scope"""
        self.out_of_scope_domains.add(target)

    def is_safe_operation(self, operation: str) -> bool:
        """Check if operation is allowed in safe mode"""
        if not self.safe_mode:
            return True

        # Dangerous operations blocked in safe mode
        dangerous_operations = [
            "DROP TABLE",
            "DELETE FROM",
            "TRUNCATE",
            "rm -rf",
            "format",
            "shutdown",
            "reboot",
            "; rm ",
            "& del ",
        ]

        operation_upper = operation.upper()

        for dangerous in dangerous_operations:
            if dangerous.upper() in operation_upper:
                return False

        return True

    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, value))

    def get_scope_summary(self) -> dict:
        """Get summary of current scope"""
        return {
            "in_scope_domains": list(self.in_scope_domains),
            "in_scope_ips": list(self.in_scope_ips),
            "in_scope_patterns": self.in_scope_patterns,
            "out_of_scope_domains": list(self.out_of_scope_domains),
            "out_of_scope_paths": self.out_of_scope_paths,
            "safe_mode": self.safe_mode,
            "max_depth": self.max_depth,
            "respect_robots_txt": self.respect_robots_txt,
        }


class RateLimiter:
    """Advanced rate limiting with adaptive throttling"""

    def __init__(self, requests_per_second: int = 5):
        self.requests_per_second = requests_per_second
        self.request_times: List[float] = []
        self.backoff_factor = 1.0
        self.max_backoff = 10.0

    async def wait(self):
        """Wait if necessary to respect rate limit"""
        import asyncio
        import time

        current_time = time.time()

        # Remove old request times (older than 1 second)
        self.request_times = [t for t in self.request_times if current_time - t < 1.0]

        # Check if we need to wait
        if len(self.request_times) >= self.requests_per_second * self.backoff_factor:
            wait_time = 1.0 - (current_time - self.request_times[0])
            if wait_time > 0:
                await asyncio.sleep(wait_time)

        self.request_times.append(time.time())

    def increase_backoff(self):
        """Increase backoff (e.g., after receiving 429)"""
        self.backoff_factor = min(self.backoff_factor * 2, self.max_backoff)

    def reset_backoff(self):
        """Reset backoff to normal"""
        self.backoff_factor = 1.0


class SafetyValidator:
    """Validates operations for safety"""

    # Blocked payloads that could cause harm
    DESTRUCTIVE_PATTERNS = [
        r'DROP\s+TABLE',
        r'DELETE\s+FROM',
        r'TRUNCATE',
        r'rm\s+-rf',
        r'format\s+[cd]:',
        r'del\s+/[fqs]',
        r'shutdown',
        r'reboot',
        r'killall',
        r'pkill',
    ]

    # Blocked targets (localhost, internal IPs, etc.)
    BLOCKED_TARGETS = [
        r'^localhost$',
        r'^127\.0\.0\.1$',
        r'^0\.0\.0\.0$',
        r'^10\.\d+\.\d+\.\d+$',  # Private 10.0.0.0/8
        r'^172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+$',  # Private 172.16.0.0/12
        r'^192\.168\.\d+\.\d+$',  # Private 192.168.0.0/16
        r'^169\.254\.\d+\.\d+$',  # Link-local
    ]

    @classmethod
    def is_safe_payload(cls, payload: str) -> bool:
        """Check if payload is safe"""
        for pattern in cls.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return False
        return True

    @classmethod
    def is_safe_target(cls, target: str) -> bool:
        """Check if target is safe (not internal/localhost)"""
        try:
            parsed = urlparse(target)
            host = parsed.netloc or target

            # Remove port
            if ":" in host:
                host = host.split(":")[0]

            for pattern in cls.BLOCKED_TARGETS:
                if re.match(pattern, host):
                    return False

            return True

        except Exception:
            return False
