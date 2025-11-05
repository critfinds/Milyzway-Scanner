"""Async HTTP requester with simple rate limiting."""
import asyncio
from typing import Any, Optional, Dict

try:
    import aiohttp
except Exception:
    aiohttp = None

try:
    from aiolimiter import AsyncLimiter
except Exception:
    AsyncLimiter = None

from scanner.logger import get_logger

LOG = get_logger("http")


import random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
]

class AioRequester:
    def __init__(self, rate_limit: int = 5, timeout: int = 20, proxies: Optional[Dict[str, str]] = None, username: Optional[str] = None, password: Optional[str] = None, login_url: Optional[str] = None, max_field_size: int = 8190):
        self._rate_limit = rate_limit or 5
        self._timeout_value = timeout or 20
        self._proxies = proxies
        self._limiter = AsyncLimiter(self._rate_limit, 1) if AsyncLimiter else None
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self._timeout_value), max_field_size=max_field_size) if aiohttp else None
        self._username = username
        self._password = password
        self._login_url = login_url

    async def login(self) -> bool:
        if not (self._username and self._password and self._login_url):
            LOG.debug("Missing credentials or login URL for authentication.")
            return False

        LOG.info(f"Attempting to log in to {self._login_url} with username {self._username}")
        try:
            # Assuming a simple form submission for login
            data = {
                "username": self._username,
                "password": self._password
            }
            async with self._session.post(self._login_url, data=data) as resp:
                if resp.status == 200:
                    LOG.info(f"Successfully logged in to {self._login_url}")
                    return True
                else:
                    LOG.warning(f"Login failed to {self._login_url} with status {resp.status}")
                    return False
        except Exception as e:
            LOG.error(f"Error during login to {self._login_url}: {e}")
            return False

    async def request(self, method: str, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Perform an HTTP request and return a dict with status/text/headers or None on error."""
        if not self._session:
            raise RuntimeError("aiohttp is required for AioRequester")

        headers = kwargs.get("headers", {})
        headers["User-Agent"] = random.choice(USER_AGENTS)
        kwargs["headers"] = headers

        proxy = None
        if self._proxies:
            scheme = url.split("://")[0]
            if scheme in self._proxies:
                proxy = self._proxies[scheme]

        try:
            if self._limiter:
                async with self._limiter:
                    async with self._session.request(method, url, proxy=proxy, **kwargs) as resp:
                        text = await resp.text()
                        return {"status": resp.status, "text": text, "headers": dict(resp.headers)}
            else:
                async with self._session.request(method, url, proxy=proxy, **kwargs) as resp:
                    text = await resp.text()
                    return {"status": resp.status, "text": text, "headers": dict(resp.headers)}
        except Exception as e:
            LOG.debug("HTTP request failed: %s %s -> %s", method, url, e)
            return None

    async def get(self, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, data=None, json=None, **kwargs) -> Optional[Dict[str, Any]]:
        return await self.request("POST", url, data=data, json=json, **kwargs)

    async def close(self) -> None:
        if self._session:
            await self._session.close()
