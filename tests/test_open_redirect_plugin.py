import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.open_redirect import Plugin as OpenRedirectPlugin

class TestOpenRedirectPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = OpenRedirectPlugin()
        self.plugin.test_domain = "evil.com"

    def test_find_redirect_parameters(self):
        requester = MagicMock()
        requester.get = AsyncMock(return_value={"text": ""})

        params = asyncio.run(self.plugin._find_redirect_parameters("https://example.com?redirect_url=test", requester))

        self.assertEqual(len(params), 1)
        self.assertEqual(params[0], ("url", "redirect_url"))

    def test_parameter_redirect_vulnerability(self):
        requester = MagicMock()

        async def mock_get(url, params=None, allow_redirects=False):
            if params and "evil.com" in params.get("next", ""):
                return {"headers": {"Location": "https://evil.com"}}
            return {"headers": {}}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(self.plugin.run("https://example.com?next=test", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "open_redirect")

    def test_oauth_redirect_vulnerability(self):
        requester = MagicMock()

        async def mock_get(url, allow_redirects=False):
            if "evil.com" in url:
                return {"headers": {"Location": "https://evil.com"}}
            return {"headers": {}}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(self.plugin.run("https://example.com/oauth/authorize?client_id=123", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "oauth_open_redirect")

    def test_no_vulnerable_parameters(self):
        requester = MagicMock()
        requester.get = AsyncMock(return_value={"text": ""})

        result = asyncio.run(self.plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 0)

if __name__ == "__main__":
    unittest.main()
