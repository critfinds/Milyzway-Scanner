
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.csrf import Plugin as CsrfPlugin

class TestCsrfPlugin(unittest.TestCase):
    def test_form_without_csrf_token(self):
        plugin = CsrfPlugin()
        requester = MagicMock()

        requester.get = AsyncMock(return_value={
            "text": "<html><body><form><input type='text' name='username'></form></body></html>",
            "headers": {}
        })

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "missing_csrf_token")

    def test_cookie_without_samesite(self):
        plugin = CsrfPlugin()
        requester = MagicMock()

        requester.get = AsyncMock(return_value={
            "text": "<html><body></body></html>",
            "headers": {"Set-Cookie": "sessionid=123"}
        })

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "missing_samesite_cookie")

if __name__ == "__main__":
    unittest.main()
