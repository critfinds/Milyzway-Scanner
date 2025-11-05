
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.csrf import Plugin as CsrfPlugin

class TestCsrfPlugin(unittest.TestCase):
    def test_form_without_csrf_token(self):
        plugin = CsrfPlugin()
        requester = MagicMock()

        mock_response = AsyncMock()
        mock_response.raise_for_status = AsyncMock()
        mock_response.text.return_value = "<html><body><form><input type='text' name='username'></form></body></html>"
        mock_response.cookies = {}

        requester.get = AsyncMock(return_value=mock_response)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "form")

    def test_cookie_without_samesite(self):
        plugin = CsrfPlugin()
        requester = MagicMock()

        mock_response = AsyncMock()
        mock_response.raise_for_status = AsyncMock()
        mock_response.text.return_value = "<html><body></body></html>"
        mock_response.cookies = {"sessionid": MagicMock(keys=lambda: [])}

        requester.get = AsyncMock(return_value=mock_response)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "cookie")

if __name__ == "__main__":
    unittest.main()
