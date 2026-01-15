
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.ssrf import Plugin as SsrfPlugin

class TestSsrfPlugin(unittest.TestCase):
    def test_url_parameter(self):
        plugin = SsrfPlugin()
        requester = MagicMock()

        requester.get = AsyncMock(return_value={"text": "<a href='/redirect?url=https://example.com'>Redirect</a>"})

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "ssrf_passive")

    def test_form_input(self):
        plugin = SsrfPlugin()
        requester = MagicMock()

        requester.get = AsyncMock(return_value={"text": "<form><input type='text' name='target'></form>"})

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 0)

if __name__ == "__main__":
    unittest.main()
