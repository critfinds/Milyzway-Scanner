
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

        self.assertIn("ssrf_findings", result)
        self.assertEqual(len(result["ssrf_findings"]), 1)
        self.assertEqual(result["ssrf_findings"][0]["param"], "url")

    def test_form_input(self):
        plugin = SsrfPlugin()
        requester = MagicMock()

        requester.get = AsyncMock(return_value={"text": "<form><input type='text' name='target'></form>"})

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIn("ssrf_findings", result)
        self.assertEqual(len(result["ssrf_findings"]), 1)
        self.assertEqual(result["ssrf_findings"][0]["param"], "target")

if __name__ == "__main__":
    unittest.main()
