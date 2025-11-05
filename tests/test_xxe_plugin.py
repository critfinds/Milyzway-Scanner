
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.xxe import Plugin as XxePlugin

class TestXxePlugin(unittest.TestCase):
    def test_in_band_xxe(self):
        plugin = XxePlugin()
        requester = MagicMock()

        async def mock_post(url, data, headers):
            if "file:///etc/passwd" in data:
                return {"text": "root:x:0:0:root"}
            return {"text": ""}

        requester.post = AsyncMock(side_effect=mock_post)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertIn("XXE vulnerability found", result)

    def test_oast_based_xxe(self):
        plugin = XxePlugin()
        requester = MagicMock()

        async def mock_post(url, data, headers):
            return {"text": ""}

        requester.post = AsyncMock(side_effect=mock_post)

        oast_server = "oast.example.com"
        result = asyncio.run(plugin.run("https://example.com", requester, oast_server))

        self.assertIsNotNone(result)
        self.assertIn("OAST-based XXE payload sent", result)

if __name__ == "__main__":
    unittest.main()
