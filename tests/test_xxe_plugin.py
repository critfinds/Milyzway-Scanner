
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.xxe import Plugin as XxePlugin

class TestXxePlugin(unittest.TestCase):
    def test_in_band_xxe(self):
        plugin = XxePlugin()
        requester = MagicMock()

        async def mock_post(url, data=None, headers=None, params=None):
            if data and "file:///etc/passwd" in str(data):
                return {"status": 200, "text": "root:x:0:0:root:/root:/bin/bash"}
            return {"status": 200, "text": "OK"}

        requester.post = AsyncMock(side_effect=mock_post)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["type"], "inband_xxe")

    def test_oast_based_xxe(self):
        plugin = XxePlugin()
        requester = MagicMock()

        async def mock_post(url, data=None, headers=None, params=None):
            return {"status": 200, "text": "OK"}

        requester.post = AsyncMock(side_effect=mock_post)

        oast_server = "oast.example.com"
        result = asyncio.run(plugin.run("https://example.com", requester, oast_server))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["type"], "oast_based_xxe")

if __name__ == "__main__":
    unittest.main()
