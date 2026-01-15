import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.ssti import Plugin as SstiPlugin

class TestSstiPlugin(unittest.TestCase):
    def test_ssti_in_url_parameter(self):
        plugin = SstiPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            from urllib.parse import unquote
            # Decode URL and check for SSTI payloads
            decoded_url = unquote(url)
            if any(payload in decoded_url for payload in ["{{7*7}}", "${7*7}", "<%=", "#{7*7}"]):
                return {"status": 200, "text": "Result: 49"}
            return {"status": 200, "text": "Result: normal"}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(plugin.run("https://example.com?param=test", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        # Check for SSTI-related types
        self.assertTrue(any(typ in result[0]["type"] for typ in ["ssti", "template", "reflected"]))

    def test_ssti_in_form(self):
        plugin = SstiPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            return {"status": 200, "text": "<html><body><form action='/search' method='post'><input name='q'></form></body></html>"}

        async def mock_post(url, data=None, params=None):
            if data:
                data_str = str(data.values())
                # Check for all SSTI payloads
                if any(payload in data_str for payload in ["{{7*7}}", "${7*7}", "<%=", "#{7*7}"]):
                    return {"status": 200, "text": "Results: 49"}
            return {"status": 200, "text": "Results: normal"}

        requester.get = AsyncMock(side_effect=mock_get)
        requester.post = AsyncMock(side_effect=mock_post)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        # Type could be various SSTI types
        self.assertTrue(any(typ in result[0]["type"] for typ in ["ssti", "template", "form"]))

if __name__ == "__main__":
    unittest.main()