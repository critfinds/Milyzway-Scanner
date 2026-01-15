
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.xpath import Plugin as XpathPlugin

class TestXpathPlugin(unittest.TestCase):
    def test_error_based_vulnerability(self):
        plugin = XpathPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            if params and any("'" in str(v) or "xpath" in str(v).lower() for v in params.values()):
                return {"status": 200, "text": "<html><body>XPathException: syntax error</body></html>"}
            return {"status": 200, "text": "<html><body>OK</body></html>"}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(plugin.run("https://example.com?param=test", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "error_based_xpath")

    def test_boolean_based_vulnerability(self):
        plugin = XpathPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            return {"status": 200, "text": "<html><body><form action='/search' method='post'><input name='q'></form></body></html>"}

        async def mock_post(url, data=None, params=None):
            if data:
                payload = str(list(data.values())[0]) if data.values() else ""
                # True payload returns content
                if " and 1=1" in payload.lower() or " or 1=1" in payload.lower():
                    return {"status": 200, "text": "<html><body>Welcome back! User data: email@example.com</body></html>"}
                # False payload returns different content
                elif " and 1=2" in payload.lower():
                    return {"status": 200, "text": "<html><body></body></html>"}
            return {"status": 200, "text": "<html><body>Normal</body></html>"}

        requester.get = AsyncMock(side_effect=mock_get)
        requester.post = AsyncMock(side_effect=mock_post)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        # Type could be either variant
        self.assertIn(result[0]["type"], ["boolean_based_xpath", "boolean_based_blind_xpath"])

    def test_non_vulnerable_target(self):
        plugin = XpathPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            return {"status": 200, "text": "<html><body>OK</body></html>"}

        async def mock_post(url, data=None, params=None):
            return {"status": 200, "text": "<html><body>OK</body></html>"}

        requester.get = AsyncMock(side_effect=mock_get)
        requester.post = AsyncMock(side_effect=mock_post)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 0)

if __name__ == "__main__":
    unittest.main()
