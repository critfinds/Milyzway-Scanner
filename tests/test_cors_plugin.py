
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.cors import Plugin as CorsPlugin

class TestCorsPlugin(unittest.TestCase):
    def test_wildcard_no_credentials(self):
        plugin = CorsPlugin()
        requester = MagicMock()

        async def mock_get(target, headers):
            if headers["Origin"] == "https://evil.example":
                return {
                    "status": 200,
                    "headers": {"Access-Control-Allow-Origin": "*"}
                }
            return {"status": 200, "headers": {}}

        requester.get = mock_get

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "wildcard_no_credentials")

if __name__ == "__main__":
    unittest.main()
