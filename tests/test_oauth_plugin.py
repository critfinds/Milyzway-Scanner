
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.oauth import Plugin as OauthPlugin

class TestOauthPlugin(unittest.TestCase):
    def test_oauth_in_response(self):
        plugin = OauthPlugin()
        requester = MagicMock()

        requester.get = AsyncMock(return_value={"text": "oauth2 is used here"})

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "oauth_indicator")

if __name__ == "__main__":
    unittest.main()
