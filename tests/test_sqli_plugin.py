
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.sqli import Plugin as SqliPlugin

class TestSqliPlugin(unittest.TestCase):
    def test_error_based_sqli_in_url(self):
        plugin = SqliPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            if params and any("'" in str(v) for v in params.values()):
                return {"status": 200, "text": "you have an error in your sql syntax;"}
            return {"status": 200, "text": "Normal response"}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(plugin.run("https://example.com?id=1", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["type"], "error_based_sqli")

    def test_boolean_based_sqli_in_form(self):
        plugin = SqliPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            return {"status": 200, "text": "<form action='/login' method='post'><input type='text' name='username'><input type='password' name='password'></form>"}

        async def mock_post(url, data=None, params=None):
            if data and any("AND 1=1" in str(v) or "OR 1=1" in str(v) for v in data.values()):
                return {"status": 200, "text": "Welcome back! Here is your account data and profile information"}
            return {"status": 200, "text": "Invalid credentials"}

        requester.get = AsyncMock(side_effect=mock_get)
        requester.post = AsyncMock(side_effect=mock_post)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["type"], "boolean_based_blind_sqli")

    def test_time_based_sqli_in_url(self):
        plugin = SqliPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            if params and any("SLEEP" in str(v) for v in params.values()):
                await asyncio.sleep(5)  # Simulate delay
                return {"status": 200, "text": "Normal response"}
            return {"status": 200, "text": "Normal response"}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(plugin.run("https://example.com?id=1", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["type"], "time_based_blind_sqli")

    def test_oast_based_sqli_in_form(self):
        plugin = SqliPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            return {"status": 200, "text": "<form action='/login' method='post'><input type='text' name='username'><input type='password' name='password'></form>"}

        async def mock_post(url, data=None, params=None):
            return {"status": 200, "text": "Processing..."}

        requester.get = AsyncMock(side_effect=mock_get)
        requester.post = AsyncMock(side_effect=mock_post)

        oast_server = "http://oast.example.com"
        result = asyncio.run(plugin.run("https://example.com", requester, oast_server))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["type"], "oast_based_sqli")
