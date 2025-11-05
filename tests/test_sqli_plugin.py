
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.sqli import Plugin as SqliPlugin

class TestSqliPlugin(unittest.TestCase):
    def test_error_based_sqli_in_url(self):
        plugin = SqliPlugin()
        requester = MagicMock()

        async def mock_get(url, params):
            if params and "'" in list(params.values())[0]:
                return AsyncMock(text=AsyncMock(return_value="you have an error in your sql syntax;"))
            return AsyncMock(text=AsyncMock(return_value=""))

        requester.get = mock_get

        result = asyncio.run(plugin.run("https://example.com?id=1", requester))

        self.assertIsNotNone(result)
        self.assertIn("Error-based SQLi found", result[0])

    def test_boolean_based_sqli_in_form(self):
        plugin = SqliPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            return AsyncMock(text=AsyncMock(return_value="<form action='/login' method='post'><input type='text' name='username'><input type='password' name='password'></form>"))

        async def mock_post(url, data):
            if "AND 1=1 --" in list(data.values())[0]:
                return AsyncMock(text=AsyncMock(return_value="Welcome"))
            return AsyncMock(text=AsyncMock(return_value="Invalid credentials"))

        requester.get = mock_get
        requester.post = mock_post

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertIn("Boolean-based SQLi found", result[0])

    def test_boolean_based_sqli_in_form(self):
        plugin = SqliPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            return AsyncMock(text=AsyncMock(return_value="<form action='/login' method='post'><input type='text' name='username'><input type='password' name='password'></form>"))

        async def mock_post(url, data):
            if "AND 1=1 --" in list(data.values())[0]:
                return AsyncMock(text=AsyncMock(return_value="Welcome"))
            return AsyncMock(text=AsyncMock(return_value="Invalid credentials"))

        requester.get = mock_get
        requester.post = mock_post

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertIn("Boolean-based SQLi found", result[0])

    def test_time_based_sqli_in_url(self):
        plugin = SqliPlugin()
        requester = MagicMock()

        async def mock_get(url, params):
            if params and "SLEEP(5)" in list(params.values())[0]:
                await asyncio.sleep(5)  # Simulate delay
                return AsyncMock(text=AsyncMock(return_value=""))
            return AsyncMock(text=AsyncMock(return_value=""))

        requester.get = mock_get

        result = asyncio.run(plugin.run("https://example.com?id=1", requester))

        self.assertIsNotNone(result)
        self.assertIn("Time-based SQLi found", result[0])

    def test_oast_based_sqli_in_form(self):
        plugin = SqliPlugin()
        requester = MagicMock()

        async def mock_get(url, params=None):
            return AsyncMock(text=AsyncMock(return_value="<form action='/login' method='post'><input type='text' name='username'><input type='password' name='password'></form>"))

        async def mock_post(url, data):
            return AsyncMock(text=AsyncMock(return_value=""))

        requester.get = mock_get
        requester.post = mock_post

        oast_server = "http://oast.example.com"
        result = asyncio.run(plugin.run("https://example.com", requester, oast_server))

        self.assertIsNotNone(result)
        self.assertIn("OAST-based SQLi payload sent", result[0])
