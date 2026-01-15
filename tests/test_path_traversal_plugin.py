import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.path_traversal import Plugin as PathTraversalPlugin

class TestPathTraversalPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = PathTraversalPlugin()

    def test_find_path_parameters(self):
        requester = MagicMock()
        requester.get = AsyncMock(return_value={"text": ""})

        params = asyncio.run(self.plugin._find_path_parameters("https://example.com?file=test.txt", requester))

        self.assertEqual(len(params), 1)
        self.assertEqual(params[0], ("url", "file"))

    def test_linux_traversal_vulnerability(self):
        requester = MagicMock()

        async def mock_get(url, params=None):
            if params and "etc/passwd" in params.get("file", ""):
                return {"text": "root:x:0:0:root:/root:/bin/bash"}
            return {"text": ""}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(self.plugin.run("https://example.com?file=test.txt", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["type"], "path_traversal_linux")

    def test_windows_traversal_vulnerability(self):
        requester = MagicMock()

        async def mock_get(url, params=None):
            if params and "win.ini" in params.get("file", ""):
                return {"text": "[extensions]"}
            return {"text": ""}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(self.plugin.run("https://example.com?file=test.txt", requester))

        # This will run linux tests first, so we need to account for that
        # in a real scenario. For this unit test, we can isolate the windows test.
        windows_result = asyncio.run(self.plugin._test_windows_traversal("https://example.com", "file", requester))

        self.assertIsNotNone(windows_result)
        self.assertEqual(len(windows_result), 1)
        self.assertEqual(windows_result[0]["type"], "path_traversal_windows")

    def test_no_vulnerable_parameters(self):
        requester = MagicMock()
        requester.get = AsyncMock(return_value={"text": ""})

        result = asyncio.run(self.plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "path_traversal_info")

if __name__ == "__main__":
    unittest.main()
