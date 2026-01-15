
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.insecure_deserialization import Plugin as InsecureDeserializationPlugin

class TestInsecureDeserializationPlugin(unittest.TestCase):
    def test_vulnerable_server(self):
        plugin = InsecureDeserializationPlugin()
        requester = MagicMock()

        requester.post = AsyncMock(return_value={"text": "java.io.InvalidClassException: filter status: REJECTED"})

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "java_deserialization_error")

    def test_non_vulnerable_server(self):
        plugin = InsecureDeserializationPlugin()
        requester = MagicMock()

        requester.post = AsyncMock(return_value={"text": "<html><body>OK</body></html>"})

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(result, [])

if __name__ == "__main__":
    unittest.main()
