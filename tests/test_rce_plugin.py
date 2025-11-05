import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.rce import Plugin as RcePlugin

class TestRcePlugin(unittest.TestCase):
    def test_time_based_rce(self):
        plugin = RcePlugin()
        requester = MagicMock()

        async def slow_response(*args, **kwargs):
            # Simulate a delay only when the payload is present
            if "sleep 5" in kwargs.get("params", {}).get("dummy_param", ""):
                await asyncio.sleep(5)
            return {"text": ""}

        requester.get = AsyncMock(side_effect=slow_response)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertIn("Time-based RCE detected", result[0])

if __name__ == "__main__":
    unittest.main()