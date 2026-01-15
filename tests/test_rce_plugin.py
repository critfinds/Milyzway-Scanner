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
        # baseline requests
        requester.post = AsyncMock(return_value={"text": ""})


        result = asyncio.run(plugin.run("https://example.com?dummy_param=test", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "time_based_rce")

if __name__ == "__main__":
    unittest.main()