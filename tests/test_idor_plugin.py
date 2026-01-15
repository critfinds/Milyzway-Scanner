import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.idor import Plugin as IDORPlugin

class TestIDORPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = IDORPlugin()

    def test_numeric_idor_vulnerability(self):
        requester = MagicMock()

        async def mock_get(url, params=None):
            if "user_id=2" in url:  # Baseline request
                return {"status": 200, "text": "Content for user 2. email: user2@example.com, name: User Two, profile: data, account, address, phone"}
            elif "user_id=1" in url:
                return {"status": 200, "text": "Content for user 1. email: user1@example.com, name: User One, profile: data, account, address, phone"}
            elif "user_id=3" in url:
                return {"status": 200, "text": "Content for user 3. email: user3@example.com, name: User Three, profile: data, account, address, phone"}
            return {"status": 404, "text": "Not Found"}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(self.plugin.run("https://example.com?user_id=2", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "idor_numeric")
        # Check that some IDs were accessible (could be 1, 3, or others)
        self.assertGreater(len(result[0]["accessible_ids"]), 0)

    def test_path_idor_vulnerability(self):
        requester = MagicMock()

        async def mock_get(url, params=None):
            # Need longer content (>100 chars) for plugin to detect
            user1_data = "Content for user 1. email: user1@example.com, name: User One, profile: data, account info, address details, phone number"
            user2_data = "Content for user 2. email: user2@example.com, name: User Two, profile: data, account info, address details, phone number"

            if url == "https://example.com/api/user/1":
                return {"status": 200, "text": user1_data}
            elif url == "https://example.com/api/user/2":
                return {"status": 200, "text": user2_data}
            return {"status": 404, "text": "Not Found"}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(self.plugin.run("https://example.com/api/user/2", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        self.assertEqual(result[0]["type"], "idor_path")
        # Accessible ID could be 1 or 3
        self.assertIn(result[0]["accessible_id"], [1, 3])

    def test_no_vulnerable_parameters(self):
        requester = MagicMock()
        requester.get = AsyncMock(return_value={"status": 404, "text": "Not Found"})

        result = asyncio.run(self.plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 0)

if __name__ == "__main__":
    unittest.main()
