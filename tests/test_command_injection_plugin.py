
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.command_injection import Plugin as CommandInjectionPlugin

class TestCommandInjectionPlugin(unittest.TestCase):
    def test_os_system_injection(self):
        plugin = CommandInjectionPlugin()
        requester = MagicMock()

        mock_response = AsyncMock()
        mock_response.raise_for_status = AsyncMock()
        mock_response.text.return_value = "import os\nos.system('ls')"

        requester.get = AsyncMock(return_value=mock_response)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "os.system")

if __name__ == "__main__":
    unittest.main()

