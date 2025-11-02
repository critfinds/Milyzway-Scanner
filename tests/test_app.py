import asyncio
import unittest
from unittest.mock import MagicMock, patch, AsyncMock, mock_open

from scanner.app import main_async, scan_target


class TestApp(unittest.TestCase):
    def test_main_async(self):
        args = MagicMock()
        args.config = "config.yml"
        args.target = None
        args.targets_file = "targets.txt"

        with patch("scanner.app.load_config") as mock_load_config, \
             patch("scanner.app.load_plugins") as mock_load_plugins, \
             patch("scanner.app.AioRequester") as mock_aio_requester, \
             patch("builtins.open", mock_open(read_data="https://example.com")), \
             patch("pathlib.Path.is_file", return_value=True):

            mock_load_config.return_value = {}
            mock_load_plugins.return_value = []
            mock_aio_requester.return_value = MagicMock()

            asyncio.run(main_async(args))

    def test_scan_target(self):
        plugin = MagicMock()
        # plugin.run is awaited in scan_target, so provide an AsyncMock
        plugin.run = AsyncMock(return_value={"vulnerability": "test"})

        requester = MagicMock()

        result = asyncio.run(scan_target("https://example.com", [plugin], requester))

        self.assertEqual(len(result["vulnerabilities"]), 1)
        self.assertEqual(result["vulnerabilities"][0]["result"], {"vulnerability": "test"})


if __name__ == "__main__":
    unittest.main()
