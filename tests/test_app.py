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
        args.username = None
        args.password = None
        args.login_url = None
        args.no_crawl = True  # disable crawling to simplify
        args.oast_server = None
        args.output_format = "json"
        args.concurrency = None

        with patch("scanner.app.load_config") as mock_load_config, \
             patch("scanner.app.load_plugins") as mock_load_plugins, \
             patch("scanner.app.AioRequester") as mock_aio_requester, \
             patch("scanner.app.Path.open", mock_open(read_data="https://example.com")):

            mock_load_config.return_value = {"concurrency": 1}
            mock_load_plugins.return_value = []

            # Create AioRequester mock instance
            mock_aio_requester_instance = MagicMock()
            mock_aio_requester_instance.login = AsyncMock(return_value=True)
            mock_aio_requester_instance.close = AsyncMock(return_value=None)
            mock_aio_requester.return_value = mock_aio_requester_instance

            asyncio.run(main_async(args))

    def test_scan_target(self):
        plugin = MagicMock()
        plugin.run = AsyncMock(return_value={"vulnerability": "test"})
        requester = MagicMock()

        result = asyncio.run(scan_target("https://example.com", [plugin], requester))

        self.assertEqual(len(result["vulnerabilities"]), 1)
        self.assertEqual(result["vulnerabilities"][0]["result"], {"vulnerability": "test"})


if __name__ == "__main__":
    unittest.main()
