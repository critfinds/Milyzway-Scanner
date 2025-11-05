
import asyncio
import unittest
from unittest.mock import MagicMock, patch

from scanner.plugins.subdomain_takeover import Plugin as SubdomainTakeoverPlugin

class TestSubdomainTakeoverPlugin(unittest.TestCase):
    def test_subdomain_takeover(self):
        plugin = SubdomainTakeoverPlugin()
        requester = MagicMock()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = '{"vulnerable": [{"subdomain": "test.example.com", "service": "cloudfront"}]}'
            mock_run.return_value.returncode = 0

            result = asyncio.run(plugin.run("https://example.com", requester))

            self.assertIn("subdomain_takeover_findings", result)
            self.assertEqual(len(result["subdomain_takeover_findings"]["vulnerable"]), 1)
            self.assertEqual(result["subdomain_takeover_findings"]["vulnerable"][0]["subdomain"], "test.example.com")

if __name__ == "__main__":
    unittest.main()
