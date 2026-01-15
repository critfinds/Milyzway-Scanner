import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.waf_bypass import WAFBypass

class TestWAFBypassPlugin(unittest.TestCase):
    def test_detect_cloudflare_waf(self):
        plugin = WAFBypass()
        requester = MagicMock()

        async def mock_get(target, params=None):
            if params and any(p in params.get("param", "") for p in plugin.MALICIOUS_PAYLOADS):
                return {
                    "status": 403,
                    "headers": {"Server": "cloudflare"},
                    "text": "cloudflare security check",
                }
            return {"status": 200, "headers": {}, "text": "ok"}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 0)
        # First finding should be WAF detection
        self.assertEqual(result[0]["type"], "waf_detected")
        self.assertEqual(result[0]["message"], "WAF detected: Cloudflare")

    def test_bypass_cloudflare_waf(self):
        plugin = WAFBypass()
        requester = MagicMock()

        async def mock_get(target, params=None):
            payload = params.get("param", "") if params else ""
            if "%00" in payload:
                return {"status": 200, "headers": {}, "text": "ok"}
            if params and any(p in payload for p in plugin.MALICIOUS_PAYLOADS):
                return {
                    "status": 403,
                    "headers": {"Server": "cloudflare"},
                    "text": "cloudflare security check",
                }
            return {"status": 200, "headers": {}, "text": "ok"}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertGreater(len(result), 1)  # At least detection + one bypass

        # First finding should be WAF detection
        self.assertEqual(result[0]["type"], "waf_detected")

        # Should have at least one bypass finding
        bypass_findings = [f for f in result if f["type"] == "waf_bypass_successful"]
        self.assertGreater(len(bypass_findings), 0)
        # Check that at least one bypass uses null_byte technique
        null_byte_bypass = next((f for f in bypass_findings if "null_byte" in f.get("message", "")), None)
        self.assertIsNotNone(null_byte_bypass)

    def test_no_waf(self):
        plugin = WAFBypass()
        requester = MagicMock()

        async def mock_get(target, params=None):
            return {"status": 200, "headers": {}, "text": "ok"}

        requester.get = AsyncMock(side_effect=mock_get)

        result = asyncio.run(plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 0)

if __name__ == "__main__":
    unittest.main()
