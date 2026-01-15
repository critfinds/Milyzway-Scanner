import asyncio
import json
import unittest
from unittest.mock import MagicMock, patch, mock_open

from aiohttp import web

from scanner.app import main_async

# --- Test Server Handlers ---

async def vulnerable_xss_handler(request):
    param = request.query.get("param", "")
    # This is a classic reflected XSS vulnerability
    return web.Response(text=f"<html><body>Hello, {param}</body></html>", content_type="text/html")

async def vulnerable_ssrf_handler(request):
    # This endpoint has a parameter that suggests SSRF
    url_param = request.query.get("url", "default")
    return web.Response(text=f"URL parameter is: {url_param}")

async def vulnerable_cors_handler(request):
    # This endpoint has a wildcard CORS policy
    headers = {"Access-Control-Allow-Origin": "*"}
    return web.Response(text="CORS test", headers=headers)

class TestEndToEnd(unittest.TestCase):

    def test_full_scan(self):
        # unittest.TestCase doesn't directly support async test methods,
        # so we use a sync method to set up and run the async test.
        asyncio.run(self.run_full_scan())

    async def run_full_scan(self):
        app = web.Application()
        app.router.add_get("/xss", vulnerable_xss_handler)
        app.router.add_get("/ssrf", vulnerable_ssrf_handler)
        app.router.add_get("/cors", vulnerable_cors_handler)

        runner = web.AppRunner(app)
        await runner.setup()
        # Use port 0 to let the OS choose an arbitrary free port
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        base_url = f"http://127.0.0.1:{port}"

        # --- Configure and Run Scanner ---

        args = MagicMock()
        args.config = "config.yml"
        args.target = None
        args.targets_file = "dummy_targets.txt"
        args.username = None
        args.password = None
        args.login_url = None
        args.no_crawl = True
        args.oast_server = "my-oast-server.com"
        args.output_format = "json"
        args.concurrency = 1
        args.plugins = None  # Use auto-discovery

        # Create a dummy targets file in memory
        targets_content = (
            f"{base_url}/xss?param=test\n"
            f"{base_url}/ssrf?url=test\n"
            f"{base_url}/cors"
        )

        # Patch the file open and the JSON writer to capture results
        with patch("pathlib.Path.open", mock_open(read_data=targets_content)), \
             patch("scanner.app.write_json") as mock_write_json:
            
            await main_async(args)

        # --- Cleanup ---
        await runner.cleanup()

        # --- Assertions ---
        self.assertTrue(mock_write_json.called, "write_json was not called")
        
        # Retrieve the results that were passed to write_json
        results = mock_write_json.call_args[0][1]
        
        # Flatten all vulnerabilities from all targets into a single list
        all_vulns = []
        for res in results:
            all_vulns.extend(res.get("vulnerabilities", []))

        # 1. Verify that multiple plugins ran
        plugin_names = {v["plugin"] for v in all_vulns}
        self.assertIn("xss", plugin_names)
        self.assertIn("ssrf", plugin_names)
        self.assertIn("cors", plugin_names)

        # 2. Verify severity and confidence are present
        ssrf_finding = next((v for v in all_vulns if v["plugin"] == "ssrf"), None)
        self.assertIsNotNone(ssrf_finding)
        self.assertIn("severity", ssrf_finding)
        self.assertIn("confidence", ssrf_finding)

        # 3. Verify OAST-based SSRF check was triggered and has high severity
        active_ssrf_finding = next((v for v in all_vulns if v["result"].get("type") == "ssrf_oast"), None)
        self.assertIsNotNone(active_ssrf_finding, "OAST-based SSRF check missing")
        self.assertEqual(active_ssrf_finding["severity"], "high")
        self.assertIn("my-oast-server.com", active_ssrf_finding["result"]["payload"])

        # 4. Verify CORS finding
        cors_finding = next((v for v in all_vulns if v["plugin"] == "cors"), None)
        self.assertIsNotNone(cors_finding)
        self.assertEqual(cors_finding["severity"], "low") # Wildcard without credentials

        # 5. Verify Reflected XSS finding
        xss_finding = next((v for v in all_vulns if v["plugin"] == "xss"), None)
        self.assertIsNotNone(xss_finding)
        self.assertEqual(xss_finding["severity"], "medium")
        self.assertEqual(xss_finding["result"]["type"], "reflected_xss")

if __name__ == "__main__":
    unittest.main()
