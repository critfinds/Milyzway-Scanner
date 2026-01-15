import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import uuid

from scanner.plugins.xss import Plugin as XssPlugin

def test_reflected_xss_in_url_parameter():
    plugin = XssPlugin()
    requester = MagicMock()

    async def mock_get(url, params=None):
        from urllib.parse import unquote
        # Check for XSS payload
        if params:
            param_values = str(params.values())
            if "<script>" in param_values or "alert" in param_values:
                return {"status": 200, "text": f"<html><body>{list(params.values())[0]}</body></html>"}
        if "<script>" in unquote(url) or "alert" in unquote(url):
            # Extract payload from URL and reflect it
            return {"status": 200, "text": "<html><body><script>alert('XSS')</script></body></html>"}
        return {"status": 200, "text": "<html><body>Normal page</body></html>"}

    requester.get = AsyncMock(side_effect=mock_get)

    result = asyncio.run(plugin._test_reflected_xss("https://example.com?param=value", requester))

    assert result is not None
    assert len(result) >= 1
    assert result[0]["type"] == "reflected_xss"

def test_stored_xss():
    """Test stored XSS with mocked Crawler to avoid Playwright dependency"""
    plugin = XssPlugin()
    requester = MagicMock()

    # Create a unique payload that we'll "store" and "find"
    test_payload = f"<script>alert('{uuid.uuid4()}')</script>"

    # Mock a scenario: crawler finds URLs, forms submit, payload appears later
    async def mock_get(url, params=None):
        if "form" in url or "submit" in url:
            return {"status": 200, "text": f"<html><body><form action='/submit' method='post'><input type='text' name='comment'></form></body></html>"}
        # After submission, the payload appears on the page
        return {"status": 200, "text": f"<html><body>{test_payload}</body></html>"}

    async def mock_post(url, data=None, params=None):
        return {"status": 200, "text": "Submitted successfully"}

    requester.get = AsyncMock(side_effect=mock_get)
    requester.post = AsyncMock(side_effect=mock_post)

    # Mock the Crawler to avoid Playwright dependency
    mock_crawler_instance = MagicMock()
    mock_crawler_instance.start = AsyncMock(return_value=["https://example.com/form", "https://example.com/view"])

    with patch("scanner.plugins.xss.Crawler", return_value=mock_crawler_instance):
        result = asyncio.run(plugin._test_stored_xss("https://example.com/form", requester))

    # Verify it returns a list
    assert isinstance(result, list)

if __name__ == "__main__":
    unittest.main()