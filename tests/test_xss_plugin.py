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
        if params and "<script>alert('XSS')</script>" in params.get("param", ""):
            return {"text": "<script>alert('XSS')</script>"}
        if "<script>alert('XSS')</script>" in unquote(url):
            return {"text": "<script>alert('XSS')</script>"}
        return {"text": ""}

    requester.get = AsyncMock(side_effect=mock_get)

    result = asyncio.run(plugin._test_reflected_xss("https://example.com?param=value", requester))

    assert result is not None
    assert len(result) == 1
    assert "Reflected XSS found" in result[0]

def test_stored_xss():
    plugin = XssPlugin()
    requester = MagicMock()
    
    test_uuid = "fixed-uuid-for-testing"
    stored_content = "<html><body>No XSS here</body></html>"

    async def mock_get_post(url, params=None, data=None):
        nonlocal stored_content
        if url == "https://example.com/page_with_form":
            return {"text": "<html><body><form action='/submit' method='post'><input type='text' name='comment'></form></body></html>"}
        elif url == "https://example.com/page_with_payload":
            return {"text": stored_content}
        elif url == "https://example.com/submit" and data:
            from urllib.parse import unquote
            stored_content = f"<html><body>{unquote(str(data.get('comment')))}</body></html>"
            return {"text": "Submission successful"}
        return {"text": ""}

    requester.get = AsyncMock(side_effect=mock_get_post)
    requester.post = AsyncMock(side_effect=mock_get_post)

    with patch("uuid.uuid4", return_value=test_uuid), \
         patch("scanner.utils.crawler.Crawler") as mock_crawler, \
         patch("scanner.plugins.xss.BeautifulSoup") as mock_beautiful_soup:

         mock_crawler.return_value.start = AsyncMock(return_value=["https://example.com/page_with_form", "https://example.com/page_with_payload"])
         
         mock_form = MagicMock()
         mock_form.get.side_effect = lambda attr, default=None: {"action": "/submit", "method": "post"}.get(attr, default)
         mock_form.find_all.return_value = [MagicMock(get=lambda attr: {"name": "comment"}.get(attr))]
         mock_beautiful_soup.return_value.find_all.return_value = [mock_form]

         result = asyncio.run(plugin._test_stored_xss("https://example.com", requester))

         assert result is not None
         assert len(result) == 1
         assert "Stored XSS found" in result[0]
         assert test_uuid in result[0]

if __name__ == "__main__":
    unittest.main()
