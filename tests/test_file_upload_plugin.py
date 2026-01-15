import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.file_upload import Plugin as FileUploadPlugin

class TestFileUploadPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = FileUploadPlugin()

    def test_find_upload_forms(self):
        requester = MagicMock()
        requester.get = AsyncMock(return_value={
            "text": """
                <html><body>
                    <form action="/upload" method="post" enctype="multipart/form-data">
                        <input type="file" name="file1">
                        <input type="submit">
                    </form>
                </body></html>
            """
        })

        forms = asyncio.run(self.plugin._find_upload_forms("https://example.com", requester))

        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["url"], "https://example.com/upload")
        self.assertEqual(forms[0]["file_fields"], ["file1"])

    def test_php_upload_vulnerability(self):
        requester = MagicMock()
        requester.post = AsyncMock(return_value={
            "text": "File uploaded successfully: test.php",
            "status": 200
        })

        form_info = {
            "url": "https://example.com/upload",
            "method": "post",
            "file_fields": ["file1"],
            "form_data": {}
        }

        result = asyncio.run(self.plugin._test_php_upload(form_info, requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "file_upload_php")

    def test_svg_xss_upload_vulnerability(self):
        requester = MagicMock()
        requester.post = AsyncMock(return_value={
            "text": "Upload successful: test.svg",
            "status": 200
        })

        form_info = {
            "url": "https://example.com/upload",
            "method": "post",
            "file_fields": ["file1"],
            "form_data": {}
        }

        result = asyncio.run(self.plugin._test_svg_xss_upload(form_info, requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "file_upload_svg_xss")

    def test_no_forms_found(self):
        requester = MagicMock()
        requester.get = AsyncMock(return_value={"text": "<html><body></body></html>"})

        result = asyncio.run(self.plugin.run("https://example.com", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "file_upload_info")

if __name__ == "__main__":
    unittest.main()
