import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock

from scanner.plugins.jwt_auth import Plugin as JWTAuthPlugin

class TestJWTAuthPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = JWTAuthPlugin()
        # A valid JWT for testing: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        self.test_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    def test_extract_jwt_from_header(self):
        headers = {"Authorization": f"Bearer {self.test_jwt}"}
        jwt = self.plugin._extract_jwt(headers, "")
        self.assertEqual(jwt, self.test_jwt)

    def test_extract_jwt_from_cookie(self):
        cookies = f"session={self.test_jwt}; other=value"
        jwt = self.plugin._extract_jwt({}, cookies)
        self.assertEqual(jwt, self.test_jwt)

    def test_none_algorithm_bypass(self):
        requester = MagicMock()
        requester.get = AsyncMock(return_value={"status": 200})

        result = asyncio.run(self.plugin._test_jwt_none_algorithm("https://example.com", self.test_jwt, requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "jwt_none_algorithm")

    def test_weak_secret(self):
        # This JWT is signed with 'secret' (properly generated)
        weak_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"
        requester = MagicMock()

        result = asyncio.run(self.plugin._test_jwt_weak_secret("https://example.com", weak_jwt, requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "jwt_weak_secret")
        self.assertEqual(result[0]["weak_secret"], "secret")

    def test_verb_tampering(self):
        requester = MagicMock()
        requester.get = AsyncMock(return_value={"status": 403})
        requester.post = AsyncMock(return_value={"status": 200})
        requester.put = AsyncMock(return_value={"status": 403})
        requester.delete = AsyncMock(return_value={"status": 403})

        result = asyncio.run(self.plugin._test_verb_tampering("https://example.com/admin", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "http_verb_tampering")
        self.assertEqual(result[0]["bypass_method"], "POST")

if __name__ == "__main__":
    unittest.main()
