import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock
import json

from scanner.plugins.graphql import Plugin as GraphQLPlugin

class TestGraphQLPlugin(unittest.TestCase):
    def setUp(self):
        self.plugin = GraphQLPlugin()

    def test_discover_graphql_endpoints(self):
        requester = MagicMock()

        async def mock_post(url, json=None):
            if url == "https://example.com/graphql":
                return {"status": 200, "text": '{"data": {"__typename": "Query"}}'}
            return {"status": 404, "text": ""}

        requester.post = AsyncMock(side_effect=mock_post)

        endpoints = asyncio.run(self.plugin._discover_graphql_endpoints("https://example.com", requester))

        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0], "https://example.com/graphql")

    def test_introspection_enabled(self):
        requester = MagicMock()
        introspection_response = {
            "data": {
                "__schema": {
                    "types": [{"name": "User"}, {"name": "Post"}]
                }
            }
        }
        requester.post = AsyncMock(return_value={"status": 200, "text": json.dumps(introspection_response)})

        result = asyncio.run(self.plugin._test_introspection("https://example.com/graphql", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "graphql_introspection_enabled")

    def test_field_suggestions(self):
        requester = MagicMock()
        suggestion_response = {
            "errors": [{"message": "Did you mean 'user'?"}]
        }
        requester.post = AsyncMock(return_value={"status": 400, "text": json.dumps(suggestion_response)})

        result = asyncio.run(self.plugin._test_field_suggestions("https://example.com/graphql", requester))

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "graphql_field_suggestions")

    def test_no_graphql_endpoint(self):
        requester = MagicMock()
        requester.post = AsyncMock(return_value={"status": 404, "text": ""})

        result = asyncio.run(self.plugin.run("https://example.com", requester))

        self.assertEqual(len(result), 0)

if __name__ == "__main__":
    unittest.main()
