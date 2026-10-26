"""Run against a running backend; EXPECT_DB=down tests the failure path."""
import json
import os
import unittest
from urllib.request import urlopen
from urllib.error import HTTPError

class HealthTests(unittest.TestCase):
    def request(self, path):
        try:
            response = urlopen(os.getenv("BASE_URL", "http://127.0.0.1:8080") + path, timeout=8)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, json.load(response), response.headers

    def test_health(self):
        status, body, headers = self.request("/api/v1/health")
        if os.getenv("EXPECT_DB") == "down":
            self.assertEqual(status, 503)
            self.assertEqual(body, {"error": {"code": "DATABASE_UNAVAILABLE",
                                             "message": "Service temporarily unavailable"}})
        else:
            self.assertEqual(status, 200)
            self.assertEqual(body, {"status": "ok", "database": "ok"})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Set-Cookie", headers)

    def test_source_files_are_not_served(self):
        for path in ("/README.md", "/backend/config/config.json", "/.env"):
            status, body, _ = self.request(path)
            self.assertIn(status, (403, 404))
            self.assertEqual(set(body), {"error"})

    def test_unknown_route(self):
        status, body, _ = self.request("/api/v1/does-not-exist")
        self.assertEqual(status, 404)
        self.assertEqual(set(body), {"error"})
        self.assertEqual(set(body["error"]), {"code", "message"})

if __name__ == "__main__":
    unittest.main()
