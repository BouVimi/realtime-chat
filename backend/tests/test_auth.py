"""HTTP integration tests. Run only against a migrated dedicated test server.

Manual Cookie headers intentionally exercise server behavior even on local HTTP;
this does not simulate a browser enforcing Secure. Use HTTPS in production.
Set AUTH_TEST_DB=1 for database-assisted expiration/lock-expiry checks and cleanup.
"""
import base64
import hashlib
import json
import os
import statistics
import time
import unittest
import uuid
from http.cookies import SimpleCookie
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = os.getenv("BASE_URL", "http://127.0.0.1:8080")
ORIGIN = os.getenv("TEST_ORIGIN", os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")[0].strip())
PASSWORD = "Cobalt7!Sunrise"
GENERIC = {"error": {"code": "INVALID_CREDENTIALS", "message": "Invalid credentials"}}


def database():
    import psycopg
    return psycopg.connect(host=os.getenv("DB_HOST", "127.0.0.1"),
        port=os.getenv("DB_PORT", "5434"), dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"], password=os.environ["POSTGRES_PASSWORD"], connect_timeout=5)


class AuthFlow(unittest.TestCase):
    created = []

    def call(self, path, data=None, cookie=None, origin=ORIGIN, content_type="application/json", raw=None, method=None):
        headers = {}
        if origin is not None:
            headers["Origin"] = origin
        if cookie:
            headers["Cookie"] = cookie
        body = None
        if data is not None or raw is not None:
            body = raw if raw is not None else json.dumps(data).encode()
            headers["Content-Type"] = content_type
        request = Request(BASE + path, data=body, headers=headers, method=method)
        start = time.perf_counter()
        try:
            response = urlopen(request, timeout=20)
        except HTTPError as exc:
            response = exc
        elapsed = time.perf_counter() - start
        with response:
            payload = response.read()
            parsed = json.loads(payload) if payload else None
            return response.status, parsed, response.headers, elapsed

    def account(self):
        name = "u" + uuid.uuid4().hex[:18]
        email = name + "@example.invalid"
        status, body, headers, _ = self.call("/api/v1/auth/register",
            {"email": email, "username": name, "password": PASSWORD})
        self.assertEqual(status, 201)
        self.safe_user(body)
        self.assertIsNone(headers.get("Set-Cookie"))
        self.created.append(int(body["user"]["id"]))
        return name, email, body["user"]["id"]

    def safe_user(self, body):
        self.assertTrue(isinstance(body, dict) and set(body) == {"user"}, "Unexpected response envelope")
        user = body["user"]
        self.assertTrue(set(user) == {"id", "email", "username", "created_at", "updated_at"}, "Unsafe user projection")
        self.assertTrue(isinstance(user["id"], str) and user["id"].isdigit(), "Bigint id must be a string")

    def login(self, identifier, password=PASSWORD):
        return self.call("/api/v1/auth/login", {"identifier": identifier, "password": password})

    def session(self, headers):
        jar = SimpleCookie()
        jar.load(headers.get("Set-Cookie", ""))
        self.assertIn("session", jar)
        value = jar["session"]
        self.assertTrue(bool(value["httponly"]))
        self.assertEqual(value["samesite"].lower(), "lax")
        self.assertEqual(value["path"], "/")
        self.assertEqual(value["domain"], "")
        secure = os.getenv("EXPECT_COOKIE_SECURE", os.getenv("COOKIE_SECURE", "true")) == "true"
        self.assertEqual(bool(value["secure"]), secure)
        ttl = int(os.getenv("SESSION_TTL_HOURS", "168")) * 3600
        self.assertEqual(int(value["max-age"]), ttl)
        token = value.value
        self.assertTrue(len(token) == 43, "Unexpected token size")
        return "session=" + token

    def denied(self, result):
        status, body, headers, _ = result
        self.assertEqual(status, 401)
        self.assertTrue(body == GENERIC, "Credential failures must be identical")
        self.assertIsNone(headers.get("Set-Cookie"))

    def test_register_duplicates_validation(self):
        name, email, _ = self.account()
        status, body, _, _ = self.call("/api/v1/auth/register",
            {"email": email.upper(), "username": name + "x", "password": PASSWORD})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "EMAIL_TAKEN")
        status, body, _, _ = self.call("/api/v1/auth/register",
            {"email": "x" + email, "username": name.upper(), "password": PASSWORD})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "USERNAME_TAKEN")
        status, body, _, _ = self.call("/api/v1/auth/register",
            {"email": "y" + email, "username": name + "y", "password": "password123"})
        self.assertEqual(status, 400)
        self.assertTrue(any(f["field"] == "password" for f in body["error"]["fields"]))

    def test_login_me_logout_tampering(self):
        name, email, user_id = self.account()
        self.assertEqual(self.call("/api/v1/users/me")[0], 401)
        self.assertEqual(self.call("/api/v1/auth/logout", {})[0], 401)
        self.denied(self.login(name, "Wrong7!Sunrise"))
        self.denied(self.login("unknown_" + uuid.uuid4().hex[:12], "Wrong7!Sunrise"))
        status, body, headers, _ = self.login(email.upper())
        self.assertEqual(status, 200)
        self.safe_user(body)
        self.assertEqual(body["user"]["id"], user_id)
        cookie = self.session(headers)
        status, body, _, _ = self.call("/api/v1/users/me", cookie=cookie)
        self.assertEqual(status, 200)
        self.safe_user(body)
        self.assertEqual(body["user"]["id"], user_id)
        token = cookie.split("=", 1)[1]
        tampered = ("A" if token[0] != "A" else "B") + token[1:]
        self.assertEqual(self.call("/api/v1/users/me", cookie="session=" + tampered)[0], 401)
        self.assertEqual(self.call("/api/v1/users/me", cookie="session=malformed")[0], 401)
        self.assertEqual(self.call("/api/v1/auth/logout", {}, cookie=cookie, origin="https://evil.example")[0], 403)
        self.assertEqual(self.call("/api/v1/users/me", cookie=cookie)[0], 200)
        status, body, headers, _ = self.call("/api/v1/auth/logout", {}, cookie=cookie)
        self.assertEqual(status, 204)
        self.assertIsNone(body)
        cleared = SimpleCookie(); cleared.load(headers.get("Set-Cookie", ""))
        self.assertTrue("session" in cleared and cleared["session"]["max-age"] == "0", "Cookie must be cleared")
        self.assertEqual(self.call("/api/v1/users/me", cookie=cookie)[0], 401)
        # Username login is also supported.
        status, _, _, _ = self.login(name.upper())
        self.assertEqual(status, 200)

    def test_logout_without_body_or_content_type(self):
        name, _, _ = self.account()
        status, _, headers, _ = self.login(name)
        self.assertEqual(status, 200)
        cookie = self.session(headers)
        # Explicit POST with data=None: no body and no Content-Type header.
        self.assertEqual(self.call("/api/v1/auth/logout", cookie=cookie,
                                   origin="https://evil.example", method="POST")[0], 403)
        self.assertEqual(self.call("/api/v1/users/me", cookie=cookie)[0], 200)
        status, body, headers, _ = self.call("/api/v1/auth/logout", cookie=cookie, method="POST")
        self.assertEqual(status, 204)
        self.assertIsNone(body)
        cleared = SimpleCookie()
        cleared.load(headers.get("Set-Cookie", ""))
        self.assertTrue("session" in cleared and cleared["session"]["max-age"] == "0",
                        "Bodyless logout must clear the cookie")
        self.assertEqual(self.call("/api/v1/users/me", cookie=cookie)[0], 401)
        self.assertEqual(self.call("/api/v1/auth/logout", method="POST")[0], 401)

    def test_lockout(self):
        name, _, _ = self.account()
        for _ in range(4):
            self.denied(self.login(name, "Wrong7!Sunrise"))
        self.assertEqual(self.login(name)[0], 200)  # Four failures have not locked it; success resets.
        for _ in range(5):
            self.denied(self.login(name, "Wrong7!Sunrise"))
        self.denied(self.login(name))  # Correct password denied once locked.

    def test_unknown_and_wrong_similar_response_and_timing(self):
        name, _, _ = self.account()
        unknown = "z" + uuid.uuid4().hex[:18]
        wrong_times, unknown_times = [], []
        for _ in range(3):
            wrong = self.login(name, "Wrong7!Sunrise")
            missing = self.login(unknown, "Wrong7!Sunrise")
            self.denied(wrong); self.denied(missing)
            wrong_times.append(wrong[3]); unknown_times.append(missing[3])
        a, b = statistics.median(wrong_times), statistics.median(unknown_times)
        # A loose smoke check, not evidence of constant-time behavior over a network.
        self.assertTrue(min(a, b) >= max(a, b) * 0.25 and
                        abs(a - b) <= max(0.15, min(a, b) * 2),
                        "Credential response timings diverge")

    def test_json_and_origin(self):
        # Register/login still require input, but an absent body is not a MIME error.
        for path in ("/api/v1/auth/register", "/api/v1/auth/login"):
            self.assertEqual(self.call(path, method="POST")[0], 400)
        for raw in (b"{", b"[]", b"{} {}", b'{"x":1,"x":2}'):
            self.assertEqual(self.call("/api/v1/auth/login", raw=raw)[0], 400)
        deep = b'{"x":' + b'[' * 100 + b'0' + b']' * 100 + b'}'
        self.assertEqual(self.call("/api/v1/auth/login", raw=deep)[0], 400)
        self.assertEqual(self.call("/api/v1/auth/login", raw=b"{}", content_type="text/plain")[0], 415)
        self.assertEqual(self.call("/api/v1/auth/login", raw=b"x" * 4097)[0], 413)
        self.assertEqual(self.call("/api/v1/auth/login", {}, origin="https://evil.example")[0], 403)
        self.assertEqual(self.call("/api/v1/auth/login", {}, origin="null")[0], 403)
        self.assertEqual(self.call("/api/v1/auth/login", {}, origin="")[0], 403)
        self.assertEqual(self.call("/api/v1/auth/login", {}, origin=None)[0], 400)  # Missing schema, not missing Origin.

    @unittest.skipUnless(os.getenv("AUTH_TEST_DB") == "1", "Set AUTH_TEST_DB=1 for DB-assisted expiry test")
    def test_expired_session_and_expired_lock(self):
        name, _, user_id = self.account()
        status, _, headers, _ = self.login(name)
        self.assertEqual(status, 200)
        cookie = self.session(headers)
        token = cookie.split("=", 1)[1]
        digest = hashlib.sha256(base64.urlsafe_b64decode(token + "=")).digest()
        with database() as conn:
            updated = conn.execute("""UPDATE sessions SET created_at = now() - INTERVAL '2 days',
                expires_at = now() - INTERVAL '1 day' WHERE token_hash = %s AND user_id = %s""",
                (digest, int(user_id)))
            self.assertEqual(updated.rowcount, 1)
        self.assertEqual(self.call("/api/v1/users/me", cookie=cookie)[0], 401)
        with database() as conn:
            conn.execute("UPDATE users SET failed_login_count = 5, locked_until = now() - INTERVAL '1 second' WHERE id = %s", (int(user_id),))
        self.assertEqual(self.login(name)[0], 200)
        with database() as conn:
            count, locked = conn.execute("SELECT failed_login_count, locked_until FROM users WHERE id = %s", (int(user_id),)).fetchone()
            self.assertTrue(count == 0 and locked is None, "Successful login must clear lockout")

    @classmethod
    def tearDownClass(cls):
        if os.getenv("AUTH_TEST_DB") == "1" and cls.created:
            with database() as conn:
                conn.execute("DELETE FROM users WHERE id = ANY(%s)", (cls.created,))


if __name__ == "__main__":
    unittest.main()
