from __future__ import annotations

import tempfile
import base64
import os
import threading
import unittest
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path

from fd_sightings.review_ui import ReviewServer
from fd_sightings.store import Store


class ReviewUITest(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = {
            "VA_REVIEW_USERNAME": "analyst",
            "VA_REVIEW_PASSWORD": "correct horse",
            "VA_REVIEW_PREFIX": "/review",
            "VA_REVIEW_ALLOWED_NETWORKS": "192.0.2.0/24",
            "VA_REVIEW_TRUSTED_PROXIES": "127.0.0.0/8",
        }
        self.previous = {key: os.environ.get(key) for key in self.environment}
        os.environ.update(self.environment)
        self.temporary = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temporary.name) / "review.sqlite")
        self.server = ReviewServer(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.close()
        self.temporary.cleanup()
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def request(self, path: str, *, address: str = "192.0.2.10", authenticated: bool = True,
                method: str = "GET") -> urllib.request.Request:
        headers = {"X-Forwarded-For": address}
        if authenticated:
            token = base64.b64encode(b"analyst:correct horse").decode()
            headers["Authorization"] = f"Basic {token}"
        return urllib.request.Request(self.base + path, data=b"" if method == "POST" else None,
                                      method=method, headers=headers)

    def test_review_ui_has_no_external_connection_endpoint(self) -> None:
        with urllib.request.urlopen(self.request("/")) as response:
            body = response.read().decode()
        self.assertNotIn("Vulnerability-Lookup", body)
        self.assertNotIn("Connection settings", body)
        self.assertIn('href="/review/publish"', body)
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(self.request("/connection"))
        self.assertEqual(raised.exception.code, 404)
        request = self.request("/connect", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request)
        self.assertEqual(raised.exception.code, 404)

    def test_authentication_and_forwarded_ip_filter(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(self.request("/", authenticated=False))
        self.assertEqual(raised.exception.code, 401)
        self.assertIn("Basic", raised.exception.headers["WWW-Authenticate"])
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(self.request("/", address="198.51.100.5"))
        self.assertEqual(raised.exception.code, 403)

    def test_historical_import_worker_can_be_started_from_ui(self) -> None:
        class Workers:
            def __init__(self):
                self.submitted = []

            def submit(self, start, end, *, limit=0, semantic=False, refresh=False):
                self.submitted.append((start, end, limit, semantic, refresh))
                return {"id": "abc123"}

            def jobs(self):
                return [{
                    "id": "abc123", "from_period": "2024-01", "to_period": "2024-03",
                    "status": "queued", "created_at": "2026-09-07T12:00:00Z", "return_code": None,
                }]

            def get(self, job_id):
                return self.jobs()[0] if job_id == "abc123" else None

            def log_tail(self, job):
                return ""

        workers = Workers()
        self.server.workers = workers
        with urllib.request.urlopen(self.request("/workers")) as response:
            page = response.read().decode()
        self.assertIn("Historical archive imports", page)
        self.assertIn('action="/review/workers"', page)

        encoded = urllib.parse.urlencode({
            "csrf": self.server.csrf_token,
            "from_period": "2024-01",
            "to_period": "2024-03",
            "limit": "25",
            "semantic": "1",
            "refresh": "1",
        }).encode()
        request = self.request("/workers", method="POST")
        request.data = encoded
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        with self.assertRaises(urllib.error.HTTPError) as redirected:
            urllib.request.build_opener(NoRedirect()).open(request)
        self.assertEqual(redirected.exception.code, 303)
        self.assertIn("/review/workers?job=abc123", redirected.exception.headers["Location"])
        self.assertEqual(workers.submitted, [("2024-01", "2024-03", 25, True, True)])
        with urllib.request.urlopen(self.request("/workers?job=abc123")) as response:
            live_page = response.read().decode()
        self.assertIn('<meta http-equiv="refresh" content="2">', live_page)
        self.assertIn("This view refreshes every 2 seconds.", live_page)


if __name__ == "__main__":
    unittest.main()
