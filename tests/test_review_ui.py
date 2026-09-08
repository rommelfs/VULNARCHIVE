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
from fd_sightings.models import Extraction, Message
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

    def test_review_queue_paginates_and_sorts_by_confidence(self) -> None:
        from fd_sightings.models import Match
        for number, confidence in ((1, .2), (2, .9), (3, .5)):
            self.store.save(
                Message(f"https://example.test/{number}", f"Widget {number}", published=f"2026-09-0{number}"),
                Extraction(relevant=True),
                [Match(f"CVE-2026-{number:04d}", "candidate", confidence)],
            )
        query = urllib.parse.urlencode({"sort": "confidence", "order": "desc", "per_page": 2})
        with urllib.request.urlopen(self.request("/?" + query)) as response:
            page = response.read().decode()
        self.assertLess(page.index("Widget 2"), page.index("Widget 3"))
        self.assertNotIn("Widget 1", page)
        self.assertIn("Page 1 of 2 · 3 observations", page)
        self.assertIn('rel="next"', page)
        self.assertIn("sort=confidence", page)

    def test_review_queue_rejects_invalid_list_query(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(self.request("/?sort=matches_json"))
        self.assertEqual(raised.exception.code, 400)

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

            def submit(self, start, end, *, limit=0, semantic=False, refresh=False, sources=None):
                self.submitted.append((start, end, limit, semantic, refresh, sources))
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
        self.assertEqual(page.count('type="month"'), 2)
        self.assertEqual(page.count('min="2002-01" max="'), 2)
        self.assertIn("Use the calendar controls", page)
        self.assertIn("Import source configuration", page)
        self.assertIn("only to the new historical worker", page)
        self.assertIn("deliberately cannot edit", page)
        self.assertIn('name="source" value="full-disclosure" checked', page)
        self.assertIn('name="source" value="bugtraq"', page)

        encoded = urllib.parse.urlencode({
            "csrf": self.server.csrf_token,
            "from_period": "2024-01",
            "to_period": "2024-03",
            "limit": "25",
            "semantic": "1",
            "refresh": "1",
            "source": ["full-disclosure", "bugtraq"],
        }, doseq=True).encode()
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
        self.assertEqual(workers.submitted, [(
            "2024-01", "2024-03", 25, True, True,
            ["full-disclosure", "bugtraq"],
        )])
        with urllib.request.urlopen(self.request("/workers?job=abc123")) as response:
            live_page = response.read().decode()
        self.assertIn('<meta http-equiv="refresh" content="2">', live_page)
        self.assertIn("This view refreshes every 2 seconds.", live_page)

    def test_approved_observation_links_to_publication_and_published_record(self) -> None:
        source = "https://seclists.org/fulldisclosure/2026/Sep/42"
        self.store.save(Message(source, "Searchable Widget flaw", body="distinctive heap corruption"), Extraction(relevant=True), [])
        self.store.review(source, "approved", [], "seen")
        with urllib.request.urlopen(self.request("/observation?" + urllib.parse.urlencode({"source": source}))) as response:
            approved = response.read().decode()
        self.assertIn("Publish this approved entry locally", approved)
        self.assertIn('href="/review/publish"', approved)

        record = {
            "dataType": "CVE_RECORD", "dataVersion": "5.2",
            "cveMetadata": {"vulnId": "GCVE-1988-2026-0042", "state": "PUBLISHED"},
            "containers": {"cna": {"title": "Searchable Widget flaw"}},
        }
        self.store.save_publication(source, "gcve:advisory", "gcve", gcve_id="GCVE-1988-2026-0042", status="published", payload=record)
        with urllib.request.urlopen(self.request("/observation?" + urllib.parse.urlencode({"source": source}))) as response:
            published = response.read().decode()
        self.assertIn("Open published GCVE-1988-2026-0042", published)
        self.assertIn("https://vuln.freearchive.org/vulnerability/GCVE-1988-2026-0042", published)


if __name__ == "__main__":
    unittest.main()
