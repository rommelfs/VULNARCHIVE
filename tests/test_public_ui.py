from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from fd_sightings.public_ui import PublicServer
from fd_sightings.models import Extraction, Message
from fd_sightings.store import Store


class PublicUITest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.sqlite")
        for serial, updated in ((1, "2026-09-01T00:00:00Z"), (2, "2026-09-03T00:00:00Z")):
            record = {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.2",
                "cveMetadata": {"vulnId": f"GCVE-1988-2026-{serial}", "state": "PUBLISHED",
                                "assignerOrgId": os.getenv("VA_GNA_ORG_UUID", ""),
                                "datePublished": updated, "dateUpdated": updated},
            }
            self.store.save_publication(
                f"source-{serial}", f"gcve:{serial}", "gcve", gcve_id=record["cveMetadata"]["vulnId"],
                status="published", payload=record,
            )
        for serial, published in enumerate((
            "Thu, 01 Oct 2026 12:00:00 +0000",
            "Wed, 30 Sep 2026 12:00:00 +0000",
            "Tue, 15 Sep 2026 12:00:00 +0000",
            "Tue, 01 Sep 2026 12:00:00 +0000",
            "Mon, 31 Aug 2026 12:00:00 +0000",
        ), 1):
            self.store.save(
                Message(
                    f"https://seclists.org/fulldisclosure/2026/Post/{serial}",
                    f"Archive post {serial}", published=published, body="vulnerability report",
                ),
                Extraction(relevant=True),
                [],
            )
        self.server = PublicServer(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.close()
        self.temp.cleanup()

    def get(self, path: str) -> tuple[int, bytes, str]:
        with urllib.request.urlopen(self.base + path) as response:
            return response.status, response.read(), response.headers.get_content_type()

    def test_publication_pagination_and_since(self) -> None:
        _, body, content_type = self.get("/api/gcve/publication?date_sort=updated&since=2026-09-02T00%3A00%3A00Z&per_page=1")
        value = json.loads(body)
        self.assertEqual("application/json", content_type)
        self.assertEqual(["GCVE-1988-2026-2"], [item["cveMetadata"]["vulnId"] for item in value])

    def test_dump_and_security_txt_are_public(self) -> None:
        _, dump, content_type = self.get("/dumps/gna-1988.ndjson")
        self.assertEqual("application/x-ndjson", content_type)
        self.assertEqual(2, len(dump.splitlines()))
        _, security, _ = self.get("/.well-known/security.txt")
        self.assertEqual(b"GCVE: https://vuln.freearchive.org\n", security)

    def test_archive_is_grouped_by_month_with_dates_and_pagination(self) -> None:
        _, body, content_type = self.get("/archive/?per_page=2")
        page = body.decode()
        self.assertEqual("text/html", content_type)
        self.assertIn("October 2026", page)
        self.assertIn("September 2026", page)
        self.assertIn('<time datetime="2026-10-01">2026-10-01</time>', page)
        self.assertIn("Page 1 of 3 · 5 posts", page)
        self.assertIn('rel="next"', page)
        self.assertLess(page.index("Archive post 1"), page.index("Archive post 2"))
        first = next(row for row in self.store.rows() if row["title"] == "Archive post 1")
        self.assertIn(f'/archive/item/{first["content_hash"]}', page)
        _, detail, _ = self.get(f'/archive/item/{first["content_hash"]}')
        self.assertIn("Archive post 1", detail.decode())

        _, second_body, _ = self.get("/archive/?per_page=2&page=2")
        second = second_body.decode()
        self.assertIn("Page 2 of 3 · 5 posts", second)
        self.assertIn('rel="prev"', second)
        self.assertIn("Archive post 3", second)
        self.assertNotIn("Archive post 1</a>", second)

    def test_archive_month_filter_and_invalid_query(self) -> None:
        _, body, _ = self.get("/archive/?month=2026-09&per_page=10")
        page = body.decode()
        self.assertIn("Page 1 of 1 · 3 posts", page)
        self.assertIn("Archive post 2", page)
        self.assertNotIn("Archive post 1</a>", page)

        for query in ("page=0", "per_page=101", "month=September"):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.get("/archive/?" + query)
            self.assertEqual(400, raised.exception.code)

    def test_archive_full_text_search_and_public_record_page(self) -> None:
        _, body, _ = self.get("/archive/?q=Archive+post+3")
        page = body.decode()
        self.assertIn("Archive post 3", page)
        self.assertNotIn("Archive post 2</a>", page)
        self.assertIn('type="search"', page)

        record = {
            "dataType": "CVE_RECORD", "dataVersion": "5.2",
            "cveMetadata": {"vulnId": "GCVE-1988-2026-0042", "state": "PUBLISHED"},
            "containers": {"cna": {"title": "Public Widget record"}},
        }
        self.store.save_publication("record-source", "gcve:record", "gcve", gcve_id="GCVE-1988-2026-0042", status="published", payload=record)
        _, record_body, content_type = self.get("/vulnerability/GCVE-1988-2026-0042")
        self.assertEqual(content_type, "text/html")
        self.assertIn("GCVE-1988-2026-0042", record_body.decode())

    def test_admin_and_write_routes_are_unavailable(self) -> None:
        for path in ("/review", "/connection", "/publish", "/observation"):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.get(path)
            self.assertEqual(404, raised.exception.code)
        request = urllib.request.Request(self.base + "/api/gcve/publication", data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request)
        self.assertEqual(405, raised.exception.code)


if __name__ == "__main__":
    unittest.main()
