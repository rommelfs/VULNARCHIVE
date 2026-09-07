from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from fd_sightings.public_ui import PublicServer
from fd_sightings.store import Store


class PublicUITest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.sqlite")
        for serial, updated in ((1, "2026-09-01T00:00:00Z"), (2, "2026-09-03T00:00:00Z")):
            record = {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.2",
                "cveMetadata": {"vulnId": f"GCVE-1988-2026-{serial}", "dateUpdated": updated},
            }
            self.store.save_publication(
                f"source-{serial}", f"gcve:{serial}", "gcve", gcve_id=record["cveMetadata"]["vulnId"],
                status="published", payload=record,
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
        _, body, content_type = self.get("/api/gcve/publication?since=2026-09-02T00%3A00%3A00Z&per_page=1")
        value = json.loads(body)
        self.assertEqual("application/json", content_type)
        self.assertEqual(["GCVE-1988-2026-2"], [item["cveMetadata"]["vulnId"] for item in value["data"]])
        self.assertEqual(1, value["metadata"]["total"])

    def test_dump_and_security_txt_are_public(self) -> None:
        _, dump, content_type = self.get("/dumps/gna-1988.ndjson")
        self.assertEqual("application/x-ndjson", content_type)
        self.assertEqual(2, len(dump.splitlines()))
        _, security, _ = self.get("/.well-known/security.txt")
        self.assertTrue(security.startswith(b"Contact:"))

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
