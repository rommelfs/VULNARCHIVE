from __future__ import annotations

import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from fd_sightings.review_ui import ReviewServer
from fd_sightings.store import Store


class ReviewUITest(unittest.TestCase):
    def setUp(self) -> None:
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

    def test_review_ui_has_no_external_connection_endpoint(self) -> None:
        with urllib.request.urlopen(self.base + "/") as response:
            body = response.read().decode()
        self.assertNotIn("Vulnerability-Lookup", body)
        self.assertNotIn("Connection settings", body)
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(self.base + "/connection")
        self.assertEqual(raised.exception.code, 404)
        request = urllib.request.Request(self.base + "/connect", data=b"", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request)
        self.assertEqual(raised.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
