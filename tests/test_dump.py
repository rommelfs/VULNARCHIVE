from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fd_sightings.dump import ndjson_lines, record_id
from fd_sightings.review_ui import ReviewServer
from fd_sightings.store import Store


def record(identifier: str, *, state: str = "PUBLISHED", description: str = "test") -> dict[str, object]:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"vulnId": identifier, "state": state},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": description}]}},
    }


class FakeClient:
    def __init__(self, pages: list[object]) -> None:
        self.pages = pages
        self.requests: list[dict[str, str]] = []

    def get_json(self, url: str, params: dict[str, str]) -> object:
        self.requests.append(params)
        return self.pages[int(params["page"]) - 1]


class DumpTest(unittest.TestCase):
    def test_dump_and_rest_records_have_identical_ids_and_json(self) -> None:
        api_records = [
            record("GCVE-1988-2025-10", description="Überlauf"),
            record("GCVE-9999-2025-1"),
            record("GCVE-1988-2024-2"),
            record("GCVE-1988-2023-1", state="RESERVED"),
        ]
        client = FakeClient([{"data": api_records[:2]}, {"data": api_records[2:]}, {"data": []}])
        lookup = SimpleNamespace(client=client, base_url="http://lookup")

        with patch("fd_sightings.dump.PAGE_SIZE", 2), ndjson_lines(lookup) as lines:
            body = b"".join(lines)

        self.assertTrue(body.endswith(b"\n"))
        self.assertNotIn(b"\n\n", body)
        dumped = [json.loads(line) for line in body.decode("utf-8").splitlines()]
        expected = sorted(
            (item for item in api_records if record_id(item).startswith("GCVE-1988-") and item["cveMetadata"]["state"] == "PUBLISHED"),
            key=record_id,
        )
        self.assertEqual([record_id(item) for item in dumped], [record_id(item) for item in expected])
        self.assertEqual(dumped, expected)
        self.assertEqual(client.requests, [{"page": "1", "per_page": "2"}, {"page": "2", "per_page": "2"}, {"page": "3", "per_page": "2"}])

    def test_http_dump_has_ndjson_content_type_and_no_envelope(self) -> None:
        client = FakeClient([[record("GCVE-1988-2024-1")]])
        lookup = SimpleNamespace(client=client, base_url="http://lookup")
        with tempfile.TemporaryDirectory() as directory:
            store = Store(str(Path(directory) / "test.sqlite"))
            server = ReviewServer(("127.0.0.1", 0), store, lookup)
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            connection = http.client.HTTPConnection(*server.server_address)
            connection.request("GET", "/dumps/gna-1988.ndjson")
            response = connection.getresponse()
            body = response.read()
            thread.join(timeout=2)
            server.server_close()
            store.close()

        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers.get_content_type(), "application/x-ndjson")
        self.assertEqual(json.loads(body), record("GCVE-1988-2024-1"))
        self.assertTrue(body.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
