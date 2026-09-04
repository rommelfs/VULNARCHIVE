#!/usr/bin/env python3
"""Exercise the BCP-03 API against an isolated, local VULNARCHIVE store.

This is deliberately a hermetic contract test.  It neither needs credentials nor
writes to a running Vulnerability-Lookup instance.  The HTTP fixture reads the
records from a temporary NDJSON store, just like the public feed and dump do.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


MAX_PER_PAGE = 100
LOCAL_ORG = "00000000-0000-4000-8000-000000001988"
FOREIGN_ORG = "00000000-0000-4000-8000-000000000001"
DATE_FIELDS = {"published": "datePublished", "updated": "dateUpdated"}
SORT_ORDERS = ("asc", "desc")


def timestamp(day: int, hour: int = 0) -> str:
    value = datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(days=day, hours=hour)
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def make_record(
    serial: int,
    *,
    state: str = "PUBLISHED",
    org_id: str = LOCAL_ORG,
    assigner: str = "VULNARCHIVE",
    product: str = "ArchiveWidget",
    cwe: str = "CWE-79",
    source: str = "VULNARCHIVE",
) -> dict[str, Any]:
    """Create a complete, deterministic CVE 5 / BCP-05 fixture."""
    published, updated = timestamp(serial), timestamp(serial, 6)
    identifier = f"GCVE-1988-2025-{serial:06d}"
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "vulnId": identifier,
            "state": state,
            "assignerOrgId": org_id,
            "assignerShortName": assigner,
            "datePublished": published,
            "dateUpdated": updated,
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": org_id,
                    "shortName": source,
                    "dateUpdated": updated,
                },
                "title": f"VULNARCHIVE fixture {serial}",
                "descriptions": [{"lang": "en", "value": f"Complete fixture record {serial}."}],
                "affected": [{
                    "vendor": "FreeArchive",
                    "product": product,
                    "versions": [{"version": "1.0", "status": "affected"}],
                }],
                "problemTypes": [{"descriptions": [{"lang": "en", "cweId": cwe, "description": cwe}]}],
                "references": [{"url": f"https://vuln.freearchive.org/archive/{serial}"}],
                "x_gcve": [{"vulnId": identifier, "recordType": "advisory", "relationships": []}],
            }
        },
    }


def record_id(record: dict[str, Any]) -> str:
    return str(record["cveMetadata"]["vulnId"])


def validate_bcp05(record: dict[str, Any]) -> None:
    """Check all structural fields consumers need from a complete BCP-05 record."""
    assert record["dataType"] == "CVE_RECORD"
    assert isinstance(record["dataVersion"], str)
    metadata = record["cveMetadata"]
    for field in ("vulnId", "state", "assignerOrgId", "assignerShortName", "datePublished", "dateUpdated"):
        assert isinstance(metadata[field], str) and metadata[field]
    for field in ("datePublished", "dateUpdated"):
        datetime.fromisoformat(metadata[field].replace("Z", "+00:00"))
    cna = record["containers"]["cna"]
    assert cna["providerMetadata"]["orgId"]
    assert cna["providerMetadata"]["shortName"]
    assert cna["descriptions"] and cna["descriptions"][0]["lang"]
    assert cna["affected"] and cna["affected"][0]["versions"]
    assert cna["problemTypes"][0]["descriptions"][0]["cweId"]
    assert cna["references"] and cna["references"][0]["url"]
    assert cna["x_gcve"] and cna["x_gcve"][0]["recordType"]
    assert isinstance(cna["x_gcve"][0]["relationships"], list)


class LocalStoreApplication:
    """Small HTTP adapter over the temporary store used only by this test."""

    def __init__(self, store: Path) -> None:
        self.store = store

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.store.read_text(encoding="utf-8").splitlines() if line]

    def publication(self, query: dict[str, list[str]]) -> tuple[int, Any]:
        def one(name: str, default: str) -> str:
            return query.get(name, [default])[-1]

        try:
            page, per_page = int(one("page", "1")), int(one("per_page", "30"))
        except ValueError:
            return 400, {"error": "page and per_page must be integers"}
        date_sort, order = one("date_sort", "published"), one("sort_order", "desc")
        if page < 1 or not 1 <= per_page <= MAX_PER_PAGE or date_sort not in DATE_FIELDS or order not in SORT_ORDERS:
            return 400, {"error": "invalid query parameter"}
        since = one("since", "")
        if since:
            try:
                datetime.fromisoformat(since.replace("Z", "+00:00"))
            except ValueError:
                return 400, {"error": "invalid since timestamp"}

        values = [record for record in self.records()
                  if record["cveMetadata"]["state"] == "PUBLISHED"
                  and record["cveMetadata"]["assignerOrgId"] == LOCAL_ORG]
        field = DATE_FIELDS[date_sort]
        if since:
            values = [record for record in values if record["cveMetadata"][field] >= since]
        source, cwe = one("source", "").casefold(), one("cwe", "").casefold()
        product, assigner = one("product", "").casefold(), one("assigner", "").casefold()
        if source:
            values = [r for r in values if r["containers"]["cna"]["providerMetadata"]["shortName"].casefold() == source]
        if cwe:
            values = [r for r in values if any(
                d.get("cweId", "").casefold() == cwe
                for group in r["containers"]["cna"].get("problemTypes", [])
                for d in group.get("descriptions", []))]
        if product:
            values = [r for r in values if any(product in item.get("product", "").casefold()
                                                for item in r["containers"]["cna"]["affected"])]
        if assigner:
            values = [r for r in values if assigner in r["cveMetadata"]["assignerShortName"].casefold()]
        values.sort(key=lambda r: (r["cveMetadata"][field], record_id(r)), reverse=order == "desc")
        start = (page - 1) * per_page
        return 200, values[start:start + per_page]


class Handler(BaseHTTPRequestHandler):
    app: LocalStoreApplication

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/api/gcve/publication":
            status, value = self.app.publication(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
            self._send(status, json.dumps(value, separators=(",", ":")).encode(), "application/json")
        elif parsed.path == "/dumps/gna-1988.ndjson":
            records = [record for record in self.app.records()
                       if record["cveMetadata"]["state"] == "PUBLISHED"
                       and record["cveMetadata"]["assignerOrgId"] == LOCAL_ORG]
            body = "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records).encode()
            self._send(200, body, "application/x-ndjson")
        else:
            self._send(404, b'{"error":"not found"}', "application/json")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        pass


class PublicationContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="vulnarchive-bcp03-")
        cls.store = Path(cls.temporary.name) / "gna-1988.ndjson"
        records = [make_record(i,
                               assigner="CaseSensitiveAssigner" if i == 17 else "VULNARCHIVE",
                               product="MixedCaseProduct" if i == 17 else "ArchiveWidget",
                               cwe="CWE-89" if i == 17 else "CWE-79",
                               source="SPECIAL-SOURCE" if i == 17 else "VULNARCHIVE")
                   for i in range(1, 136)]
        records.extend((make_record(900, state="RESERVED"), make_record(901, org_id=FOREIGN_ORG)))
        cls.store.write_text("".join(json.dumps(item, separators=(",", ":")) + "\n" for item in records), encoding="utf-8")
        Handler.app = LocalStoreApplication(cls.store)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temporary.cleanup()

    def request(self, **parameters: object) -> tuple[int, Any]:
        url = self.base + "/api/gcve/publication"
        if parameters:
            url += "?" + urllib.parse.urlencode(parameters)
        try:
            response = urllib.request.urlopen(url, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    def successful(self, **parameters: object) -> list[dict[str, Any]]:
        status, value = self.request(**parameters)
        self.assertEqual(status, 200)
        self.assertIsInstance(value, list, "every successful response must be a JSON array")
        return value

    def test_json_array_and_page_sizes(self) -> None:
        self.assertLessEqual(len(self.successful()), 30)
        self.assertEqual(len(self.successful(per_page=100)), 100)
        self.assertIn(self.request(per_page=101)[0], (400, 422))

    def test_all_date_sort_and_sort_order_values(self) -> None:
        for date_sort, field in DATE_FIELDS.items():
            for order in SORT_ORDERS:
                with self.subTest(date_sort=date_sort, sort_order=order):
                    values = self.successful(date_sort=date_sort, sort_order=order, per_page=100)
                    keys = [(r["cveMetadata"][field], record_id(r)) for r in values]
                    self.assertEqual(keys, sorted(keys, reverse=order == "desc"))

    def test_since_uses_selected_publication_or_update_date(self) -> None:
        boundary = timestamp(100, 3)
        published = self.successful(date_sort="published", sort_order="asc", since=boundary, per_page=100)
        updated = self.successful(date_sort="updated", sort_order="asc", since=boundary, per_page=100)
        self.assertTrue(all(r["cveMetadata"]["datePublished"] >= boundary for r in published))
        self.assertTrue(all(r["cveMetadata"]["dateUpdated"] >= boundary for r in updated))
        self.assertNotEqual([record_id(r) for r in published], [record_id(r) for r in updated])

    def test_filters_and_case_insensitive_search(self) -> None:
        expected = "GCVE-1988-2025-000017"
        for parameters in ({"source": "SPECIAL-SOURCE"}, {"cwe": "CWE-89"},
                           {"product": "mixedcaseproduct"}, {"product": "MIXEDCASEPRODUCT"},
                           {"assigner": "casesensitiveassigner"}, {"assigner": "CASESENSITIVEASSIGNER"}):
            with self.subTest(parameters=parameters):
                self.assertEqual([record_id(r) for r in self.successful(**parameters)], [expected])

    def test_pagination_is_stable(self) -> None:
        first = self.successful(page=1, per_page=30, date_sort="updated", sort_order="desc")
        second = self.successful(page=2, per_page=30, date_sort="updated", sort_order="desc")
        combined = self.successful(page=1, per_page=60, date_sort="updated", sort_order="desc")
        self.assertEqual([record_id(r) for r in first + second], [record_id(r) for r in combined])
        self.assertEqual(first, self.successful(page=1, per_page=30, date_sort="updated", sort_order="desc"))

    def test_records_are_complete_and_match_dump(self) -> None:
        feed: list[dict[str, Any]] = []
        for page in (1, 2):
            feed.extend(self.successful(page=page, per_page=100, date_sort="published", sort_order="asc"))
        for record in feed:
            validate_bcp05(record)
        with urllib.request.urlopen(self.base + "/dumps/gna-1988.ndjson", timeout=5) as response:
            dumped = [json.loads(line) for line in response if line.strip()]
        dumped.sort(key=lambda r: (r["cveMetadata"]["datePublished"], record_id(r)))
        self.assertEqual(feed, dumped)

    def test_unpublished_and_foreign_gna_records_are_excluded(self) -> None:
        values = self.successful(page=1, per_page=100) + self.successful(page=2, per_page=100)
        ids = {record_id(record) for record in values}
        self.assertNotIn("GCVE-1988-2025-000900", ids)
        self.assertNotIn("GCVE-1988-2025-000901", ids)
        self.assertTrue(all(r["cveMetadata"]["state"] == "PUBLISHED" for r in values))
        self.assertTrue(all(r["cveMetadata"]["assignerOrgId"] == LOCAL_ORG for r in values))
        with urllib.request.urlopen(self.base + "/dumps/gna-1988.ndjson", timeout=5) as response:
            dump_ids = {record_id(json.loads(line)) for line in response if line.strip()}
        self.assertNotIn("GCVE-1988-2025-000900", dump_ids)
        self.assertNotIn("GCVE-1988-2025-000901", dump_ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
