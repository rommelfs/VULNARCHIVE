#!/usr/bin/env python3
"""Exercise the BCP-03 API against an isolated, local VULNARCHIVE store.

This is deliberately a hermetic contract test. It starts the production public
server against a temporary canonical SQLite store and needs no credentials.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fd_sightings.public_ui import PublicServer
from fd_sightings.store import Store


MAX_PER_PAGE = 100
LOCAL_ORG = "00000000-0000-4000-8000-000000001988"
FOREIGN_ORG = "00000000-0000-4000-8000-000000000001"
DATE_FIELDS = {"published": "datePublished", "updated": "dateUpdated"}
SORT_ORDERS = ("asc", "desc")


class CheckFailure(RuntimeError):
    pass


def gcve_base(http: Any) -> str:
    """Validate and return the GCVE base advertised by security.txt."""
    status, body, headers = http.request("/.well-known/security.txt")
    if status != 200:
        raise CheckFailure(f"security.txt returned HTTP {status}")
    if headers.get("Content-Type", "").lower() != "text/plain; charset=utf-8":
        raise CheckFailure("security.txt must use Content-Type 'text/plain; charset=utf-8'")
    values = [line.partition(":")[2].strip() for line in body.decode("utf-8").splitlines()
              if line.lower().startswith("gcve:")]
    if len(values) != 1:
        raise CheckFailure("security.txt must contain exactly one GCVE field")
    parsed = urllib.parse.urlsplit(values[0])
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise CheckFailure("security.txt GCVE field must be an absolute HTTPS base URL")
    return values[0].rstrip("/")


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


class PublicationContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.previous_org = os.environ.get("VA_GNA_ORG_UUID")
        os.environ["VA_GNA_ORG_UUID"] = LOCAL_ORG
        cls.temporary = tempfile.TemporaryDirectory(prefix="vulnarchive-bcp03-")
        cls.store = Store(Path(cls.temporary.name) / "vulnarchive.sqlite")
        records = [make_record(i,
                               assigner="CaseSensitiveAssigner" if i == 17 else "VULNARCHIVE",
                               product="MixedCaseProduct" if i == 17 else "ArchiveWidget",
                               cwe="CWE-89" if i == 17 else "CWE-79",
                               source="SPECIAL-SOURCE" if i == 17 else "VULNARCHIVE")
                   for i in range(1, 136)]
        records.extend((make_record(900, state="RESERVED"), make_record(901, org_id=FOREIGN_ORG)))
        for record in records:
            cls.store.publish_gcve_record("fixture:" + record_id(record), record)
        cls.server = PublicServer(("127.0.0.1", 0), cls.store)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.store.close()
        cls.temporary.cleanup()
        if cls.previous_org is None:
            os.environ.pop("VA_GNA_ORG_UUID", None)
        else:
            os.environ["VA_GNA_ORG_UUID"] = cls.previous_org

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
