import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fd_sightings.store import Store


def record(identifier: str, updated: str, *, product: str = "Widget", cwe: str = "CWE-79") -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "vulnId": identifier,
            "state": "PUBLISHED",
            "assignerShortName": "VULNARCHIVE",
            "datePublished": "2026-01-01T00:00:00Z",
            "dateUpdated": updated,
        },
        "containers": {"cna": {
            "affected": [{"vendor": "Example Corp", "product": product}],
            "problemTypes": [{"descriptions": [{"cweId": cwe}]}],
            "x_gcve": [{"recordType": "analysis"}],
        }},
    }


class GCVEStoreTests(unittest.TestCase):
    def test_reservations_are_atomic_and_scoped_by_year(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gcve.sqlite"
            Store(path).close()  # Complete schema creation before concurrent connections.

            def reserve(_: int) -> str:
                store = Store(path)
                try:
                    return store.reserve_gcve_id(2026)
                finally:
                    store.close()

            with ThreadPoolExecutor(max_workers=8) as pool:
                identifiers = list(pool.map(reserve, range(20)))
            self.assertEqual(len(set(identifiers)), 20)
            self.assertEqual(sorted(int(item.rsplit("-", 1)[1]) for item in identifiers), list(range(1, 21)))
            store = Store(path)
            try:
                self.assertEqual(store.reserve_gcve_id(2025), "GCVE-1988-2025-0001")
            finally:
                store.close()

    def test_publish_filter_update_and_deterministic_dump(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "gcve.sqlite")
            try:
                second_id = store.reserve_gcve_id(2026)
                first_id = store.reserve_gcve_id(2025)
                second = record(second_id, "2026-03-02T00:00:00Z", product="Gadget", cwe="CWE-89")
                first = record(first_id, "2026-03-01T00:00:00Z")
                store.publish_gcve_record("https://example.test/2", second)
                store.publish_gcve_record("https://example.test/1", first)

                self.assertEqual(store.query_gcve_records(product=" widget "), [first])
                self.assertEqual(store.query_gcve_records(vendor="EXAMPLE CORP", cwe="cwe-89"), [second])
                self.assertEqual(store.query_gcve_records(since="2026-03-02T00:00:00Z"), [second])
                self.assertEqual(store.dump_gcve_records(), [first, second])

                updated = record(first_id, "2026-03-03T00:00:00Z", product="Widget 2")
                store.update_gcve_record(first_id, updated)
                self.assertEqual(store.dump_gcve_records(), [second, updated])
                with self.assertRaises(sqlite3.IntegrityError):
                    store.publish_gcve_record("https://example.test/duplicate", updated)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
