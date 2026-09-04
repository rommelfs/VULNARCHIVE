import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fd_sightings.store import Store


UTC = timezone.utc


class PublicationDateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "dates.sqlite")

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def save(self, identifier, reserved, published, *, source_date="1999-01-01T00:00:00Z"):
        key = f"gcve:{identifier}"
        source = f"https://example.test/{identifier}"
        payload = {
            "cveMetadata": {"vulnId": identifier, "datePublished": published.isoformat()},
            "containers": {"cna": {"x_gcve": [{"x_vulnarchive": {"sourcePublishedAt": source_date}}]}},
        }
        self.store.save_publication(source, key, "gcve", gcve_id=identifier, status="reserved", at=reserved)
        self.store.save_publication(
            source, key, "gcve", gcve_id=identifier, status="published", payload=payload, at=published
        )
        return source, key, payload

    def test_historical_backfill_uses_actual_publication_time(self):
        reserved = datetime(2026, 9, 4, 10, tzinfo=UTC)
        published = reserved + timedelta(seconds=10)
        self.save("GCVE-1988-1999-0001", reserved, published)
        item = self.store.gcve_records()[0]
        self.assertEqual(item["reserved_at"], "2026-09-04T10:00:00.000000Z")
        self.assertEqual(item["published_at"], "2026-09-04T10:00:10.000000Z")
        self.assertEqual(item["updated_at"], item["published_at"])
        self.assertEqual(
            item["record"]["containers"]["cna"]["x_gcve"][0]["x_vulnarchive"]["sourcePublishedAt"],
            "1999-01-01T00:00:00Z",
        )

    def test_since_is_strict_at_boundary_and_includes_immediately_after(self):
        boundary = datetime(2026, 9, 4, 12, tzinfo=UTC)
        self.save("GCVE-1988-2026-0001", boundary - timedelta(seconds=1), boundary)
        self.save("GCVE-1988-2026-0002", boundary, boundary + timedelta(microseconds=1))
        found = [item["gcve_id"] for item in self.store.gcve_records(since="2026-09-04T12:00:00Z")]
        self.assertEqual(found, ["GCVE-1988-2026-0002"])

    def test_since_includes_an_updated_old_record(self):
        old = datetime(2020, 1, 1, tzinfo=UTC)
        source, key, payload = self.save("GCVE-1988-2020-0001", old, old + timedelta(seconds=1))
        changed = {**payload, "revision": 2}
        changed_at = datetime(2026, 9, 4, tzinfo=UTC)
        self.store.save_publication(
            source, key, "gcve", gcve_id="GCVE-1988-2020-0001", status="published",
            payload=changed, at=changed_at,
        )
        found = self.store.gcve_records(since="2026-01-01T00:00:00Z")
        self.assertEqual([item["gcve_id"] for item in found], ["GCVE-1988-2020-0001"])
        self.assertEqual(found[0]["updated_at"], "2026-09-04T00:00:00.000000Z")

    def test_date_sort_modes_and_stable_tie_breaker(self):
        same = datetime(2026, 9, 4, tzinfo=UTC)
        self.save("GCVE-1988-2026-0002", same, same)
        self.save("GCVE-1988-2026-0001", same, same)
        expected = ["GCVE-1988-2026-0001", "GCVE-1988-2026-0002"]
        for date_sort in ("", "published", "updated", "reserved"):
            with self.subTest(date_sort=date_sort):
                self.assertEqual(
                    [item["gcve_id"] for item in self.store.gcve_records(date_sort=date_sort)], expected
                )

    def test_rejects_invalid_or_timezone_less_parameters(self):
        with self.assertRaises(ValueError):
            self.store.gcve_records(date_sort="source")
        with self.assertRaises(ValueError):
            self.store.gcve_records(since="2026-09-04T00:00:00")


if __name__ == "__main__":
    unittest.main()
