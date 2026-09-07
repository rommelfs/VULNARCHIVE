from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fd_sightings.dump import ndjson_lines, record_id
from fd_sightings.store import Store


def record(identifier: str, description: str = "test") -> dict[str, object]:
    return {
        "dataType": "CVE_RECORD", "dataVersion": "5.2",
        "cveMetadata": {"vulnId": identifier, "state": "PUBLISHED",
                        "datePublished": "2026-01-01T00:00:00Z",
                        "dateUpdated": "2026-01-01T00:00:00Z"},
        "containers": {"cna": {"descriptions": [{"lang": "en", "value": description}]}},
    }


class DumpTest(unittest.TestCase):
    def test_dump_uses_canonical_local_store_and_compact_ndjson(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "test.sqlite")
            try:
                records = [record("GCVE-1988-2026-0002", "Überlauf"),
                           record("GCVE-1988-2026-0001")]
                for item in records:
                    store.publish_gcve_record("fixture:" + record_id(item), item)
                body = b"".join(ndjson_lines(store))
                dumped = [json.loads(line) for line in body.splitlines()]
                self.assertEqual(store.dump_gcve_records(), dumped)
                self.assertTrue(body.endswith(b"\n"))
                self.assertNotIn(b"\n\n", body)
                self.assertNotIn(b'": ', body)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
