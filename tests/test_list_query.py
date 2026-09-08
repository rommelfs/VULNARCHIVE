from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fd_sightings.models import Extraction, Match, Message
from fd_sightings.query import ListQuery
from fd_sightings.store import Store


class ListQueryTest(unittest.TestCase):
    def test_validates_collection_parameters(self) -> None:
        for values in (
            {"page": 0}, {"per_page": 101}, {"sort": "body"}, {"order": "DESC"},
            {"status": "pending"}, {"review_state": "unknown"}, {"search": "x" * 201},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                ListQuery(**values)

    def test_store_filters_sorts_and_paginates_in_sql(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "query.sqlite")
            try:
                for number, confidence in ((1, .2), (2, .9), (3, .5)):
                    source = f"https://example.test/{number}"
                    store.save(
                        Message(source, f"Widget {number}", published=f"2026-09-0{number}"),
                        Extraction(relevant=True),
                        [Match(f"CVE-2026-{number:04d}", "candidate", confidence)],
                    )
                first = store.observation_page(ListQuery(per_page=2, sort="confidence", order="desc"))
                second = store.observation_page(ListQuery(page=2, per_page=2, sort="confidence", order="desc"))
                self.assertEqual(first.total, 3)
                self.assertEqual(first.pages, 2)
                self.assertEqual([row["title"] for row in first.items], ["Widget 2", "Widget 3"])
                self.assertEqual([row["title"] for row in second.items], ["Widget 1"])
                searched = store.observation_page(ListQuery(search="Widget 2"))
                self.assertEqual([row["title"] for row in searched.items], ["Widget 2"])
            finally:
                store.close()

    def test_malformed_legacy_json_cannot_blank_the_review_collection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite"
            store = Store(path)
            store.save(Message("https://example.test/broken", "Recoverable"), Extraction(), [])
            store.db.execute(
                "UPDATE observations SET matches_json='', extraction_json='truncated'"
            )
            store.db.commit()
            # Runtime reads are defensive even before a process restart.
            page = store.observation_page(ListQuery(sort="confidence"))
            self.assertEqual(page.items[0]["title"], "Recoverable")
            self.assertEqual(page.items[0]["matches"], [])
            self.assertEqual(page.items[0]["extraction"], {})
            store.close()

            # Startup migration repairs the persisted values for future reads.
            reopened = Store(path)
            try:
                values = reopened.db.execute(
                    "SELECT matches_json, extraction_json FROM observations"
                ).fetchone()
                self.assertEqual(tuple(values), ("[]", "{}"))
            finally:
                reopened.close()
