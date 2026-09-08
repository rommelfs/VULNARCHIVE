from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fd_sightings.models import Extraction, Message
from fd_sightings.store import Store


class ReviewEventTests(unittest.TestCase):
    def test_decisions_are_append_only_and_current_state_is_projected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "events.sqlite")
            try:
                source = "https://example.test/advisory"
                store.save(Message(source, "Advisory"), Extraction(relevant=True), [])
                store.review(source, "rejected", [], note="needs evidence", actor="alice")
                store.review(
                    source, "approved", ["cve-2026-1234"], "seen", "verified", actor="bob",
                )

                self.assertEqual(store.get(source)["review_state"], "approved")
                events = store.review_events(source)
                self.assertEqual([event["review_state"] for event in events], ["approved", "rejected"])
                self.assertEqual(events[0]["actor"], "bob")
                self.assertEqual(events[0]["vulnerability_ids"], ["CVE-2026-1234"])
                self.assertEqual(events[1]["note"], "needs evidence")
            finally:
                store.close()

    def test_existing_review_is_backfilled_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite"
            store = Store(path)
            source = "https://example.test/legacy"
            store.save(Message(source, "Legacy"), Extraction(), [])
            store.db.execute(
                """UPDATE observations SET review_state='rejected', review_note='old',
                reviewed_at='2026-01-02T03:04:05Z' WHERE source_url=?""", (source,),
            )
            store.db.commit()
            store.close()

            reopened = Store(path)
            self.assertEqual(len(reopened.review_events(source)), 1)
            self.assertEqual(reopened.review_events(source)[0]["actor"], "legacy-migration")
            reopened.close()

            reopened_again = Store(path)
            try:
                self.assertEqual(len(reopened_again.review_events(source)), 1)
            finally:
                reopened_again.close()


if __name__ == "__main__":
    unittest.main()
