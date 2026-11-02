import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from fd_sightings.cli import main
from fd_sightings.models import Extraction, Message
from fd_sightings.relevance_audit import audit_relevance
from fd_sightings.store import Store


class RelevanceAuditTests(unittest.TestCase):
    def test_audit_covers_all_negative_rows_without_network_or_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "archive.sqlite"
            store = Store(database)
            try:
                for title, relevant, source in (
                    ("Widget Integer Overflow", False, "full-disclosure"),
                    ("Widget community meeting", False, "full-disclosure"),
                    ("Widget security update", False, "bugtraq"),
                    ("Widget already recognized", True, "full-disclosure"),
                ):
                    store.save(Message(f"https://example.test/{title.replace(' ', '-')}", title, source_id=source),
                               Extraction(relevant=relevant), [])
            finally:
                store.close()
            before = database.read_bytes()
            output = io.StringIO()
            with patch("fd_sightings.cli._clients", side_effect=AssertionError("no network")), \
                    patch.object(Store, "__init__", side_effect=AssertionError("no migrations")), redirect_stdout(output):
                self.assertEqual(main(["--db", str(database), "audit-relevance"]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["scanned"], 4)
            self.assertEqual(report["stored_non_relevant"], 3)
            self.assertEqual(report["newly_relevant"], 2)
            self.assertEqual(report["still_non_relevant"], 1)
            self.assertEqual(len(report["observations"]), 3)
            self.assertEqual(database.read_bytes(), before)
            filtered = audit_relevance(database, sources=["bugtraq"])
            self.assertEqual(filtered["scanned"], 1)
            self.assertEqual(filtered["newly_relevant"], 1)

    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "missing.sqlite"
            with self.assertRaises(sqlite3.OperationalError):
                audit_relevance(database)
            self.assertFalse(database.exists())

    def test_invalid_extraction_is_reported_instead_of_silently_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "archive.sqlite"
            store = Store(database)
            store.save(Message("https://example.test/report", "Widget Integer Overflow"), Extraction(), [])
            store.db.execute("UPDATE observations SET extraction_json='invalid'")
            store.db.commit()
            store.close()
            report = audit_relevance(database)
            self.assertEqual(report["invalid_stored_extraction"], 1)
            self.assertEqual(report["newly_relevant"], 1)


if __name__ == "__main__":
    unittest.main()
