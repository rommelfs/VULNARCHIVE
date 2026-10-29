from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from fd_sightings.cli import main
from fd_sightings.http import HTTPError
from fd_sightings.sources import SOURCES
from fd_sightings.store import Store


class ArchiveFailureTests(unittest.TestCase):
    def run_archive(self, sources, months, failure=None):
        url = "https://seclists.org/fulldisclosure/2026/Oct/0"
        client = Mock()
        client.get_text.return_value = (
            '<html><head><meta name="Subject" content="List announcement">'
            '</head><body><pre>Mailing list announcement.</pre></body></html>'
        )
        output, errors = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "archive.sqlite")
            args = ["--db", db, "archive", "--from-period", "2026-10",
                    "--to-period", months]
            for source in sources:
                args.extend(["--source", source])
            with (patch("fd_sightings.cli._clients", return_value=(client, Mock(), None)),
                  patch.object(type(SOURCES["full-disclosure"]), "month",
                               return_value=[url]) as full_disclosure,
                  patch.object(type(SOURCES["bugtraq"]), "month",
                               side_effect=failure) as bugtraq,
                  redirect_stdout(output), redirect_stderr(errors)):
                status = main(args)
            with_store = Store(db)
            try:
                stored = with_store.get(url)
            finally:
                with_store.close()
        return status, json.loads(output.getvalue()), errors.getvalue(), stored, full_disclosure, bugtraq

    def test_failed_source_keeps_imported_messages_and_prints_summary(self):
        status, summary, errors, stored, _, _ = self.run_archive(
            ["full-disclosure", "bugtraq"], "2026-10",
            RuntimeError("connection refused"),
        )
        self.assertEqual(status, 1)
        self.assertIsNotNone(stored)
        self.assertEqual(summary["processed"], 1)
        self.assertEqual(summary["failed"], 0)  # Message and listing failures are distinct.
        self.assertEqual(summary["failed_archives"], 1)
        self.assertEqual(summary["archive_errors"], [{
            "source": "bugtraq", "period": "2026-10", "error": "connection refused",
        }])
        self.assertIn("Archive listing failed for bugtraq 2026-10", errors)
        self.assertNotIn("Traceback", errors)

    def test_failed_listing_does_not_block_later_months_or_sources(self):
        status, summary, _, stored, full_disclosure, bugtraq = self.run_archive(
            ["bugtraq", "full-disclosure"], "2026-11",
            [HTTPError(503, "Service Unavailable"), []],
        )
        self.assertEqual(status, 1)
        self.assertEqual(summary["failed_archives"], 1)
        self.assertEqual(summary["processed"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertIsNotNone(stored)
        self.assertEqual(full_disclosure.call_count, 2)
        self.assertEqual(bugtraq.call_count, 2)
        self.assertEqual(bugtraq.call_args.args[1:], (2026, 11))

    def test_successful_archive_still_exits_zero(self):
        status, summary, errors, stored, _, _ = self.run_archive(
            ["full-disclosure"], "2026-10",
        )
        self.assertEqual(status, 0)
        self.assertEqual(summary["processed"], 1)
        self.assertEqual(summary["failed_archives"], 0)
        self.assertEqual(summary["archive_errors"], [])
        self.assertIsNotNone(stored)
        self.assertNotIn("Archive listing failed", errors)
