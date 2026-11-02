from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fd_sightings.cli import main
from fd_sightings.dump import ndjson_lines
from fd_sightings.models import Extraction, Match, Message
from fd_sightings.policy import PublicationPolicy, plan_observation
from fd_sightings.store import Store


class ArchivePublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "archive.sqlite"
        self.urls = [f"https://seclists.org/fulldisclosure/2026/Oct/{i}" for i in range(6)]
        store = Store(self.database)
        try:
            for i, url in enumerate(self.urls):
                store.save(
                    Message(url, f"Widget{i} vulnerability", published="2026-10-30",
                            body=f"Widget{i} affected versions allow remote code execution. " * 15),
                    Extraction(relevant=i != 3, product_hint=f"Widget{i}" if i != 3 else ""),
                    [Match("CVE-2026-1234", "product-title-overlap", 0.6)] if i == 4 else [],
                )
        finally:
            store.close()

    def run_archive(self, *options, urls=None, refresh=False):
        adapter = SimpleNamespace(
            source_id="full-disclosure",
            month=lambda client, year, month: self.urls[:1] if urls is None else urls,
        )
        # Existing observations must not require downloads or lookup requests.
        client = SimpleNamespace(get_text=lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("download failed")))
        output = io.StringIO()
        with patch("fd_sightings.cli._clients", return_value=(client, None, None)), \
                patch("fd_sightings.cli.adapters", return_value=[adapter]), redirect_stdout(output):
            self.assertEqual(main([
                "--db", str(self.database), *(["--refresh"] if refresh else []),
                "archive", "--from-period", "2026-10", *options,
            ]), 0)
        return json.loads(output.getvalue())

    def records(self):
        store = Store(self.database)
        try:
            return [json.loads(line) for line in ndjson_lines(store)]
        finally:
            store.close()

    def test_skipped_posts_publish_without_reanalysis_and_without_unrelated_posts(self):
        result = self.run_archive("--publish")
        self.assertEqual(result["import"]["skipped"], 1)
        self.assertEqual(result["import"]["processed"], 0)
        self.assertEqual(result["publications"][0]["plan"]["action"], "new-advisory")
        records = self.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["containers"]["cna"]["title"], "Widget0 vulnerability")
        self.run_archive("--publish")
        self.assertEqual(self.records(), records)

    def test_import_only_explains_missing_publication(self):
        result = self.run_archive()
        self.assertEqual(result["publication"]["status"], "not-requested")
        self.assertEqual(self.records(), [])

    def test_policy_and_per_month_import_limit_apply_to_publication(self):
        result = self.run_archive("--publish", "--limit", "2", urls=self.urls[3:])
        self.assertEqual(result["import"]["skipped"], 2)
        store = Store(self.database)
        try:
            self.assertEqual(plan_observation(store.get(self.urls[3]), PublicationPolicy()).action, "archive-only")
            self.assertEqual(plan_observation(store.get(self.urls[4]), PublicationPolicy()).action, "review-required")
        finally:
            store.close()
        self.assertEqual(self.records(), [])

    def test_failed_refresh_does_not_publish_stored_analysis(self):
        result = self.run_archive("--publish", refresh=True)
        self.assertEqual(result["import"]["failed"], 1)
        self.assertEqual(result["publications"], [])
        self.assertEqual(self.records(), [])


if __name__ == "__main__":
    unittest.main()
