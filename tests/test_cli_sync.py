from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from xml.etree.ElementTree import ParseError

from fd_sightings.cli import main
from fd_sightings.dump import ndjson_lines
from fd_sightings.models import Extraction, Message
from fd_sightings.policy import PublicationPolicy
from fd_sightings.store import Store


class AutomaticSyncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "sync.sqlite"
        self.client = Mock()
        self.client.get_text.return_value = "source evidence"
        self.lookup = SimpleNamespace(match=lambda *args, **kwargs: [])

    @staticmethod
    def message(url, source_id="full-disclosure"):
        return Message(
            url, "Widget 1.0 Remote Code Execution", published="2026-11-02",
            body="Affected versions of Widget allow remote code execution via a crafted request payload. " * 12,
            source_id=source_id,
        )

    def adapter(self, source_id, urls=None, error=None):
        return SimpleNamespace(
            source_id=source_id, has_current_feed=True,
            feed=Mock(side_effect=error, return_value=urls or []),
            parse=lambda html, url: self.message(url, source_id),
        )

    def seed(self, url):
        store = Store(self.database)
        try:
            store.save(self.message(url), Extraction(relevant=True, product_hint="Widget"), [])
        finally:
            store.close()

    def sync(self, adapters, *options):
        output = io.StringIO()
        with (patch("fd_sightings.cli._clients", return_value=(self.client, self.lookup, None)),
              patch("fd_sightings.cli.adapters", return_value=adapters),
              patch("fd_sightings.policy.PublicationPolicy.from_env", return_value=PublicationPolicy()),
              redirect_stdout(output), redirect_stderr(io.StringIO())):
            status = main(["--db", str(self.database), "sync", *options])
        return status, json.loads(output.getvalue())

    def records(self):
        store = Store(self.database)
        try:
            return [json.loads(line) for line in ndjson_lines(store)]
        finally:
            store.close()

    def test_failed_first_feed_does_not_block_later_source_or_stored_publication(self):
        self.seed("https://example.test/old")
        failed = self.adapter("bugtraq", error=RuntimeError("unavailable"))
        healthy = self.adapter("full-disclosure", ["https://example.test/new"])
        status, output = self.sync([failed, healthy])
        self.assertEqual(status, 1)
        self.assertEqual(output["import"]["processed"], 1)
        self.assertEqual(output["import"]["feed_errors"], [{"source": "bugtraq", "error": "unavailable"}])
        self.assertEqual(len(self.records()), 2)
        healthy.feed.assert_called_once()

    def test_all_feeds_failing_still_publish_stored_observations(self):
        self.seed("https://example.test/old")
        status, output = self.sync([self.adapter("bugtraq", error=ParseError("malformed feed"))])
        self.assertEqual(status, 1)
        self.assertEqual(output["import"]["failed_feeds"], 1)
        self.assertEqual(len(self.records()), 1)

    def test_new_posts_are_fetched_and_published_idempotently(self):
        adapter = self.adapter("full-disclosure", ["https://example.test/new"])
        status, output = self.sync([adapter])
        self.assertEqual(status, 0)
        self.assertEqual(output["import"]["processed"], 1)
        first = self.records()
        self.assertEqual(len(first), 1)
        status, output = self.sync([adapter])
        self.assertEqual(status, 0)
        self.assertEqual(output["import"]["skipped"], 1)
        self.assertEqual(self.client.get_text.call_count, 1)
        self.assertEqual(self.records(), first)

    def test_retry_recovers_failed_refresh_even_when_post_has_left_the_feed(self):
        url = "https://example.test/retry"
        store = Store(self.database)
        try:
            store.save(self.message(url), Extraction(), [])
            store.record_import_failure(url, "full-disclosure", "previous failed refresh")
            store.record_import_failure("https://example.test/other", "bugtraq", "other source")
        finally:
            store.close()
        status, output = self.sync([self.adapter("full-disclosure")], "--retry-failed")
        self.assertEqual(status, 0)
        self.assertEqual(output["import"]["processed"], 1)
        self.assertEqual(len(self.records()), 1)
        store = Store(self.database)
        try:
            self.assertEqual(store.import_failures(["full-disclosure"]), [])
            self.assertEqual(len(store.import_failures(["bugtraq"])), 1)
        finally:
            store.close()

    def test_failed_retry_is_attempted_once_per_sync_and_other_posts_publish(self):
        bad, good = "https://example.test/bad", "https://example.test/good"
        store = Store(self.database)
        try:
            store.record_import_failure(bad, "full-disclosure", "unavailable")
        finally:
            store.close()

        def download(url, **kwargs):
            if url == bad:
                raise RuntimeError("still unavailable")
            return "source evidence"

        self.client.get_text.side_effect = download
        status, output = self.sync([self.adapter("full-disclosure", [bad, good])], "--retry-failed")
        self.assertEqual(status, 1)
        self.assertEqual(output["import"]["failed"], 1)
        self.assertEqual(output["import"]["processed"], 1)
        self.assertEqual(self.client.get_text.call_count, 2)
        self.assertEqual(len(self.records()), 1)


if __name__ == "__main__":
    unittest.main()
