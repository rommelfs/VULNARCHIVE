from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from fd_sightings.cli import make_parser
from fd_sightings.models import Extraction, Message
from fd_sightings.sources import SOURCES, adapters, configured_source_ids
from fd_sightings.store import Store


MESSAGE = """<html><head><meta name="Subject" content="Widget advisory">
<meta name="Message-ID" content="same@example.test"></head><body>
<h1 class="m-title">Widget advisory</h1><pre>CVE-2026-1234</pre></body></html>"""


class SourcesTest(unittest.TestCase):
    def test_registry_exposes_full_disclosure_and_bugtraq(self) -> None:
        self.assertEqual([item.source_id for item in adapters(["bugtraq", "full-disclosure", "bugtraq"])],
                         ["bugtraq", "full-disclosure"])
        message = SOURCES["bugtraq"].parse(MESSAGE, "https://seclists.org/bugtraq/2026/Sep/1")
        self.assertEqual(message.source_id, "bugtraq")
        self.assertEqual(message.message_id, "same@example.test")

    def test_cli_accepts_multiple_sources(self) -> None:
        args = make_parser().parse_args(["rss", "--source", "full-disclosure", "--source", "bugtraq"])
        self.assertEqual(args.sources, ["full-disclosure", "bugtraq"])

    def test_environment_configures_unattended_default_sources(self) -> None:
        with patch.dict("os.environ", {"VA_SOURCES": "bugtraq,full-disclosure,bugtraq"}):
            self.assertEqual(configured_source_ids(), ["bugtraq", "full-disclosure"])
            self.assertEqual([adapter.source_id for adapter in adapters(None)],
                             ["bugtraq", "full-disclosure"])
        with patch.dict("os.environ", {"VA_SOURCES": "unknown"}):
            with self.assertRaises(ValueError):
                configured_source_ids()

    def test_store_migrates_source_metadata_and_deduplicates_message_id_per_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "sources.sqlite")
            try:
                first = Message("https://mirror.test/1", "First", message_id="duplicate@test", source_id="bugtraq")
                second = Message("https://mirror.test/2", "Updated", message_id="duplicate@test", source_id="bugtraq")
                other = Message("https://other.test/1", "FD", message_id="duplicate@test", source_id="full-disclosure")
                for message in (first, second, other):
                    store.save(message, Extraction(relevant=True), [])
                rows = store.rows()
                self.assertEqual(len(rows), 2)
                bugtraq = next(row for row in rows if row["source_id"] == "bugtraq")
                self.assertEqual(bugtraq["source_url"], "https://mirror.test/1")
                self.assertEqual(bugtraq["title"], "Updated")
            finally:
                store.close()
