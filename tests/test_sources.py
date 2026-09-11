from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from fd_sightings.cli import make_parser, period
from fd_sightings.parsers import parse_rss
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
        hyperkitty = '''<html><head><meta property="og:title" content="Widget advisory"></head>
        <body><h1>Widget advisory</h1><span class="sender-name">Researcher</span>
        <time datetime="2026-09-11T10:00:00Z"></time><div class="email-body">
        CVE-2026-1234<br><a href="https://vendor.test/advisory">Details</a></div></body></html>'''
        message = SOURCES["bugtraq"].parse(
            hyperkitty,
            "https://lists.securityfocus.com/hyperkitty/list/bugtraq@securityfocus.com/message/abc/",
        )
        self.assertEqual(message.source_id, "bugtraq")
        self.assertEqual(message.title, "Widget advisory")
        self.assertIn("CVE-2026-1234", message.body)
        self.assertEqual(message.links, ["https://vendor.test/advisory"])
        self.assertTrue(SOURCES["bugtraq"].has_current_feed)
        self.assertIn("bugtraq-ai", SOURCES)

    def test_atom_feed_used_by_hyperkitty(self) -> None:
        atom = '''<feed xmlns="http://www.w3.org/2005/Atom"><entry>
        <link rel="alternate" href="https://lists.example/message/abc/"/></entry></feed>'''
        self.assertEqual(parse_rss(atom), ["https://lists.example/message/abc/"])

    def test_hyperkitty_month_expands_threads_and_ignores_compose_link(self) -> None:
        root = "https://lists.securityfocus.com/hyperkitty/list/bugtraq@securityfocus.com"
        pages = {
            root + "/2026/9/": '''<a href="/hyperkitty/list/bugtraq@securityfocus.com/message/new">Post</a>
                <a href="/hyperkitty/list/bugtraq@securityfocus.com/thread/thread1/">Advisory</a>''',
            root + "/thread/thread1/": '''<a href="/hyperkitty/list/bugtraq@securityfocus.com/message/first1/">permalink</a>''',
            root + "/thread/thread1/replies": '''<a href="/hyperkitty/list/bugtraq@securityfocus.com/message/reply2/">permalink</a>''',
        }

        class Client:
            def get_text(self, url):
                return pages[url]

        self.assertEqual(SOURCES["bugtraq"].month(Client(), 2026, 9), [
            root + "/message/first1/", root + "/message/reply2/",
        ])

    def test_cli_accepts_multiple_sources(self) -> None:
        args = make_parser().parse_args(["rss", "--source", "full-disclosure", "--source", "bugtraq"])
        self.assertEqual(args.sources, ["full-disclosure", "bugtraq"])
        self.assertEqual(period("1993-01"), (1993, 1))
        retry = make_parser().parse_args(["retry-failed", "--source", "bugtraq-ai"])
        self.assertEqual(retry.sources, ["bugtraq-ai"])

    def test_failed_downloads_are_persisted_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "failures.sqlite")
            try:
                store.record_import_failure("https://example.test/1", "bugtraq", "HTTP 503")
                store.record_import_failure("https://example.test/1", "bugtraq", "timeout")
                failure = store.import_failures(["bugtraq"])[0]
                self.assertEqual(failure["attempts"], 2)
                self.assertEqual(failure["error"], "timeout")
                store.clear_import_failure("https://example.test/1")
                self.assertEqual(store.import_failures(), [])
            finally:
                store.close()

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
