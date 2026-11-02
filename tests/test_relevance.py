import json
import tempfile
import unittest
from pathlib import Path

from fd_sightings.dump import ndjson_lines
from fd_sightings.extract import extract
from fd_sightings.models import Message
from fd_sightings.policy import PublicationPolicy, plan_observation
from fd_sightings.publication import execute_automatic_publication
from fd_sightings.store import Store


class RelevanceTests(unittest.TestCase):
    def test_all_eight_observed_missed_reports_are_relevant_with_evidence(self):
        fixture = Path(__file__).parent / "fixtures" / "relevance-missed-reports.json"
        cases = json.loads(fixture.read_text())
        self.assertEqual(len(cases), 8)
        for case in cases:
            with self.subTest(source=case["message"]["source_url"]):
                extraction = extract(Message(**case["message"]))
                self.assertTrue(extraction.relevant)
                self.assertTrue(extraction.relevance_evidence)

    def test_structured_report_requires_impact_and_examples(self):
        for body in ("Description\nAn example\nExamples\nSample code", "Impact\nLow\nExamples\nExample"):
            with self.subTest(body=body):
                self.assertFalse(extract(Message("https://example.test/news", "Widget report", body=body)).relevant)

    def test_identifiers_and_recognized_weaknesses_always_mark_relevance(self):
        for title in ("GHSA-2345-6789-cfgh", "GCVE-1988-2026-0001", "Integer overflow", "Server-side request forgery"):
            with self.subTest(title=title):
                extraction = extract(Message("https://example.test/report", title))
                self.assertTrue(extraction.relevant)
                self.assertTrue(extraction.relevance_evidence)

    def test_code_execution_and_sandbox_escape_are_relevant_without_cve(self):
        for term in ("arbitrary code execution", "arbitrary-code-execution", "sandbox escape", "sandbox-escape"):
            with self.subTest(term=term):
                extraction = extract(Message("https://example.test/report", f"Widget {term}"))
                self.assertTrue(extraction.relevant)
                self.assertEqual(extraction.cve_ids, [])

    def test_code_and_sandbox_alone_do_not_mark_announcements_relevant(self):
        for title in ("Widget code examples", "Widget sandbox setup", "Widget arbitrary configuration"):
            with self.subTest(title=title):
                self.assertFalse(extract(Message("https://example.test/news", title)).relevant)

    def test_struts2_ognl_report_qualifies_and_is_published_after_reanalysis(self):
        fixture = Path(__file__).parent / "fixtures" / "struts2-ognl-sandbox-escape.json"
        message = Message(**json.loads(fixture.read_text()))
        extraction = extract(message)
        self.assertTrue(extraction.relevant)
        self.assertEqual(extraction.cve_ids, [])
        self.assertEqual(extraction.product_hint, "Apache Struts2 Core")
        policy = PublicationPolicy()
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "archive.sqlite")
            try:
                # Reproduce an existing archive row classified by the old code.
                extraction.relevant = False
                store.save(message, extraction, [])
                self.assertEqual(plan_observation(store.get(message.source_url), policy).action, "archive-only")
                self.assertEqual(list(ndjson_lines(store)), [])
                store.save(message, extract(message), [], analysis_trigger="reprocess")
                self.assertEqual(plan_observation(store.get(message.source_url), policy).action, "new-advisory")
                execute_automatic_publication(store, policy)
                records = [json.loads(line) for line in ndjson_lines(store)]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["containers"]["cna"]["title"], message.title)
                execute_automatic_publication(store, policy)
                self.assertEqual(len(list(ndjson_lines(store))), 1)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
