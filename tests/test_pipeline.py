import unittest
import tempfile
from pathlib import Path

from fd_sightings.extract import extract, product_hint
from fd_sightings.parsers import parse_message, parse_month, parse_rss
from fd_sightings.models import Match
from fd_sightings.store import Store
from fd_sightings.vulnerability_lookup import VulnerabilityLookup
from fd_sightings.policy import PublicationPolicy, plan_observation
from fd_sightings.publication import build_gcve_record, execute_automatic_publication, publication_year, public_archive_url, validate_gcve_record
from fd_sightings.cli import make_parser


class FakeClient:
    def get_json(self, url, params=None):
        return {"instance": {"name": "test"}}

    def request(self, url, **kwargs):
        return 200, '{"login":"analyst"}', {}


MESSAGE_HTML = """
<html><head><meta name="Subject" content="Flextype v1.0 RCE"/>
<meta name="Author" content="Ron E"/></head><body>
<h1 class="m-title">Flextype v1.0 RCE</h1>
<em>Date</em>: Thu, 03 Sep 2026 10:00:00 +0000<br>
<pre>Proof of Concept
POST /api/v1/query HTTP/1.1
Payload: CVE-2026-77939 CWE-94
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
marker_exists=yes
<a href="https://example.test/poc">PoC</a></pre>
</body></html>
"""


class ParserTests(unittest.TestCase):
    def test_message_and_extraction(self):
        message = parse_message(MESSAGE_HTML, "https://seclists.org/fulldisclosure/2026/Sep/27")
        self.assertEqual(message.author, "Ron E")
        self.assertIn("POST /api/v1/query", message.body)
        self.assertEqual(message.links, ["https://example.test/poc"])
        result = extract(message)
        self.assertEqual(result.cve_ids, ["CVE-2026-77939"])
        self.assertEqual(result.cwe_ids, ["CWE-94"])
        self.assertEqual(result.product_hint, "Flextype")
        self.assertEqual(result.proposed_type, "published-proof-of-concept")
        self.assertTrue(result.relevant)

    def test_month(self):
        html = '<blockquote><a name="1" href="1">one</a><a href="2">two</a></blockquote><a href="3">no</a>'
        self.assertEqual(parse_month(html, "https://seclists.org/fulldisclosure/2026/Sep/date.html"), [
            "https://seclists.org/fulldisclosure/2026/Sep/1",
            "https://seclists.org/fulldisclosure/2026/Sep/2",
        ])

    def test_rss(self):
        xml = '<rss><channel><item><link>https://example.test/1</link></item><item><guid>https://example.test/2</guid></item></channel></rss>'
        self.assertEqual(parse_rss(xml), ["https://example.test/1", "https://example.test/2"])

    def test_sync_command_is_available(self):
        args = make_parser().parse_args(["sync"])
        self.assertEqual(args.command, "sync")

    def test_product_hint(self):
        self.assertEqual(product_hint("[ADVISORY] Cisco Catalyst 8000V v1.2 RCE"), "Cisco Catalyst 8000V")

    def test_review_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "review.sqlite")
            try:
                message = parse_message(MESSAGE_HTML, "https://seclists.org/fulldisclosure/2026/Sep/27")
                result = extract(message)
                store.save(message, result, [Match("CVE-2026-77939", "explicit-id", 1.0, "Flextype")])
                store.review(message.source_url, "approved", "CVE-2026-77939", "published-proof-of-concept", "verified")
                approved = store.approved()
                self.assertEqual(len(approved), 1)
                self.assertEqual(approved[0]["review_state"], "approved")
                store.record_submission(message.source_url, "CVE-2026-77939", "published-proof-of-concept", {"ok": True})
                self.assertEqual(store.approved(), [])
            finally:
                store.close()

    def test_authenticated_connection_status(self):
        lookup = VulnerabilityLookup(FakeClient(), "https://vulnerability.example", "secret")
        status = lookup.connection_status()
        self.assertTrue(status["reachable"])
        self.assertTrue(status["authenticated"])
        self.assertEqual(status["login"], "analyst")

    def test_read_only_connection_status(self):
        lookup = VulnerabilityLookup(FakeClient(), "https://vulnerability.example")
        status = lookup.connection_status()
        self.assertTrue(status["reachable"])
        self.assertFalse(status["authenticated"])

    def test_publication_policy_known_id_creates_context_and_sighting(self):
        row = {
            "source_url": "https://seclists.org/fulldisclosure/2026/Sep/27",
            "title": "Flextype RCE",
            "published": "Thu, 03 Sep 2026 10:00:00 +0000",
            "body": "Proof of Concept\nPOST /api/v1/query HTTP/1.1\n" + "A" * 600,
            "links": ["https://example.test/poc"],
            "extraction": {
                "relevant": True, "product_hint": "Flextype", "poc_score": 5,
                "poc_evidence": ["explicit PoC wording"], "cwe_ids": ["CWE-94"],
                "cvss_vectors": [], "proposed_type": "published-proof-of-concept",
            },
            "matches": [{"vulnerability_id": "CVE-2026-77939"}],
        }
        plan = plan_observation(row, PublicationPolicy())
        self.assertEqual(plan.action, "context-and-sightings")
        self.assertEqual(plan.record_type, "analysis")
        self.assertEqual(plan.targets, ("CVE-2026-77939",))
        self.assertEqual(publication_year(row), 2026)
        self.assertEqual(
            public_archive_url(row, PublicationPolicy()),
            "https://vuln.freearchive.org/archive/full-disclosure/2026/Sep/27",
        )

    def test_unmatched_relevant_post_creates_new_advisory_plan(self):
        row = {
            "source_url": "https://example.test/post",
            "title": "Widget buffer overflow",
            "published": "2014-02-03T10:00:00Z",
            "body": "buffer overflow payload " + "B" * 600,
            "links": [],
            "extraction": {
                "relevant": True, "product_hint": "Widget", "poc_score": 3,
                "poc_evidence": [], "cwe_ids": [], "cvss_vectors": [],
                "proposed_type": "published-proof-of-concept",
            },
            "matches": [],
        }
        plan = plan_observation(row, PublicationPolicy())
        self.assertEqual(plan.action, "new-advisory")
        self.assertEqual(publication_year(row), 2014)

    def test_gcve_record_has_relationship_and_archive_provenance(self):
        row = {
            "source_url": "https://seclists.org/fulldisclosure/2026/Sep/27",
            "content_hash": "abc123", "source_format": "text/html", "message_id": "<x@example>",
            "title": "Flextype RCE", "author": "Researcher",
            "published": "Thu, 03 Sep 2026 10:00:00 +0000", "body": "technical body",
            "links": [],
            "extraction": {"product_hint": "Flextype", "cwe_ids": ["CWE-94"]},
            "matches": [{"vulnerability_id": "CVE-2026-77939", "method": "explicit-id", "confidence": 1.0}],
        }
        from fd_sightings.policy import PublicationPlan
        plan = PublicationPlan(row["source_url"], 8, "context-and-sightings", ("CVE-2026-77939",), "seen", "analysis")
        record = build_gcve_record(row, "GCVE-1988-2026-0001", plan, PublicationPolicy())
        self.assertEqual(record["cveMetadata"]["vulnId"], "GCVE-1988-2026-0001")
        x_gcve = record["containers"]["cna"]["x_gcve"][0]
        self.assertEqual(x_gcve["relationships"][0]["type"], "related")
        self.assertEqual(x_gcve["x_vulnarchive"]["contentSha256"], "abc123")
        self.assertEqual(x_gcve["x_vulnarchive"]["archiveUrl"], "https://vuln.freearchive.org/archive/full-disclosure/2026/Sep/27")
        self.assertEqual(x_gcve["x_vulnarchive"]["sourcePublishedAt"], "2026-09-03T10:00:00Z")
        self.assertNotEqual(record["cveMetadata"]["datePublished"], x_gcve["x_vulnarchive"]["sourcePublishedAt"])

    def test_inferred_match_uses_possibly_related(self):
        row = {
            "source_url": "https://example.test/report", "content_hash": "hash",
            "title": "Widget issue", "published": "2024-01-01T00:00:00Z",
            "body": "technical description", "links": [],
            "extraction": {"product_hint": "Widget", "cwe_ids": []},
            "matches": [{"vulnerability_id": "CVE-2024-1234", "method": "product-title-overlap", "confidence": 0.81}],
        }
        from fd_sightings.policy import PublicationPlan
        plan = PublicationPlan(row["source_url"], 5, "context-and-sightings", ("CVE-2024-1234",), "seen", "reference")
        record = build_gcve_record(row, "GCVE-1988-2024-0001", plan, PublicationPolicy())
        relationship = record["containers"]["cna"]["x_gcve"][0]["relationships"][0]
        self.assertEqual(relationship["type"], "possibly_related")

    def test_dry_run_does_not_write_publication_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "auto.sqlite")
            try:
                message = parse_message(MESSAGE_HTML, "https://seclists.org/fulldisclosure/2026/Sep/27")
                result = extract(message)
                store.save(message, result, [Match("CVE-2026-77939", "explicit-id", 1.0, "Flextype")])
                outcomes = execute_automatic_publication(store, PublicationPolicy(min_body_chars=20), dry_run=True)
                self.assertEqual(len(outcomes), 1)
                self.assertEqual(store.publication_rows(), [])
                self.assertTrue(any(item["kind"] == "gcve" for item in outcomes[0]["operations"]))
            finally:
                store.close()

    def test_automatic_publication_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "publish.sqlite")
            try:
                message = parse_message(MESSAGE_HTML, "https://seclists.org/fulldisclosure/2026/Sep/27")
                result = extract(message)
                store.save(message, result, [Match("CVE-2026-77939", "explicit-id", 1.0, "Flextype")])
                policy = PublicationPolicy(min_body_chars=20)
                first = execute_automatic_publication(store, policy)
                self.assertTrue(any(op.get("id") == "GCVE-1988-2026-0001" for op in first[0]["operations"]))
                execute_automatic_publication(store, policy)
                self.assertEqual(len(store.publication_rows()), 3)
                records = store.bcp03_publications()
                self.assertEqual(records[0]["cveMetadata"]["vulnId"], "GCVE-1988-2026-0001")
                validate_gcve_record(records[0])
            finally:
                store.close()

    def test_local_reservation_is_reused_and_record_ledger_commit_together(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "transaction.sqlite")
            try:
                first = store.reserve_gcve("source", "gcve:advisory", 1988, 2026)
                repeated = store.reserve_gcve("source", "gcve:advisory", 1988, 2026)
                self.assertEqual(first, repeated)
                self.assertEqual(first, "GCVE-1988-2026-0001")
                with self.assertRaises(ValueError):
                    store.publish_gcve("source", "gcve:advisory", "GCVE-1988-2026-9999", {})
                self.assertEqual(store.bcp03_publications(), [])
                self.assertEqual(store.publication("source", "gcve:advisory")["status"], "reserved")
            finally:
                store.close()

    def test_invalid_bcp05_record_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "BCP-05-1.7"):
            validate_gcve_record({"dataType": "CVE_RECORD"})

    def test_publication_limit_skips_completed_old_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "limit.sqlite")
            try:
                first = parse_message(MESSAGE_HTML, "https://seclists.org/fulldisclosure/2026/Sep/1")
                second = parse_message(MESSAGE_HTML, "https://seclists.org/fulldisclosure/2026/Sep/2")
                result = extract(first)
                match = Match("CVE-2026-77939", "explicit-id", 1.0, "Flextype")
                store.save(first, result, [match])
                store.save(second, result, [match])
                key = "sighting:CVE-2026-77939:published-proof-of-concept"
                store.save_publication(first.source_url, key, "sighting", target_id=match.vulnerability_id, status="published")
                policy = PublicationPolicy(publish_context_records=False, min_body_chars=20)
                outcomes = execute_automatic_publication(store, policy, limit=1)
                self.assertEqual(outcomes[0]["plan"]["source_url"], second.source_url)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
