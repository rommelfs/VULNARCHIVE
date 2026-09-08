from __future__ import annotations

import json
import unittest

from fd_sightings.llm import LLMMatcher
from fd_sightings.models import Extraction, Message
from fd_sightings.vulnerability_lookup import VulnerabilityLookup


class FakeResponsesClient:
    def __init__(self, candidate_id: str = "CVE-2026-1234") -> None:
        self.candidate_id = candidate_id
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = {
            "candidate_id": self.candidate_id,
            "confidence": 0.96,
            "supporting_facts": ["same product and affected version"],
            "contradictions": [],
            "missing_information": ["fixed version"],
        }
        return 200, json.dumps({"id": "resp_test", "output_text": json.dumps(result)}), {}


class LLMMatcherTests(unittest.TestCase):
    record = {
        "cveMetadata": {"vulnId": "CVE-2026-1234"},
        "containers": {"cna": {
            "title": "Widget RCE",
            "descriptions": [{"value": "Widget 1.2 remote code execution"}],
            "affected": [{"product": "Widget", "versions": [{"version": "1.2"}]}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-94"}]}],
        }},
    }

    def test_responses_request_is_bounded_structured_and_not_stored(self):
        client = FakeResponsesClient()
        matcher = LLMMatcher(client, "https://api.example/v1/responses", "secret", "model-test", "shadow")
        decision = matcher.compare(
            Message("https://source.example", "Widget RCE", body="untrusted report", published="2026-01-01"),
            Extraction(product_hint="Widget", affected_versions=["1.2"], cwe_ids=["CWE-94"]),
            [self.record],
        )
        self.assertEqual(decision.candidate_id, "CVE-2026-1234")
        self.assertEqual(decision.prompt_version, "vulnerability-match-v1")
        self.assertEqual(decision.provider, "openai-responses-compatible")
        self.assertEqual(decision.output["confidence"], 0.96)
        self.assertEqual(decision.candidates[0]["id"], "CVE-2026-1234")
        self.assertEqual(decision.response_id, "resp_test")
        _, request = client.calls[0]
        self.assertFalse(request["json_body"]["store"])
        self.assertEqual(request["json_body"]["text"]["format"]["type"], "json_schema")
        self.assertNotIn("untrusted report", request["json_body"]["instructions"])
        self.assertIn("untrusted report", request["json_body"]["input"])
        self.assertEqual(request["headers"], {"Authorization": "Bearer secret"})

    def test_rejects_identifier_outside_candidate_set(self):
        matcher = LLMMatcher(FakeResponsesClient("CVE-2026-9999"), "https://api.example", "secret", "model-test", "review")
        with self.assertRaisesRegex(ValueError, "outside the supplied candidate set"):
            matcher.compare(Message("source", "Widget"), Extraction(product_hint="Widget"), [self.record])

    def test_disabled_without_mode_model_or_key(self):
        self.assertFalse(LLMMatcher(FakeResponsesClient(), "url", "", "model", "shadow").enabled)
        self.assertFalse(LLMMatcher(FakeResponsesClient(), "url", "key", "", "shadow").enabled)
        self.assertFalse(LLMMatcher(FakeResponsesClient(), "url", "key", "model", "off").enabled)

    def test_automatic_mode_enriches_bounded_static_candidate(self):
        class CandidateClient:
            def get_json(inner_self, url, params=None):
                return [self.record]

        matcher = LLMMatcher(FakeResponsesClient(), "https://api.example", "secret", "model-test", "automatic")
        lookup = VulnerabilityLookup(CandidateClient(), "https://vuln.example", llm=matcher)
        matches = lookup.match(
            Message("source", "Widget RCE", body="Widget 1.2 remote code execution"),
            Extraction(product_hint="Widget", affected_versions=["1.2"], cwe_ids=["CWE-94"], relevant=True),
        )
        self.assertEqual(matches[0].method, "llm-automatic")
        self.assertEqual(matches[0].confidence, 0.96)
        self.assertIn("llm-model:model-test", matches[0].evidence)
        self.assertTrue(any(item.startswith("llm-input-sha256:") for item in matches[0].evidence))

    def test_same_product_candidate_is_retained_for_llm_review(self):
        class CandidateClient:
            def get_json(inner_self, url, params=None):
                record = json.loads(json.dumps(self.record))
                record["containers"]["cna"]["title"] = "Unrelated wording"
                return [record]

        matcher = LLMMatcher(FakeResponsesClient(), "https://api.example", "secret", "model-test", "review")
        lookup = VulnerabilityLookup(CandidateClient(), "https://vuln.example", llm=matcher)
        matches = lookup.match(
            Message("source", "Widget security issue", body="Widget issue"),
            Extraction(product_hint="Widget", relevant=True),
        )
        self.assertEqual(matches[0].method, "llm-assisted")
        self.assertEqual(matches[0].vulnerability_id, "CVE-2026-1234")


if __name__ == "__main__":
    unittest.main()
