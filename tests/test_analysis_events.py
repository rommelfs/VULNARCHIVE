from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fd_sightings.models import Extraction, Match, Message
from fd_sightings.store import Store


class AnalysisEventTests(unittest.TestCase):
    def test_analysis_runs_are_append_only_and_fully_decoded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "analysis.sqlite")
            try:
                source = "https://example.test/advisory"
                store.save(Message(source, "Widget"), Extraction(relevant=True), [])
                analysis = {
                    "provider": "openai-responses-compatible", "model": "model-test",
                    "prompt_version": "vulnerability-match-v1", "input_sha256": "abc",
                    "response_id": "resp_1", "retrieval_at": "2026-09-08T12:00:00+00:00",
                    "semantic": True, "explicit_ids": [],
                    "candidates": [{"cveMetadata": {"vulnId": "CVE-2026-1234"}}],
                    "deterministic_matches": [Match("CVE-2026-1234", "candidate", .8).as_dict()],
                    "llm_output": {"candidate_id": "CVE-2026-1234", "confidence": .96},
                    "result": [Match("CVE-2026-1234", "llm-assisted", .91).as_dict()],
                }
                store.record_analysis_event(source, "import", analysis)
                store.record_analysis_event(source, "reprocess", {**analysis, "response_id": "resp_2"})

                events = store.analysis_events(source)
                self.assertEqual([event["trigger_name"] for event in events], ["reprocess", "import"])
                self.assertEqual(events[0]["response_id"], "resp_2")
                self.assertEqual(events[0]["context"], {"semantic": True, "explicit_ids": []})
                self.assertEqual(events[0]["llm_output"]["confidence"], .96)
                self.assertEqual(events[0]["candidates"][0]["cveMetadata"]["vulnId"], "CVE-2026-1234")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
