from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fd_sightings.cli import main, make_parser
from fd_sightings.evaluation import evaluate_cases, load_cases, valid_automatic_gate
from fd_sightings.llm import LLMMatcher, PROMPT_VERSION


FIXTURES = Path(__file__).parent / "fixtures" / "matching"


class EvaluationTests(unittest.TestCase):
    def test_labelled_fixture_suite_passes_gates(self) -> None:
        report = evaluate_cases(load_cases([FIXTURES]))
        self.assertTrue(report.passed)
        self.assertEqual(report.cases, 2)
        self.assertEqual((report.precision, report.recall), (1.0, 1.0))

    def test_false_positive_fails_precision_gate(self) -> None:
        case = load_cases([FIXTURES])[0]
        case["expected_ids"] = []
        report = evaluate_cases([case], min_precision=.99, min_recall=0)
        self.assertFalse(report.passed)
        self.assertEqual(report.false_positive, 1)

    def test_cli_writes_machine_readable_report_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            status = main(["evaluate", str(FIXTURES), "--output", str(target)])
            report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(status, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["prompt_version"], PROMPT_VERSION)
        self.assertEqual(make_parser().parse_args(["evaluate", str(FIXTURES)]).command, "evaluate")

    def test_automatic_mode_requires_current_passing_report(self) -> None:
        class Client:
            pass
        with patch.dict(os.environ, {
            "VA_LLM_MODE": "automatic", "VA_LLM_MODEL": "model-test", "OPENAI_API_KEY": "secret",
            "VA_MATCH_EVALUATION_REPORT": "/missing/report.json",
        }, clear=False):
            with self.assertRaises(ValueError):
                LLMMatcher.from_env(Client())
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            report_path.write_text(json.dumps({
                "passed": True, "prompt_version": PROMPT_VERSION, "cases": 2,
                "min_precision": .98, "min_recall": .8, "precision": 1, "recall": 1,
            }))
            self.assertTrue(valid_automatic_gate(report_path, PROMPT_VERSION))
            with patch.dict(os.environ, {
                "VA_LLM_MODE": "automatic", "VA_LLM_MODEL": "model-test", "OPENAI_API_KEY": "secret",
                "VA_MATCH_EVALUATION_REPORT": str(report_path),
            }, clear=False):
                self.assertTrue(LLMMatcher.from_env(Client()).enabled)


if __name__ == "__main__":
    unittest.main()
