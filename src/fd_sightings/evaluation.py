from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .extract import extract
from .models import Message
from .vulnerability_lookup import VulnerabilityLookup


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    cases: int
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    passed: bool
    min_precision: float
    min_recall: float
    case_results: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class _FixtureClient:
    def __init__(self, candidates: list[dict[str, Any]]) -> None:
        self.candidates = candidates

    def get_json(self, url: str, params: dict[str, str] | None = None) -> object:
        if params is not None:
            return self.candidates
        identifier = url.rsplit("/", 1)[-1].upper()
        return next((item for item in self.candidates if _record_id(item) == identifier), {})


def _record_id(record: dict[str, Any]) -> str:
    metadata = record.get("cveMetadata", {})
    return str(metadata.get("vulnId") or metadata.get("cveId") or record.get("id") or "").upper()


def load_cases(paths: list[str | Path]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for value in paths:
        path = Path(value)
        candidates = sorted(path.glob("*.json")) if path.is_dir() else [path]
        for candidate in candidates:
            decoded = json.loads(candidate.read_text(encoding="utf-8"))
            items = decoded if isinstance(decoded, list) else [decoded]
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError(f"fixture {candidate} must contain an object or array of objects")
                item = dict(item)
                item["fixture"] = str(candidate)
                cases.append(item)
    if not cases:
        raise ValueError("no evaluation fixtures found")
    return cases


def evaluate_cases(
    cases: list[dict[str, Any]], *, min_precision: float = 0.98, min_recall: float = 0.80,
) -> EvaluationReport:
    if not 0 <= min_precision <= 1 or not 0 <= min_recall <= 1:
        raise ValueError("evaluation thresholds must be between 0 and 1")
    tp = fp = fn = 0
    results: list[dict[str, Any]] = []
    for number, case in enumerate(cases, 1):
        message_data = case.get("message")
        candidates = case.get("candidates", [])
        expected = {str(value).upper() for value in case.get("expected_ids", [])}
        if not isinstance(message_data, dict) or not isinstance(candidates, list):
            raise ValueError(f"evaluation case {number} requires message and candidates")
        message = Message(**message_data)
        extraction = extract(message)
        lookup = VulnerabilityLookup(_FixtureClient(candidates), "https://fixture.invalid")
        matches = lookup.match(message, extraction, semantic=bool(case.get("semantic", True)))
        predicted = {match.vulnerability_id for match in matches}
        tp += len(predicted & expected)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        results.append({
            "name": str(case.get("name") or f"case-{number}"), "fixture": case.get("fixture", ""),
            "expected_ids": sorted(expected), "predicted_ids": sorted(predicted),
            "excluded_candidates": lookup.last_analysis.get("excluded_candidates", []),
            "passed": predicted == expected,
        })
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return EvaluationReport(
        len(cases), tp, fp, fn, precision, recall,
        precision >= min_precision and recall >= min_recall,
        min_precision, min_recall, results,
    )


def valid_automatic_gate(path: str | Path, prompt_version: str) -> bool:
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        return (
            bool(report.get("passed")) and report.get("prompt_version") == prompt_version
            and int(report.get("cases", 0)) > 0
            and float(report.get("min_precision", 0)) >= 0.98
            and float(report.get("min_recall", 0)) >= 0.80
            and float(report.get("precision", 0)) >= float(report["min_precision"])
            and float(report.get("recall", 0)) >= float(report["min_recall"])
        )
    except (OSError, ValueError, TypeError):
        return False
