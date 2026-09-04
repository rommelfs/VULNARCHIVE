from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any


def _boolean(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def _integer(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value is not None else default


@dataclass(frozen=True, slots=True)
class PublicationPolicy:
    """The public assertions made by VULNARCHIVE GNA 1988.

    These scores are publication policy, not truth or trust scores.  They are
    deliberately configurable so other deployments can use a different GNA
    model without changing parser code.
    """

    gna_id: int = 1988
    gna_short_name: str = "VULNARCHIVE"
    public_base_url: str = "https://vuln.freearchive.org"
    gna_org_uuid: str = "4e2abfbf-4a2a-4b76-a4e0-d77c18ba156c"
    publish_sightings: bool = True
    publish_context_records: bool = True
    min_new_record_score: int = 5
    min_context_record_score: int = 3
    min_body_chars: int = 160
    require_product_for_new: bool = True
    auto_create_year_range: bool = True
    max_description_chars: int = 12000

    @classmethod
    def from_env(cls) -> "PublicationPolicy":
        return cls(
            gna_id=_integer("VA_GNA_ID", 1988),
            gna_short_name=os.getenv("VA_GNA_SHORT_NAME", "VULNARCHIVE"),
            public_base_url=os.getenv("VA_PUBLIC_BASE_URL", "https://vuln.freearchive.org").rstrip("/"),
            gna_org_uuid=os.getenv("VA_GNA_ORG_UUID", "4e2abfbf-4a2a-4b76-a4e0-d77c18ba156c"),
            publish_sightings=_boolean("VA_PUBLISH_SIGHTINGS", True),
            publish_context_records=_boolean("VA_PUBLISH_CONTEXT_RECORDS", True),
            min_new_record_score=_integer("VA_MIN_NEW_RECORD_SCORE", 5),
            min_context_record_score=_integer("VA_MIN_CONTEXT_RECORD_SCORE", 3),
            min_body_chars=_integer("VA_MIN_BODY_CHARS", 160),
            require_product_for_new=_boolean("VA_REQUIRE_PRODUCT_FOR_NEW", True),
            auto_create_year_range=_boolean("VA_AUTO_CREATE_YEAR_RANGE", True),
            max_description_chars=_integer("VA_MAX_DESCRIPTION_CHARS", 12000),
        )


@dataclass(frozen=True, slots=True)
class PublicationPlan:
    source_url: str
    evidence_score: int
    action: str
    targets: tuple[str, ...]
    sighting_type: str
    record_type: str = ""
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "evidence_score": self.evidence_score,
            "action": self.action,
            "targets": list(self.targets),
            "sighting_type": self.sighting_type,
            "record_type": self.record_type,
            "reason": self.reason,
        }


TECHNICAL_DETAIL = re.compile(
    r"\b(memcpy|function pointer|stack pivot|heap|buffer overflow|use-after-free|"
    r"request|response|payload|reproducer|proof[- ]of[- ]concept|pseudocode|"
    r"affected versions?|authentication|privileges?|remote code execution)\b",
    re.IGNORECASE,
)


def evidence_score(row: dict[str, object]) -> int:
    extraction = dict(row.get("extraction") or {})
    body = str(row.get("body") or "")
    score = 2 if extraction.get("relevant") else 0
    score += 2 if extraction.get("product_hint") else 0
    score += 2 if int(extraction.get("poc_score") or 0) >= 3 else 0
    score += 1 if extraction.get("cwe_ids") else 0
    score += 1 if extraction.get("cvss_vectors") else 0
    score += 1 if row.get("links") else 0
    score += 1 if len(body) >= 500 else 0
    score += 1 if TECHNICAL_DETAIL.search(body) else 0
    return score


def plan_observation(row: dict[str, object], policy: PublicationPolicy) -> PublicationPlan:
    extraction = dict(row.get("extraction") or {})
    targets = tuple(dict.fromkeys(
        str(match.get("vulnerability_id", "")).upper()
        for match in list(row.get("matches") or [])
        if isinstance(match, dict) and match.get("vulnerability_id")
    ))
    score = evidence_score(row)
    enough_body = len(str(row.get("body") or "")) >= policy.min_body_chars
    sighting_type = str(extraction.get("proposed_type") or "seen")

    if targets:
        if policy.publish_context_records and enough_body and score >= policy.min_context_record_score:
            record_type = "analysis" if int(extraction.get("poc_score") or 0) >= 3 else "reference"
            return PublicationPlan(
                str(row["source_url"]), score, "context-and-sightings", targets,
                sighting_type, record_type, "known identifier with publishable independent context",
            )
        return PublicationPlan(
            str(row["source_url"]), score, "sightings", targets, sighting_type,
            reason="known identifier; context threshold not reached",
        )

    product_present = bool(extraction.get("product_hint"))
    qualifies = enough_body and score >= policy.min_new_record_score
    if policy.require_product_for_new:
        qualifies = qualifies and product_present
    if extraction.get("relevant") and qualifies:
        return PublicationPlan(
            str(row["source_url"]), score, "new-advisory", (), sighting_type,
            "advisory", "no known identifier and new-record threshold reached",
        )
    return PublicationPlan(
        str(row["source_url"]), score, "archive-only", (), sighting_type,
        reason="new-record publication threshold not reached",
    )
