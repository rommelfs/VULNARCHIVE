from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Message:
    source_url: str
    title: str
    author: str = ""
    published: str = ""
    body: str = ""
    links: list[str] = field(default_factory=list)
    raw_source: str = ""
    source_format: str = "text/html"
    message_id: str = ""
    source_id: str = "full-disclosure"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Extraction:
    cve_ids: list[str] = field(default_factory=list)
    ghsa_ids: list[str] = field(default_factory=list)
    gcve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    cvss_vectors: list[str] = field(default_factory=list)
    product_hint: str = ""
    vendor_hint: str = ""
    component_hint: str = ""
    product_aliases: list[str] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)
    version_constraints: list[dict[str, str]] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    commits: list[str] = field(default_factory=list)
    vulnerability_types: list[str] = field(default_factory=list)
    poc_score: int = 0
    poc_evidence: list[str] = field(default_factory=list)
    relevant: bool = False

    @property
    def proposed_type(self) -> str:
        return "published-proof-of-concept" if self.poc_score >= 3 else "seen"

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["proposed_type"] = self.proposed_type
        return data


@dataclass(slots=True)
class Match:
    vulnerability_id: str
    method: str
    confidence: float
    title: str = ""
    evidence: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
