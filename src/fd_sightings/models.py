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

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
