from __future__ import annotations

from dataclasses import dataclass
import math


OBSERVATION_SORTS = frozenset({"published", "title", "author", "status", "review", "confidence"})
OBSERVATION_SOURCES = frozenset({"full-disclosure", "bugtraq", "bugtraq-ai"})


@dataclass(frozen=True, slots=True)
class ListQuery:
    """Validated collection query shared by stores and HTTP interfaces."""

    page: int = 1
    per_page: int = 50
    sort: str = "published"
    order: str = "desc"
    search: str = ""
    status: str = ""
    review_state: str = ""
    source_id: str = ""
    confidence_min: float = 0.0
    confidence_max: float = 1.0

    def __post_init__(self) -> None:
        if self.page < 1:
            raise ValueError("page must be a positive integer")
        if not 1 <= self.per_page <= 100:
            raise ValueError("per_page must be between 1 and 100")
        if self.sort not in OBSERVATION_SORTS:
            raise ValueError("sort is not supported")
        if self.order not in {"asc", "desc"}:
            raise ValueError("order must be asc or desc")
        if len(self.search) > 200:
            raise ValueError("q must contain at most 200 characters")
        if self.status not in {"", "matched", "unmatched"}:
            raise ValueError("match is not supported")
        if self.review_state not in {"", "pending", "approved", "rejected"}:
            raise ValueError("review is not supported")
        if self.source_id not in {"", *OBSERVATION_SOURCES}:
            raise ValueError("source is not supported")
        if not math.isfinite(self.confidence_min) or not math.isfinite(self.confidence_max):
            raise ValueError("confidence bounds must be finite")
        if not 0 <= self.confidence_min <= self.confidence_max <= 1:
            raise ValueError("confidence range must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class ListPage:
    items: list[dict[str, object]]
    total: int
    page: int
    per_page: int

    @property
    def pages(self) -> int:
        return max(1, (self.total + self.per_page - 1) // self.per_page)
