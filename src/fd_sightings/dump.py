from __future__ import annotations

import json
from collections.abc import Iterator

from .store import Store


def record_id(record: dict[str, object]) -> str:
    metadata = record.get("cveMetadata")
    if not isinstance(metadata, dict):
        return ""
    identifier = metadata.get("vulnId") or metadata.get("cveId")
    return str(identifier).upper() if isinstance(identifier, str) else ""

def ndjson_lines(store: Store) -> Iterator[bytes]:
    """Yield the canonical local publication set as compact UTF-8 NDJSON."""
    for record in store.published_gcve_records():
        yield json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
