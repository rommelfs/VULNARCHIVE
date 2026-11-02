"""Offline inspection of stored relevance decisions without database writes."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .extract import extract
from .models import Message


def audit_relevance(database: str | Path, *, sources: list[str] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "scanned": 0, "stored_non_relevant": 0, "newly_relevant": 0,
        "still_non_relevant": 0, "invalid_stored_extraction": 0, "observations": [],
    }
    # Do not use Store here: its constructor applies migrations. An audit must
    # also work against production without initializing or modifying the store.
    connection = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        for row in connection.execute("SELECT * FROM observations ORDER BY source_url"):
            source_id = str(row["source_id"] or "full-disclosure") if "source_id" in row.keys() else "full-disclosure"
            if sources is not None and source_id not in sources:
                continue
            report["scanned"] += 1
            try:
                stored = json.loads(row["extraction_json"])
                if not isinstance(stored, dict):
                    raise ValueError("extraction is not an object")
            except (ValueError, TypeError):
                stored = {}
                report["invalid_stored_extraction"] += 1
            if stored.get("relevant"):
                continue
            report["stored_non_relevant"] += 1
            extraction = extract(Message(
                source_url=str(row["source_url"]), title=str(row["title"] or ""),
                body=str(row["body"] or ""), source_id=source_id,
            ))
            report["newly_relevant" if extraction.relevant else "still_non_relevant"] += 1
            report["observations"].append({
                "source_url": row["source_url"], "source_id": source_id, "title": row["title"],
                "review_state": row["review_state"] if "review_state" in row.keys() else "",
                "current_relevant": extraction.relevant,
                "relevance_evidence": extraction.relevance_evidence,
                "stored_relevance_evidence": stored.get("relevance_evidence", []),
            })
    finally:
        connection.close()
    return report
