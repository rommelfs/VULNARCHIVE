from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from .models import Extraction, Match, Message


SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    source_url TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    published TEXT NOT NULL,
    body TEXT NOT NULL,
    raw_source TEXT NOT NULL DEFAULT '',
    source_format TEXT NOT NULL DEFAULT 'text/html',
    message_id TEXT NOT NULL DEFAULT '',
    links_json TEXT NOT NULL,
    extraction_json TEXT NOT NULL,
    matches_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    review_state TEXT NOT NULL DEFAULT 'pending',
    reviewed_vulnerability_id TEXT NOT NULL DEFAULT '',
    reviewed_sighting_type TEXT NOT NULL DEFAULT '',
    review_note TEXT NOT NULL DEFAULT '',
    reviewed_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS submissions (
    source_url TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    sighting_type TEXT NOT NULL,
    response_json TEXT NOT NULL,
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_url, vulnerability_id, sighting_type)
);
CREATE TABLE IF NOT EXISTS automatic_publications (
    source_url TEXT NOT NULL,
    publication_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    target_id TEXT NOT NULL DEFAULT '',
    gcve_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'planned',
    payload_json TEXT NOT NULL DEFAULT '{}',
    response_json TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_url, publication_key)
);
"""


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # HTTP servers may be started from a supervisor/test thread; each server
        # remains single-threaded and SQLite serializes access with busy_timeout.
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(observations)")}
        additions = {
            "review_state": "TEXT NOT NULL DEFAULT 'pending'",
            "reviewed_vulnerability_id": "TEXT NOT NULL DEFAULT ''",
            "reviewed_sighting_type": "TEXT NOT NULL DEFAULT ''",
            "review_note": "TEXT NOT NULL DEFAULT ''",
            "reviewed_at": "TEXT",
            "raw_source": "TEXT NOT NULL DEFAULT ''",
            "source_format": "TEXT NOT NULL DEFAULT 'text/html'",
            "message_id": "TEXT NOT NULL DEFAULT ''",
        }
        for name, definition in additions.items():
            if name not in columns:
                self.db.execute(f"ALTER TABLE observations ADD COLUMN {name} {definition}")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def seen(self, source_url: str) -> bool:
        return self.db.execute("SELECT 1 FROM observations WHERE source_url = ?", (source_url,)).fetchone() is not None

    def save(self, message: Message, extraction: Extraction, matches: list[Match]) -> None:
        canonical_source = message.raw_source or (message.title + "\n" + message.body)
        digest = hashlib.sha256(canonical_source.encode()).hexdigest()
        status = "matched" if matches else "unmatched"
        self.db.execute(
            """INSERT INTO observations
            (source_url, content_hash, title, author, published, body, raw_source, source_format,
             message_id, links_json, extraction_json, matches_json, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_url) DO UPDATE SET
              content_hash=excluded.content_hash, title=excluded.title, author=excluded.author,
              published=excluded.published, body=excluded.body, raw_source=excluded.raw_source,
              source_format=excluded.source_format, message_id=excluded.message_id, links_json=excluded.links_json,
              extraction_json=excluded.extraction_json, matches_json=excluded.matches_json,
              status=excluded.status, updated_at=CURRENT_TIMESTAMP""",
            (
                message.source_url,
                digest,
                message.title,
                message.author,
                message.published,
                message.body,
                message.raw_source,
                message.source_format,
                message.message_id,
                json.dumps(message.links),
                json.dumps(extraction.as_dict()),
                json.dumps([match.as_dict() for match in matches]),
                status,
            ),
        )
        self.db.commit()

    def record_submission(self, source_url: str, vulnerability_id: str, sighting_type: str, response: object) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO submissions (source_url, vulnerability_id, sighting_type, response_json) VALUES (?, ?, ?, ?)",
            (source_url, vulnerability_id, sighting_type, json.dumps(response)),
        )
        self.db.commit()

    def _decode(self, row: sqlite3.Row, include_body: bool = False) -> dict[str, object]:
        item = dict(row)
        for key in ("links_json", "extraction_json", "matches_json"):
            item[key.removesuffix("_json")] = json.loads(str(item.pop(key)))
        if not include_body:
            item.pop("body", None)
            item.pop("raw_source", None)
        return item

    def rows(self, status: str | None = None, review_state: str | None = None) -> list[dict[str, object]]:
        self.db.row_factory = sqlite3.Row
        query = "SELECT * FROM observations"
        clauses: list[str] = []
        params: list[str] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if review_state:
            clauses.append("review_state = ?")
            params.append(review_state)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY published DESC, source_url DESC"
        return [self._decode(row) for row in self.db.execute(query, tuple(params))]

    def get(self, source_url: str) -> dict[str, object] | None:
        self.db.row_factory = sqlite3.Row
        row = self.db.execute("SELECT * FROM observations WHERE source_url = ?", (source_url,)).fetchone()
        return self._decode(row, include_body=True) if row else None

    def review(self, source_url: str, state: str, vulnerability_id: str = "", sighting_type: str = "", note: str = "") -> None:
        if state not in {"pending", "approved", "rejected"}:
            raise ValueError("invalid review state")
        if state == "approved" and (not vulnerability_id or sighting_type not in {"seen", "published-proof-of-concept"}):
            raise ValueError("approved observations require a vulnerability ID and valid sighting type")
        self.db.execute(
            """UPDATE observations SET review_state=?, reviewed_vulnerability_id=?,
            reviewed_sighting_type=?, review_note=?, reviewed_at=CURRENT_TIMESTAMP
            WHERE source_url=?""",
            (state, vulnerability_id.upper(), sighting_type, note[:2000], source_url),
        )
        self.db.commit()

    def approved(self, limit: int = 0) -> list[dict[str, object]]:
        self.db.row_factory = sqlite3.Row
        query = """SELECT o.* FROM observations o
        WHERE o.review_state='approved' AND NOT EXISTS (
          SELECT 1 FROM submissions s
          WHERE s.source_url=o.source_url
            AND s.vulnerability_id=o.reviewed_vulnerability_id
            AND s.sighting_type=o.reviewed_sighting_type
        ) ORDER BY o.reviewed_at, o.source_url"""
        params: tuple[int, ...] = ()
        if limit:
            query += " LIMIT ?"
            params = (limit,)
        return [self._decode(row, include_body=True) for row in self.db.execute(query, params)]

    def publication(self, source_url: str, publication_key: str) -> dict[str, object] | None:
        self.db.row_factory = sqlite3.Row
        row = self.db.execute(
            "SELECT * FROM automatic_publications WHERE source_url=? AND publication_key=?",
            (source_url, publication_key),
        ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["payload"] = json.loads(str(item.pop("payload_json")))
        item["response"] = json.loads(str(item.pop("response_json")))
        return item

    def save_publication(
        self,
        source_url: str,
        publication_key: str,
        kind: str,
        *,
        target_id: str = "",
        gcve_id: str = "",
        status: str = "planned",
        payload: object | None = None,
        response: object | None = None,
        error: str = "",
    ) -> None:
        previous = self.publication(source_url, publication_key) or {}
        self.db.execute(
            """INSERT INTO automatic_publications
            (source_url, publication_key, kind, target_id, gcve_id, status, payload_json, response_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_url, publication_key) DO UPDATE SET
              kind=excluded.kind, target_id=excluded.target_id,
              gcve_id=CASE WHEN excluded.gcve_id='' THEN automatic_publications.gcve_id ELSE excluded.gcve_id END,
              status=excluded.status, payload_json=excluded.payload_json,
              response_json=excluded.response_json, error=excluded.error,
              updated_at=CURRENT_TIMESTAMP""",
            (
                source_url,
                publication_key,
                kind,
                target_id,
                gcve_id,
                status,
                json.dumps(payload if payload is not None else previous.get("payload", {})),
                json.dumps(response if response is not None else previous.get("response", {})),
                error[:4000],
            ),
        )
        self.db.commit()

    def automatic_candidates(self, limit: int = 0) -> list[dict[str, object]]:
        """Return relevant archived observations; the publication ledger provides idempotency."""
        self.db.row_factory = sqlite3.Row
        query = "SELECT * FROM observations WHERE status IN ('matched', 'unmatched') ORDER BY published, source_url"
        params: tuple[int, ...] = ()
        if limit:
            query += " LIMIT ?"
            params = (limit,)
        return [self._decode(row, include_body=True) for row in self.db.execute(query, params)]

    def publication_rows(self) -> list[dict[str, object]]:
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute("SELECT * FROM automatic_publications ORDER BY updated_at DESC").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(str(item.pop("payload_json")))
            item["response"] = json.loads(str(item.pop("response_json")))
            result.append(item)
        return result

    def public_gcve_records(self) -> list[dict[str, object]]:
        """Return only successfully published GCVE payloads for the public feed."""
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute(
            """SELECT payload_json FROM automatic_publications
            WHERE kind='gcve' AND status='published'
            ORDER BY json_extract(payload_json, '$.cveMetadata.dateUpdated'), gcve_id"""
        ).fetchall()
        return [json.loads(str(row["payload_json"])) for row in rows]
