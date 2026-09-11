from __future__ import annotations

import hashlib
import base64
import hmac
import json
import os
import re
import secrets
import sqlite3
from difflib import SequenceMatcher
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Extraction, Match, Message
from .query import ListPage, ListQuery


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
    reviewed_vulnerability_ids_json TEXT NOT NULL DEFAULT '[]',
    reviewed_sighting_type TEXT NOT NULL DEFAULT '',
    review_note TEXT NOT NULL DEFAULT '',
    reviewed_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS import_failures (
    source_url TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    error TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    first_failed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_failed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS submissions (
    source_url TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    sighting_type TEXT NOT NULL,
    response_json TEXT NOT NULL,
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_url, vulnerability_id, sighting_type)
);
CREATE TABLE IF NOT EXISTS review_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url TEXT NOT NULL,
    review_state TEXT NOT NULL CHECK (review_state IN ('pending', 'approved', 'rejected')),
    vulnerability_ids_json TEXT NOT NULL DEFAULT '[]',
    sighting_type TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_url) REFERENCES observations(source_url) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS review_events_source_idx
    ON review_events (source_url, event_id DESC);
CREATE TABLE IF NOT EXISTS review_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'reviewer')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS review_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analysis_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url TEXT NOT NULL,
    trigger_name TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    prompt_version TEXT NOT NULL DEFAULT '',
    input_sha256 TEXT NOT NULL DEFAULT '',
    response_id TEXT NOT NULL DEFAULT '',
    retrieval_at TEXT NOT NULL,
    context_json TEXT NOT NULL DEFAULT '{}',
    candidates_json TEXT NOT NULL DEFAULT '[]',
    deterministic_json TEXT NOT NULL DEFAULT '[]',
    excluded_json TEXT NOT NULL DEFAULT '[]',
    llm_output_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT NOT NULL DEFAULT '[]',
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_url) REFERENCES observations(source_url) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS analysis_events_source_idx
    ON analysis_events (source_url, event_id DESC);
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
    reserved_at TEXT,
    published_at TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source_url, publication_key)
);
CREATE TABLE IF NOT EXISTS gcve_reservations (
    source_url TEXT NOT NULL,
    publication_key TEXT NOT NULL,
    gcve_id TEXT NOT NULL UNIQUE,
    gna_id INTEGER NOT NULL,
    publication_year INTEGER NOT NULL,
    serial INTEGER NOT NULL,
    reserved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_url, publication_key),
    UNIQUE (gna_id, publication_year, serial)
);
CREATE TABLE IF NOT EXISTS gcve_records (
    vuln_id TEXT PRIMARY KEY,
    source_url TEXT NOT NULL,
    record_json TEXT NOT NULL,
    record_type TEXT NOT NULL,
    assigner TEXT NOT NULL,
    reserved_at TEXT NOT NULL,
    published_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    product_normalized TEXT,
    vendor_normalized TEXT,
    cwe_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS gcve_year_sequences (
    year INTEGER PRIMARY KEY CHECK (year BETWEEN 1000 AND 9999),
    last_serial INTEGER NOT NULL CHECK (last_serial >= 0),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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

    def record_import_failure(self, source_url: str, source_id: str, error: str) -> None:
        self.db.execute(
            """INSERT INTO import_failures(source_url, source_id, error) VALUES(?,?,?)
            ON CONFLICT(source_url) DO UPDATE SET source_id=excluded.source_id,
            error=excluded.error, attempts=import_failures.attempts+1,
            last_failed_at=CURRENT_TIMESTAMP""",
            (source_url, source_id, error),
        )
        self.db.commit()

    def clear_import_failure(self, source_url: str) -> None:
        self.db.execute("DELETE FROM import_failures WHERE source_url=?", (source_url,))
        self.db.commit()

    def import_failures(self, source_ids: list[str] | None = None) -> list[dict[str, object]]:
        self.db.row_factory = sqlite3.Row
        if source_ids:
            placeholders = ",".join("?" for _ in source_ids)
            rows = self.db.execute(
                f"SELECT * FROM import_failures WHERE source_id IN ({placeholders}) ORDER BY last_failed_at",
                source_ids,
            )
        else:
            rows = self.db.execute("SELECT * FROM import_failures ORDER BY last_failed_at")
        return [dict(row) for row in rows]

    @staticmethod
    def _password_hash(password: str) -> str:
        if len(password) < 12:
            raise ValueError("password must contain at least 12 characters")
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
        return "pbkdf2_sha256$600000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()

    def save_review_user(self, username: str, password: str, role: str = "reviewer") -> None:
        username = username.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{2,64}", username):
            raise ValueError("username must contain 2-64 safe characters")
        if role not in {"admin", "reviewer"}:
            raise ValueError("invalid user role")
        encoded = self._password_hash(password)
        self.db.execute(
            """INSERT INTO review_users(username,password_hash,role,active) VALUES(?,?,?,1)
            ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,
            role=excluded.role, active=1, updated_at=CURRENT_TIMESTAMP""",
            (username, encoded, role),
        )
        self.db.commit()

    def authenticate_review_user(self, username: str, password: str) -> str | None:
        row = self.db.execute(
            "SELECT password_hash, role FROM review_users WHERE username=? AND active=1", (username,),
        ).fetchone()
        if not row:
            return None
        try:
            algorithm, rounds, salt, expected = str(row[0]).split("$")
            if algorithm != "pbkdf2_sha256":
                return None
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), base64.b64decode(salt), int(rounds),
            )
            return str(row[1]) if hmac.compare_digest(actual, base64.b64decode(expected)) else None
        except (ValueError, TypeError):
            return None

    def review_users(self) -> list[dict[str, object]]:
        self.db.row_factory = sqlite3.Row
        return [dict(row) for row in self.db.execute(
            "SELECT username, role, active, created_at, updated_at FROM review_users ORDER BY username COLLATE NOCASE"
        )]

    def has_review_users(self) -> bool:
        return self.db.execute("SELECT 1 FROM review_users WHERE active=1 LIMIT 1").fetchone() is not None

    def set_review_user_active(self, username: str, active: bool) -> None:
        cursor = self.db.execute(
            "UPDATE review_users SET active=?, updated_at=CURRENT_TIMESTAMP WHERE username=?",
            (int(active), username),
        )
        if cursor.rowcount != 1:
            raise ValueError("review user not found")
        self.db.commit()

    def four_eyes_enabled(self) -> bool:
        row = self.db.execute(
            "SELECT setting_value FROM review_settings WHERE setting_key='four_eyes'"
        ).fetchone()
        return bool(row and row[0] == "1")

    def set_four_eyes(self, enabled: bool) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO review_settings(setting_key, setting_value) VALUES('four_eyes', ?)",
            ("1" if enabled else "0",),
        )
        self.db.commit()

    def _migrate(self) -> None:
        record_columns = {row[1] for row in self.db.execute("PRAGMA table_info(gcve_records)")}
        if "vuln_id" not in record_columns:
            # Merge-era databases used a second, incompatible two-column GCVE
            # table.  Rebuild it once and recover its canonical records before
            # creating indexes used by the local publication API.
            self.db.execute("ALTER TABLE gcve_records RENAME TO gcve_records_legacy")
            self.db.execute("""CREATE TABLE gcve_records (
                vuln_id TEXT PRIMARY KEY, source_url TEXT NOT NULL,
                record_json TEXT NOT NULL, record_type TEXT NOT NULL,
                assigner TEXT NOT NULL, reserved_at TEXT NOT NULL,
                published_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                product_normalized TEXT, vendor_normalized TEXT,
                cwe_json TEXT NOT NULL DEFAULT '[]')""")
            for identifier, encoded, stored_published in self.db.execute(
                "SELECT gcve_id, record_json, published_at FROM gcve_records_legacy"
            ).fetchall():
                record = json.loads(encoded)
                defaults = self._record_defaults(record)
                published = str(defaults["published_at"] or stored_published)
                updated = str(defaults["updated_at"] or published)
                self._insert_canonical_record(str(identifier), "legacy", record, published, published, updated)
            self.db.execute("DROP TABLE gcve_records_legacy")
        self.db.executescript("""
            CREATE INDEX IF NOT EXISTS gcve_records_chronological_idx
                ON gcve_records (updated_at, published_at, vuln_id);
            CREATE INDEX IF NOT EXISTS gcve_records_assigner_idx
                ON gcve_records (assigner, updated_at, vuln_id);
            CREATE INDEX IF NOT EXISTS gcve_records_product_idx
                ON gcve_records (product_normalized, updated_at, vuln_id);
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(observations)")}
        additions = {
            "source_id": "TEXT NOT NULL DEFAULT 'full-disclosure'",
            "canonical_key": "TEXT NOT NULL DEFAULT ''",
            "review_state": "TEXT NOT NULL DEFAULT 'pending'",
            "reviewed_vulnerability_id": "TEXT NOT NULL DEFAULT ''",
            "reviewed_vulnerability_ids_json": "TEXT NOT NULL DEFAULT '[]'",
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
        # Pilot-era/manual databases may contain truncated JSON values. One
        # malformed row must not make the complete review queue return an empty
        # connection when JSON1 computes confidence values.
        for column, fallback in (
            ("links_json", "[]"), ("extraction_json", "{}"),
            ("matches_json", "[]"), ("reviewed_vulnerability_ids_json", "[]"),
        ):
            self.db.execute(
                f"UPDATE observations SET {column}=? WHERE NOT json_valid({column})",
                (fallback,),
            )
        self.db.execute("UPDATE observations SET canonical_key=source_url WHERE canonical_key='' ")
        self.db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS observations_source_key_idx "
            "ON observations(source_id, canonical_key)"
        )
        self.db.execute(
            "INSERT OR IGNORE INTO sources(source_id, name) VALUES ('full-disclosure', 'Full Disclosure')"
        )
        self.db.execute(
            """UPDATE observations SET reviewed_vulnerability_ids_json=json_array(reviewed_vulnerability_id)
            WHERE reviewed_vulnerability_id<>'' AND reviewed_vulnerability_ids_json='[]'"""
        )
        self.db.execute(
            """INSERT INTO review_events
            (source_url, review_state, vulnerability_ids_json, sighting_type, note, actor, created_at)
            SELECT o.source_url, o.review_state, o.reviewed_vulnerability_ids_json,
                   o.reviewed_sighting_type, o.review_note, 'legacy-migration',
                   COALESCE(o.reviewed_at, o.updated_at)
            FROM observations o
            WHERE o.reviewed_at IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM review_events e WHERE e.source_url=o.source_url)"""
        )
        analysis_columns = {row[1] for row in self.db.execute("PRAGMA table_info(analysis_events)")}
        if "excluded_json" not in analysis_columns:
            self.db.execute("ALTER TABLE analysis_events ADD COLUMN excluded_json TEXT NOT NULL DEFAULT '[]'")
        publication_columns = {row[1] for row in self.db.execute("PRAGMA table_info(automatic_publications)")}
        for name in ("reserved_at", "published_at"):
            if name not in publication_columns:
                self.db.execute(f"ALTER TABLE automatic_publications ADD COLUMN {name} TEXT")
        # Older ledgers only had SQLite's timezone-less CURRENT_TIMESTAMP. Treat
        # those values as UTC and preserve them as the best known event time.
        for rowid, kind, status, reserved, published, updated in self.db.execute(
            "SELECT rowid, kind, status, reserved_at, published_at, updated_at FROM automatic_publications"
        ).fetchall():
            normalized = self._normalize_stored_timestamp(str(updated))
            self.db.execute(
                "UPDATE automatic_publications SET reserved_at=?, published_at=?, updated_at=? WHERE rowid=?",
                (
                    reserved or (normalized if kind == "gcve" else None),
                    published or (normalized if kind == "gcve" and status == "published" else None),
                    normalized,
                    rowid,
                ),
            )
        # Older publication paths could commit the durable ledger without
        # populating the canonical table consumed by the public detail route.
        # Recover valid published payloads so a "Published" link cannot lead to
        # a 404 merely because the two projections predate the atomic writer.
        for source_url, gcve_id, payload_json, reserved, published, updated in self.db.execute(
            """SELECT source_url, gcve_id, payload_json, reserved_at, published_at, updated_at
            FROM automatic_publications p
            WHERE kind='gcve' AND status='published' AND gcve_id<>''
              AND NOT EXISTS (SELECT 1 FROM gcve_records r WHERE r.vuln_id=p.gcve_id)"""
        ).fetchall():
            try:
                record = json.loads(str(payload_json))
                if not isinstance(record, dict) or self._record_id(record) != str(gcve_id).upper():
                    continue
            except (json.JSONDecodeError, ValueError, TypeError):
                continue
            timestamp = str(published or updated or reserved or self._utc_now())
            self._insert_canonical_record(
                str(gcve_id), str(source_url), record,
                str(reserved or timestamp), str(published or timestamp), str(updated or timestamp),
            )
        self.db.commit()
        self._setup_full_text_index()

    def _setup_full_text_index(self) -> None:
        """Create and synchronize the optional SQLite FTS5 observation index."""
        try:
            self.db.executescript("""
                CREATE VIRTUAL TABLE IF NOT EXISTS observations_fts USING fts5(
                    source_url UNINDEXED, title, author, body, metadata,
                    tokenize='unicode61 remove_diacritics 2'
                );
                CREATE TRIGGER IF NOT EXISTS observations_fts_insert AFTER INSERT ON observations BEGIN
                    INSERT INTO observations_fts(source_url,title,author,body,metadata)
                    VALUES (new.source_url,new.title,new.author,new.body,new.extraction_json);
                END;
                CREATE TRIGGER IF NOT EXISTS observations_fts_delete AFTER DELETE ON observations BEGIN
                    DELETE FROM observations_fts WHERE source_url=old.source_url;
                END;
                CREATE TRIGGER IF NOT EXISTS observations_fts_update AFTER UPDATE ON observations BEGIN
                    DELETE FROM observations_fts WHERE source_url=old.source_url;
                    INSERT INTO observations_fts(source_url,title,author,body,metadata)
                    VALUES (new.source_url,new.title,new.author,new.body,new.extraction_json);
                END;
            """)
            indexed = int(self.db.execute("SELECT COUNT(*) FROM observations_fts").fetchone()[0])
            observed = int(self.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0])
            if indexed != observed:
                self.db.execute("DELETE FROM observations_fts")
                self.db.execute(
                    "INSERT INTO observations_fts(source_url,title,author,body,metadata) "
                    "SELECT source_url,title,author,body,extraction_json FROM observations"
                )
            self.db.commit()
            self.fts_enabled = True
        except sqlite3.OperationalError:
            self.fts_enabled = False

    def close(self) -> None:
        self.db.close()

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _utc_iso(value: datetime) -> str:
        if value.tzinfo is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

    @staticmethod
    def _normalize_stored_timestamp(value: str) -> str:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return Store._utc_iso(parsed)

    @staticmethod
    def _parse_timestamp(value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("since must be an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("since must include a timezone")
        return Store._utc_iso(parsed)

    @staticmethod
    def _record_id(record: dict[str, Any]) -> str:
        metadata = record.get("cveMetadata")
        value = metadata.get("vulnId") if isinstance(metadata, dict) else None
        if not isinstance(value, str) or not value.strip():
            raise ValueError("record requires cveMetadata.vulnId")
        return value.strip().upper()

    @staticmethod
    def _record_defaults(record: dict[str, Any]) -> dict[str, object]:
        metadata = record.get("cveMetadata") if isinstance(record.get("cveMetadata"), dict) else {}
        containers = record.get("containers") if isinstance(record.get("containers"), dict) else {}
        cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}
        affected = cna.get("affected") if isinstance(cna.get("affected"), list) else []
        first_affected = affected[0] if affected and isinstance(affected[0], dict) else {}
        extensions = cna.get("x_gcve") if isinstance(cna.get("x_gcve"), list) else []
        extension = extensions[0] if extensions and isinstance(extensions[0], dict) else {}
        cwes: list[str] = []
        for problem in cna.get("problemTypes", []) if isinstance(cna.get("problemTypes"), list) else []:
            if not isinstance(problem, dict):
                continue
            for description in problem.get("descriptions", []) if isinstance(problem.get("descriptions"), list) else []:
                if isinstance(description, dict) and description.get("cweId"):
                    cwes.append(str(description["cweId"]).upper())
        return {
            "record_type": str(extension.get("recordType") or "unknown"),
            "assigner": str(metadata.get("assignerShortName") or metadata.get("assignerOrgId") or "unknown"),
            "published_at": str(metadata.get("datePublished") or ""),
            "updated_at": str(metadata.get("dateUpdated") or ""),
            "product_normalized": Store._normalize_filter(first_affected.get("product")),
            "vendor_normalized": Store._normalize_filter(first_affected.get("vendor")),
            "cwes": sorted(set(cwes)),
        }

    @staticmethod
    def _normalize_filter(value: object) -> str | None:
        text = " ".join(str(value or "").strip().casefold().split())
        return text or None

    def reserve_gcve_id(self, year: int) -> str:
        """Atomically allocate the next local GNA 1988 identifier for *year*."""
        if isinstance(year, bool) or not isinstance(year, int) or not 1000 <= year <= 9999:
            raise ValueError("year must be a four-digit integer")
        try:
            # BEGIN IMMEDIATE obtains SQLite's write lock before reading the counter,
            # so separate Store instances cannot observe and allocate the same value.
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT last_serial FROM gcve_year_sequences WHERE year=?", (year,)
            ).fetchone()
            serial = int(row[0]) + 1 if row else 1
            self.db.execute(
                """INSERT INTO gcve_year_sequences (year, last_serial) VALUES (?, ?)
                ON CONFLICT(year) DO UPDATE SET
                  last_serial=excluded.last_serial, updated_at=CURRENT_TIMESTAMP""",
                (year, serial),
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return f"GCVE-1988-{year}-{serial:04d}"

    def publish_gcve_record(
        self,
        source_url: str,
        record: dict[str, Any],
        *,
        record_type: str | None = None,
        assigner: str | None = None,
        reserved_at: str | None = None,
        published_at: str | None = None,
        updated_at: str | None = None,
        product_normalized: str | None = None,
        vendor_normalized: str | None = None,
        cwes: list[str] | tuple[str, ...] | None = None,
    ) -> str:
        """Persist the first published version; an existing ID is never overwritten."""
        vuln_id = self._record_id(record)
        defaults = self._record_defaults(record)
        now = self._utc_now()
        published = published_at or str(defaults["published_at"]) or now
        updated = updated_at or str(defaults["updated_at"]) or published
        cwe_values = sorted(set(str(value).upper() for value in (cwes if cwes is not None else defaults["cwes"])))
        self.db.execute(
            """INSERT INTO gcve_records
            (vuln_id, source_url, record_json, record_type, assigner, reserved_at,
             published_at, updated_at, product_normalized, vendor_normalized, cwe_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                vuln_id, source_url, json.dumps(record, ensure_ascii=False, sort_keys=True),
                record_type or defaults["record_type"], assigner or defaults["assigner"],
                reserved_at or now, published, updated,
                self._normalize_filter(product_normalized) if product_normalized is not None else defaults["product_normalized"],
                self._normalize_filter(vendor_normalized) if vendor_normalized is not None else defaults["vendor_normalized"],
                json.dumps(cwe_values),
            ),
        )
        self.db.commit()
        return vuln_id

    def _insert_canonical_record(
        self, vuln_id: str, source_url: str, record: dict[str, Any],
        reserved_at: str, published_at: str, updated_at: str,
    ) -> None:
        defaults = self._record_defaults(record)
        self.db.execute(
            """INSERT OR REPLACE INTO gcve_records
            (vuln_id, source_url, record_json, record_type, assigner, reserved_at,
             published_at, updated_at, product_normalized, vendor_normalized, cwe_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (vuln_id.upper(), source_url, json.dumps(record, ensure_ascii=False, sort_keys=True),
             defaults["record_type"], defaults["assigner"], reserved_at, published_at,
             updated_at, defaults["product_normalized"], defaults["vendor_normalized"],
             json.dumps(defaults["cwes"])),
        )

    def update_gcve_record(
        self,
        vuln_id: str,
        record: dict[str, Any],
        *,
        record_type: str | None = None,
        assigner: str | None = None,
        updated_at: str | None = None,
        product_normalized: str | None = None,
        vendor_normalized: str | None = None,
        cwes: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        """Replace a published record while preserving its reservation and publication dates."""
        identifier = vuln_id.strip().upper()
        if self._record_id(record) != identifier:
            raise ValueError("record identifier does not match vuln_id")
        defaults = self._record_defaults(record)
        cwe_values = sorted(set(str(value).upper() for value in (cwes if cwes is not None else defaults["cwes"])))
        cursor = self.db.execute(
            """UPDATE gcve_records SET record_json=?, record_type=?, assigner=?, updated_at=?,
            product_normalized=?, vendor_normalized=?, cwe_json=? WHERE vuln_id=?""",
            (
                json.dumps(record, ensure_ascii=False, sort_keys=True),
                record_type or defaults["record_type"], assigner or defaults["assigner"],
                updated_at or str(defaults["updated_at"]) or self._utc_now(),
                self._normalize_filter(product_normalized) if product_normalized is not None else defaults["product_normalized"],
                self._normalize_filter(vendor_normalized) if vendor_normalized is not None else defaults["vendor_normalized"],
                json.dumps(cwe_values), identifier,
            ),
        )
        if cursor.rowcount != 1:
            self.db.rollback()
            raise KeyError(identifier)
        self.db.commit()

    def query_gcve_records(
        self,
        *,
        since: str | None = None,
        record_type: str | None = None,
        assigner: str | None = None,
        product: str | None = None,
        vendor: str | None = None,
        cwe: str | None = None,
        page: int = 1,
        per_page: int = 100,
    ) -> list[dict[str, Any]]:
        """Return canonical records selected by BCP-03 publication-feed filters."""
        if page < 1 or not 1 <= per_page <= 100:
            raise ValueError("page must be positive and per_page must be between 1 and 100")
        clauses: list[str] = []
        params: list[object] = []
        for column, value in (("updated_at", since), ("record_type", record_type), ("assigner", assigner)):
            if value is not None:
                clauses.append(f"{column} >= ?" if column == "updated_at" else f"{column} = ?")
                params.append(value)
        for column, value in (("product_normalized", product), ("vendor_normalized", vendor)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(self._normalize_filter(value))
        if cwe is not None:
            clauses.append("EXISTS (SELECT 1 FROM json_each(cwe_json) WHERE value = ?)")
            params.append(cwe.upper())
        query = "SELECT record_json FROM gcve_records"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY updated_at, published_at, vuln_id LIMIT ? OFFSET ?"
        params.extend((per_page, (page - 1) * per_page))
        return [json.loads(row[0]) for row in self.db.execute(query, params)]

    def dump_gcve_records(self) -> list[dict[str, Any]]:
        """Return the complete canonical dump in stable chronological order."""
        rows = self.db.execute(
            "SELECT record_json FROM gcve_records ORDER BY updated_at, published_at, vuln_id"
        )
        return [json.loads(row[0]) for row in rows]

    def seen(self, source_url: str) -> bool:
        return self.db.execute("SELECT 1 FROM observations WHERE source_url = ?", (source_url,)).fetchone() is not None

    def save(
        self, message: Message, extraction: Extraction, matches: list[Match], *,
        analysis: dict[str, object] | None = None, analysis_trigger: str = "import",
    ) -> None:
        canonical_key = message.message_id.strip().casefold() or message.source_url
        existing = self.db.execute(
            "SELECT source_url FROM observations WHERE source_id=? AND canonical_key=?",
            (message.source_id, canonical_key),
        ).fetchone()
        if existing:
            message.source_url = str(existing[0])
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
        self.db.execute(
            "UPDATE observations SET source_id=?, canonical_key=? WHERE source_url=?",
            (message.source_id, canonical_key, message.source_url),
        )
        self.db.execute(
            "INSERT OR IGNORE INTO sources(source_id, name) VALUES (?, ?)",
            (message.source_id, message.source_id.replace("-", " ").title()),
        )
        if analysis is not None:
            self._insert_analysis_event(message.source_url, analysis_trigger, analysis)
        self.db.commit()

    def record_submission(self, source_url: str, vulnerability_id: str, sighting_type: str, response: object) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO submissions (source_url, vulnerability_id, sighting_type, response_json) VALUES (?, ?, ?, ?)",
            (source_url, vulnerability_id, sighting_type, json.dumps(response)),
        )
        self.db.commit()

    def _decode(self, row: sqlite3.Row, include_body: bool = False) -> dict[str, object]:
        item = dict(row)
        fallbacks: dict[str, object] = {
            "links_json": [], "extraction_json": {}, "matches_json": [],
            "reviewed_vulnerability_ids_json": [],
        }
        for key in ("links_json", "extraction_json", "matches_json", "reviewed_vulnerability_ids_json"):
            encoded = str(item.pop(key))
            try:
                item[key.removesuffix("_json")] = json.loads(encoded)
            except json.JSONDecodeError:
                item[key.removesuffix("_json")] = fallbacks[key]
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

    def cpe_enrichment_candidates(self, limit: int = 0) -> list[dict[str, object]]:
        """Return observations whose product/vendor pair can be canonicalized."""
        self.db.row_factory = sqlite3.Row
        query = """SELECT * FROM observations
            WHERE COALESCE(json_extract(extraction_json, '$.product_hint'), '') <> ''
            ORDER BY published DESC, source_url DESC"""
        params: tuple[int, ...] = ()
        if limit > 0:
            query += " LIMIT ?"
            params = (limit,)
        return [self._decode(row) for row in self.db.execute(query, params)]

    def update_extraction(self, source_url: str, extraction: Extraction) -> None:
        """Persist enrichment without re-fetching or re-parsing source evidence."""
        cursor = self.db.execute(
            """UPDATE observations SET extraction_json=?, updated_at=CURRENT_TIMESTAMP
            WHERE source_url=?""",
            (json.dumps(extraction.as_dict()), source_url),
        )
        if cursor.rowcount != 1:
            self.db.rollback()
            raise ValueError(f"unknown observation: {source_url}")
        self.db.commit()

    def update_published_vendor(self, source_url: str, vendor: str) -> int:
        """Publish a vendor correction for local GCVE records from an observation."""
        return self.update_published_affected(
            source_url, vendor=vendor,
        )

    def update_published_affected(
        self, source_url: str, *args: object, **changes: object,
    ) -> int:
        """Compatibility entry point for affected-metadata corrections.

        Older callers may still send ``previous_product`` and newer callers
        omit it.  Accept both forms without making that migration-only value
        part of the repair implementation's required interface.
        """
        vendor = str(changes.pop("vendor", args[0] if args else "") or "")
        product = str(changes.pop("product", args[1] if len(args) > 1 else "") or "")
        changes.pop("previous_product", None)
        if len(args) > 2 or changes:
            unexpected = ", ".join(sorted(changes)) or "positional arguments"
            raise TypeError(f"unexpected affected correction arguments: {unexpected}")
        return self._update_published_affected(source_url, vendor, product)

    def _update_published_affected(
        self, source_url: str, vendor: str, product: str,
    ) -> int:
        """Correct placeholder or identifier-like affected metadata.

        Vendor-prefixed products may be replaced by their canonical suffix;
        unrelated affected products remain untouched.
        """
        keys = self.db.execute(
            """SELECT publication_key FROM automatic_publications
            WHERE source_url=? AND kind='gcve' AND status='published'""",
            (source_url,),
        ).fetchall()
        updated = 0
        for (publication_key,) in keys:
            entry = self.publication(source_url, str(publication_key))
            record = entry.get("payload") if entry else None
            if not isinstance(record, dict):
                continue
            containers = record.get("containers")
            cna = containers.get("cna") if isinstance(containers, dict) else None
            affected = cna.get("affected") if isinstance(cna, dict) else None
            if not isinstance(affected, list):
                continue
            changed = False
            for affected_product in affected:
                if not isinstance(affected_product, dict):
                    continue
                old_vendor = str(affected_product.get("vendor") or "").strip()
                old_product = str(affected_product.get("product") or "").strip()
                invalid_vendor = old_vendor.casefold() in {"", "unknown", "n/a", "cve", "gcve", "ghsa"}
                invalid_product = old_product.casefold() in {"", "unknown", "n/a"} or bool(
                    re.fullmatch(r"(?:CVE-\d{4}-\d{4,}|GCVE-\d+-\d{4}-\d{4,}|GHSA-[\w-]+)", old_product, re.IGNORECASE)
                    or re.match(
                        r"(?:[A-Z][A-Z0-9._]*)-SA-\d{1,4}(?:-\d{1,4}){2,4}\s+(?=\S)",
                        old_product, re.IGNORECASE,
                    )
                )
                invalid_product = invalid_product or bool(
                    product and old_product.casefold().endswith(" " + product.casefold())
                )
                if vendor and invalid_vendor:
                    affected_product["vendor"] = vendor
                    changed = True
                if product and invalid_product:
                    affected_product["product"] = product
                    changed = True
            if not changed:
                continue
            now = self._utc_now()
            metadata = record.get("cveMetadata")
            if isinstance(metadata, dict):
                metadata["dateUpdated"] = now
            provider = cna.get("providerMetadata") if isinstance(cna, dict) else None
            if isinstance(provider, dict):
                provider["dateUpdated"] = now
            self.save_publication(
                source_url, str(publication_key), "gcve",
                gcve_id=str(entry.get("gcve_id") or ""), status="published", payload=record,
            )
            updated += 1
        return updated

    def update_published_affected(
        self, source_url: str, vendor: str, product: str, *, previous_product: str,
    ) -> int:
        """Apply a registry-validated product identity to local publications."""
        keys = self.db.execute(
            """SELECT publication_key FROM automatic_publications
            WHERE source_url=? AND kind='gcve' AND status='published'""", (source_url,),
        ).fetchall()
        updated = 0
        for (publication_key,) in keys:
            entry = self.publication(source_url, str(publication_key))
            record = entry.get("payload") if entry else None
            cna = (record.get("containers") or {}).get("cna") if isinstance(record, dict) else None
            affected = cna.get("affected") if isinstance(cna, dict) else None
            if not isinstance(affected, list):
                continue
            changed = False
            for item in affected:
                if (isinstance(item, dict)
                        and self._normalize_filter(item.get("product"))
                        == self._normalize_filter(previous_product)
                        and (item.get("vendor") != vendor or item.get("product") != product)):
                    item["vendor"], item["product"] = vendor, product
                    changed = True
            if not changed:
                continue
            now = self._utc_now()
            record.get("cveMetadata", {})["dateUpdated"] = now
            cna.get("providerMetadata", {})["dateUpdated"] = now
            self.save_publication(
                source_url, str(publication_key), "gcve", gcve_id=str(entry.get("gcve_id") or ""),
                status="published", payload=record,
            )
            updated += 1
        return updated

    def observation_page(self, request: ListQuery) -> ListPage:
        """Return one stable, SQL-paginated observation collection."""
        tokens = re.findall(r"[^\W_]+", request.search, re.UNICODE)[:12]
        if request.search and not tokens:
            return ListPage([], 0, request.page, request.per_page)
        joins = ""
        clauses: list[str] = []
        params: list[object] = []
        rank = ""
        confidence = (
            "COALESCE((SELECT MAX(CAST(json_extract(value, '$.confidence') AS REAL)) "
            "FROM json_each(CASE WHEN json_valid(o.matches_json) "
            "THEN o.matches_json ELSE '[]' END)), 0)"
        )
        if tokens and self.fts_enabled:
            joins = " JOIN observations_fts ON observations_fts.source_url=o.source_url"
            clauses.append("observations_fts MATCH ?")
            params.append(" AND ".join(f'"{token}"*' for token in tokens))
            rank = ", bm25(observations_fts, 0.0, 5.0, 2.0, 1.0, 3.0) AS search_rank"
        elif tokens:
            needle = "%" + " ".join(tokens) + "%"
            clauses.append("(o.title LIKE ? OR o.author LIKE ? OR o.body LIKE ? OR o.extraction_json LIKE ?)")
            params.extend((needle, needle, needle, needle))
        if request.status:
            clauses.append("o.status = ?")
            params.append(request.status)
        if request.review_state:
            clauses.append("o.review_state = ?")
            params.append(request.review_state)
        if request.confidence_min > 0:
            clauses.append(f"{confidence} >= ?")
            params.append(request.confidence_min)
        if request.confidence_max < 1:
            clauses.append(f"{confidence} <= ?")
            params.append(request.confidence_max)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        total = int(self.db.execute("SELECT COUNT(*) FROM observations o" + joins + where, params).fetchone()[0])
        sort_columns = {
            "published": "o.published", "title": "o.title COLLATE NOCASE",
            "author": "o.author COLLATE NOCASE", "status": "o.status",
            "review": "o.review_state", "confidence": confidence,
        }
        direction = request.order.upper()
        primary = "search_rank ASC, " if tokens and self.fts_enabled and request.sort == "published" else ""
        order = f" ORDER BY {primary}{sort_columns[request.sort]} {direction}, o.source_url {direction}"
        select = f"SELECT o.*, {confidence} AS max_confidence{rank} FROM observations o"
        page_params = [*params, request.per_page, (request.page - 1) * request.per_page]
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute(select + joins + where + order + " LIMIT ? OFFSET ?", page_params)
        return ListPage([self._decode(row) for row in rows], total, request.page, request.per_page)

    def review_counts(self) -> dict[str, int]:
        counts = {"pending": 0, "approved": 0, "rejected": 0}
        for state, count in self.db.execute(
            "SELECT review_state, COUNT(*) FROM observations GROUP BY review_state"
        ):
            if state in counts:
                counts[str(state)] = int(count)
        return counts

    def search_rows(
        self, query: str, status: str | None = None, review_state: str | None = None,
    ) -> list[dict[str, object]]:
        """Search titles, authors, bodies and extracted metadata using FTS5."""
        tokens = re.findall(r"[^\W_]+", query, re.UNICODE)[:12]
        if not tokens:
            return []
        if not self.fts_enabled:
            needle = "%" + " ".join(tokens) + "%"
            self.db.row_factory = sqlite3.Row
            clauses = ["(title LIKE ? OR author LIKE ? OR body LIKE ? OR extraction_json LIKE ?)"]
            params: list[str] = [needle, needle, needle, needle]
            if status:
                clauses.append("status = ?")
                params.append(status)
            if review_state:
                clauses.append("review_state = ?")
                params.append(review_state)
            rows = self.db.execute(
                "SELECT * FROM observations WHERE " + " AND ".join(clauses) +
                " ORDER BY published DESC, source_url DESC", params,
            )
            return [self._decode(row) for row in rows]
        expression = " AND ".join(f'"{token}"*' for token in tokens)
        clauses = ["observations_fts MATCH ?"]
        params: list[str] = [expression]
        if status:
            clauses.append("o.status = ?")
            params.append(status)
        if review_state:
            clauses.append("o.review_state = ?")
            params.append(review_state)
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute(
            "SELECT o.*, bm25(observations_fts, 0.0, 5.0, 2.0, 1.0, 3.0) AS search_rank "
            "FROM observations_fts JOIN observations o ON o.source_url=observations_fts.source_url "
            "WHERE " + " AND ".join(clauses) + " ORDER BY search_rank, o.published DESC, o.source_url DESC",
            params,
        )
        return [self._decode(row) for row in rows]

    def published_gcve_for_source(self, source_url: str) -> str:
        row = self.db.execute(
            "SELECT p.gcve_id FROM automatic_publications p JOIN gcve_records r ON r.vuln_id=p.gcve_id "
            "WHERE p.source_url=? AND p.kind='gcve' AND p.status='published' AND p.gcve_id<>'' "
            "ORDER BY p.published_at DESC LIMIT 1", (source_url,),
        ).fetchone()
        return str(row[0]) if row else ""

    def gcve_record(self, vulnerability_id: str) -> dict[str, object] | None:
        row = self.db.execute("SELECT record_json FROM gcve_records WHERE vuln_id=?", (vulnerability_id.upper(),)).fetchone()
        return json.loads(str(row[0])) if row else None

    def get(self, source_url: str) -> dict[str, object] | None:
        self.db.row_factory = sqlite3.Row
        row = self.db.execute("SELECT * FROM observations WHERE source_url = ?", (source_url,)).fetchone()
        return self._decode(row, include_body=True) if row else None

    def get_by_content_hash(self, content_hash: str) -> dict[str, object] | None:
        self.db.row_factory = sqlite3.Row
        row = self.db.execute(
            "SELECT * FROM observations WHERE content_hash=? ORDER BY source_url LIMIT 1",
            (content_hash,),
        ).fetchone()
        return self._decode(row, include_body=True) if row else None

    def review(
        self, source_url: str, state: str,
        vulnerability_ids: str | list[str] | tuple[str, ...] = (),
        sighting_type: str = "", note: str = "", *, actor: str = "",
    ) -> None:
        if state not in {"pending", "approved", "rejected"}:
            raise ValueError("invalid review state")
        candidates = [vulnerability_ids] if isinstance(vulnerability_ids, str) else list(vulnerability_ids)
        identifiers = list(dict.fromkeys(value.strip().upper() for value in candidates if value.strip()))
        if state == "approved" and sighting_type not in {"seen", "published-proof-of-concept"}:
            raise ValueError("approved observations require a valid sighting type")
        projected_state = self._projected_review_state(source_url, state, actor)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            cursor = self.db.execute(
                """UPDATE observations SET review_state=?, reviewed_vulnerability_id=?, reviewed_vulnerability_ids_json=?,
                reviewed_sighting_type=?, review_note=?, reviewed_at=CURRENT_TIMESTAMP
                WHERE source_url=?""",
                (projected_state, identifiers[0] if identifiers else "", json.dumps(identifiers),
                 sighting_type, note[:2000], source_url),
            )
            if cursor.rowcount != 1:
                raise ValueError("observation not found")
            self._record_review_event(source_url, state, identifiers, sighting_type, note, actor)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def review_many(
        self, source_urls: list[str], state: str, note: str = "", *, actor: str = "",
    ) -> int:
        """Apply one review decision to a bounded set of explicitly selected rows."""
        sources = list(dict.fromkeys(value for value in source_urls if value))
        if not sources or len(sources) > 100:
            raise ValueError("select between 1 and 100 observations")
        if state not in {"approved", "rejected", "pending"}:
            raise ValueError("invalid bulk review state")
        updated = 0
        try:
            self.db.execute("BEGIN IMMEDIATE")
            for source_url in sources:
                row = self.get(source_url)
                if not row:
                    continue
                extraction = dict(row.get("extraction") or {})
                matches = list(row.get("matches") or [])
                identifiers = list(dict.fromkeys(
                    str(match.get("vulnerability_id") or "").strip().upper()
                    for match in matches if isinstance(match, dict) and match.get("vulnerability_id")
                )) if state == "approved" else []
                sighting_type = str(extraction.get("proposed_type") or "seen") if state == "approved" else ""
                if sighting_type not in {"seen", "published-proof-of-concept"}:
                    sighting_type = "seen"
                projected_state = self._projected_review_state(source_url, state, actor)
                cursor = self.db.execute(
                    """UPDATE observations SET review_state=?, reviewed_vulnerability_id=?,
                    reviewed_vulnerability_ids_json=?, reviewed_sighting_type=?, review_note=?,
                    reviewed_at=CURRENT_TIMESTAMP WHERE source_url=?""",
                    (projected_state, identifiers[0] if identifiers else "", json.dumps(identifiers),
                     sighting_type, note[:2000], source_url),
                )
                updated += cursor.rowcount
                self._record_review_event(source_url, state, identifiers, sighting_type, note, actor)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return updated

    def _projected_review_state(self, source_url: str, requested: str, actor: str) -> str:
        if requested != "approved" or not self.four_eyes_enabled():
            return requested
        if not actor:
            raise ValueError("four-eyes approval requires an authenticated reviewer")
        barrier = self.db.execute(
            """SELECT COALESCE(MAX(event_id), 0) FROM review_events
            WHERE source_url=? AND review_state<>'approved'""", (source_url,),
        ).fetchone()[0]
        prior = self.db.execute(
            """SELECT 1 FROM review_events WHERE source_url=? AND review_state='approved'
            AND event_id>? AND actor<>? AND actor<>'' LIMIT 1""", (source_url, barrier, actor),
        ).fetchone()
        return "approved" if prior else "pending"

    def _record_review_event(
        self, source_url: str, state: str, identifiers: list[str],
        sighting_type: str, note: str, actor: str,
    ) -> None:
        self.db.execute(
            """INSERT INTO review_events
            (source_url, review_state, vulnerability_ids_json, sighting_type, note, actor)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (source_url, state, json.dumps(identifiers), sighting_type, note[:2000], actor[:200]),
        )

    def review_events(self, source_url: str) -> list[dict[str, object]]:
        """Return the immutable decision history, newest event first."""
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute(
            """SELECT event_id, review_state, vulnerability_ids_json, sighting_type,
                      note, actor, created_at
            FROM review_events WHERE source_url=? ORDER BY event_id DESC""",
            (source_url,),
        )
        events = []
        for row in rows:
            event = dict(row)
            event["vulnerability_ids"] = json.loads(str(event.pop("vulnerability_ids_json")))
            events.append(event)
        return events

    def record_analysis_event(self, source_url: str, trigger_name: str, analysis: dict[str, object]) -> None:
        """Persist one immutable matching run after its observation projection."""
        self._insert_analysis_event(source_url, trigger_name, analysis)
        self.db.commit()

    def _insert_analysis_event(self, source_url: str, trigger_name: str, analysis: dict[str, object]) -> None:
        self.db.execute(
            """INSERT INTO analysis_events
            (source_url, trigger_name, provider, model, prompt_version, input_sha256,
             response_id, retrieval_at, context_json, candidates_json, deterministic_json,
             excluded_json, llm_output_json, result_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                source_url, trigger_name, str(analysis.get("provider") or ""),
                str(analysis.get("model") or ""), str(analysis.get("prompt_version") or ""),
                str(analysis.get("input_sha256") or ""), str(analysis.get("response_id") or ""),
                str(analysis.get("retrieval_at") or self._utc_now()),
                json.dumps({"semantic": analysis.get("semantic"), "explicit_ids": analysis.get("explicit_ids") or []}),
                json.dumps(analysis.get("candidates") or []),
                json.dumps(analysis.get("deterministic_matches") or []),
                json.dumps(analysis.get("excluded_candidates") or []),
                json.dumps(analysis.get("llm_output") or {}),
                json.dumps(analysis.get("result") or []), str(analysis.get("error") or "")[:2000],
            ),
        )

    def analysis_events(self, source_url: str, limit: int = 20) -> list[dict[str, object]]:
        if not 1 <= limit <= 100:
            raise ValueError("analysis event limit must be between 1 and 100")
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute(
            "SELECT * FROM analysis_events WHERE source_url=? ORDER BY event_id DESC LIMIT ?",
            (source_url, limit),
        )
        events = []
        for row in rows:
            event = dict(row)
            for name in ("context_json", "candidates_json", "deterministic_json", "excluded_json", "llm_output_json", "result_json"):
                event[name.removesuffix("_json")] = json.loads(str(event.pop(name)))
            events.append(event)
        return events

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
        at: datetime | None = None,
    ) -> None:
        previous = self.publication(source_url, publication_key) or {}
        timestamp = self._utc_iso(at or datetime.now(timezone.utc))
        payload_value = payload if payload is not None else previous.get("payload", {})
        response_value = response if response is not None else previous.get("response", {})
        reserved_at = previous.get("reserved_at")
        if kind == "gcve" and gcve_id and not reserved_at:
            reserved_at = timestamp
        published_at = previous.get("published_at")
        if kind == "gcve" and status == "published" and not published_at:
            published_at = timestamp
        # Transport/status retries do not constitute record changes.  Publication
        # does, as does a changed payload after publication.
        content_changed = payload is not None and payload_value != previous.get("payload")
        updated_at = previous.get("updated_at") or timestamp
        if kind == "gcve" and (not previous or (status == "published" and not previous.get("published_at")) or
                               (previous.get("published_at") and content_changed)):
            updated_at = timestamp
        self.db.execute(
            """INSERT INTO automatic_publications
            (source_url, publication_key, kind, target_id, gcve_id, status, payload_json, response_json,
             error, reserved_at, published_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_url, publication_key) DO UPDATE SET
              kind=excluded.kind, target_id=excluded.target_id,
              gcve_id=CASE WHEN excluded.gcve_id='' THEN automatic_publications.gcve_id ELSE excluded.gcve_id END,
              status=excluded.status, payload_json=excluded.payload_json,
              response_json=excluded.response_json, error=excluded.error,
              reserved_at=excluded.reserved_at, published_at=excluded.published_at,
              updated_at=excluded.updated_at""",
            (
                source_url,
                publication_key,
                kind,
                target_id,
                gcve_id,
                status,
                json.dumps(payload_value),
                json.dumps(response_value),
                error[:4000],
                reserved_at,
                published_at,
                updated_at,
            ),
        )
        if kind == "gcve" and status == "published" and gcve_id and isinstance(payload_value, dict):
            self._insert_canonical_record(
                gcve_id, source_url, payload_value, str(reserved_at or timestamp),
                str(published_at or timestamp), str(updated_at),
            )
        self.db.commit()

    def reserve_gcve(self, source_url: str, publication_key: str, gna_id: int, year: int) -> str:
        """Reserve an identifier locally, serializing allocators with BEGIN IMMEDIATE."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            existing = self.db.execute(
                "SELECT gcve_id FROM gcve_reservations WHERE source_url=? AND publication_key=?",
                (source_url, publication_key),
            ).fetchone()
            if existing:
                return str(existing[0])
            serial = int(self.db.execute(
                "SELECT COALESCE(MAX(serial), 0) + 1 FROM gcve_reservations WHERE gna_id=? AND publication_year=?",
                (gna_id, year),
            ).fetchone()[0])
            gcve_id = f"GCVE-{gna_id}-{year}-{serial:04d}"
            self.db.execute(
                """INSERT INTO gcve_reservations
                (source_url, publication_key, gcve_id, gna_id, publication_year, serial)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (source_url, publication_key, gcve_id, gna_id, year, serial),
            )
            self._upsert_publication(
                source_url, publication_key, "gcve", gcve_id=gcve_id, status="reserved"
            )
            return gcve_id

    def publish_gcve(
        self, source_url: str, publication_key: str, gcve_id: str, record: object
    ) -> None:
        """Atomically make a record public and mark its ledger entry published."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            reservation = self.db.execute(
                "SELECT gcve_id FROM gcve_reservations WHERE source_url=? AND publication_key=?",
                (source_url, publication_key),
            ).fetchone()
            if not reservation or reservation[0] != gcve_id:
                raise ValueError(f"{gcve_id} is not reserved for this publication")
            if not isinstance(record, dict):
                raise ValueError("GCVE record must be a JSON object")
            timestamp = self._utc_now()
            self._insert_canonical_record(gcve_id, source_url, record, timestamp, timestamp, timestamp)
            self._upsert_publication(
                source_url, publication_key, "gcve", gcve_id=gcve_id,
                status="published", payload=record,
            )

    def _upsert_publication(
        self, source_url: str, publication_key: str, kind: str, *, target_id: str = "",
        gcve_id: str = "", status: str, payload: object | None = None,
        response: object | None = None, error: str = "",
    ) -> None:
        """Write a ledger row without committing, for callers managing a transaction."""
        row = self.db.execute(
            "SELECT payload_json, response_json FROM automatic_publications WHERE source_url=? AND publication_key=?",
            (source_url, publication_key),
        ).fetchone()
        old_payload, old_response = row if row else ("{}", "{}")
        self.db.execute(
            """INSERT INTO automatic_publications
            (source_url, publication_key, kind, target_id, gcve_id, status, payload_json, response_json, error, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_url, publication_key) DO UPDATE SET
              kind=excluded.kind, target_id=excluded.target_id,
              gcve_id=CASE WHEN excluded.gcve_id='' THEN automatic_publications.gcve_id ELSE excluded.gcve_id END,
              status=excluded.status, payload_json=excluded.payload_json,
              response_json=excluded.response_json, error=excluded.error, updated_at=CURRENT_TIMESTAMP""",
            (source_url, publication_key, kind, target_id, gcve_id, status,
             json.dumps(payload) if payload is not None else old_payload,
             json.dumps(response) if response is not None else old_response, error[:4000], self._utc_now()),
        )

    def gcve_records(self, *, date_sort: str = "", since: str | None = None) -> list[dict[str, object]]:
        """Return publication-ledger metadata for compatibility and auditing."""
        sort = date_sort or "updated"
        if sort not in {"published", "updated", "reserved"}:
            raise ValueError("date_sort must be published, updated, reserved, or empty")
        params: list[str] = []
        where = "kind='gcve' AND status='published'"
        if since is not None:
            boundary = self._parse_timestamp(since)
            where += " AND (published_at > ? OR updated_at > ?)"
            params.extend((boundary, boundary))
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute(
            f"SELECT * FROM automatic_publications WHERE {where} "
            f"ORDER BY {sort}_at DESC, gcve_id ASC", params,
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["record"] = json.loads(str(item.pop("payload_json")))
            item.pop("response_json")
            result.append(item)
        return result

    def bcp03_publications(self) -> list[dict[str, object]]:
        """Return committed records in the order expected by a BCP-03 pull endpoint."""
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT record_json FROM gcve_records ORDER BY vuln_id"
        )]

    def automatic_candidates(self, limit: int = 0) -> list[dict[str, object]]:
        """Return relevant archived observations; the publication ledger provides idempotency."""
        self.db.row_factory = sqlite3.Row
        query = "SELECT * FROM observations WHERE status IN ('matched', 'unmatched') ORDER BY published, source_url"
        params: tuple[int, ...] = ()
        if limit:
            query += " LIMIT ?"
            params = (limit,)
        candidates = [self._decode(row, include_body=True) for row in self.db.execute(query, params)]
        for candidate in candidates:
            if candidate["review_state"] != "approved":
                continue
            existing = {
                str(match.get("vulnerability_id", "")).upper(): match
                for match in candidate["matches"] if isinstance(match, dict)
            }
            candidate["matches"] = [
                {
                    **existing.get(identifier, {}),
                    "vulnerability_id": identifier,
                    "method": "analyst-approved",
                    "confidence": 1.0,
                    "title": str(existing.get(identifier, {}).get("title") or ""),
                }
                for identifier in candidate["reviewed_vulnerability_ids"]
            ]
        return candidates

    @staticmethod
    def _normalized_subject(value: object) -> str:
        subject = str(value or "").casefold()
        # Lists and gateways commonly add multiple routing markers.
        previous = None
        while subject != previous:
            previous = subject
            subject = re.sub(r"^\s*(?:(?:re|fw|fwd)\s*:\s*|\[[^\]]{1,40}\]\s*)", "", subject)
        return " ".join(re.findall(r"[a-z0-9][a-z0-9_.+-]*", subject))

    @staticmethod
    def _normalized_body(value: object) -> str:
        body = str(value or "").casefold().replace("\r\n", "\n")
        body = re.sub(
            r"-----begin pgp signature-----.*?-----end pgp signature-----", " ", body,
            flags=re.DOTALL,
        )
        body = re.sub(r"-----begin pgp signed message-----\s*(?:hash:[^\n]*\n)?", "", body)
        lines = []
        for line in body.splitlines():
            stripped = line.strip()
            if re.match(r"^(?:list-|x-mailing-list|x-beenthere|precedence|delivered-to):", stripped):
                continue
            if any(marker in stripped for marker in (
                "to unsubscribe", "mailing list archive", "/mailman/listinfo/", "manage your subscription",
            )):
                continue
            lines.append(line)
        return " ".join(re.findall(r"[a-z0-9][a-z0-9_.+-]*", "\n".join(lines)))

    @classmethod
    def _observation_fingerprint(cls, row: dict[str, object]) -> str:
        normalized = cls._normalized_subject(row.get("title")) + "\n" + cls._normalized_body(row.get("body"))
        return hashlib.sha256(normalized.encode()).hexdigest()

    @staticmethod
    def _shingles(value: str, size: int = 4) -> set[tuple[str, ...]]:
        words = value.split()
        return {tuple(words[index:index + size]) for index in range(max(0, len(words) - size + 1))}

    @classmethod
    def _fuzzy_duplicate(cls, left: dict[str, object], right: dict[str, object]) -> bool:
        left_extraction = dict(left.get("extraction") or {})
        right_extraction = dict(right.get("extraction") or {})
        left_ids = {str(item).upper() for item in left_extraction.get("cve_ids") or []}
        right_ids = {str(item).upper() for item in right_extraction.get("cve_ids") or []}
        if left_ids and right_ids and left_ids.isdisjoint(right_ids):
            return False
        left_product = str(left_extraction.get("product_hint") or "").casefold().strip()
        right_product = str(right_extraction.get("product_hint") or "").casefold().strip()
        if left_product and right_product and left_product != right_product:
            return False
        subject_similarity = SequenceMatcher(
            None, cls._normalized_subject(left.get("title")), cls._normalized_subject(right.get("title")),
            autojunk=False,
        ).ratio()
        left_shingles = cls._shingles(cls._normalized_body(left.get("body")))
        right_shingles = cls._shingles(cls._normalized_body(right.get("body")))
        if min(len(left_shingles), len(right_shingles)) < 20:
            return False
        overlap = len(left_shingles & right_shingles)
        jaccard = overlap / len(left_shingles | right_shingles)
        containment = overlap / min(len(left_shingles), len(right_shingles))
        return subject_similarity >= 0.88 and (jaccard >= 0.72 or containment >= 0.90)

    def published_duplicate(self, candidate: dict[str, object]) -> tuple[str, dict[str, object], str] | None:
        """Find an already-published copy from another mailing-list source.

        Message-ID is the strongest cross-list identity. A gateway-tolerant
        fingerprint and conservative shingle similarity cover
        changed subjects, transport headers, list footers, and PGP signatures.
        """
        self.db.row_factory = sqlite3.Row
        rows = self.db.execute(
            """SELECT o.*, p.gcve_id FROM observations o
            JOIN automatic_publications p ON p.source_url=o.source_url
            WHERE p.kind='gcve' AND p.status='published' AND p.gcve_id<>''
              AND o.source_url<>? AND o.source_id<>?""",
            (candidate["source_url"], candidate.get("source_id", "")),
        )
        message_id = str(candidate.get("message_id") or "").strip().casefold()
        fingerprint = self._observation_fingerprint(candidate)
        for row in rows:
            item = self._decode(row, include_body=True)
            same_message = message_id and str(item.get("message_id") or "").strip().casefold() == message_id
            exact_content = (
                len(self._normalized_body(candidate.get("body")).split()) >= 20
                and self._observation_fingerprint(item) == fingerprint
            )
            fuzzy_content = self._fuzzy_duplicate(candidate, item)
            if same_message or exact_content or fuzzy_content:
                record = self.gcve_record(str(row["gcve_id"]))
                if record:
                    method = "message-id" if same_message else "normalized-content" if exact_content else "fuzzy-content"
                    return str(row["gcve_id"]), record, method
        return None

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
        """Compatibility alias for the single canonical local GCVE store."""
        return self.published_gcve_records()

    def published_gcve_records(self) -> list[dict[str, object]]:
        """Return the canonical records consumed by all public representations."""
        local_org = os.getenv("VA_GNA_ORG_UUID", "").casefold()
        return [record for record in self.dump_gcve_records()
                if self._record_id(record).startswith("GCVE-1988-")
                and str(record.get("cveMetadata", {}).get("state", "")).upper() == "PUBLISHED"
                and (not local_org or str(
                    record.get("cveMetadata", {}).get("assignerOrgId", "")
                ).casefold() == local_org)]
