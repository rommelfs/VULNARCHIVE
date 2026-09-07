from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from collections.abc import Iterator
from typing import Any

from .vulnerability_lookup import VulnerabilityLookup


PAGE_SIZE = 100
LOCAL_PREFIX = "GCVE-1988-"


def publication_records(response: Any) -> list[dict[str, Any]]:
    """Return BCP-05 records from supported BCP-03 response envelopes."""
    if isinstance(response, list):
        values = response
    elif isinstance(response, dict):
        collections = [response[key] for key in ("data", "vulnerabilities", "items") if key in response]
        if len(collections) != 1:
            raise ValueError("publication response has no unambiguous record collection")
        values = collections[0]
    else:
        raise ValueError("publication response is neither an array nor an object")
    if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
        raise ValueError("publication record collection is not an array of objects")
    return values


def record_id(record: dict[str, Any]) -> str:
    metadata = record.get("cveMetadata")
    if not isinstance(metadata, dict):
        return ""
    identifier = metadata.get("vulnId") or metadata.get("cveId")
    return str(identifier).upper() if isinstance(identifier, str) else ""


def _is_public_local_record(record: dict[str, Any]) -> bool:
    metadata = record.get("cveMetadata")
    return (
        record_id(record).startswith(LOCAL_PREFIX)
        and isinstance(metadata, dict)
        and str(metadata.get("state", "")).upper() == "PUBLISHED"
    )


@contextmanager
def ndjson_lines(lookup: VulnerabilityLookup) -> Iterator[Iterator[bytes]]:
    """Stage and externally sort publication pages, then yield UTF-8 NDJSON lines.

    SQLite keeps memory use bounded while giving the response a stable ordering and
    lets all upstream pages be checked before HTTP response headers are committed.
    """
    descriptor, path = tempfile.mkstemp(prefix="vulnarchive-dump-", suffix=".sqlite")
    os.close(descriptor)
    database = sqlite3.connect(path)
    try:
        database.execute("CREATE TABLE records (vuln_id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        page = 1
        while True:
            response = lookup.client.get_json(
                f"{lookup.base_url}/api/gcve/publication",
                {"page": str(page), "per_page": str(PAGE_SIZE)},
            )
            records = publication_records(response)
            for record in records:
                if _is_public_local_record(record):
                    database.execute(
                        "INSERT INTO records (vuln_id, body) VALUES (?, ?)",
                        (record_id(record), json.dumps(record, ensure_ascii=False, separators=(",", ":"))),
                    )
            database.commit()
            if len(records) < PAGE_SIZE:
                break
            page += 1

        def lines() -> Iterator[bytes]:
            cursor = database.execute("SELECT body FROM records ORDER BY vuln_id")
            for (body,) in cursor:
                yield body.encode("utf-8") + b"\n"

        yield lines()
    finally:
        database.close()
        os.unlink(path)
