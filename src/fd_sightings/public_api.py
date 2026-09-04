from __future__ import annotations

import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from .store import Store


LOCAL_ID_PREFIX = "GCVE-1988-"
_CWE = re.compile(r"^(?:CWE[-_ ]?)?(\d+)$", re.IGNORECASE)


class InvalidParameter(ValueError):
    def __init__(self, parameter: str, message: str) -> None:
        super().__init__(message)
        self.parameter = parameter


def _one(parameters: dict[str, list[str]], name: str, default: str) -> str:
    values = parameters.get(name)
    if not values:
        return default
    if len(values) != 1:
        raise InvalidParameter(name, "must be specified at most once")
    return values[0]


def _integer(parameters: dict[str, list[str]], name: str, default: int, minimum: int, maximum: int | None = None) -> int:
    value = _one(parameters, name, str(default))
    try:
        result = int(value)
    except ValueError as exc:
        raise InvalidParameter(name, "must be an integer") from exc
    if result < minimum or (maximum is not None and result > maximum):
        limit = f"between {minimum} and {maximum}" if maximum is not None else f"at least {minimum}"
        raise InvalidParameter(name, f"must be {limit}")
    return result


def _timestamp(value: object) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            return None
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _metadata(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("cveMetadata")
    return value if isinstance(value, dict) else {}


def _products(record: dict[str, Any]) -> set[str]:
    cna = (record.get("containers") or {}).get("cna") or {}
    return {
        str(affected.get("product", "")).casefold()
        for affected in cna.get("affected", [])
        if isinstance(affected, dict)
    }


def _cwes(record: dict[str, Any]) -> set[str]:
    cna = (record.get("containers") or {}).get("cna") or {}
    values: set[str] = set()
    for problem_type in cna.get("problemTypes", []):
        if not isinstance(problem_type, dict):
            continue
        for description in problem_type.get("descriptions", []):
            if not isinstance(description, dict):
                continue
            for candidate in (description.get("cweId"), description.get("description")):
                match = _CWE.fullmatch(str(candidate or "").strip())
                if match:
                    values.add(f"CWE-{int(match.group(1))}")
    return values


def publication_records(store: Store, query: str) -> list[dict[str, Any]]:
    parameters = urllib.parse.parse_qs(query, keep_blank_values=True)
    page = _integer(parameters, "page", 1, 1)
    per_page = _integer(parameters, "per_page", 30, 1, 100)

    sort_order = _one(parameters, "sort_order", "desc")
    if sort_order not in {"asc", "desc"}:
        raise InvalidParameter("sort_order", "must be 'asc' or 'desc'")
    date_sort = _one(parameters, "date_sort", "")
    if date_sort not in {"", "published", "updated", "reserved"}:
        raise InvalidParameter("date_sort", "must be empty, 'published', 'updated', or 'reserved'")

    since_text = _one(parameters, "since", "")
    since = _timestamp(since_text)
    if "since" in parameters and since is None:
        raise InvalidParameter("since", "must be an ISO-8601 timestamp with a timezone")

    product = _one(parameters, "product", "").casefold()
    assigner = _one(parameters, "assigner", "").casefold()
    cwe_text = _one(parameters, "cwe", "").strip()
    cwe = ""
    if cwe_text:
        match = _CWE.fullmatch(cwe_text)
        if not match:
            raise InvalidParameter("cwe", "must be a CWE ID")
        cwe = f"CWE-{int(match.group(1))}"

    records = []
    for record in store.published_gcve_records():
        metadata = _metadata(record)
        vuln_id = str(metadata.get("vulnId") or metadata.get("cveId") or "")
        if not vuln_id.upper().startswith(LOCAL_ID_PREFIX):
            continue
        published = _timestamp(metadata.get("datePublished"))
        updated = _timestamp(metadata.get("dateUpdated"))
        if since is not None and not any(value is not None and value >= since for value in (published, updated)):
            continue
        if product and product not in _products(record):
            continue
        if assigner and assigner not in {
            str(metadata.get("assignerShortName", "")).casefold(),
            str(metadata.get("assignerOrgId", "")).casefold(),
        }:
            continue
        if cwe and cwe not in _cwes(record):
            continue
        records.append(record)

    date_fields = {"published": "datePublished", "updated": "dateUpdated", "reserved": "dateReserved"}
    field = date_fields.get(date_sort)
    # Stable two-pass sorting makes vuln_id the secondary key for date sorts.
    reverse = sort_order == "desc"
    records.sort(key=lambda item: str(_metadata(item).get("vulnId") or _metadata(item).get("cveId") or "").upper(), reverse=reverse)
    if field:
        records.sort(key=lambda item: _timestamp(_metadata(item).get(field)) or datetime.min.replace(tzinfo=timezone.utc), reverse=reverse)
    start = (page - 1) * per_page
    return records[start:start + per_page]


def publication_response(store: Store, query: str) -> tuple[int, bytes]:
    try:
        body: object = publication_records(store, query)
        status = 200
    except InvalidParameter as exc:
        status = 400
        body = {"error": "invalid_parameter", "parameter": exc.parameter, "message": str(exc)}
    return status, json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
