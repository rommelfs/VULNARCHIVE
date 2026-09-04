#!/usr/bin/env python3
"""Destructive BCP-03 acceptance check for a disposable VL test instance.

The check reserves and publishes one GCVE, so it deliberately requires both an
API key and an explicit --allow-write flag.  It only uses Python's standard
library and exits non-zero on the first failed assertion.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "bcp03" / "historical-record.json"
MAX_PER_PAGE = 100


class CheckFailure(RuntimeError):
    pass


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class HTTP:
    def __init__(self, base: str, api_key: str, timeout: float) -> None:
        self.base = base.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def request(self, path: str, *, method: str = "GET", payload: Any = None) -> tuple[int, bytes, Any]:
        headers = {"Accept": "application/json", "User-Agent": "VULNARCHIVE-BCP03-acceptance/1"}
        if self.api_key:
            headers["X-API-KEY"] = self.api_key
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=self.timeout)
            with response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers

    def json(self, path: str, *, expected: tuple[int, ...] = (200,), method: str = "GET", payload: Any = None) -> tuple[Any, Any]:
        status, body, headers = self.request(path, method=method, payload=payload)
        if status not in expected:
            raise CheckFailure(f"{method} {path}: expected HTTP {expected}, got {status}: {body[:500]!r}")
        content_type = headers.get_content_type().lower()
        if content_type not in {"application/json", "application/problem+json"}:
            raise CheckFailure(f"{method} {path}: expected JSON Content-Type, got {headers.get('Content-Type')!r}")
        try:
            return json.loads(body), headers
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CheckFailure(f"{method} {path}: invalid JSON: {exc}") from exc


def records(response: Any) -> list[dict[str, Any]]:
    """Extract records while accepting the two BCP-03 envelope revisions."""
    if isinstance(response, list):
        values = response
    elif isinstance(response, dict):
        keys = [key for key in ("data", "vulnerabilities", "items") if key in response]
        if len(keys) != 1:
            raise CheckFailure("BCP-03 envelope must contain exactly one record collection")
        values = response[keys[0]]
        if not isinstance(values, list):
            raise CheckFailure(f"BCP-03 {keys[0]!r} member is not an array")
        metadata = response.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise CheckFailure("BCP-03 metadata member is not an object")
    else:
        raise CheckFailure("BCP-03 response must be an array or object envelope")
    if not all(isinstance(item, dict) for item in values):
        raise CheckFailure("BCP-03 record collection contains a non-object")
    return values


def record_id(record: dict[str, Any]) -> str:
    metadata = record.get("cveMetadata")
    if not isinstance(metadata, dict):
        raise CheckFailure("record has no cveMetadata object")
    value = metadata.get("vulnId") or metadata.get("cveId")
    if not isinstance(value, str) or not value:
        raise CheckFailure("record has no cveMetadata.vulnId/cveId")
    return value.upper()


def validate_record(record: dict[str, Any]) -> None:
    identifier = record_id(record)
    if record.get("dataType") != "CVE_RECORD" or not isinstance(record.get("dataVersion"), str):
        raise CheckFailure(f"{identifier}: invalid CVE record type/version")
    metadata = record["cveMetadata"]
    if metadata.get("state") != "PUBLISHED":
        raise CheckFailure(f"{identifier}: record is not PUBLISHED")
    for field in ("datePublished", "dateUpdated"):
        value = metadata.get(field)
        try:
            datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise CheckFailure(f"{identifier}: invalid {field}") from exc
    containers = record.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    if not isinstance(cna, dict):
        raise CheckFailure(f"{identifier}: missing containers.cna")
    for field in ("providerMetadata", "descriptions", "affected", "references"):
        if field not in cna:
            raise CheckFailure(f"{identifier}: missing containers.cna.{field}")
    if not isinstance(cna["descriptions"], list) or not cna["descriptions"]:
        raise CheckFailure(f"{identifier}: descriptions must be a non-empty array")


def query(**parameters: object) -> str:
    return "/api/gcve/publication?" + urllib.parse.urlencode(parameters)


def check_parameters(http: HTTP) -> None:
    for params in ({"page": 0}, {"per_page": 0}, {"per_page": MAX_PER_PAGE + 1}, {"since": "not-a-timestamp"}):
        path = query(**params)
        status, _, _ = http.request(path)
        if status not in (400, 422):
            raise CheckFailure(f"GET {path}: invalid parameter was accepted with HTTP {status}")
    for params in ({"page": 1, "per_page": 1}, {"page": 1, "per_page": MAX_PER_PAGE}):
        response, _ = http.json(query(**params))
        for item in records(response):
            validate_record(item)


def reserve(http: HTTP, year: int) -> str:
    path = "/api/cna/cve-id?" + urllib.parse.urlencode(
        {"amount": 1, "cve_year": year, "short_name": "VULNARCHIVE"}
    )
    response, _ = http.json(path, expected=(200, 201), method="POST", payload={})
    values = response.get("cve_ids") if isinstance(response, dict) else None
    if not isinstance(values, list) or not values or not isinstance(values[0], dict):
        raise CheckFailure("reservation response contains no cve_ids entry")
    identifier = str(values[0].get("vuln_id", "")).upper()
    if not identifier.startswith(f"GCVE-1988-{year}-"):
        raise CheckFailure(f"reserved unexpected identifier {identifier!r}")
    return identifier


def load_fixture(identifier: str, org_id: str, now: str) -> dict[str, Any]:
    text = FIXTURE.read_text(encoding="utf-8")
    return json.loads(text.replace("{{VULN_ID}}", identifier).replace("{{ORG_ID}}", org_id).replace("{{NOW}}", now))


def wait_for_record(http: HTTP, since: str, identifier: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        response, _ = http.json(query(since=since, page=1, per_page=MAX_PER_PAGE))
        found = next((item for item in records(response) if record_id(item) == identifier), None)
        if found:
            return found
        if time.monotonic() >= deadline:
            raise CheckFailure(f"{identifier} did not appear in the since feed within {timeout:g}s")
        time.sleep(2)


def dump_records(http: HTTP) -> dict[str, dict[str, Any]]:
    status, body, headers = http.request("/dumps/gna-1988.ndjson")
    if status != 200:
        raise CheckFailure(f"dump returned HTTP {status}")
    if headers.get_content_type().lower() not in {"application/x-ndjson", "application/ndjson", "text/plain", "application/json"}:
        raise CheckFailure(f"dump has unexpected Content-Type {headers.get('Content-Type')!r}")
    output: dict[str, dict[str, Any]] = {}
    for number, line in enumerate(body.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            validate_record(item)
            output[record_id(item)] = item
        except (json.JSONDecodeError, CheckFailure) as exc:
            raise CheckFailure(f"invalid dump record on line {number}: {exc}") from exc
    return output


def run(args: argparse.Namespace) -> None:
    if not args.allow_write:
        raise CheckFailure("refusing destructive check without --allow-write")
    if not args.api_key:
        raise CheckFailure("--api-key or VL_API_KEY is required")
    http = HTTP(args.url, args.api_key, args.timeout)

    first, _ = http.json(query(page=1, per_page=args.page_size))
    second, _ = http.json(query(page=2, per_page=args.page_size))
    page_records = records(first) + records(second)
    if len(records(first)) != args.page_size or not records(second):
        raise CheckFailure("test instance needs enough seed data to fill page one and page two")
    for item in page_records:
        validate_record(item)
    ids = [record_id(item) for item in page_records]
    if len(ids) != len(set(ids)):
        raise CheckFailure("duplicate record across the first two pages")
    baseline, _ = http.json(query(page=1, per_page=args.page_size * 2))
    if ids != [record_id(item) for item in records(baseline)][: len(ids)]:
        raise CheckFailure("pagination contains a gap, duplicate, or unstable ordering")
    check_parameters(http)

    before = datetime.now(timezone.utc) - timedelta(seconds=2)
    identifier = reserve(http, args.historical_year)
    published = datetime.now(timezone.utc)
    fixture = load_fixture(identifier, args.org_id, iso(published))
    http.json(f"/api/cna/cve/{urllib.parse.quote(identifier)}", expected=(200, 201), method="POST", payload=fixture)
    fetched = wait_for_record(http, iso(before), identifier, args.eventual_timeout)
    validate_record(fetched)

    later = published + timedelta(seconds=2)
    response, _ = http.json(query(since=iso(later), page=1, per_page=MAX_PER_PAGE))
    if identifier in {record_id(item) for item in records(response)}:
        raise CheckFailure(f"{identifier} incorrectly appeared after a later since timestamp")

    deadline = time.monotonic() + args.eventual_timeout
    while True:
        dumped = dump_records(http)
        if identifier in dumped:
            break
        if time.monotonic() >= deadline:
            raise CheckFailure(f"{identifier} did not appear in dumps/gna-1988.ndjson")
        time.sleep(2)
    if dumped[identifier] != fetched:
        raise CheckFailure("published record differs between BCP-03 response and NDJSON dump")
    missing = sorted(set(ids) - set(dumped))
    if missing:
        raise CheckFailure(f"paginated BCP-03 records missing from dump: {', '.join(missing)}")
    print(f"PASS: BCP-03 pagination, validation, since semantics, and dump agree ({identifier})")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--url", default=os.environ.get("VL_URL", ""), required=not bool(os.environ.get("VL_URL")))
    result.add_argument("--api-key", default=os.environ.get("VL_API_KEY", ""))
    result.add_argument("--org-id", default=os.environ.get("VA_GNA_ORG_UUID", ""), required=not bool(os.environ.get("VA_GNA_ORG_UUID")))
    result.add_argument("--allow-write", action="store_true", help="confirm that the target is a disposable test instance")
    result.add_argument("--historical-year", type=int, default=1999)
    result.add_argument("--page-size", type=int, default=2, choices=range(2, MAX_PER_PAGE // 2 + 1), metavar="2..50")
    result.add_argument("--timeout", type=float, default=30)
    result.add_argument("--eventual-timeout", type=float, default=60)
    return result


if __name__ == "__main__":
    try:
        run(parser().parse_args())
    except (CheckFailure, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
