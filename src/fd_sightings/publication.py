from __future__ import annotations

import json
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

from .http import HTTPError
from .policy import PublicationPlan, PublicationPolicy, plan_observation
from .store import Store
from .vulnerability_lookup import VulnerabilityLookup


def _published(value: object) -> datetime:
    text = str(value or "").strip()
    if text:
        try:
            result = parsedate_to_datetime(text)
            if result.tzinfo is None:
                result = result.replace(tzinfo=timezone.utc)
            return result.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            try:
                result = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if result.tzinfo is None:
                    result = result.replace(tzinfo=timezone.utc)
                return result.astimezone(timezone.utc)
            except ValueError:
                pass
    return datetime.now(timezone.utc)


def publication_year(row: dict[str, object]) -> int:
    """VULNARCHIVE IDs use the source post's publication year."""
    return _published(row.get("published")).year


def public_archive_url(row: dict[str, object], policy: PublicationPolicy) -> str:
    parsed = urlparse(str(row["source_url"]))
    marker = "/fulldisclosure/"
    if marker in parsed.path:
        suffix = parsed.path.split(marker, 1)[1].strip("/")
        return f"{policy.public_base_url}/archive/full-disclosure/{suffix}"
    return f"{policy.public_base_url}/archive/item/{row.get('content_hash', '')}"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_sighting_payload(row: dict[str, object], target: str, sighting_type: str) -> dict[str, Any]:
    extraction = dict(row.get("extraction") or {})
    content = f"Full Disclosure: {row.get('title', '')}"
    evidence = extraction.get("poc_evidence") or []
    if evidence:
        content += ". PoC indicators: " + ", ".join(str(item) for item in evidence)
    match = next(
        (
            item for item in list(row.get("matches") or [])
            if isinstance(item, dict) and str(item.get("vulnerability_id", "")).upper() == target.upper()
        ),
        None,
    )
    if match and match.get("method") != "explicit-id":
        content += f". Automated candidate match: {match.get('method')} (confidence {match.get('confidence')})"
    return {
        "vulnerability": target,
        "type": sighting_type,
        "source": str(row["source_url"]),
        "content": content[:2000],
    }


def build_gcve_record(
    row: dict[str, object],
    gcve_id: str,
    plan: PublicationPlan,
    policy: PublicationPolicy,
) -> dict[str, Any]:
    extraction = dict(row.get("extraction") or {})
    source_date = _published(row.get("published"))
    now = datetime.now(timezone.utc)
    product = str(extraction.get("product_hint") or "unknown")
    archive_url = public_archive_url(row, policy)
    references = [{"url": archive_url, "tags": ["technical-description"]}]
    if str(row["source_url"]) != archive_url:
        references.append({"url": str(row["source_url"]), "tags": ["technical-description"]})
    for link in list(row.get("links") or []):
        if str(link) != str(row["source_url"]):
            references.append({"url": str(link)})
    if plan.sighting_type == "published-proof-of-concept":
        references[0]["tags"].append("exploit")

    cna: dict[str, Any] = {
        "providerMetadata": {
            "orgId": policy.gna_org_uuid,
            "shortName": policy.gna_short_name,
            "dateUpdated": _iso(now),
        },
        "title": str(row.get("title") or gcve_id),
        "descriptions": [{"lang": "en", "value": str(row.get("body") or row.get("title") or "")[:policy.max_description_chars]}],
        "affected": [{
            "vendor": "unknown",
            "product": product,
            "versions": [{"version": "unknown", "status": "affected"}],
        }],
        "references": references,
        "source": {
            "discovery": "EXTERNAL",
            "defect": [str(row.get("message_id") or row["source_url"])],
        },
        "x_gcve": [{
            "vulnId": gcve_id,
            "recordType": plan.record_type,
            "relationships": [
                {
                    "destId": target,
                    "type": "related" if any(
                        isinstance(match, dict)
                        and str(match.get("vulnerability_id", "")).upper() == target.upper()
                        and match.get("method") == "explicit-id"
                        for match in list(row.get("matches") or [])
                    ) else "possibly_related",
                }
                for target in plan.targets
            ],
            "x_vulnarchive": {
                "archiveUrl": archive_url,
                "originalUrl": str(row["source_url"]),
                "contentSha256": str(row.get("content_hash") or ""),
                "sourceFormat": str(row.get("source_format") or "text/html"),
                "messageId": str(row.get("message_id") or ""),
                "sourcePublishedAt": _iso(source_date),
                "automated": True,
                "evidenceScore": plan.evidence_score,
                "policy": "vulnarchive-1",
            },
        }],
    }
    cwe_ids = list(extraction.get("cwe_ids") or [])
    if cwe_ids:
        cna["problemTypes"] = [{
            "descriptions": [{"lang": "en", "type": "CWE", "cweId": str(cwe), "description": str(cwe)} for cwe in cwe_ids]
        }]
    if row.get("author"):
        cna["credits"] = [{"lang": "en", "type": "finder", "value": str(row["author"])}]

    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "vulnId": gcve_id,
            "state": "PUBLISHED",
            "assignerOrgId": policy.gna_org_uuid,
            "assignerShortName": policy.gna_short_name,
            "datePublished": _iso(now),
            "dateUpdated": _iso(now),
        },
        "containers": {"cna": cna},
    }


def _reserve(lookup: VulnerabilityLookup, year: int, policy: PublicationPolicy) -> str:
    try:
        vulnerability_id = lookup.reserve_gcve(year, policy.gna_short_name)
    except HTTPError as exc:
        if not policy.auto_create_year_range or exc.status != 400 or "range" not in exc.body.casefold():
            raise
        lookup.create_gcve_year_range(year)
        vulnerability_id = lookup.reserve_gcve(year, policy.gna_short_name)
    expected_prefix = f"GCVE-{policy.gna_id}-{year}-"
    if not vulnerability_id.upper().startswith(expected_prefix):
        raise RuntimeError(
            f"Local instance reserved {vulnerability_id}; expected an identifier beginning with {expected_prefix}"
        )
    return vulnerability_id.upper()


def _publish_sighting(
    store: Store,
    lookup: VulnerabilityLookup,
    row: dict[str, object],
    plan: PublicationPlan,
    target: str,
    current: list[dict[str, Any]],
    *,
    dry_run: bool,
    retry_failed: bool,
) -> None:
    key = f"sighting:{target}:{plan.sighting_type}"
    previous = store.publication(plan.source_url, key)
    if previous and previous["status"] == "published":
        current.append({"kind": "sighting", "target": target, "status": "already-published"})
        return
    if previous and previous["status"] == "failed" and not retry_failed:
        current.append({"kind": "sighting", "target": target, "status": "failed-not-retried"})
        return
    payload = build_sighting_payload(row, target, plan.sighting_type)
    if dry_run:
        current.append({"kind": "sighting", "target": target, "status": "dry-run", "payload": payload})
        return
    store.save_publication(plan.source_url, key, "sighting", target_id=target, status="sending", payload=payload)
    try:
        status, body, _ = lookup.client.request(
            f"{lookup.base_url}/api/sighting/", method="POST",
            headers={"X-API-KEY": lookup.api_key}, json_body=payload,
        )
        response = json.loads(body) if body else {}
        store.save_publication(plan.source_url, key, "sighting", target_id=target, status="published", payload=payload, response=response)
        current.append({"kind": "sighting", "target": target, "status": status})
    except HTTPError as exc:
        completed = exc.status == 409
        store.save_publication(
            plan.source_url, key, "sighting", target_id=target,
            status="published" if completed else "failed", payload=payload,
            response={"duplicate": True} if completed else {}, error="" if completed else str(exc),
        )
        current.append({
            "kind": "sighting", "target": target,
            "status": exc.status if completed else "failed",
            **({} if completed else {"error": str(exc)}),
        })
    except Exception as exc:
        store.save_publication(
            plan.source_url, key, "sighting", target_id=target,
            status="failed", payload=payload, error=str(exc),
        )
        current.append({"kind": "sighting", "target": target, "status": "failed", "error": str(exc)})


def _plan_is_complete(store: Store, plan: PublicationPlan, policy: PublicationPolicy) -> bool:
    if plan.action == "archive-only":
        return True
    if policy.publish_sightings:
        for target in plan.targets:
            item = store.publication(plan.source_url, f"sighting:{target}:{plan.sighting_type}")
            if not item or item["status"] != "published":
                return False
    if plan.action not in {"context-and-sightings", "new-advisory"}:
        return True
    key = "gcve:context" if plan.action == "context-and-sightings" else "gcve:advisory"
    gcve = store.publication(plan.source_url, key)
    if not gcve or gcve["status"] != "published":
        return False
    if policy.publish_sightings:
        gcve_id = str(gcve.get("gcve_id") or "")
        item = store.publication(plan.source_url, f"sighting:{gcve_id}:{plan.sighting_type}")
        if not item or item["status"] != "published":
            return False
    return True


def execute_automatic_publication(
    store: Store,
    lookup: VulnerabilityLookup,
    policy: PublicationPolicy,
    *,
    limit: int = 0,
    dry_run: bool = False,
    retry_failed: bool = False,
) -> list[dict[str, Any]]:
    outcomes: list[dict[str, Any]] = []
    actionable = 0
    for row in store.automatic_candidates():
        plan = plan_observation(row, policy)
        if not dry_run and _plan_is_complete(store, plan, policy):
            continue
        if plan.action != "archive-only":
            if limit and actionable >= limit:
                break
            actionable += 1
        outcomes.append({"plan": plan.as_dict(), "operations": []})
        current = outcomes[-1]["operations"]
        if plan.action == "archive-only":
            current.append({"kind": "archive", "status": "complete"})
            continue

        if policy.publish_sightings:
            for target in plan.targets:
                _publish_sighting(
                    store, lookup, row, plan, target, current,
                    dry_run=dry_run, retry_failed=retry_failed,
                )

        if plan.action not in {"context-and-sightings", "new-advisory"}:
            continue
        key = "gcve:context" if plan.action == "context-and-sightings" else "gcve:advisory"
        previous = store.publication(plan.source_url, key)
        gcve_id = str(previous.get("gcve_id") or "") if previous else ""
        if previous and previous["status"] == "published":
            current.append({"kind": "gcve", "id": gcve_id, "status": "already-published"})
            if policy.publish_sightings:
                _publish_sighting(
                    store, lookup, row, plan, gcve_id, current,
                    dry_run=dry_run, retry_failed=retry_failed,
                )
            continue
        if previous and previous["status"] == "failed" and not retry_failed:
            current.append({"kind": "gcve", "id": previous["gcve_id"], "status": "failed-not-retried"})
            continue
        if dry_run:
            preview_id = f"GCVE-{policy.gna_id}-{publication_year(row)}-<reserved>"
            current.append({"kind": "gcve", "status": "dry-run", "payload": build_gcve_record(row, preview_id, plan, policy)})
            continue

        try:
            if not gcve_id:
                gcve_id = _reserve(lookup, publication_year(row), policy)
                store.save_publication(plan.source_url, key, "gcve", gcve_id=gcve_id, status="reserved")
            payload = build_gcve_record(row, gcve_id, plan, policy)
            store.save_publication(plan.source_url, key, "gcve", gcve_id=gcve_id, status="sending", payload=payload)
            status, response = lookup.publish_gcve(gcve_id, payload)
            store.save_publication(plan.source_url, key, "gcve", gcve_id=gcve_id, status="published", payload=payload, response=response)
            current.append({"kind": "gcve", "id": gcve_id, "status": status})
            if policy.publish_sightings:
                _publish_sighting(
                    store, lookup, row, plan, gcve_id, current,
                    dry_run=False, retry_failed=retry_failed,
                )
        except Exception as exc:
            store.save_publication(plan.source_url, key, "gcve", gcve_id=gcve_id, status="failed", error=str(exc))
            current.append({"kind": "gcve", "id": gcve_id, "status": "failed", "error": str(exc)})
    return outcomes
