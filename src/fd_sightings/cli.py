from __future__ import annotations

import argparse
import json
import os
import sys
from calendar import month_abbr
from datetime import date
from pathlib import Path

from .http import Client, HTTPError
from .parsers import parse_month, parse_rss
from .pipeline import Result, process_urls
from .store import Store
from .vulnerability_lookup import VulnerabilityLookup


DEFAULT_ARCHIVE = "https://seclists.org/fulldisclosure"
DEFAULT_RSS = "https://seclists.org/rss/fulldisclosure.rss"
DEFAULT_VL = "https://vuln.freearchive.org"


def period(value: str) -> tuple[int, int]:
    try:
        year, month = (int(part) for part in value.split("-", 1))
        if year < 2002 or not 1 <= month <= 12:
            raise ValueError
        return year, month
    except ValueError as exc:
        raise argparse.ArgumentTypeError("period must be YYYY-MM") from exc


def periods(start: tuple[int, int], end: tuple[int, int]):
    year, month = start
    while (year, month) <= end:
        yield year, month
        month += 1
        if month == 13:
            year += 1
            month = 1


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fd-sightings")
    parser.add_argument("--db", default=os.getenv("FD_SIGHTINGS_DB", "data/fd-sightings.sqlite"))
    parser.add_argument("--vl-url", default=os.getenv("VL_URL", DEFAULT_VL))
    parser.add_argument("--user-agent", default=os.getenv("FD_USER_AGENT", "VULNARCHIVE/0.2 (set FD_USER_AGENT with contact)"))
    parser.add_argument("--no-semantic", action="store_true", help="Only resolve identifiers explicitly present in a message")
    parser.add_argument("--refresh", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    rss = sub.add_parser("rss", help="Process the current RSS feed")
    rss.add_argument("--feed", default=DEFAULT_RSS)
    rss.add_argument("--limit", type=int, default=0)

    sync = sub.add_parser("sync", help="Import the current RSS feed and automatically publish eligible records")
    sync.add_argument("--feed", default=DEFAULT_RSS)
    sync.add_argument("--limit", type=int, default=0)
    sync.add_argument("--retry-failed", action="store_true")

    archive = sub.add_parser("archive", help="Process one or more archive months")
    archive.add_argument("--from-period", type=period, required=True)
    archive.add_argument("--to-period", type=period)
    archive.add_argument("--archive-url", default=DEFAULT_ARCHIVE)
    archive.add_argument("--limit", type=int, default=0, help="Maximum messages per month; useful for a pilot")

    one = sub.add_parser("url", help="Process one archive message")
    one.add_argument("url")

    export = sub.add_parser("export", help="Export review data as JSON Lines")
    export.add_argument("--status", choices=["matched", "unmatched"])
    export.add_argument("--output", default="-")

    submit = sub.add_parser("submit", help="Submit reviewed, matched observations as sightings")
    submit.add_argument("--source-url", required=True)
    submit.add_argument("--vulnerability-id", required=True)
    submit.add_argument("--write", action="store_true", help="Required safety switch; otherwise show payload intent only")

    review = sub.add_parser("review", help="Run the local analyst review interface")
    review.add_argument("--bind", default="127.0.0.1")
    review.add_argument("--port", type=int, default=8765)

    public = sub.add_parser("public", help="Run the read-only public archive and GCVE API")
    public.add_argument("--bind", default="127.0.0.1")
    public.add_argument("--port", type=int, default=8766)

    approved = sub.add_parser("submit-approved", help="Process analyst-approved observations")
    approved.add_argument("--limit", type=int, default=0)
    approved.add_argument("--write", action="store_true", help="Required safety switch; otherwise print payloads")

    policy = sub.add_parser("policy", help="Show the active VULNARCHIVE publication policy")

    plan_auto = sub.add_parser("plan-auto", help="Plan automatic Sightings and GCVE-1988 records without publishing")
    plan_auto.add_argument("--limit", type=int, default=0)

    publish_auto = sub.add_parser("publish-auto", help="Automatically publish according to the VULNARCHIVE policy")
    publish_auto.add_argument("--limit", type=int, default=0)
    publish_auto.add_argument("--retry-failed", action="store_true")

    publication_export = sub.add_parser("export-publications", help="Export the automatic publication ledger as JSON Lines")
    publication_export.add_argument("--output", default="-")
    return parser


def _clients(args: argparse.Namespace) -> tuple[Client, VulnerabilityLookup]:
    api_key = os.getenv("VL_API_KEY", "")
    source_client = Client(args.user_agent, min_interval=0.5)
    lookup_client = Client(args.user_agent, timeout=8, min_interval=1.6 if api_key else 3.1)
    return source_client, VulnerabilityLookup(lookup_client, args.vl_url, api_key)


def _progress(index: int, total: int, url: str) -> None:
    print(f"[{index}/{total}] {url}", file=sys.stderr)


def _summary(results: list[Result]) -> dict[str, int]:
    return {
        "total": len(results),
        "processed": sum(not result.skipped for result in results),
        "skipped": sum(result.skipped for result in results),
        "relevant": sum(result.extraction.relevant for result in results if not result.skipped),
        "matched": sum(bool(result.matches) for result in results),
        "poc": sum(result.extraction.proposed_type == "published-proof-of-concept" for result in results if not result.skipped),
    }


def _process(args: argparse.Namespace, urls: list[str], store: Store, source_client: Client, lookup: VulnerabilityLookup) -> None:
    if getattr(args, "limit", 0):
        urls = urls[: args.limit]
    results = process_urls(
        urls,
        source_client=source_client,
        lookup=lookup,
        store=store,
        semantic=not args.no_semantic,
        refresh=args.refresh,
        progress=_progress,
    )
    print(json.dumps(_summary(results), indent=2))


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    store = Store(args.db)
    try:
        if args.command == "policy":
            from dataclasses import asdict
            from .policy import PublicationPolicy
            print(json.dumps(asdict(PublicationPolicy.from_env()), indent=2))
            return 0

        if args.command == "export-publications":
            rows = store.publication_rows()
            output = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + ("\n" if rows else "")
            if args.output == "-":
                sys.stdout.write(output)
            else:
                Path(args.output).write_text(output, encoding="utf-8")
            return 0

        if args.command in {"plan-auto", "publish-auto"}:
            from .policy import PublicationPolicy
            from .publication import execute_automatic_publication
            _, lookup = _clients(args)
            if args.command == "publish-auto" and not lookup.api_key:
                raise RuntimeError("VL_API_KEY is required for automatic publication")
            outcomes = execute_automatic_publication(
                store,
                lookup,
                PublicationPolicy.from_env(),
                limit=args.limit,
                dry_run=args.command == "plan-auto",
                retry_failed=getattr(args, "retry_failed", False),
            )
            print(json.dumps({"count": len(outcomes), "outcomes": outcomes}, indent=2))
            return 0

        if args.command == "review":
            from .review_ui import serve
            _, lookup = _clients(args)
            serve(store, lookup, args.bind, args.port)
            return 0

        if args.command == "public":
            from .public_ui import serve
            serve(store, args.bind, args.port)
            return 0

        if args.command == "export":
            rows = store.rows(args.status)
            output = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + ("\n" if rows else "")
            if args.output == "-":
                sys.stdout.write(output)
            else:
                Path(args.output).write_text(output, encoding="utf-8")
            return 0

        source_client, lookup = _clients(args)
        if args.command == "rss":
            _process(args, parse_rss(source_client.get_text(args.feed)), store, source_client, lookup)
        elif args.command == "sync":
            if not lookup.api_key:
                raise RuntimeError("VL_API_KEY is required for automatic synchronization")
            urls = parse_rss(source_client.get_text(args.feed))
            if args.limit:
                urls = urls[: args.limit]
            results = process_urls(
                urls,
                source_client=source_client,
                lookup=lookup,
                store=store,
                semantic=not args.no_semantic,
                refresh=args.refresh,
                progress=_progress,
            )
            from .policy import PublicationPolicy
            from .publication import execute_automatic_publication
            publications = execute_automatic_publication(
                store,
                lookup,
                PublicationPolicy.from_env(),
                limit=args.limit,
                retry_failed=args.retry_failed,
            )
            print(json.dumps({"import": _summary(results), "publications": publications}, indent=2))
        elif args.command == "url":
            _process(args, [args.url], store, source_client, lookup)
        elif args.command == "archive":
            end = args.to_period or args.from_period
            aggregate: list[Result] = []
            for year, month in periods(args.from_period, end):
                month_url = f"{args.archive_url.rstrip('/')}/{year}/{month_abbr[month]}/date.html"
                try:
                    urls = parse_month(source_client.get_text(month_url), month_url)
                except HTTPError as exc:
                    if exc.status == 404:
                        continue
                    raise
                if args.limit:
                    urls = urls[: args.limit]
                aggregate.extend(process_urls(
                    urls,
                    source_client=source_client,
                    lookup=lookup,
                    store=store,
                    semantic=not args.no_semantic,
                    refresh=args.refresh,
                    progress=_progress,
                ))
            print(json.dumps(_summary(aggregate), indent=2))
        elif args.command == "submit":
            rows = [row for row in store.rows() if row["source_url"] == args.source_url]
            if not rows:
                raise RuntimeError("source URL is not present in the local database")
            row = rows[0]
            extraction = row["extraction"]
            match = next((item for item in row["matches"] if item["vulnerability_id"].upper() == args.vulnerability_id.upper()), None)
            if not match:
                raise RuntimeError("requested vulnerability ID is not an existing match; review/export first")
            intent = {
                "vulnerability": match["vulnerability_id"],
                "type": extraction["proposed_type"],
                "source": args.source_url,
                "content": f"Full Disclosure: {row['title']}",
            }
            if not args.write:
                print(json.dumps({"dry_run": True, "payload": intent}, indent=2))
                return 0
            # Re-fetching preserves a single canonical payload builder and detects source changes.
            html = source_client.get_text(args.source_url)
            from .extract import extract
            from .models import Match
            from .parsers import parse_message
            message = parse_message(html, args.source_url)
            extracted = extract(message)
            status, response = lookup.submit_sighting(message, extracted, Match(**match))
            store.record_submission(args.source_url, match["vulnerability_id"], extracted.proposed_type, response)
            print(json.dumps({"status": status, "response": response}, indent=2))
        elif args.command == "submit-approved":
            from .models import Extraction, Match, Message
            approved_rows = store.approved(args.limit)
            outcomes = []
            for row in approved_rows:
                vulnerability_id = str(row["reviewed_vulnerability_id"])
                sighting_type = str(row["reviewed_sighting_type"])
                payload = {
                    "vulnerability": vulnerability_id,
                    "type": sighting_type,
                    "source": row["source_url"],
                    "content": f"Full Disclosure: {row['title']}",
                }
                if not args.write:
                    outcomes.append({"dry_run": True, "payload": payload})
                    continue
                record = lookup.lookup(vulnerability_id)
                if not record:
                    outcomes.append({"source": row["source_url"], "error": "vulnerability ID not found"})
                    continue
                extraction_data = dict(row["extraction"])
                extraction_data.pop("proposed_type", None)
                message = Message(
                    source_url=str(row["source_url"]), title=str(row["title"]), author=str(row["author"]),
                    published=str(row["published"]), body=str(row["body"]), links=list(row["links"]),
                )
                extracted = Extraction(**extraction_data)
                match = Match(vulnerability_id, "analyst-approved", 1.0, "")
                status, response = lookup.submit_sighting(message, extracted, match, sighting_type)
                store.record_submission(str(row["source_url"]), vulnerability_id, sighting_type, response)
                outcomes.append({"source": row["source_url"], "status": status, "response": response})
            print(json.dumps({"count": len(outcomes), "outcomes": outcomes}, indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
