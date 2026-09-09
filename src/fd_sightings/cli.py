from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from .cpe import CPERegistry
from .http import Client
from .parsers import parse_rss
from .pipeline import Result, process_urls
from .store import Store
from .vulnerability_lookup import VulnerabilityLookup
from .sources import SOURCES, SourceAdapter, adapters


DEFAULT_ARCHIVE = "https://seclists.org/fulldisclosure"
DEFAULT_RSS = "https://seclists.org/rss/fulldisclosure.rss"
DEFAULT_VL = "https://vulnerability.circl.lu"
DEFAULT_CPE = "https://cpe.gcve.eu"


def period(value: str) -> tuple[int, int]:
    try:
        year, month = (int(part) for part in value.split("-", 1))
        if year < 1993 or not 1 <= month <= 12:
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
    parser.add_argument("--cpe-url", default=os.getenv("CPE_URL", DEFAULT_CPE),
                        help="GCVE CPE registry base URL; use an empty value to disable enrichment")
    parser.add_argument("--user-agent", default=os.getenv("FD_USER_AGENT", "VULNARCHIVE/0.2 (set FD_USER_AGENT with contact)"))
    parser.add_argument("--no-semantic", action="store_true", help="Only resolve identifiers explicitly present in a message")
    parser.add_argument("--refresh", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    rss = sub.add_parser("rss", help="Process the current RSS feed")
    rss.add_argument("--source", action="append", choices=sorted(SOURCES), dest="sources")
    rss.add_argument("--feed", default=DEFAULT_RSS)
    rss.add_argument("--limit", type=int, default=0)

    sync = sub.add_parser("sync", help="Import the current RSS feed and automatically publish eligible records")
    sync.add_argument("--source", action="append", choices=sorted(SOURCES), dest="sources")
    sync.add_argument("--feed", default=DEFAULT_RSS)
    sync.add_argument("--limit", type=int, default=0)
    sync.add_argument("--retry-failed", action="store_true")

    archive = sub.add_parser("archive", help="Process one or more archive months")
    archive.add_argument("--source", action="append", choices=sorted(SOURCES), dest="sources")
    archive.add_argument("--from-period", type=period, required=True)
    archive.add_argument("--to-period", type=period)
    archive.add_argument("--archive-url", default=DEFAULT_ARCHIVE)
    archive.add_argument("--limit", type=int, default=0, help="Maximum messages per month; useful for a pilot")

    one = sub.add_parser("url", help="Process one archive message")
    one.add_argument("url")

    export = sub.add_parser("export", help="Export review data as JSON Lines")
    export.add_argument("--status", choices=["matched", "unmatched"])
    export.add_argument("--output", default="-")

    review = sub.add_parser("review", help="Run the local analyst review interface")
    review.add_argument("--bind", default="127.0.0.1")
    review.add_argument("--port", type=int, default=8765)

    public = sub.add_parser("public", help="Run the read-only public archive and GCVE API")
    public.add_argument("--bind", default="127.0.0.1")
    public.add_argument("--port", type=int, default=8766)

    policy = sub.add_parser("policy", help="Show the active VULNARCHIVE publication policy")

    plan_auto = sub.add_parser("plan-auto", help="Plan automatic Sightings and GCVE-1988 records without publishing")
    plan_auto.add_argument("--limit", type=int, default=0)

    publish_auto = sub.add_parser("publish-auto", help="Automatically publish according to the VULNARCHIVE policy")
    publish_auto.add_argument("--limit", type=int, default=0)
    publish_auto.add_argument("--retry-failed", action="store_true")

    publication_export = sub.add_parser("export-publications", help="Export the automatic publication ledger as JSON Lines")
    publication_export.add_argument("--output", default="-")
    enrich_cpe = sub.add_parser(
        "enrich-cpe", help="Backfill missing vendors in stored observations from the GCVE CPE registry",
    )
    enrich_cpe.add_argument("--limit", type=int, default=0, help="Maximum observations; 0 processes all")
    evaluate = sub.add_parser("evaluate", help="Evaluate deterministic matching against labelled JSON fixtures")
    evaluate.add_argument("fixtures", nargs="+", help="Fixture JSON files or directories")
    evaluate.add_argument("--min-precision", type=float, default=0.98)
    evaluate.add_argument("--min-recall", type=float, default=0.80)
    evaluate.add_argument("--output", default="-", help="Write the JSON report to this path")
    return parser


def _clients(args: argparse.Namespace) -> tuple[Client, VulnerabilityLookup, CPERegistry]:
    from .llm import LLMMatcher
    api_key = os.getenv("VL_API_KEY", "")
    source_client = Client(args.user_agent, timeout=15, min_interval=0.5)
    lookup_client = Client(args.user_agent, timeout=8, min_interval=1.6 if api_key else 3.1)
    llm_client = Client(args.user_agent, timeout=45, min_interval=0.0)
    cpe_client = Client(args.user_agent, timeout=8, min_interval=0.2)
    return (
        source_client,
        VulnerabilityLookup(lookup_client, args.vl_url, api_key, LLMMatcher.from_env(llm_client)),
        CPERegistry(cpe_client, args.cpe_url),
    )


def _progress(index: int, total: int, url: str) -> None:
    print(f"[{index}/{total}] {url}", file=sys.stderr)


def _summary(results: list[Result], vulnerability_lookup_url: str = "") -> dict[str, object]:
    matches = [match for result in results for match in result.matches]
    method_counts: dict[str, int] = {}
    for match in matches:
        method_counts[match.method] = method_counts.get(match.method, 0) + 1
    return {
        "total": len(results),
        "processed": sum(not result.skipped and not result.error for result in results),
        "skipped": sum(result.skipped for result in results),
        "failed": sum(bool(result.error) for result in results),
        "relevant": sum(result.extraction.relevant for result in results if not result.skipped),
        "matched": sum(bool(result.matches) for result in results),
        "match_methods": method_counts,
        "llm_evaluated": sum(any(item.startswith("llm-model:") for item in match.evidence) for match in matches),
        "llm_errors": sum(any(item.startswith("llm-error:") for item in match.evidence) for match in matches),
        "vulnerability_lookup_url": vulnerability_lookup_url,
        "poc": sum(result.extraction.proposed_type == "published-proof-of-concept" for result in results if not result.skipped),
        "errors": [
            {"source": result.message.source_url, "error": result.error}
            for result in results if result.error
        ],
    }


def _process(args: argparse.Namespace, urls: list[str], store: Store, source_client: Client,
             lookup: VulnerabilityLookup, adapter: SourceAdapter | None = None,
             cpe_registry: CPERegistry | None = None) -> list[Result]:
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
        adapter=adapter,
        cpe_registry=cpe_registry,
    )
    return results


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    if args.command == "evaluate":
        from .evaluation import evaluate_cases, load_cases
        from .llm import PROMPT_VERSION
        report = evaluate_cases(
            load_cases(args.fixtures), min_precision=args.min_precision, min_recall=args.min_recall,
        ).as_dict()
        report["prompt_version"] = PROMPT_VERSION
        encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output == "-":
            sys.stdout.write(encoded)
        else:
            Path(args.output).write_text(encoded, encoding="utf-8")
        return 0 if report["passed"] else 2
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

        if args.command == "enrich-cpe":
            registry = CPERegistry(Client(args.user_agent, timeout=8, min_interval=0.2), args.cpe_url)
            print(json.dumps(registry.enrich_store(store, limit=args.limit), indent=2))
            return 0

        if args.command in {"plan-auto", "publish-auto"}:
            from .policy import PublicationPolicy
            from .publication import execute_automatic_publication
            outcomes = execute_automatic_publication(
                store,
                PublicationPolicy.from_env(),
                limit=args.limit,
                dry_run=args.command == "plan-auto",
                retry_failed=getattr(args, "retry_failed", False),
            )
            print(json.dumps({"count": len(outcomes), "outcomes": outcomes}, indent=2))
            return 0

        if args.command == "review":
            from .review_ui import serve
            serve(store, args.bind, args.port)
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

        source_client, lookup, cpe_registry = _clients(args)
        if args.command == "rss":
            aggregate = []
            selected = adapters(args.sources)
            if args.feed != DEFAULT_RSS and len(selected) != 1:
                raise ValueError("--feed can only override one source")
            for adapter in selected:
                if args.feed == DEFAULT_RSS and not adapter.has_current_feed:
                    print(
                        f"source {adapter.source_id} has no current RSS feed; "
                        "use the archive command for historical import",
                        file=sys.stderr,
                    )
                urls = (adapter.feed(source_client) if args.feed == DEFAULT_RSS
                        else parse_rss(source_client.get_text(args.feed)))
                aggregate.extend(_process(args, urls, store, source_client, lookup, adapter, cpe_registry))
            print(json.dumps(_summary(aggregate, args.vl_url), indent=2))
        elif args.command == "sync":
            results = []
            selected = adapters(args.sources)
            if args.feed != DEFAULT_RSS and len(selected) != 1:
                raise ValueError("--feed can only override one source")
            for adapter in selected:
                if args.feed == DEFAULT_RSS and not adapter.has_current_feed:
                    print(
                        f"source {adapter.source_id} has no current RSS feed; "
                        "use the archive command for historical import",
                        file=sys.stderr,
                    )
                urls = (adapter.feed(source_client) if args.feed == DEFAULT_RSS
                        else parse_rss(source_client.get_text(args.feed)))
                results.extend(_process(args, urls, store, source_client, lookup, adapter, cpe_registry))
            from .policy import PublicationPolicy
            from .publication import execute_automatic_publication
            publications = execute_automatic_publication(
                store,
                PublicationPolicy.from_env(),
                limit=args.limit,
                retry_failed=args.retry_failed,
            )
            print(json.dumps({"import": _summary(results, args.vl_url), "publications": publications}, indent=2))
        elif args.command == "url":
            results = _process(args, [args.url], store, source_client, lookup, cpe_registry=cpe_registry)
            print(json.dumps(_summary(results, args.vl_url), indent=2))
        elif args.command == "archive":
            end = args.to_period or args.from_period
            aggregate: list[Result] = []
            selected = adapters(args.sources)
            if args.archive_url != DEFAULT_ARCHIVE and len(selected) != 1:
                raise ValueError("--archive-url can only override one source")
            for adapter in selected:
                if args.archive_url != DEFAULT_ARCHIVE:
                    from dataclasses import replace
                    adapter = replace(adapter, archive_url=args.archive_url)
                for year, month in periods(args.from_period, end):
                    aggregate.extend(_process(
                        args, adapter.month(source_client, year, month), store,
                        source_client, lookup, adapter, cpe_registry,
                    ))
            print(json.dumps(_summary(aggregate, args.vl_url), indent=2))
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
