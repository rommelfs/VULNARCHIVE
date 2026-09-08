from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .extract import extract
from .http import Client
from .models import Extraction, Match, Message
from .parsers import parse_message
from .store import Store
from .vulnerability_lookup import VulnerabilityLookup
from .sources import SourceAdapter


@dataclass(slots=True)
class Result:
    message: Message
    extraction: Extraction
    matches: list[Match]
    skipped: bool = False
    error: str = ""


def process_urls(
    urls: list[str],
    *,
    source_client: Client,
    lookup: VulnerabilityLookup,
    store: Store,
    semantic: bool = True,
    refresh: bool = False,
    progress: Callable[[int, int, str], None] | None = None,
    adapter: SourceAdapter | None = None,
) -> list[Result]:
    results: list[Result] = []
    total = len(urls)
    for index, url in enumerate(urls, 1):
        if progress:
            progress(index, total, url)
        if store.seen(url) and not refresh:
            results.append(Result(Message(url, ""), Extraction(), [], skipped=True))
            continue
        try:
            # One retry bounds a stalled archive item while allowing the rest of
            # the month to continue and be summarized.
            html = source_client.get_text(url, retries=1)
            message = adapter.parse(html, url) if adapter else parse_message(html, url)
            extraction = extract(message)
            matches = lookup.match(message, extraction, semantic=semantic) if extraction.relevant else []
            analysis = getattr(
                lookup, "last_analysis", {"result": [match.as_dict() for match in matches]},
            ) if extraction.relevant else None
            store.save(
                message, extraction, matches, analysis=analysis,
                analysis_trigger="reprocess" if refresh else "import",
            )
            results.append(Result(message, extraction, matches))
        except (OSError, RuntimeError, ValueError) as exc:
            results.append(Result(Message(url, ""), Extraction(), [], error=str(exc)))
    return results
