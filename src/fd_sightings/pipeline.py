from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .extract import extract
from .http import Client
from .models import Extraction, Match, Message
from .parsers import parse_message
from .store import Store
from .vulnerability_lookup import VulnerabilityLookup


@dataclass(slots=True)
class Result:
    message: Message
    extraction: Extraction
    matches: list[Match]
    skipped: bool = False


def process_urls(
    urls: list[str],
    *,
    source_client: Client,
    lookup: VulnerabilityLookup,
    store: Store,
    semantic: bool = True,
    refresh: bool = False,
    progress: Callable[[int, int, str], None] | None = None,
) -> list[Result]:
    results: list[Result] = []
    total = len(urls)
    for index, url in enumerate(urls, 1):
        if progress:
            progress(index, total, url)
        if store.seen(url) and not refresh:
            results.append(Result(Message(url, ""), Extraction(), [], skipped=True))
            continue
        html = source_client.get_text(url)
        message = parse_message(html, url)
        extraction = extract(message)
        matches = lookup.match(message, extraction, semantic=semantic) if extraction.relevant else []
        store.save(message, extraction, matches)
        results.append(Result(message, extraction, matches))
    return results
