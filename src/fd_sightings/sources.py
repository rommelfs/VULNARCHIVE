from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Protocol

from .http import Client, HTTPError
from .models import Message
from .parsers import (
    parse_hyperkitty_archive_page, parse_hyperkitty_index, parse_hyperkitty_message,
    parse_message, parse_month, parse_rss,
)


class SourceAdapter(Protocol):
    source_id: str
    name: str
    archive_url: str
    feed_url: str

    @property
    def has_current_feed(self) -> bool: ...

    def parse(self, content: str, url: str) -> Message: ...
    def feed(self, client: Client) -> list[str]: ...
    def month(self, client: Client, year: int, month: int) -> list[str]: ...


@dataclass(frozen=True, slots=True)
class SeclistsAdapter:
    source_id: str
    name: str
    archive_url: str
    feed_url: str

    @property
    def has_current_feed(self) -> bool:
        return bool(self.feed_url)

    def parse(self, content: str, url: str) -> Message:
        message = parse_message(content, url)
        message.source_id = self.source_id
        return message

    def feed(self, client: Client) -> list[str]:
        if not self.feed_url:
            return []
        return parse_rss(client.get_text(self.feed_url))

    def month(self, client: Client, year: int, month: int) -> list[str]:
        from calendar import month_abbr
        url = f"{self.archive_url.rstrip('/')}/{year}/{month_abbr[month]}/date.html"
        try:
            return parse_month(client.get_text(url), url)
        except HTTPError as exc:
            if exc.status == 404:
                return []
            raise


@dataclass(frozen=True, slots=True)
class HyperKittyAdapter:
    source_id: str
    name: str
    archive_url: str
    feed_url: str

    @property
    def has_current_feed(self) -> bool:
        return True

    def parse(self, content: str, url: str) -> Message:
        message = parse_hyperkitty_message(content, url)
        message.source_id = self.source_id
        return message

    def feed(self, client: Client) -> list[str]:
        return parse_rss(client.get_text(self.feed_url))

    def month(self, client: Client, year: int, month: int) -> list[str]:
        url = f"{self.archive_url.rstrip('/')}/{year}/{month}/"
        try:
            messages: list[str] = []
            pending_pages = [url]
            seen_pages: set[str] = set()
            threads: list[str] = []
            while pending_pages and len(seen_pages) < 100:
                page_url = pending_pages.pop(0)
                if page_url in seen_pages:
                    continue
                seen_pages.add(page_url)
                found_messages, found_threads, next_pages = parse_hyperkitty_archive_page(
                    client.get_text(page_url), page_url,
                )
                source_prefix = self.archive_url.rstrip("/") + "/"
                messages.extend(item for item in found_messages if item.startswith(source_prefix))
                threads.extend(item for item in found_threads if item.startswith(source_prefix))
                pending_pages.extend(item for item in next_pages if item.startswith(url))
            # Month pages list threads (and the compose link ``message/new``),
            # not posts. Expand each thread's initial post and asynchronously
            # rendered replies into stable message permalinks.
            for thread_url in dict.fromkeys(threads):
                messages.extend(parse_hyperkitty_index(client.get_text(thread_url), thread_url))
                replies_url = thread_url.rstrip("/") + "/replies"
                try:
                    messages.extend(parse_hyperkitty_index(client.get_text(replies_url), replies_url))
                except HTTPError as exc:
                    if exc.status != 404:
                        raise
            return list(dict.fromkeys(messages))
        except HTTPError as exc:
            if exc.status == 404:
                return []
            raise


SOURCES: dict[str, SourceAdapter] = {
    "full-disclosure": SeclistsAdapter(
        "full-disclosure", "Full Disclosure",
        "https://seclists.org/fulldisclosure", "https://seclists.org/rss/fulldisclosure.rss",
    ),
    "bugtraq": HyperKittyAdapter(
        "bugtraq", "Bugtraq",
        "https://lists.securityfocus.com/hyperkitty/list/bugtraq@securityfocus.com",
        "https://lists.securityfocus.com/hyperkitty/list/bugtraq@securityfocus.com/latest/feed",
    ),
    "bugtraq-ai": HyperKittyAdapter(
        "bugtraq-ai", "Bugtraq AI",
        "https://lists.securityfocus.com/hyperkitty/list/bugtraq@bugtraq.ai",
        "https://lists.securityfocus.com/hyperkitty/list/bugtraq@bugtraq.ai/latest/feed",
    ),
}


def configured_source_ids(value: str | None = None) -> list[str]:
    configured = value if value is not None else os.getenv("VA_SOURCES", "full-disclosure")
    selected = list(dict.fromkeys(item.strip() for item in configured.split(",") if item.strip()))
    if not selected:
        raise ValueError("at least one source must be configured")
    unknown = [source_id for source_id in selected if source_id not in SOURCES]
    if unknown:
        raise ValueError("unknown source: " + ", ".join(unknown))
    return selected


def adapters(source_ids: list[str] | None) -> list[SourceAdapter]:
    selected = source_ids if source_ids is not None else configured_source_ids()
    return [SOURCES[source_id] for source_id in dict.fromkeys(selected)]


def adapter_for_url(url: str) -> SourceAdapter | None:
    return next(
        (adapter for adapter in SOURCES.values() if url.startswith(adapter.archive_url.rstrip("/") + "/")),
        None,
    )
