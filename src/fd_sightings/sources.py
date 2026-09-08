from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Protocol

from .http import Client, HTTPError
from .models import Message
from .parsers import parse_message, parse_month, parse_rss


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


SOURCES: dict[str, SourceAdapter] = {
    "full-disclosure": SeclistsAdapter(
        "full-disclosure", "Full Disclosure",
        "https://seclists.org/fulldisclosure", "https://seclists.org/rss/fulldisclosure.rss",
    ),
    "bugtraq": SeclistsAdapter(
        "bugtraq", "Bugtraq",
        "https://seclists.org/bugtraq", "",
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
