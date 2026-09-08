from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .http import Client, HTTPError
from .models import Message
from .parsers import parse_message, parse_month, parse_rss


class SourceAdapter(Protocol):
    source_id: str
    name: str
    archive_url: str
    feed_url: str

    def parse(self, content: str, url: str) -> Message: ...
    def feed(self, client: Client) -> list[str]: ...
    def month(self, client: Client, year: int, month: int) -> list[str]: ...


@dataclass(frozen=True, slots=True)
class SeclistsAdapter:
    source_id: str
    name: str
    archive_url: str
    feed_url: str

    def parse(self, content: str, url: str) -> Message:
        message = parse_message(content, url)
        message.source_id = self.source_id
        return message

    def feed(self, client: Client) -> list[str]:
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
        "https://seclists.org/bugtraq", "https://seclists.org/rss/bugtraq.rss",
    ),
}


def adapters(source_ids: list[str] | None) -> list[SourceAdapter]:
    selected = source_ids or ["full-disclosure"]
    return [SOURCES[source_id] for source_id in dict.fromkeys(selected)]
