from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .models import Message


class _MessageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.in_title = False
        self.in_pre = False
        self.title_parts: list[str] = []
        self.body_parts: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "meta" and values.get("name") in {"Subject", "Author", "Message-ID"}:
            self.meta[values["name"]] = values.get("content", "")
        if tag == "h1" and "m-title" in (values.get("class") or "").split():
            self.in_title = True
        if tag == "pre" and not self.in_pre:
            self.in_pre = True
        if self.in_pre and tag == "a" and values.get("href"):
            self.links.append(values["href"] or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1":
            self.in_title = False
        if tag == "pre" and self.in_pre:
            self.in_pre = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self.in_pre:
            self.body_parts.append(data)


class _MonthParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.in_blockquote = False
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "blockquote":
            self.in_blockquote = True
        if self.in_blockquote and tag == "a" and re.fullmatch(r"\d+", values.get("href") or ""):
            self.urls.append(urljoin(self.base_url, values["href"] or ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "blockquote":
            self.in_blockquote = False


class _HyperKittyIndexParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        href = dict(attrs).get("href") if tag == "a" else None
        if href and "/message/" in href:
            self.urls.append(urljoin(self.base_url, href))


class _HyperKittyMessageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.body_depth = 0
        self.title_depth = 0
        self.author_depth = 0
        self.title_parts: list[str] = []
        self.author_parts: list[str] = []
        self.body_parts: list[str] = []
        self.links: list[str] = []
        self.published = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = set((values.get("class") or "").split())
        if tag == "meta":
            key = values.get("name") or values.get("property") or ""
            self.meta[key.casefold()] = values.get("content") or ""
        if self.body_depth:
            self.body_depth += 1
            if tag == "a" and values.get("href"):
                self.links.append(values["href"] or "")
            if tag in {"br", "p", "div", "li"}:
                self.body_parts.append("\n")
        elif "email-body" in classes:
            self.body_depth = 1
        if self.title_depth:
            self.title_depth += 1
        elif tag == "h1" or classes.intersection({"subject", "email-subject"}):
            self.title_depth = 1
        if self.author_depth:
            self.author_depth += 1
        elif classes.intersection({"sender-name", "email-sender", "author"}):
            self.author_depth = 1
        if tag == "time" and not self.published:
            self.published = values.get("datetime") or ""

    def handle_endtag(self, tag: str) -> None:
        if self.body_depth:
            self.body_depth -= 1
        if self.title_depth:
            self.title_depth -= 1
        if self.author_depth:
            self.author_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.body_depth:
            self.body_parts.append(data)
        if self.title_depth:
            self.title_parts.append(data)
        if self.author_depth:
            self.author_parts.append(data)


def _safe_links(source_url: str, links: list[str]) -> list[str]:
    """Resolve usable HTTP references without rejecting the whole message.

    Advisory examples regularly contain placeholders such as
    ``http://[CWP_Host]/``. Python validates bracketed hosts as IPv6 literals
    while joining them and raises ValueError. Such an illustrative link is not
    a retrievable reference and must not make the surrounding post fail.
    """
    resolved: set[str] = set()
    for link in links:
        if not link:
            continue
        try:
            value = urljoin(source_url, link)
            parsed = urlsplit(value)
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            resolved.add(value)
    return sorted(resolved)


def parse_message(html: str, source_url: str) -> Message:
    parser = _MessageParser()
    parser.feed(html)
    title = " ".join("".join(parser.title_parts).split()) or parser.meta.get("Subject", "")
    author = parser.meta.get("Author", "")
    date_match = re.search(r"<em>Date</em>:\s*([^<]+)<br", html, re.IGNORECASE)
    published = date_match.group(1).strip() if date_match else ""
    body = "".join(parser.body_parts).strip()
    links = _safe_links(source_url, parser.links)
    message_id = parser.meta.get("Message-ID", "")
    if not message_id:
        match = re.search(r"^Message-ID:\s*(\S+)", body, re.IGNORECASE | re.MULTILINE)
        message_id = match.group(1) if match else ""
    return Message(
        source_url=source_url,
        title=title,
        author=author,
        published=published,
        body=body,
        links=links,
        raw_source=html,
        source_format="text/html",
        message_id=message_id,
    )


def parse_month(html: str, base_url: str) -> list[str]:
    parser = _MonthParser(base_url)
    parser.feed(html)
    return list(dict.fromkeys(parser.urls))


def parse_hyperkitty_index(html: str, base_url: str) -> list[str]:
    parser = _HyperKittyIndexParser(base_url)
    parser.feed(html)
    return list(dict.fromkeys(parser.urls))


def parse_hyperkitty_message(html: str, source_url: str) -> Message:
    parser = _HyperKittyMessageParser()
    parser.feed(html)
    title = " ".join("".join(parser.title_parts).split())
    title = title or parser.meta.get("og:title", "")
    author = " ".join("".join(parser.author_parts).split())
    body = "\n".join(line.strip() for line in "".join(parser.body_parts).splitlines() if line.strip())
    message_id = parser.meta.get("message-id", "")
    match = re.search(r"^Message-ID:\s*(\S+)", body, re.IGNORECASE | re.MULTILINE)
    return Message(
        source_url=source_url, title=title, author=author,
        published=parser.published, body=body,
        links=_safe_links(source_url, parser.links), raw_source=html,
        source_format="text/html", message_id=message_id or (match.group(1) if match else ""),
    )


def parse_rss(xml_text: str) -> list[str]:
    root = ET.fromstring(xml_text)
    urls: list[str] = []
    for item in root.findall("./channel/item"):
        link = (item.findtext("link") or item.findtext("guid") or "").strip()
        if link:
            urls.append(link)
    # HyperKitty exposes an Atom feed rather than RSS on some deployments.
    namespace = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall("atom:entry", namespace):
        link_element = entry.find("atom:link[@rel='alternate']", namespace)
        if link_element is None:
            link_element = entry.find("atom:link", namespace)
        link = (link_element.get("href", "") if link_element is not None else "").strip()
        if link:
            urls.append(link)
    return list(dict.fromkeys(urls))
