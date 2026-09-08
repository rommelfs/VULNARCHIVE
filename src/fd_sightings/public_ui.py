from __future__ import annotations

import json
import urllib.parse
import html
import math
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from .public_api import publication_response
from .dump import ndjson_lines
from .review_ui import _e
from .store import Store


def _public_layout(title: str, content: str) -> bytes:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{_e(title)} · VULNARCHIVE</title>
<style>body{{max-width:960px;margin:2rem auto;padding:0 1rem;font:16px/1.5 system-ui,sans-serif;color:#1d242c}}
a{{color:#315e52}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f5f6;padding:1rem}}
.months,.pagination{{display:flex;flex-wrap:wrap;gap:.5rem 1rem;padding:0;list-style:none}}
.archive-list{{list-style:none;padding:0}}.archive-list li{{display:grid;grid-template-columns:7rem 1fr;gap:1rem;padding:.45rem 0;border-bottom:1px solid #e5e7e9}}
time{{color:#59636e}}.muted{{color:#59636e}}@media(max-width:560px){{.archive-list li{{grid-template-columns:1fr;gap:0}}}}</style>
</head><body><header><a href="/"><strong>VULNARCHIVE</strong></a></header><main>{content}</main></body></html>""".encode()


def _post_date(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        result = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        try:
            result = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _positive_int(params: dict[str, list[str]], name: str, default: int, maximum: int) -> int:
    raw = params.get(name, [str(default)])
    if len(raw) != 1 or not raw[0].isdigit():
        raise ValueError(f"{name} must be a positive integer")
    value = int(raw[0])
    if value < 1 or value > maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


class PublicServer(HTTPServer):
    def __init__(self, address: tuple[str, int], store: Store):
        super().__init__(address, PublicHandler)
        self.store = store


class PublicHandler(BaseHTTPRequestHandler):
    server: PublicServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, body: bytes, content_type: str, status: int = 200, **headers: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value: object, status: int = 200, **headers: str) -> None:
        self._send(json.dumps(value, ensure_ascii=False).encode(), "application/json", status, **headers)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/":
            body = _public_layout("Public information", """<div class=\"panel\"><h1>VULNARCHIVE</h1>
<p>Public mailing-list archive and GCVE publication feed for GNA 1988.</p>
<ul><li><a href=\"/api/gcve/publication\">GCVE publication API</a></li>
<li><a href=\"/dumps/gna-1988.ndjson\">GNA 1988 NDJSON dump</a></li>
<li><a href=\"/archive/\">Full Disclosure archive</a></li></ul></div>""")
            self._send(body, "text/html; charset=utf-8")
        elif parsed.path == "/api/gcve/publication":
            status, body = publication_response(self.server.store, parsed.query)
            self._send(body, "application/json", status)
        elif parsed.path == "/dumps/gna-1988.ndjson":
            body = b"".join(ndjson_lines(self.server.store))
            self._send(body, "application/x-ndjson", Content_Disposition='attachment; filename="gna-1988.ndjson"')
        elif parsed.path == "/.well-known/security.txt":
            self._send(b"GCVE: https://vuln.freearchive.org\n", "text/plain; charset=utf-8")
        elif parsed.path == "/archive/":
            self._archive_index(parsed.query)
        elif parsed.path.startswith("/archive/full-disclosure/"):
            suffix = parsed.path.removeprefix("/archive/full-disclosure/").strip("/")
            self._archive_detail(f"https://seclists.org/fulldisclosure/{suffix}")
        elif parsed.path.startswith("/vulnerability/"):
            self._vulnerability(parsed.path.removeprefix("/vulnerability/").strip("/"))
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        self._json({"error": "method not allowed"}, 405, Allow="GET")

    def _archive_index(self, query: str) -> None:
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        try:
            page = _positive_int(params, "page", 1, 1_000_000)
            per_page = _positive_int(params, "per_page", 50, 100)
            month = params.get("month", [""])
            if len(month) != 1 or (month[0] and not re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])", month[0])):
                raise ValueError("month must use YYYY-MM")
            selected_month = month[0]
            search = params.get("q", [""])
            if len(search) != 1 or len(search[0]) > 200:
                raise ValueError("q must contain at most 200 characters")
            search_query = search[0].strip()
        except ValueError as exc:
            self._send(_public_layout("Invalid archive query", f'<h1>Invalid archive query</h1><p>{_e(exc)}</p>'), "text/html; charset=utf-8", 400)
            return

        source_rows = self.server.store.search_rows(search_query) if search_query else self.server.store.rows()
        dated_rows = [(row, _post_date(row.get("published"))) for row in source_rows]
        dated_rows.sort(key=lambda item: (item[1] or datetime.min.replace(tzinfo=timezone.utc), str(item[0]["source_url"])), reverse=True)
        month_counts: dict[str, int] = {}
        for _, published in dated_rows:
            key = published.strftime("%Y-%m") if published else "unknown"
            month_counts[key] = month_counts.get(key, 0) + 1
        if selected_month:
            dated_rows = [item for item in dated_rows if item[1] and item[1].strftime("%Y-%m") == selected_month]

        total = len(dated_rows)
        pages = max(1, math.ceil(total / per_page))
        if page > pages:
            page = pages
        visible = dated_rows[(page - 1) * per_page:page * per_page]
        grouped: dict[str, list[tuple[dict[str, object], datetime | None]]] = {}
        for row, published in visible:
            key = published.strftime("%Y-%m") if published else "unknown"
            grouped.setdefault(key, []).append((row, published))

        sections = ""
        for key, entries in grouped.items():
            heading = entries[0][1].strftime("%B %Y") if entries[0][1] else "Unknown date"
            items = "".join(
                f'<li><time datetime="{published.date().isoformat() if published else ""}">'
                f'{published.date().isoformat() if published else "Unknown"}</time>'
                f'<a href="/archive/full-disclosure/{urllib.parse.quote(urllib.parse.urlsplit(str(row["source_url"])).path.removeprefix("/fulldisclosure/"), safe="/")}">{html.escape(str(row["title"]))}</a></li>'
                for row, published in entries
            )
            sections += f'<section><h2>{html.escape(heading)}</h2><ul class="archive-list">{items}</ul></section>'
        if not sections:
            sections = '<p class="muted">No archived posts found.</p>'

        search_suffix = "?" + urllib.parse.urlencode({"q": search_query}) if search_query else ""
        month_links = [f'<li><a href="/archive/{search_suffix}">All months</a></li>']
        for key, count in month_counts.items():
            if key == "unknown":
                continue
            label = datetime.strptime(key, "%Y-%m").strftime("%B %Y")
            month_query = {"month": key}
            if search_query:
                month_query["q"] = search_query
            month_links.append(f'<li><a href="/archive/?{urllib.parse.urlencode(month_query)}">{label} ({count})</a></li>')
        common = {"per_page": str(per_page)}
        if selected_month:
            common["month"] = selected_month
        if search_query:
            common["q"] = search_query
        pagination = []
        if page > 1:
            pagination.append(f'<li><a rel="prev" href="/archive/?{urllib.parse.urlencode({**common, "page": page - 1})}">Previous</a></li>')
        pagination.append(f'<li>Page {page} of {pages} · {total} posts</li>')
        if page < pages:
            pagination.append(f'<li><a rel="next" href="/archive/?{urllib.parse.urlencode({**common, "page": page + 1})}">Next</a></li>')
        content = (f'<div class="panel"><h1>Full Disclosure archive</h1>'
                   f'<form method="get" action="/archive/" role="search"><label>Full-text search '
                   f'<input type="search" name="q" value="{html.escape(search_query, quote=True)}" maxlength="200" placeholder="Product, CVE, author or report text"></label> '
                   f'<button>Search</button></form>'
                   f'<nav aria-label="Archive months"><ul class="months">{"".join(month_links)}</ul></nav>'
                   f'{sections}<nav aria-label="Pagination"><ul class="pagination">{"".join(pagination)}</ul></nav></div>')
        self._send(_public_layout("Archive", content), "text/html; charset=utf-8")

    def _archive_detail(self, source: str) -> None:
        row = self.server.store.get(source)
        if not row:
            self._json({"error": "not found"}, 404)
            return
        published = _post_date(row.get("published"))
        date = published.date().isoformat() if published else str(row.get("published") or "Unknown date")
        body = _public_layout(str(row["title"]), f'<div class="panel"><h1>{html.escape(str(row["title"]))}</h1><p>{html.escape(str(row["author"]))} · <time datetime="{html.escape(date)}">{html.escape(date)}</time></p><pre>{html.escape(str(row["body"]))}</pre></div>')
        self._send(body, "text/html; charset=utf-8")

    def _vulnerability(self, vulnerability_id: str) -> None:
        if not re.fullmatch(r"GCVE-[1-9][0-9]*-[0-9]{4}-[0-9]{4,19}", vulnerability_id, re.IGNORECASE):
            self._json({"error": "not found"}, 404)
            return
        record = self.server.store.gcve_record(vulnerability_id)
        if not record:
            self._json({"error": "not found"}, 404)
            return
        cna = record.get("containers", {}).get("cna", {})
        title = str(cna.get("title") or vulnerability_id.upper())
        rendered = html.escape(json.dumps(record, ensure_ascii=False, indent=2))
        self._send(_public_layout(title, f'<div class="panel"><h1>{html.escape(vulnerability_id.upper())}</h1><h2>{html.escape(title)}</h2><pre>{rendered}</pre></div>'), "text/html; charset=utf-8")


def serve(store: Store, bind: str = "127.0.0.1", port: int = 8766) -> None:
    server = PublicServer((bind, port), store)
    print(f"Public app: http://{bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
