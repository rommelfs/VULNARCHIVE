from __future__ import annotations

import json
import urllib.parse
import html
from http.server import BaseHTTPRequestHandler, HTTPServer

from .public_api import publication_response
from .dump import ndjson_lines
from .review_ui import _e
from .store import Store


def _public_layout(title: str, content: str) -> bytes:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{_e(title)} · VULNARCHIVE</title>
<style>body{{max-width:960px;margin:2rem auto;padding:0 1rem;font:16px/1.5 system-ui,sans-serif;color:#1d242c}}
a{{color:#315e52}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f5f6;padding:1rem}}</style>
</head><body><header><a href="/"><strong>VULNARCHIVE</strong></a></header><main>{content}</main></body></html>""".encode()


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
            self._archive_index()
        elif parsed.path.startswith("/archive/full-disclosure/"):
            suffix = parsed.path.removeprefix("/archive/full-disclosure/").strip("/")
            self._archive_detail(f"https://seclists.org/fulldisclosure/{suffix}")
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        self._json({"error": "method not allowed"}, 405, Allow="GET")

    def _archive_index(self) -> None:
        rows = self.server.store.rows()
        items = "".join(
            f'<li><a href="/archive/full-disclosure/{urllib.parse.quote(urllib.parse.urlsplit(str(row["source_url"])).path.removeprefix("/fulldisclosure/"), safe="/")}">{html.escape(str(row["title"]))}</a></li>'
            for row in rows
        )
        self._send(_public_layout("Archive", f'<div class="panel"><h1>Full Disclosure archive</h1><ul>{items}</ul></div>'), "text/html; charset=utf-8")

    def _archive_detail(self, source: str) -> None:
        row = self.server.store.get(source)
        if not row:
            self._json({"error": "not found"}, 404)
            return
        body = _public_layout(str(row["title"]), f'<div class="panel"><h1>{html.escape(str(row["title"]))}</h1><p>{html.escape(str(row["author"]))} · {html.escape(str(row["published"]))}</p><pre>{html.escape(str(row["body"]))}</pre></div>')
        self._send(body, "text/html; charset=utf-8")


def serve(store: Store, bind: str = "127.0.0.1", port: int = 8766) -> None:
    server = PublicServer((bind, port), store)
    print(f"Public app: http://{bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
