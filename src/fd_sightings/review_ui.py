from __future__ import annotations

import html
import secrets
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from .store import Store
from .vulnerability_lookup import VulnerabilityLookup


SIGHTING_TYPES = ("seen", "published-proof-of-concept")


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _layout(title: str, content: str) -> bytes:
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)} · VULNARCHIVE</title><style>
:root{{--bg:#f5f3ee;--panel:#fff;--ink:#1d242c;--muted:#65707b;--line:#d8d4ca;--accent:#315e52;--warn:#9d6114;--bad:#983b3b}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}}
header{{background:#18332d;color:white;padding:18px 28px}}header a{{color:white;text-decoration:none}}main{{max-width:1180px;margin:24px auto;padding:0 20px}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:18px}}
.toolbar{{display:flex;gap:10px;flex-wrap:wrap;align-items:center}}select,input,textarea,button{{font:inherit;padding:9px;border:1px solid #aaa;border-radius:6px;background:white}}
button,.button{{cursor:pointer;background:var(--accent);color:white;border:0;padding:10px 14px;border-radius:6px;text-decoration:none;display:inline-block}}
.danger{{background:var(--bad)}}.secondary{{background:#68737c}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-size:12px;text-transform:uppercase}}.tag{{display:inline-block;border-radius:99px;background:#e9eee9;padding:2px 8px;margin:2px;font-size:12px}}
.pending{{color:var(--warn)}}.approved{{color:var(--accent)}}.rejected{{color:var(--bad)}}.muted{{color:var(--muted)}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f5f6;padding:14px;border-radius:7px;max-height:520px;overflow:auto}}
.grid{{display:grid;grid-template-columns:2fr 1fr;gap:18px}}label{{display:block;font-weight:600;margin:12px 0 5px}}textarea{{width:100%;min-height:90px}}
@media(max-width:800px){{.grid{{grid-template-columns:1fr}}table{{display:block;overflow:auto}}}}
</style></head><body><header><div class="toolbar"><a href="/"><strong>VULNARCHIVE</strong></a><a href="/publish">Automatic publication</a></div></header><main>{content}</main></body></html>"""
    return page.encode("utf-8")


class ReviewServer(HTTPServer):
    def __init__(self, address: tuple[str, int], store: Store, lookup: VulnerabilityLookup):
        super().__init__(address, ReviewHandler)
        self.store = store
        self.lookup = lookup
        self.csrf_token = secrets.token_urlsafe(24)


class ReviewHandler(BaseHTTPRequestHandler):
    server: ReviewServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, body: bytes, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/dumps/gna-1988.ndjson":
            self._gna_dump()
        elif parsed.path == "/":
            self._index(params)
        elif parsed.path == "/observation":
            self._detail(params.get("source", [""])[0])
        elif parsed.path == "/connection":
            self._connection(refresh=True)
        elif parsed.path == "/publish":
            self._publication_dashboard()
        elif parsed.path.startswith("/archive/full-disclosure/"):
            suffix = parsed.path.removeprefix("/archive/full-disclosure/").strip("/")
            self._archive_detail(f"https://seclists.org/fulldisclosure/{suffix}")
        else:
            self._send(_layout("Not found", '<div class="panel"><h1>Not found</h1></div>'), 404)

    def _gna_dump(self) -> None:
        from .dump import ndjson_lines

        context = ndjson_lines(self.server.lookup)
        try:
            lines = context.__enter__()
        except Exception as exc:
            self._send(f"Unable to generate dump: {exc}".encode("utf-8"), 502, "text/plain; charset=utf-8")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            for line in lines:
                self.wfile.write(line)
        finally:
            context.__exit__(None, None, None)

    def do_POST(self) -> None:
        if self.path == "/connect":
            self._connect()
            return
        if self.path == "/publish":
            self._publish()
            return
        if self.path != "/review":
            self._send(b"Not found", 404, "text/plain")
            return
        length = int(self.headers.get("Content-Length", "0"))
        data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        if data.get("csrf", [""])[0] != self.server.csrf_token:
            self._send(b"Invalid CSRF token", 403, "text/plain")
            return
        source = data.get("source", [""])[0]
        action = data.get("action", ["pending"])[0]
        state = {"approve": "approved", "reject": "rejected", "reset": "pending"}.get(action, "pending")
        try:
            selected_id = data.get("custom_vulnerability_id", [""])[0].strip() or data.get("vulnerability_id", [""])[0].strip()
            if state == "approved" and not self.server.lookup.lookup(selected_id):
                raise ValueError(f"{selected_id} does not resolve on the configured Vulnerability-Lookup instance")
            self.server.store.review(
                source,
                state,
                selected_id,
                data.get("sighting_type", [""])[0],
                data.get("note", [""])[0],
            )
        except ValueError as exc:
            self._send(_layout("Review error", f'<div class="panel"><h1>Review error</h1><p>{_e(exc)}</p></div>'), 400)
            return
        self._redirect("/observation?" + urllib.parse.urlencode({"source": source}))

    def _connect(self) -> None:
        data = self._form_data()
        if data is None:
            return
        action = data.get("action", ["connect"])[0]
        self.server.lookup.api_key = "" if action == "disconnect" else data.get("api_key", [""])[0].strip()
        self.server.lookup._connection_cache = None
        connection = self.server.lookup.connection_status(refresh=True)
        if action == "connect" and not connection.get("authenticated"):
            self.server.lookup.api_key = ""
            self.server.lookup._connection_cache = None
            self._send(_layout("Connection failed", self._connection_panel(connection)), 401)
            return
        self._redirect("/")

    def _form_data(self) -> dict[str, list[str]] | None:
        length = int(self.headers.get("Content-Length", "0"))
        data = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        if data.get("csrf", [""])[0] != self.server.csrf_token:
            self._send(b"Invalid CSRF token", 403, "text/plain")
            return None
        return data

    def _publish(self) -> None:
        data = self._form_data()
        if data is None:
            return
        if data.get("mode", [""])[0] == "automatic":
            self._publish_automatic(data)
            return
        source = data.get("source", [""])[0]
        row = self.server.store.get(source)
        if not row or row["review_state"] != "approved":
            self._send(_layout("Publish error", '<div class="panel"><h1>Only approved observations can be published.</h1></div>'), 400)
            return
        if not self.server.lookup.connection_status(refresh=True).get("authenticated"):
            self._send(_layout("Connection required", '<div class="panel"><h1>Authenticated connection required</h1><p>Set <code>VL_API_KEY</code> and restart the review server.</p><p><a href="/">Back</a></p></div>'), 401)
            return
        from .models import Extraction, Match, Message
        extraction_data = dict(row["extraction"])
        extraction_data.pop("proposed_type", None)
        message = Message(
            source_url=str(row["source_url"]), title=str(row["title"]), author=str(row["author"]),
            published=str(row["published"]), body=str(row["body"]), links=list(row["links"]),
        )
        extraction = Extraction(**extraction_data)
        vulnerability_id = str(row["reviewed_vulnerability_id"])
        sighting_type = str(row["reviewed_sighting_type"])
        try:
            status, response = self.server.lookup.submit_sighting(
                message, extraction, Match(vulnerability_id, "analyst-approved", 1.0), sighting_type
            )
            self.server.store.record_submission(source, vulnerability_id, sighting_type, response)
        except Exception as exc:
            self._send(_layout("Publish failed", f'<div class="panel"><h1>Publish failed</h1><p>{_e(exc)}</p><p><a href="{_e("/observation?" + urllib.parse.urlencode({"source": source}))}">Back</a></p></div>'), 502)
            return
        message_text = "Already present (duplicate)" if status == 409 else "Sighting published"
        self._send(_layout(message_text, f'<div class="panel"><h1>{_e(message_text)}</h1><p>{_e(vulnerability_id)} · {_e(sighting_type)}</p><p><a href="/">Back to queue</a></p></div>'))

    def _publication_dashboard(self) -> None:
        from dataclasses import asdict
        from .policy import PublicationPolicy, plan_observation

        policy = PublicationPolicy.from_env()
        rows = self.server.store.automatic_candidates()
        plans = [plan_observation(row, policy) for row in rows]
        counts: dict[str, int] = {}
        for plan in plans:
            counts[plan.action] = counts.get(plan.action, 0) + 1
        summary = "".join(
            f'<span class="tag">{_e(name)}: {_e(count)}</span>' for name, count in sorted(counts.items())
        ) or '<span class="muted">No archived observations.</span>'
        preview_rows = "".join(
            f"<tr><td><a href=\"{_e('/observation?' + urllib.parse.urlencode({'source': plan.source_url}))}\">{_e(plan.source_url)}</a></td>"
            f"<td>{_e(plan.action)}</td><td>{_e(plan.record_type or '—')}</td><td>{_e(plan.evidence_score)}</td>"
            f"<td>{_e(', '.join(plan.targets) or 'new GCVE')}</td></tr>"
            for plan in plans[:100]
        )
        connection = self._connection_panel(self.server.lookup.connection_snapshot())
        policy_rows = "".join(
            f"<tr><th>{_e(key)}</th><td>{_e(value)}</td></tr>" for key, value in asdict(policy).items()
        )
        content = connection + f"""<div class="panel"><h1>Automatic publication</h1>
<p>Publications are assertions by GNA 1988, not validation or a trust decision.</p><div>{summary}</div>
<form method="post" action="/publish" class="toolbar" style="margin-top:16px">
<input type="hidden" name="csrf" value="{_e(self.server.csrf_token)}"><input type="hidden" name="mode" value="automatic">
<label style="margin:0">Limit</label><input type="number" min="0" name="limit" value="0" style="width:90px">
<label style="margin:0"><input type="checkbox" name="retry_failed" value="1"> Retry failed</label>
<button>Publish eligible entries</button></form></div>
<div class="panel"><h2>Active policy</h2><table>{policy_rows}</table></div>
<div class="panel"><h2>Preview</h2><table><thead><tr><th>Source</th><th>Action</th><th>Record type</th><th>Score</th><th>Targets</th></tr></thead>
<tbody>{preview_rows or '<tr><td colspan="5">Nothing to publish.</td></tr>'}</tbody></table></div>"""
        self._send(_layout("Automatic publication", content))

    def _publish_automatic(self, data: dict[str, list[str]]) -> None:
        if not self.server.lookup.connection_status(refresh=True).get("authenticated"):
            self._send(_layout("Connection required", '<div class="panel"><h1>Authenticated connection required</h1><p><a href="/connection">Connection settings</a></p></div>'), 401)
            return
        from .policy import PublicationPolicy
        from .publication import execute_automatic_publication
        try:
            limit = max(0, int(data.get("limit", ["0"])[0] or 0))
            outcomes = execute_automatic_publication(
                self.server.store,
                self.server.lookup,
                PublicationPolicy.from_env(),
                limit=limit,
                retry_failed=data.get("retry_failed", [""])[0] == "1",
            )
        except Exception as exc:
            self._send(_layout("Publication failed", f'<div class="panel"><h1>Publication failed</h1><p>{_e(exc)}</p><p><a href="/publish">Back</a></p></div>'), 502)
            return
        import json
        rendered = _e(json.dumps(outcomes, ensure_ascii=False, indent=2))
        self._send(_layout("Publication completed", f'<div class="panel"><h1>Publication run completed</h1><p>Processed {_e(len(outcomes))} archived observations.</p><p><a href="/publish">Back to publication dashboard</a></p><pre>{rendered}</pre></div>'))

    def _connection(self, refresh: bool = False) -> None:
        connection = self.server.lookup.connection_status(refresh=refresh)
        self._send(_layout("Connection", self._connection_form(connection)))

    @staticmethod
    def _connection_panel(connection: dict[str, object]) -> str:
        if not connection.get("checked"):
            label = "Connection not tested"
            css = "pending"
        elif connection.get("authenticated"):
            label = f'Connected as <strong>{_e(connection.get("login"))}</strong>'
            css = "approved"
        elif connection.get("reachable"):
            label = "Connected read-only — set VL_API_KEY to publish"
            css = "pending"
        else:
            label = f'Connection failed: {_e(connection.get("error"))}'
            css = "rejected"
        return f'<div class="panel"><div class="toolbar"><span class="{css}">{label}</span><span class="muted">{_e(connection.get("base_url"))}</span><a href="/connection" class="button secondary">Connection settings</a></div></div>'

    def _connection_form(self, connection: dict[str, object]) -> str:
        panel = self._connection_panel(connection)
        if connection.get("authenticated"):
            form = f"""<div class="panel"><h1>Connection settings</h1><p>The API key is held only in this server process.</p>
<form method="post" action="/connect"><input type="hidden" name="csrf" value="{_e(self.server.csrf_token)}"><button class="danger" name="action" value="disconnect">Disconnect</button></form></div>"""
        else:
            form = f"""<div class="panel"><h1>Connect to Vulnerability-Lookup</h1><p>Enter a personal API key. It remains in memory only and is not stored in SQLite or the browser.</p>
<form method="post" action="/connect"><input type="hidden" name="csrf" value="{_e(self.server.csrf_token)}"><label>API key</label>
<input type="password" name="api_key" required autocomplete="off" style="width:100%"><div style="margin-top:14px"><button name="action" value="connect">Connect</button></div></form></div>"""
        return '<p><a href="/">← Queue</a></p>' + panel + form

    def _index(self, params: dict[str, list[str]]) -> None:
        review = params.get("review", [""])[0]
        match_status = params.get("match", [""])[0]
        query = params.get("q", [""])[0].casefold()
        rows = self.server.store.rows(match_status or None, review or None)
        if query:
            rows = [row for row in rows if query in str(row["title"]).casefold() or query in str(row["source_url"]).casefold()]
        counts = {state: len(self.server.store.rows(review_state=state)) for state in ("pending", "approved", "rejected")}
        connection_panel = self._connection_panel(self.server.lookup.connection_snapshot())
        table_rows = []
        for row in rows:
            extraction = row["extraction"]
            matches = row["matches"]
            tags = " ".join(f'<span class="tag">{_e(value)}</span>' for value in extraction.get("cve_ids", []) + extraction.get("cwe_ids", []))
            proposed = extraction.get("proposed_type", "seen")
            confidence = max((float(match["confidence"]) for match in matches), default=0)
            href = "/observation?" + urllib.parse.urlencode({"source": row["source_url"]})
            table_rows.append(f"""<tr><td><a href="{_e(href)}"><strong>{_e(row['title'])}</strong></a><br><span class="muted">{_e(row['author'])} · {_e(row['published'])}</span><br>{tags}</td>
<td>{_e(proposed)}</td><td>{confidence:.3f}</td><td class="{_e(row['review_state'])}">{_e(row['review_state'])}</td></tr>""")
        content = connection_panel + f"""<div class="panel"><h1>Review queue</h1><div class="toolbar">
<span>Pending <strong>{counts['pending']}</strong></span><span>Approved <strong>{counts['approved']}</strong></span><span>Rejected <strong>{counts['rejected']}</strong></span></div>
<form class="toolbar" method="get" style="margin-top:16px"><input name="q" value="{_e(params.get('q',[''])[0])}" placeholder="Search title">
<select name="review"><option value="">All review states</option>{self._options(('pending','approved','rejected'), review)}</select>
<select name="match"><option value="">All match states</option>{self._options(('matched','unmatched'), match_status)}</select><button>Filter</button></form></div>
<div class="panel"><table><thead><tr><th>Observation</th><th>Proposal</th><th>Confidence</th><th>Review</th></tr></thead><tbody>{''.join(table_rows) or '<tr><td colspan="4">No observations.</td></tr>'}</tbody></table></div>"""
        self._send(_layout("Review queue", content))

    @staticmethod
    def _options(values: tuple[str, ...], selected: str) -> str:
        return "".join(f'<option value="{_e(value)}" {"selected" if value == selected else ""}>{_e(value)}</option>' for value in values)

    def _detail(self, source: str) -> None:
        row = self.server.store.get(source)
        if not row:
            self._send(_layout("Not found", '<div class="panel"><h1>Observation not found</h1></div>'), 404)
            return
        extraction = row["extraction"]
        matches = row["matches"]
        chosen = str(row["reviewed_vulnerability_id"] or (matches[0]["vulnerability_id"] if matches else ""))
        sighting_type = str(row["reviewed_sighting_type"] or extraction.get("proposed_type", "seen"))
        match_cards = "".join(
            f'<option value="{_e(match["vulnerability_id"])}" {"selected" if match["vulnerability_id"] == chosen else ""}>'
            f'{_e(match["vulnerability_id"])} — {_e(match["title"])} ({_e(match["confidence"])})</option>'
            for match in matches
        )
        evidence = "".join(f"<li>{_e(item)}</li>" for item in extraction.get("poc_evidence", []))
        content = f"""<p><a href="/">← Queue</a></p><div class="grid"><section>
<div class="panel"><h1>{_e(row['title'])}</h1><p class="muted">{_e(row['author'])} · {_e(row['published'])}</p>
<p><a href="{_e(row['source_url'])}" target="_blank" rel="noreferrer">Open Full Disclosure source</a></p>
<h3>Extraction</h3><p>Product: <strong>{_e(extraction.get('product_hint',''))}</strong> · Proposed type: <strong>{_e(extraction.get('proposed_type',''))}</strong> · PoC score: <strong>{_e(extraction.get('poc_score',0))}</strong></p><ul>{evidence or '<li>No PoC indicators</li>'}</ul>
<h3>Original body</h3><pre>{_e(row['body'])}</pre></div></section><aside><div class="panel"><h2>Decision</h2>
<p>Current state: <strong class="{_e(row['review_state'])}">{_e(row['review_state'])}</strong></p>
<form method="post" action="/review"><input type="hidden" name="csrf" value="{_e(self.server.csrf_token)}"><input type="hidden" name="source" value="{_e(source)}">
<label>Matched vulnerability</label><select name="vulnerability_id" style="width:100%"><option value="">Select…</option>{match_cards}</select>
<label>Or override with an ID</label><input name="custom_vulnerability_id" placeholder="CVE-YYYY-NNNN" style="width:100%">
<label>Sighting type</label><select name="sighting_type" style="width:100%">{self._options(SIGHTING_TYPES, sighting_type)}</select>
<label>Review note</label><textarea name="note">{_e(row['review_note'])}</textarea>
<div class="toolbar" style="margin-top:14px"><button name="action" value="approve">Approve</button><button class="danger" name="action" value="reject">Reject</button><button class="secondary" name="action" value="reset">Reset</button></div></form>
{self._publish_form(row, source)}</div></aside></div>"""
        self._send(_layout(str(row["title"]), content))

    def _archive_detail(self, source: str) -> None:
        row = self.server.store.get(source)
        if not row:
            self._send(_layout("Not found", '<div class="panel"><h1>Archived source not found</h1></div>'), 404)
            return
        extraction = dict(row.get("extraction") or {})
        identifiers = list(extraction.get("cve_ids") or []) + list(extraction.get("gcve_ids") or []) + list(extraction.get("ghsa_ids") or [])
        tags = " ".join(f'<span class="tag">{_e(identifier)}</span>' for identifier in identifiers)
        content = f"""<div class="panel"><h1>{_e(row['title'])}</h1>
<p class="muted">{_e(row['author'])} · {_e(row['published'])}</p><p>{tags}</p>
<p>SHA-256: <code>{_e(row['content_hash'])}</code></p>
<p><a href="{_e(row['source_url'])}" rel="noreferrer">Original mailing-list source</a></p>
<h2>Archived content</h2><pre>{_e(row['body'])}</pre></div>"""
        self._send(_layout(str(row["title"]), content))

    def _publish_form(self, row: dict[str, object], source: str) -> str:
        if row["review_state"] != "approved":
            return '<p class="muted">Approve this observation before publishing.</p>'
        return f"""<hr><h3>Publish to configured instance</h3><p>This creates the reviewed Sighting immediately on {_e(self.server.lookup.base_url)}.</p>
<form method="post" action="/publish"><input type="hidden" name="csrf" value="{_e(self.server.csrf_token)}"><input type="hidden" name="source" value="{_e(source)}">
<button>Publish approved Sighting</button></form>"""


def serve(store: Store, lookup: VulnerabilityLookup, bind: str = "127.0.0.1", port: int = 8765) -> None:
    server = ReviewServer((bind, port), store, lookup)
    print(f"Review UI: http://{bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
