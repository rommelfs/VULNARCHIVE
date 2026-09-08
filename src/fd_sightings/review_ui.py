from __future__ import annotations

import html
import base64
import ipaddress
import os
import re
import secrets
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from .store import Store
from .query import ListQuery
from .workers import ImportWorkerManager
from .sources import SOURCES, configured_source_ids

SIGHTING_TYPES = ("seen", "published-proof-of-concept")


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _layout(title: str, content: str, *, refresh: int = 0) -> bytes:
    refresh_meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{refresh_meta}<title>{_e(title)} · VULNARCHIVE</title><style>
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
</style></head><body><header><div class="toolbar"><a href="/"><strong>VULNARCHIVE</strong></a><a href="/publish">Automatic publication</a><a href="/workers">Archive imports</a></div></header><main>{content}</main></body></html>"""
    return page.encode("utf-8")


class ReviewServer(HTTPServer):
    def __init__(self, address: tuple[str, int], store: Store):
        super().__init__(address, ReviewHandler)
        self.store = store
        self.workers = ImportWorkerManager(store.path)
        self.csrf_token = secrets.token_urlsafe(24)
        self.auth_username = os.environ.get("VA_REVIEW_USERNAME", "")
        self.auth_password = os.environ.get("VA_REVIEW_PASSWORD", "")
        prefix = os.environ.get("VA_REVIEW_PREFIX", "/review").strip()
        self.url_prefix = "/" + prefix.strip("/") if prefix.strip("/") else ""
        self.allowed_networks = _networks(os.environ.get("VA_REVIEW_ALLOWED_NETWORKS", "127.0.0.0/8"))
        self.trusted_proxies = _networks(os.environ.get("VA_REVIEW_TRUSTED_PROXIES", "127.0.0.0/8"))


def _networks(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    try:
        return tuple(ipaddress.ip_network(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise ValueError(f"invalid review network configuration: {exc}") from exc


class ReviewHandler(BaseHTTPRequestHandler):
    server: ReviewServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, body: bytes, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        if content_type.startswith("text/html") and self.server.url_prefix:
            page = body.decode("utf-8")
            page = page.replace('href="/', f'href="{self.server.url_prefix}/')
            page = page.replace('action="/', f'action="{self.server.url_prefix}/')
            body = page.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        if location.startswith("/") and self.server.url_prefix:
            location = self.server.url_prefix + location
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def _authorize(self) -> bool:
        peer = ipaddress.ip_address(self.client_address[0])
        client = peer
        if any(peer in network for network in self.server.trusted_proxies):
            forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
            if forwarded:
                try:
                    client = ipaddress.ip_address(forwarded)
                except ValueError:
                    self._send(b"Invalid forwarded client address", 400, "text/plain; charset=utf-8")
                    return False
        if not any(client in network for network in self.server.allowed_networks):
            self._send(b"Forbidden", 403, "text/plain; charset=utf-8")
            return False
        if not self.server.auth_username or not self.server.auth_password:
            self._send(b"Review authentication is not configured", 503, "text/plain; charset=utf-8")
            return False
        expected = base64.b64encode(
            f"{self.server.auth_username}:{self.server.auth_password}".encode()
        ).decode()
        supplied = self.headers.get("Authorization", "")
        if not secrets.compare_digest(supplied, f"Basic {expected}"):
            body = b"Authentication required"
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="VULNARCHIVE Review", charset="UTF-8"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return False
        return True

    def do_GET(self) -> None:
        if not self._authorize():
            return
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/":
            self._index(params)
        elif parsed.path == "/observation":
            self._detail(params.get("source", [""])[0])
        elif parsed.path == "/publish":
            self._publication_dashboard()
        elif parsed.path == "/workers":
            self._workers(params)
        elif parsed.path.startswith("/archive/full-disclosure/"):
            suffix = parsed.path.removeprefix("/archive/full-disclosure/").strip("/")
            self._archive_detail(f"https://seclists.org/fulldisclosure/{suffix}")
        else:
            self._send(_layout("Not found", '<div class="panel"><h1>Not found</h1></div>'), 404)

    def do_POST(self) -> None:
        if not self._authorize():
            return
        if self.path == "/publish":
            self._publish()
            return
        if self.path == "/workers":
            self._start_worker()
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
            selected_ids = data.get("vulnerability_id", [])
            custom_ids = re.split(r"[\s,;]+", data.get("custom_vulnerability_ids", [""])[0])
            self.server.store.review(
                source,
                state,
                selected_ids + custom_ids,
                data.get("sighting_type", [""])[0],
                data.get("note", [""])[0],
            )
        except ValueError as exc:
            self._send(_layout("Review error", f'<div class="panel"><h1>Review error</h1><p>{_e(exc)}</p></div>'), 400)
            return
        self._redirect("/observation?" + urllib.parse.urlencode({"source": source}))

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
        mode = data.get("mode", [""])[0]
        if mode == "source":
            self._publish_source(data)
            return
        if mode != "automatic":
            self._send(_layout("Publish error", '<div class="panel"><h1>Unsupported publication mode</h1><p>VULNARCHIVE publishes only to its local BCP-03/BCP-05 store.</p></div>'), 400)
            return
        self._publish_automatic(data)

    def _start_worker(self) -> None:
        data = self._form_data()
        if data is None:
            return
        try:
            limit = int(data.get("limit", ["0"])[0] or 0)
            job = self.server.workers.submit(
                data.get("from_period", [""])[0],
                data.get("to_period", [""])[0],
                limit=limit,
                semantic=data.get("semantic", [""])[0] == "1",
                refresh=data.get("refresh", [""])[0] == "1",
                sources=data.get("source", []),
            )
        except (ValueError, OSError) as exc:
            self._send(_layout("Import error", f'<div class="panel"><h1>Import could not be started</h1><p>{_e(exc)}</p><p><a href="/workers">Back</a></p></div>'), 400)
            return
        self._redirect("/workers?" + urllib.parse.urlencode({"job": job["id"]}))

    def _workers(self, params: dict[str, list[str]]) -> None:
        jobs = self.server.workers.jobs()
        selected = self.server.workers.get(params.get("job", [""])[0])
        rows = "".join(
            f'<tr><td><a href="{_e("/workers?" + urllib.parse.urlencode({"job": job["id"]}))}">{_e(job["id"][:10])}</a></td>'
            f'<td>{_e(job["from_period"])} – {_e(job["to_period"])}</td><td class="{_e(job["status"])}">{_e(job["status"])}</td>'
            f'<td>{_e(job["created_at"])}</td></tr>' for job in jobs
        )
        detail = ""
        if selected:
            log = self.server.workers.log_tail(selected)
            feedback = "This view refreshes every 2 seconds." if selected["status"] in {"queued", "running"} else "Final output"
            detail = (f'<div class="panel"><h2>Worker {_e(selected["id"])}</h2>'
                      f'<p>Status: <strong>{_e(selected["status"])}</strong> · Return code: {_e(selected["return_code"])}</p>'
                      f'<p class="muted">{feedback}</p>'
                      f'<pre>{_e(log or "No output yet.")}</pre></div>')
        now = datetime.now(timezone.utc)
        current_month = f"{now.year:04d}-{now.month:02d}"
        previous_year = now.year if now.month > 1 else now.year - 1
        previous_month_number = now.month - 1 if now.month > 1 else 12
        previous_month = f"{previous_year:04d}-{previous_month_number:02d}"
        enabled_sources = set(configured_source_ids())
        source_controls = "".join(
            f'<label><input type="checkbox" name="source" value="{_e(source_id)}" '
            f'{"checked" if source_id in enabled_sources else ""}> {_e(adapter.name)}</label>'
            for source_id, adapter in SOURCES.items()
        )
        content = f'''<div class="panel"><h1>Historical archive imports</h1>
<p>Start one bounded background worker. Workers run sequentially and only import and match posts; they do not publish records.</p>
<form method="post" action="/workers"><input type="hidden" name="csrf" value="{_e(self.server.csrf_token)}">
<p class="muted">Use the calendar controls to select complete archive months. Future months cannot be queued.</p>
<div class="toolbar"><label>From month <input type="month" name="from_period" min="2002-01" max="{current_month}" value="{previous_month}" required aria-label="First archive month"></label>
<label>To month <input type="month" name="to_period" min="2002-01" max="{current_month}" value="{previous_month}" required aria-label="Last archive month"></label>
<label>Limit per month <input type="number" name="limit" value="0" min="0" max="10000"></label>
{source_controls}
<label><input type="checkbox" name="semantic" value="1"> Candidate search (slower)</label>
<label><input type="checkbox" name="refresh" value="1"> Reprocess existing posts</label><button>Start import worker</button></div></form></div>
<div class="panel"><h2>Workers</h2><table><thead><tr><th>ID</th><th>Period</th><th>Status</th><th>Created</th></tr></thead>
<tbody>{rows or '<tr><td colspan="4">No import workers yet.</td></tr>'}</tbody></table></div>{detail}'''
        auto_refresh = 2 if selected and selected["status"] in {"queued", "running"} else 0
        self._send(_layout("Archive imports", content, refresh=auto_refresh))

    def _publish_source(self, data: dict[str, list[str]]) -> None:
        from .policy import PublicationPolicy
        from .publication import execute_automatic_publication

        source = data.get("source", [""])[0]
        row = self.server.store.get(source)
        if not row or row["review_state"] != "approved":
            self._send(_layout("Publish error", '<div class="panel"><h1>Approve this observation before publication.</h1></div>'), 400)
            return
        outcomes = execute_automatic_publication(
            self.server.store, PublicationPolicy.from_env(),
            retry_failed=True, source_url=source,
        )
        import json
        rendered = _e(json.dumps(outcomes, ensure_ascii=False, indent=2))
        self._send(_layout("Local publication completed", f'<div class="panel"><h1>Local publication completed</h1><p>The result is available through BCP-03 when the plan published a GCVE record.</p><p><a href="{_e("/observation?" + urllib.parse.urlencode({"source": source}))}">Back</a></p><pre>{rendered}</pre></div>'))

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
        policy_rows = "".join(
            f"<tr><th>{_e(key)}</th><td>{_e(value)}</td></tr>" for key, value in asdict(policy).items()
        )
        content = f"""<div class="panel"><h1>Local automatic publication</h1>
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
        from .policy import PublicationPolicy
        from .publication import execute_automatic_publication
        try:
            limit = max(0, int(data.get("limit", ["0"])[0] or 0))
            outcomes = execute_automatic_publication(
                self.server.store,
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

    def _index(self, params: dict[str, list[str]]) -> None:
        try:
            one = lambda name, default="": params.get(name, [default])[0]
            request = ListQuery(
                page=int(one("page", "1")), per_page=int(one("per_page", "50")),
                sort=one("sort", "published"), order=one("order", "desc"),
                search=one("q").strip(), status=one("match"), review_state=one("review"),
            )
        except (ValueError, TypeError) as exc:
            self._send(_layout("Invalid review query", f'<div class="panel"><h1>Invalid review query</h1><p>{_e(exc)}</p></div>'), 400)
            return
        result = self.server.store.observation_page(request)
        rows = result.items
        counts = self.server.store.review_counts()
        table_rows = []
        for row in rows:
            extraction = row["extraction"]
            matches = row["matches"]
            tags = " ".join(f'<span class="tag">{_e(value)}</span>' for value in extraction.get("cve_ids", []) + extraction.get("cwe_ids", []))
            proposed = extraction.get("proposed_type", "seen")
            confidence = float(row["max_confidence"])
            href = "/observation?" + urllib.parse.urlencode({"source": row["source_url"]})
            table_rows.append(f"""<tr><td><a href="{_e(href)}"><strong>{_e(row['title'])}</strong></a><br><span class="muted">{_e(row['author'])} · {_e(row['published'])}</span><br>{tags}</td>
<td>{_e(proposed)}</td><td>{confidence:.3f}</td><td class="{_e(row['review_state'])}">{_e(row['review_state'])}</td></tr>""")
        def sort_link(field: str, label: str) -> str:
            order = "asc" if request.sort != field or request.order == "desc" else "desc"
            query = {"q": request.search, "review": request.review_state, "match": request.status,
                     "per_page": request.per_page, "sort": field, "order": order}
            return f'<a href="/?{_e(urllib.parse.urlencode(query))}">{_e(label)}</a>'
        common = {"q": request.search, "review": request.review_state, "match": request.status,
                  "per_page": request.per_page, "sort": request.sort, "order": request.order}
        pagination = []
        if request.page > 1:
            pagination.append(f'<a rel="prev" href="/?{_e(urllib.parse.urlencode({**common, "page": request.page - 1}))}">Previous</a>')
        pagination.append(f'<span>Page {request.page} of {result.pages} · {result.total} observations</span>')
        if request.page < result.pages:
            pagination.append(f'<a rel="next" href="/?{_e(urllib.parse.urlencode({**common, "page": request.page + 1}))}">Next</a>')
        content = f"""<div class="panel"><h1>Review queue</h1><div class="toolbar">
<span>Pending <strong>{counts['pending']}</strong></span><span>Approved <strong>{counts['approved']}</strong></span><span>Rejected <strong>{counts['rejected']}</strong></span></div>
<form class="toolbar" method="get" role="search" style="margin-top:16px"><input type="search" name="q" maxlength="200" value="{_e(request.search)}" placeholder="Search title, author, body, CVE or CWE">
<select name="review"><option value="">All review states</option>{self._options(('pending','approved','rejected'), request.review_state)}</select>
<select name="match"><option value="">All match states</option>{self._options(('matched','unmatched'), request.status)}</select><input type="hidden" name="sort" value="{_e(request.sort)}"><input type="hidden" name="order" value="{_e(request.order)}"><button>Filter</button></form></div>
<div class="panel"><table><thead><tr><th>{sort_link('title', 'Observation')}</th><th>Proposal</th><th>{sort_link('confidence', 'Confidence')}</th><th>{sort_link('review', 'Review')}</th></tr></thead><tbody>{''.join(table_rows) or '<tr><td colspan="4">No observations.</td></tr>'}</tbody></table><nav class="toolbar" aria-label="Pagination">{' '.join(pagination)}</nav></div>"""
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
        chosen = set(row["reviewed_vulnerability_ids"] or
                     [match["vulnerability_id"] for match in matches])
        sighting_type = str(row["reviewed_sighting_type"] or extraction.get("proposed_type", "seen"))
        match_cards = "".join(
            f'<option value="{_e(match["vulnerability_id"])}" {"selected" if match["vulnerability_id"] in chosen else ""}>'
            f'{_e(match["vulnerability_id"])} — {_e(match["title"])} ({_e(match["confidence"])})</option>'
            for match in matches
        )
        match_analysis = "".join(
            f'<li><strong>{_e(match.get("vulnerability_id", ""))}</strong> · {_e(match.get("method", ""))} · {_e(match.get("confidence", 0))}'
            f'<br><span class="muted">Evidence: {_e(", ".join(match.get("evidence", [])) or "none")}</span>'
            f'<br><span class="rejected">Contradictions: {_e(", ".join(match.get("contradictions", [])) or "none")}</span></li>'
            for match in matches
        )
        evidence = "".join(f"<li>{_e(item)}</li>" for item in extraction.get("poc_evidence", []))
        content = f"""<p><a href="/">← Queue</a></p><div class="grid"><section>
<div class="panel"><h1>{_e(row['title'])}</h1><p class="muted">{_e(row['author'])} · {_e(row['published'])}</p>
<p><a href="{_e(row['source_url'])}" target="_blank" rel="noreferrer">Open original source</a> · {_e(row.get('source_id', 'full-disclosure'))}</p>
<h3>Extraction</h3><p>Product: <strong>{_e(extraction.get('product_hint',''))}</strong> · Proposed type: <strong>{_e(extraction.get('proposed_type',''))}</strong> · PoC score: <strong>{_e(extraction.get('poc_score',0))}</strong></p><ul>{evidence or '<li>No PoC indicators</li>'}</ul>
<h3>Candidate analysis</h3><ul>{match_analysis or '<li>No candidates</li>'}</ul>
<h3>Original body</h3><pre>{_e(row['body'])}</pre></div></section><aside><div class="panel"><h2>Decision</h2>
<p>Current state: <strong class="{_e(row['review_state'])}">{_e(row['review_state'])}</strong></p>
<form method="post" action="/review"><input type="hidden" name="csrf" value="{_e(self.server.csrf_token)}"><input type="hidden" name="source" value="{_e(source)}">
<label>Referenced vulnerabilities (zero, one, or multiple)</label><select name="vulnerability_id" multiple size="6" style="width:100%">{match_cards}</select>
<p class="muted">Leave empty for a new advisory without a referenced ID. Use Ctrl/Cmd to select multiple entries.</p>
<label>Additional IDs</label><textarea name="custom_vulnerability_ids" placeholder="One ID per line, or comma-separated"></textarea>
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
        published_id = self.server.store.published_gcve_for_source(source)
        if published_id:
            public_base = os.environ.get("VA_PUBLIC_BASE_URL", "https://vuln.freearchive.org").rstrip("/")
            public_url = f"{public_base}/vulnerability/{urllib.parse.quote(published_id)}"
            return f'<hr><h3>Published</h3><p><a class="button" href="{_e(public_url)}" target="_blank" rel="noreferrer">Open published {_e(published_id)}</a></p>'
        if row["review_state"] != "approved":
            return '<p class="muted">Approval records the review decision; publish it locally in a second step.</p>'
        return f'''<hr><h3>Local publication</h3><p>Approval is complete. Continue directly with publication or open the batch dashboard.</p>
<p><a href="/publish">Open publication dashboard</a></p>
<form method="post" action="/publish"><input type="hidden" name="csrf" value="{_e(self.server.csrf_token)}"><input type="hidden" name="mode" value="source"><input type="hidden" name="source" value="{_e(source)}"><button>Publish this approved entry locally</button></form>'''


def serve(store: Store, bind: str = "127.0.0.1", port: int = 8765) -> None:
    server = ReviewServer((bind, port), store)
    print(f"Review UI: http://{bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
