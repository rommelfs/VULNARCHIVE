# VULNARCHIVE

## Online resources

- Explore the online VULNARCHIVE implementation at
  [vuln.freearchive.org](https://vuln.freearchive.org/).
- Browse the
  [most recent GNA 1988 vulnerabilities](https://vulnerability.circl.lu/recent?source=gna-1988)
  available in the GCVE ecosystem.

VULNARCHIVE is a provenance-preserving archive and vulnerability-publication
pipeline for historic security mailing lists. It imports messages, extracts
structured vulnerability facts, compares them with known CVEs, routes uncertain
decisions to analysts, and publishes eligible records as **GNA 1988**.

The project deliberately separates evidence collection, matching, human review,
and publication. An imported message is not treated as proof that a vulnerability
is new, and a similarity score is not treated as a final identity decision.

## Project goals

- Preserve primary mailing-list evidence with stable source attribution.
- Support multiple independently selectable sources; Full Disclosure and the
  current SecurityFocus Bugtraq and Bugtraq AI lists are built in.
- Enrich messages with structured vendor, product, component, version, commit,
  alias, reference, and vulnerability data.
- Link evidence to existing CVEs when the identity is sufficiently clear.
- Keep ambiguous cases in an auditable manual-review workflow.
- Publish qualified context or new records under GNA 1988.
- Provide searchable, sortable, paginated public and private collections.
- Keep automatic matching measurable and gated by reproducible evaluation data.

Non-goals and trust boundaries are documented in
[`documentation/GOALS.md`](documentation/GOALS.md).

## Current features

| Area | Capability |
|---|---|
| Ingestion | Full Disclosure RSS/archive, SecurityFocus HyperKitty feeds, failed-download retry, historical workers |
| Provenance | Source ID, canonical key, message ID, URL, content hash, raw message body |
| Extraction | IDs, vendors, products, components, versions, fixes, commits, aliases, references |
| Matching | Explicit-ID resolution, bounded candidate lookup, deterministic checks, optional LLM comparison |
| Review | Managed users, roles, confidence filters, sorting, pagination, bulk decisions, optional four-eyes policy |
| Audit | Append-only review events and analysis events, including LLM provider/prompt/output metadata |
| Publication | Dry-run planning, GNA 1988 allocation, context records, new records, publication ledger |
| Public site | Vulnerability pages, archive pages, publication API, NDJSON dump, `security.txt` |
| Search | SQLite FTS5 when available, with a compatible `LIKE` fallback |
| Operations | systemd units, Apache configuration, guarded upgrades, SQLite backup before migration |

See [`documentation/FEATURES.md`](documentation/FEATURES.md) for behavior,
limitations, and status.

## Architecture at a glance

```text
mailing-list source -> adapter/parser -> extraction -> candidate lookup
                                         |              |
                                         v              v
                                      SQLite <- analysis events
                                         |
                              review + optional LLM decision
                                         |
                                  publication policy
                                         |
                              GNA 1988 records + ledger
                                         |
                                  read-only public UI
```

The private review service and public read-only service are separate processes.
SQLite is the canonical local store and runs in WAL mode. See
[`documentation/ARCHITECTURE.md`](documentation/ARCHITECTURE.md).

## Requirements

- Python 3.11 or newer
- SQLite with FTS5 recommended
- Network access to configured mailing-list sources and Vulnerability-Lookup
- For production: a dedicated Unix account, systemd, Apache 2.4, and TLS
- Optional: an OpenAI-compatible Responses API for bounded LLM comparison

There are no mandatory third-party Python runtime dependencies.

## Quick start for development

```bash
git clone <repository-url> VULNARCHIVE
cd VULNARCHIVE
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cp config/vulnarchive.env.example .env.local
```

Load only a development-safe subset of `.env.local`; do not commit credentials.
The application reads configuration from process environment variables, not from
the file automatically.

Initialize the database and inspect the current publication plan:

```bash
mkdir -p data
fd-sightings policy
fd-sightings plan-auto
```

Import a small historical sample without automatic publication:

```bash
fd-sightings archive --source full-disclosure \
  --from-period 2024-01 --to-period 2024-01 --limit 5
```

Start the local interfaces on loopback:

```bash
fd-sightings review --bind 127.0.0.1 --port 8765
fd-sightings public --bind 127.0.0.1 --port 8766
```

The review UI requires `VA_REVIEW_USERNAME` and `VA_REVIEW_PASSWORD`. Never bind
it to an untrusted interface without a reverse proxy, TLS, authentication, and
network restrictions.

## Common commands

```bash
# Current feeds from configured/default sources
fd-sightings rss --source full-disclosure

# Import and publish eligible current-feed entries
fd-sightings sync --source full-disclosure --retry-failed

# Historical backfill from several sources
fd-sightings archive --source full-disclosure --source bugtraq \
  --from-period 2001-01 --to-period 2001-03

# One URL
fd-sightings url https://seclists.org/fulldisclosure/2024/Jan/1

# Re-run vendor, PoC, and vulnerability analysis for an existing URL
fd-sightings --refresh url https://seclists.org/fulldisclosure/2024/Jan/1

# Re-run analysis for every observation already stored
fd-sightings rescan

# Retry and clear successfully recovered download failures
fd-sightings retry-failed

# Review/public servers
fd-sightings review --bind 127.0.0.1 --port 8765
fd-sightings public --bind 127.0.0.1 --port 8766

# Publication preview and execution
fd-sightings plan-auto
fd-sightings publish-auto --retry-failed

# Exports
fd-sightings export --output observations.ndjson
fd-sightings export-publications --output publications.ndjson

# Offline matching evaluation; exit status 2 means the gate failed
fd-sightings evaluate tests/fixtures/matching \
  --output data/matching-evaluation.json
```

All data commands accept `--db PATH`. The default is
`data/fd-sightings.sqlite`.

## Source configuration

`VA_SOURCES` is a comma-separated list used by unattended sync and as the
default selection in the historical-import UI:

```bash
VA_SOURCES=full-disclosure,bugtraq,bugtraq-ai
```

Both Bugtraq sources use their current SecurityFocus HyperKitty feeds. Failed
post downloads are retained in the database and can be attempted again with
`fd-sightings retry-failed` (optionally restricted by `--source` or `--limit`);
a successful import removes its failure entry. Unknown source names fail
validation instead of being ignored.

Historical HyperKitty month pages contain thread links rather than post links.
The adapter expands each thread and its replies into stable `/message/<hash>/`
permalinks and explicitly ignores the `/message/new` compose action.

Administrators can also inspect and retry these failures under **Review →
Archive imports**. The public viewer exposes a paginated list of locally
published records at `/vulnerability/`. Before assigning a new GNA 1988 ID, the
publication pipeline compares cross-source Message-IDs, gateway-normalized
content, and conservative word-shingle similarity. List prefixes, transport
headers, subscription footers, and PGP signature blocks therefore do not cause
a second local GCVE, while conflicting CVE IDs or products prevent a fuzzy merge.

## Matching and LLM safety

The LLM is an optional comparator for candidates already obtained from the
configured Vulnerability-Lookup service; it is not allowed to perform an open
web search or invent candidates. Supported modes are `off`, `shadow`, `review`,
and `automatic`. Start with `shadow`.

`automatic` mode requires `VA_MATCH_EVALUATION_REPORT` to reference a passing,
current report generated by `fd-sightings evaluate`. This makes automatic-mode
activation an explicit, testable operational decision. Details are in
[`documentation/AUTOMATED_MATCHING.md`](documentation/AUTOMATED_MATCHING.md).

## Review and publication

The private UI supports managed analyst accounts, admin/reviewer roles,
confidence ranges, bulk approval/rejection, immutable event history, and an
optional four-eyes rule. A review decision and a publication are distinct
operations. Bulk actions apply only to explicitly selected rows and are bounded.

Publication policy thresholds are configured through environment variables.
Always inspect `fd-sightings plan-auto` before changing thresholds or enabling a
new source. Published output remains traceable through the publication ledger.

## Public endpoints

- `/` — project landing page
- `/archive/` — paginated mailing-list archive
- `/archive/item/<content-hash>` — archived source item
- `/vulnerability/<GCVE-ID>` — human-readable vulnerability page
- `/api/gcve/publication` — publication API
- `/dumps/gna-1988.ndjson` — publication dump
- `/.well-known/security.txt` — security contact policy

The review application is intentionally not part of the public service. A
production reverse proxy may expose it under an authenticated `/review/` prefix,
restricted to trusted networks.

## Documentation

- [Documentation index](documentation/README.md)
- [Goals and trust boundaries](documentation/GOALS.md)
- [Features and current status](documentation/FEATURES.md)
- [Architecture and data flow](documentation/ARCHITECTURE.md)
- [Configuration reference](documentation/CONFIGURATION.md)
- [Production installation and upgrades](DEPLOYMENT.md)
- [Maintenance and incident procedures](documentation/MAINTENANCE.md)
- [Automated matching](documentation/AUTOMATED_MATCHING.md)
- [Implementation review and remaining work](documentation/IMPLEMENTATION_REVIEW.md)
- [Handover checklist](HANDOVER.md)
- [Publication policy](VULNARCHIVE_POLICY.md)
- [BCP index](documentation/README.md#gcve-best-current-practices)

## Development and testing

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests
git diff --check
```

Changes to matching behavior should add labelled fixtures and regenerate the
evaluation report. Changes to storage must remain forward-migrating and be tested
against legacy rows. Changes to public/review routes should test both direct and
reverse-proxy prefixes.

## Security and responsible operation

- Keep the review backend private and authenticated.
- Store secrets only in `/etc/vulnarchive/vulnarchive.env` with restrictive
  permissions in production.
- Treat imported content, LLM output, and external API responses as untrusted.
- Back up both the SQLite database and associated WAL/SHM state correctly.
- Do not manually edit publication records without preserving an audit event.
- Report security issues using `deploy/security.txt`.

## License and governance

VULNARCHIVE is free software released under the **GNU Affero General Public
License v3.0**. See [`LICENSE`](LICENSE) for the complete terms and
[`NOTICE`](NOTICE) for attribution information.

Copyright (c) 2026 [Computer Incident Response Center Luxembourg
(CIRCL)](https://circl.lu/)<br>
Copyright (c) 2026 [Sascha Rommelfangen](https://github.com/rommelfs)

The GCVE BCP documents retain the licenses stated in those documents. GCVE
interoperability follows those BCPs; project-specific publication decisions
follow [`VULNARCHIVE_POLICY.md`](VULNARCHIVE_POLICY.md).
