# VULNARCHIVE

VULNARCHIVE (GCVE GNA 1988) imports public security mailing-list messages, beginning with Full Disclosure, preserves the source, resolves known identifiers, publishes Sightings, and allocates GCVE-1988 records for independent context or previously unidentified vulnerabilities. The `fd-sightings` command name is retained for compatibility with the pilot.

An automatic publication is an assertion by GNA 1988. It is not a validation, consensus statement, or instruction for consumers to trust the source.

The normative local behavior is documented in `VULNARCHIVE_POLICY.md`.
Production service and reverse-proxy templates are documented in `DEPLOYMENT.md`.
Project status, architectural decisions, and continuation instructions are documented in `HANDOVER.md`.
The GCVE Best Current Practices supplied with this repository are indexed in
[`documentation/README.md`](documentation/README.md).

## Capabilities

- Historical import by archive month or period
- Continuous import from the official RSS feed
- Repeatable source selection for Full Disclosure and Bugtraq
- SQLite checkpoints and idempotent re-runs
- Original source retention with SHA-256, format, and Message-ID when available
- CVE, GCVE, GHSA, CWE, and CVSS extraction
- Static affected-version and vulnerability-class extraction
- Evidence-based `seen` versus `published-proof-of-concept` proposal
- Exact Vulnerability-Lookup resolution for explicit identifiers
- Conservative product/title candidate matching for ID-less posts
- Auditable candidate evidence and contradiction-aware CWE/version comparison
- JSON Lines review export
- Local analyst review interface with filters, server-side pagination and sorting, detail view, approval, rejection, match override, and notes
- SQLite FTS5 full-text search across titles, authors, post bodies, CVE/CWE metadata
- Explicit, single-observation Sighting submission
- Dry-run or explicit batch submission of approved observations
- Configurable, fully automatic publication policy without a review gate
- Automatic GCVE-1988 reservation using the post's publication year
- BCP-05 `advisory`, `analysis`, and `reference` records with explicit relationships
- Durable publication ledger: retries reuse an already reserved identifier

## Setup

Python 3.11 or newer is sufficient:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Set a meaningful user agent. A read-only Vulnerability-Lookup URL is optional for resolving foreign identifiers:

```sh
export FD_USER_AGENT='VULNARCHIVE/0.2 (security-team@example.org)'
export VL_URL='https://vulnerability.circl.lu'
```

GCVE-1988 reservations and publications always use the canonical local SQLite store. A complete policy template is provided in `config/vulnarchive.env.example`.

`VL_URL` must point to a full Vulnerability-Lookup instance with the general
`/api/vulnerability/` search endpoint. The local VULNARCHIVE public service is
not suitable: it intentionally exposes only the GNA-1988 BCP-03 publication
feed and cannot supply the CVE candidate set required by LLM comparison.

## Pilot

Process one known message:

```sh
fd-sightings url https://seclists.org/fulldisclosure/2026/Sep/27
```

Process a small historical sample:

```sh
fd-sightings archive --from-period 2026-08 --to-period 2026-09 --limit 10
```

Archive imports use a 15-second request timeout and one retry per message. A
missing or stalled individual message is reported in the final `errors` list and
does not stop the remaining month. Progress is printed before each fetch, so a
healthy 121-message month still takes at least about a minute at the polite
request interval.

Process the current feed. Repeated runs skip URLs already stored:

```sh
fd-sightings rss
```

Import both configured Seclists sources. `--source` is repeatable for `rss`,
`sync`, and `archive`; omitting it keeps the Full Disclosure default:

```sh
fd-sightings rss --source full-disclosure --source bugtraq
fd-sightings archive --source bugtraq --from-period 2020-01 --to-period 2020-12
```

Source adapters own discovery and parsing. Observations retain a stable source
identifier and use Message-ID as their per-source canonical key when available,
so a second mirror URL does not create a duplicate observation.

For the unattended sync service, configure the enabled sources in
`/etc/vulnarchive/vulnarchive.env` (the template is
`config/vulnarchive.env.example`):

```env
VA_SOURCES=full-disclosure,bugtraq
```

**Important:** Bugtraq is an archive-only source. It has no current RSS feed,
so enabling it does not make a regular `sync` run discover historical posts.
Backfill it explicitly, for example:

```sh
fd-sightings archive --source bugtraq --from-period 2019-01 --to-period 2020-12
```

The same backfill can be queued in **Review → Archive imports** by selecting
Bugtraq and the required historical month range. A zero-item current `sync` for
Bugtraq is expected and is reported as an archive-only source, not as a
successful historical import.

The authenticated review UI exposes the same selection under **Archive
imports**. Its Full Disclosure and Bugtraq checkboxes default to `VA_SOURCES`
and are recorded with each worker job. The page also displays the unattended
configuration currently loaded by the review service. It intentionally cannot
edit `/etc/vulnarchive/vulnarchive.env` or run `systemctl`: that file is
root-owned and service control remains an operator action. The upgrade script
validates `VA_SOURCES`, warns when it is missing, and applies environment changes
when it restarts services that were active before the upgrade.

For the continuous Phase-2 operation, import the current feed and immediately apply the automatic publication policy in one idempotent run:

```sh
fd-sightings sync
```

This command does not require `VL_API_KEY`: GCVE identifiers and records are
reserved and published transactionally in the local SQLite store. An external
Vulnerability-Lookup connection remains optional for resolving foreign IDs and
finding candidates; already completed publications are skipped.

Export the review queues:

```sh
fd-sightings export --status matched --output matched.jsonl
fd-sightings export --status unmatched --output unmatched.jsonl
```

Start the local review interface:

```sh
fd-sightings review
```

In production, set `VA_REVIEW_BIND=10.205.22.135` and expose it through the authenticated reverse-proxy path at `https://vuln.freearchive.org/review/`. The CLI still
defaults to localhost when it is started outside the supplied systemd unit. The
interface supports queue filters, source evidence, match overrides, approval,
rejection, review notes, and bounded bulk review. Filter the queue with the
minimum/maximum confidence sliders, select individual rows, or use **Approve all shown** to
approve the current page (up to 100 observations per request). Bulk approval
retains all candidate IDs for each row and uses its proposed Sighting type;
publication remains a separate action.
The values beside both sliders update immediately while they are moved; submit
**Filter** to apply the selected inclusive interval to the queue.

Every manual or bulk decision is also written to an append-only review history.
The observation detail page shows the decision time, authenticated reviewer,
state, selected vulnerability IDs, Sighting type, and note. The fields on the
observation remain the current-state projection used by queue queries.

The review interface has no connection or credential settings and performs no external writes. A review can select zero, one, or multiple referenced vulnerability IDs: no ID produces a new advisory, while every selected ID becomes a relationship in the local record. Approval records the decision but does not publish implicitly; the detail view then offers **Publish this approved entry locally**, while the publication dashboard handles batches. Both paths create BCP-05 records transactionally in the local store so Vulnerability-Lookup can retrieve them from the public BCP-03 endpoint.

After approval, the observation links directly to the publication action. Once
published, that action is replaced by a link to the public record at
`/vulnerability/<GCVE-ID>`. The review queue and public archive both use the
SQLite full-text index for product, identifier, author, title, and body searches.
Review results are paginated in SQL and can be sorted by observation title,
confidence, or review state; filters and sort order are retained while paging.

Authenticated operators can also open **Archive imports** in the review interface
to queue historical month ranges. These background jobs run sequentially, retain
their status and logs below `data/workers/`, and import and match observations
without publishing them. The worker detail page refreshes its live output every
two seconds. Candidate search is disabled by default for a faster explicit-ID
first pass; enable it when semantic candidate retrieval is required, and select
**Reprocess existing posts** when applying it to an already imported range. The
month fields use the browser's native calendar picker, default to the previous
month, and prevent selection of future periods.

To reduce traffic and accept only explicit identifiers during a large first pass, add `--no-semantic` before the subcommand:

```sh
fd-sightings --no-semantic archive --from-period 2025-01 --to-period 2025-12
```

## Automatic VULNARCHIVE publication

The automated path does not use analyst approval. First inspect the active policy and a non-writing plan:

```sh
fd-sightings policy
fd-sightings plan-auto --limit 20
```

Publish every eligible, not-yet-published observation:

```sh
fd-sightings publish-auto
```

Failures are recorded and are not retried implicitly. After correcting a temporary problem:

```sh
fd-sightings publish-auto --retry-failed
```

Export the publication ledger:

```sh
fd-sightings export-publications --output publications.jsonl
```

For known CVE, GCVE, or GHSA identifiers, the default policy publishes a Sighting and—when the context threshold is met—one GCVE-1988 `analysis` or `reference` record related to all resolved identifiers in the post. For an eligible post with no resolved identifier, it publishes a new `advisory`. A PoC additionally creates a `published-proof-of-concept` Sighting for the new GCVE record.

Policy thresholds are configured through environment variables:

- `VA_MIN_NEW_RECORD_SCORE` (default `5`)
- `VA_MIN_CONTEXT_RECORD_SCORE` (default `3`)
- `VA_REQUIRE_PRODUCT_FOR_NEW` (default `true`)
- `VA_PUBLISH_CONTEXT_RECORDS` and `VA_PUBLISH_SIGHTINGS` (both default `true`)
- `VA_AUTO_CREATE_YEAR_RANGE` (default `true`)
- `VA_MAX_DESCRIPTION_CHARS` (default `12000`)
- `VA_MIN_INFERRED_MATCH_CONFIDENCE` (default `0.92`)
- `VA_MIN_INFERRED_MATCH_MARGIN` (default `0.08`)

The evidence score is deterministic and records which publication rule fired. It measures whether the post contains enough structured material to publish; it does not claim that the report is correct.

The staged matching design, including optional LLM-assisted analysis and its
required safeguards, is documented in
[`documentation/AUTOMATED_MATCHING.md`](documentation/AUTOMATED_MATCHING.md).

To pilot LLM comparison safely, set `OPENAI_API_KEY`, `VA_LLM_MODEL`, and
`VA_LLM_MODE=shadow`. After evaluating retained decisions, use `review` to route
model selections to analysts. `automatic` should only be enabled after the
precision target and data-protection review described in the matching guide.

## Local publication store and public service

The collector reserves and publishes GCVE-1988 records transactionally in its canonical SQLite store. `VL_URL` is optional and only supports read-only resolution of foreign identifiers. Run the isolated public service with `fd-sightings public`; deployment routing and the private review-service boundary are documented in `DEPLOYMENT.md`.

The public service exposes the same canonical records as a bare BCP-03 JSON list at `GET /api/gcve/publication` and as compact, deterministically ordered UTF-8 NDJSON at `GET /dumps/gna-1988.ndjson`.

## Matching policy

- An explicit identifier that resolves receives confidence `1.0`.
- ID-less reports use conservative product, title, version, and CWE candidates. They require review unless the explicitly enabled automatic LLM mode and the unattended confidence/margin policy both accept one clear winner.
- Unmatched reports remain in SQLite and can be reprocessed with `--refresh` after new CVEs arrive.
- A `Published Proof of Concept` proposal requires a PoC evidence score of at least three. Exploitation in the wild is never inferred from PoC availability.

The current parser treats one mailing-list post as one finding. Before broad multi-list production, thread-aware splitting of posts containing multiple independent vulnerabilities should be added.

## Tests

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```
