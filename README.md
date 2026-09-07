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
- SQLite checkpoints and idempotent re-runs
- Original source retention with SHA-256, format, and Message-ID when available
- CVE, GCVE, GHSA, CWE, and CVSS extraction
- Evidence-based `seen` versus `published-proof-of-concept` proposal
- Exact Vulnerability-Lookup resolution for explicit identifiers
- Conservative product/title candidate matching for ID-less posts
- JSON Lines review export
- Local analyst review interface with filters, detail view, approval, rejection, match override, and notes
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
export VL_URL='https://vuln.freearchive.org'
```

GCVE-1988 reservations and publications always use the canonical local SQLite store. A complete policy template is provided in `config/vulnarchive.env.example`.

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
rejection, and review notes.

The review interface has no connection or credential settings and performs no external writes. A review can select zero, one, or multiple referenced vulnerability IDs: no ID produces a new advisory, while every selected ID becomes a relationship in the local record. Approval records the decision but does not publish implicitly; the detail view then offers **Publish this approved entry locally**, while the publication dashboard handles batches. Both paths create BCP-05 records transactionally in the local store so Vulnerability-Lookup can retrieve them from the public BCP-03 endpoint.

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

## Local publication store and public service

The collector reserves and publishes GCVE-1988 records transactionally in its canonical SQLite store. `VL_URL` is optional and only supports read-only resolution of foreign identifiers. Run the isolated public service with `fd-sightings public`; deployment routing and the private review-service boundary are documented in `DEPLOYMENT.md`.

The public service exposes the same canonical records as a bare BCP-03 JSON list at `GET /api/gcve/publication` and as compact, deterministically ordered UTF-8 NDJSON at `GET /dumps/gna-1988.ndjson`.

## Matching policy

- An explicit identifier that resolves receives confidence `1.0`.
- ID-less reports use a deliberately conservative product and title overlap candidate. These matches never submit automatically.
- Unmatched reports remain in SQLite and can be reprocessed with `--refresh` after new CVEs arrive.
- A `Published Proof of Concept` proposal requires a PoC evidence score of at least three. Exploitation in the wild is never inferred from PoC availability.

The current parser treats one mailing-list post as one finding. Before broad multi-list production, thread-aware splitting of posts containing multiple independent vulnerabilities should be added.

## Tests

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```
