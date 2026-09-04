# VULNARCHIVE

VULNARCHIVE (GCVE GNA 1988) imports public security mailing-list messages, beginning with Full Disclosure, preserves the source, resolves known identifiers, publishes Sightings, and allocates GCVE-1988 records for independent context or previously unidentified vulnerabilities. The `fd-sightings` command name is retained for compatibility with the pilot.

An automatic publication is an assertion by GNA 1988. It is not a validation, consensus statement, or instruction for consumers to trust the source.

The normative local behavior is documented in `VULNARCHIVE_POLICY.md`.
Production service and reverse-proxy templates are documented in `DEPLOYMENT.md`.
Project status, architectural decisions, and continuation instructions are documented in `HANDOVER.md`.

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

Set a meaningful user agent. Add an API key for the authenticated rate-limit and for submissions:

```sh
export FD_USER_AGENT='VULNARCHIVE/0.2 (security-team@example.org)'
export VL_URL='https://vuln.freearchive.org'
export VL_API_KEY='...'
```

For production use `VL_URL=https://vuln.freearchive.org`. A complete policy template is provided in `config/vulnarchive.env.example`.

## Pilot

Process one known message:

```sh
fd-sightings url https://seclists.org/fulldisclosure/2026/Sep/27
```

Process a small historical sample:

```sh
fd-sightings archive --from-period 2026-08 --to-period 2026-09 --limit 10
```

Process the current feed. Repeated runs skip URLs already stored:

```sh
fd-sightings rss
```

For the continuous Phase-2 operation, import the current feed and immediately apply the automatic publication policy in one idempotent run:

```sh
fd-sightings sync
```

This command requires `VL_API_KEY`. It is suitable for a periodic service or scheduler; already completed publications are skipped.

Export the review queues:

```sh
fd-sightings export --status matched --output matched.jsonl
fd-sightings export --status unmatched --output unmatched.jsonl
```

Start the local review interface:

```sh
fd-sightings review
```

Then open `http://127.0.0.1:8765`. The interface binds only to localhost by default. It supports queue filters, the original Full Disclosure body, extracted evidence, candidate selection, manual vulnerability-ID overrides, review notes, approval, rejection, and resetting a decision.

The connection panel reports whether the configured Vulnerability-Lookup instance is unreachable, connected read-only, or authenticated. `Test connection` refreshes the check against `/.well-known/api-policy.json` and `/api/user/me`.

The API key can be supplied from the process environment or entered under `Connection settings`. It is never written to SQLite or browser storage; a key entered in the UI exists only in the server process and is lost when it stops. To start with an environment-provided key:

```sh
export VL_URL='https://vuln.freearchive.org'
export VL_API_KEY='your-personal-api-key'
fd-sightings review
```

Approving an observation validates the selected vulnerability ID against the configured live instance. Once approved, its detail page offers `Publish approved Sighting`. This is an immediate single-Sighting operation and records successful or duplicate responses in the local submission ledger.

To reduce traffic and accept only explicit identifiers during a large first pass, add `--no-semantic` before the subcommand:

```sh
fd-sightings --no-semantic archive --from-period 2025-01 --to-period 2025-12
```

## Submission

Submission is deliberately one reviewed source/ID pair at a time. Without `--write`, the command prints the proposed request:

```sh
fd-sightings submit \
  --source-url https://seclists.org/fulldisclosure/2026/Sep/27 \
  --vulnerability-id CVE-2026-77939
```

After review:

```sh
fd-sightings submit \
  --source-url https://seclists.org/fulldisclosure/2026/Sep/27 \
  --vulnerability-id CVE-2026-77939 \
  --write
```

To inspect all UI-approved observations without sending anything:

```sh
fd-sightings submit-approved
```

To submit the approved queue:

```sh
fd-sightings submit-approved --write
```

Use `--limit N` for controlled production batches. Successfully submitted source/ID/type combinations are recorded locally and excluded from later approved batches. Duplicate responses from the server are also recorded as completed.

The API key is sent only to the configured Vulnerability-Lookup host. HTTP 409 is recorded as an idempotent duplicate result. The UI refuses publication unless `/api/user/me` confirms the key first.

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

The evidence score is deterministic and records which publication rule fired. It measures whether the post contains enough structured material to publish; it does not claim that the report is correct.

## Vulnerability-Lookup node

The target instance should use the settings in `config/vulnerability-lookup.generic.json.example`, especially:

```json
{
  "local_instance_name": "gna-1988",
  "local_instance_vulnid_pattern": "^GCVE-1988-[0-9]{4}-[0-9]{4,19}$",
  "local_instance_vulnid_example": "GCVE-1988-yyyy-nnnn"
}
```

With a current Vulnerability-Lookup release this makes local records available through the BCP-03 endpoint `/api/gcve/publication`. The GNA directory's `gcve_pull_api` should point to `https://vuln.freearchive.org`.

### Publication timestamps and ordering

The local publication ledger keeps three independent UTC timestamps: `reserved_at`
for local GCVE-ID allocation, `published_at` for the first successful public
publication, and `updated_at` for the most recent content change. They are serialized
as ISO-8601 values ending in `Z`. A historical source date never initializes
`published_at`; it remains provenance in `x_vulnarchive.sourcePublishedAt`.

Publication queries accept `date_sort=published`, `date_sort=updated`, and
`date_sort=reserved`. An omitted or empty `date_sort` defaults to `updated`. Ordering
is newest first, with the GCVE ID ascending as a stable tie-breaker. The incremental
filter is strict and means `published_at > since OR updated_at > since`; a record
exactly at the boundary is therefore excluded. Input timestamps must be ISO-8601 and
include a timezone.

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
