# Configuration reference

VULNARCHIVE reads process environment variables. The production systemd units
load `/etc/vulnarchive/vulnarchive.env`; the application does not automatically
load `.env` files. Start with [`config/vulnarchive.env.example`](../config/vulnarchive.env.example).

## Core paths and HTTP behavior

| Variable | Default | Purpose |
|---|---|---|
| `FD_SIGHTINGS_DB` | `data/fd-sightings.sqlite` | SQLite database path |
| `FD_USER_AGENT` | built-in identifier | Contact-bearing HTTP User-Agent; set in production |
| `VL_URL` | `https://vulnerability.circl.lu` | Read-only Vulnerability-Lookup base URL |
| `VL_API_KEY` | empty | Optional lookup API key |
| `CPE_URL` | `https://cpe.gcve.eu` | GCVE CPE OpenAPI base URL for best-effort missing-vendor enrichment; empty disables it |

The CLI flags `--db`, `--vl-url`, `--cpe-url`, `--user-agent`, `--no-semantic`, and
`--refresh` override applicable defaults.

CPE lookup runs automatically during every new or refreshed import after product
extraction and before matching. To apply it later to all stored observations that
have a product but no vendor, run:

```bash
fd-sightings enrich-cpe
```

Use `--limit N` for a bounded pilot. The command updates only the stored
extraction; it does not rewrite GCVE records that have already been published.

## Sources

| Variable | Example | Purpose |
|---|---|---|
| `VA_SOURCES` | `full-disclosure,bugtraq` | Unattended sources and historical-worker UI defaults |

Available built-ins are `full-disclosure` and `bugtraq`. Bugtraq is archive-only.
Whitespace is tolerated around comma-separated values; unknown values are an
error. A CLI command can override selection with repeated `--source` flags.

## GNA identity

| Variable | Required production value | Purpose |
|---|---|---|
| `VA_GNA_ID` | `1988` | Numeric GNA namespace |
| `VA_GNA_SHORT_NAME` | `VULNARCHIVE` | Publisher short name |
| `VA_GNA_ORG_UUID` | permanent UUID | Provider identity in records |
| `VA_PUBLIC_BASE_URL` | canonical HTTPS origin | Stable public links |

Set these once before production publication. In particular, do not rotate the
organization UUID or canonical base URL casually.

## Review service

| Variable | Recommended production value | Purpose |
|---|---|---|
| `VA_REVIEW_BIND` | private RFC1918 address | Review listener address |
| `VA_REVIEW_PREFIX` | `/review` | Reverse-proxy path prefix |
| `VA_REVIEW_USERNAME` | bootstrap admin name | Environment bootstrap login |
| `VA_REVIEW_PASSWORD` | long random secret | Environment bootstrap password |
| `VA_REVIEW_ALLOWED_NETWORKS` | narrow CIDR list | Permitted client networks |
| `VA_REVIEW_TRUSTED_PROXIES` | proxy CIDR list | Peers allowed to supply forwarding headers |

The environment account is the bootstrap/recovery account. Day-to-day reviewers
should be managed in **Review -> Users**. Store the environment file as root with
mode `0600`. An empty or weak password is not a valid production configuration.

The optional four-eyes setting is managed in the review UI and persisted in the
database. It is not enabled by default.

## LLM comparison and evaluation

| Variable | Default | Purpose |
|---|---|---|
| `VA_LLM_MODE` | `off` | `off`, `shadow`, `review`, or `automatic` |
| `VA_LLM_MODEL` | empty | Provider model identifier |
| `VA_LLM_API_URL` | OpenAI Responses endpoint | Compatible API endpoint |
| `OPENAI_API_KEY` | empty | API credential |
| `VA_MATCH_EVALUATION_REPORT` | empty | Passing report required for `automatic` |

Use `shadow` first. Keep API credentials out of Git and logs. A report is bound
to the current prompt version and configured thresholds; stale or failing reports
must block `automatic` startup.

## Publication policy

| Variable | Example/default | Purpose |
|---|---|---|
| `VA_PUBLISH_SIGHTINGS` | `true` | Permit context/sighting publication |
| `VA_PUBLISH_CONTEXT_RECORDS` | `true` | Permit contextual records for known IDs |
| `VA_MIN_NEW_RECORD_SCORE` | `5` | Minimum evidence score for a new record |
| `VA_MIN_CONTEXT_RECORD_SCORE` | `3` | Minimum context-record evidence score |
| `VA_MIN_BODY_CHARS` | `160` | Minimum usable source body length |
| `VA_REQUIRE_PRODUCT_FOR_NEW` | `true` | Require product evidence for a new record |
| `VA_MAX_DESCRIPTION_CHARS` | `12000` | Published-description bound |
| `VA_MIN_INFERRED_MATCH_CONFIDENCE` | `0.92` | Confidence required for unattended inferred link |
| `VA_MIN_INFERRED_MATCH_MARGIN` | `0.08` | Separation required from the next candidate |
| `VA_AUTO_CREATE_YEAR_RANGE` | `true` | Create missing allocation-year range |

These are publication thresholds, not proof of correctness. Show the active
policy with `fd-sightings policy` and preview with `fd-sightings plan-auto` after
every policy change.

## Configuration procedure

1. Copy the example to the production environment path.
2. Replace all host-, network-, identity-, and secret-specific placeholders.
3. Restrict permissions: `chown root:root` and `chmod 600`.
4. Validate source names and run the policy/plan commands as the service user.
5. Restart affected services; environment changes are not visible to an already
   running process.
6. Run the health checks in [Maintenance](MAINTENANCE.md).

## Secret rotation

- Rotate `OPENAI_API_KEY`, `VL_API_KEY`, and bootstrap password independently.
- Restart review/sync processes that consume the changed secret.
- Do not rotate `VA_GNA_ORG_UUID` as if it were a credential.
- Managed-user passwords are changed through the review UI; deactivation should
  be preferred immediately when access must be revoked.
