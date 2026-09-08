# Features and implementation status

This document describes repository capability, not the configuration of a
specific deployment.

## Status summary

| Requirement | Status | Notes |
|---|---|---|
| Multiple sources | Implemented foundation | Full Disclosure and archive-only Bugtraq adapters; more adapters require code and tests |
| GNA 1988 publication | Implemented | Planning, allocation, context/new records, retry, ledger, API and dump |
| CVE comparison and LLM enrichment | Implemented with safeguards | Explicit IDs, bounded retrieval, deterministic filters, optional evaluated LLM |
| Manual approval for ambiguity | Implemented | Managed users, pending queue, event history, optional four-eyes |
| Configurable website design/content | Partial | Shared inline styling and core pages exist; no CMS/theme/content-block admin UI |
| Sortable tables | Implemented for review queue | Server-side stable ordering including confidence; not every administrative table exposes all sort fields |
| Grouping and pagination everywhere | Partial | Main review/archive collections are paginated; small admin/history lists are intentionally bounded but not uniformly pageable/groupable |
| Full-text index | Implemented with fallback | SQLite FTS5 where available; `LIKE` compatibility fallback |

## Multi-source ingestion

### Implemented

- Source-adapter registry with `full-disclosure` and `bugtraq`.
- Repeatable `--source` on current-feed and archive workflows.
- `VA_SOURCES` defaults for unattended sync and historical-import UI.
- Per-source canonical keys and source metadata.
- Historical workers with bounded date ranges and persisted job state.
- Cross-source operation without collapsing the original provenance.

### Limitations

- Bugtraq is archive-only because no current RSS feed is configured.
- Source configuration selects registered adapters; adding a completely new
  source still requires code, parser tests, and operational validation.
- Historical data is not imported merely by adding a source to `VA_SOURCES`.

## Extraction and matching

### Implemented

- Extraction of vulnerability IDs, vendors, products, components, affected and
  fixed versions, commits, aliases, references, and relevance signals.
- Explicit identifier lookup before semantic candidate comparison.
- Candidate retrieval through the configured Vulnerability-Lookup instance.
- Deterministic exclusion and scoring evidence.
- Optional LLM comparison restricted to the candidate set.
- LLM modes `off`, `shadow`, `review`, and `automatic`.
- Versioned prompts and persisted analysis events.
- Offline labelled-fixture evaluation with precision/recall thresholds.
- Mandatory passing/current evaluation report for `automatic` mode.

### Limitations

- Extraction is heuristic and source text varies substantially.
- Evaluation quality is limited by the size and representativeness of labelled
  fixtures; the fixture corpus must grow before broad automatic use.
- External lookup availability and rate limits affect enrichment.
- LLM output can be wrong and must never be treated as primary evidence.

## Review and multi-user workflow

### Implemented

- HTTP Basic authentication with a bootstrap environment account.
- Managed local users with PBKDF2-SHA256 password hashes.
- Administrator and reviewer roles.
- User creation, activation/deactivation, and password management in the web UI.
- SQL-backed search, confidence ranges, sorting, and pagination.
- Explicit row selection and bounded bulk approve/reject.
- Append-only actor-attributed review events.
- Analysis history visible next to review history.
- Optional four-eyes policy requiring a distinct second reviewer.
- Reverse-proxy prefix support and trusted-proxy/network validation.

### Limitations

- Authentication is local; SSO/OIDC, MFA, account lockout, password expiry, and
  recovery workflows are not implemented.
- Fine-grained per-source or per-action permissions are not implemented.
- Bulk actions are deliberately bounded and do not mean “all query results.”

## Publication as GNA 1988

### Implemented

- Environment-driven evidence policy.
- Dry-run publication planning.
- Context records for known vulnerabilities and new GNA 1988 allocations.
- Stable organization identity and year-based allocation handling.
- Publication ledger, retry of failed operations, NDJSON export, public API, and
  public vulnerability pages.
- Startup recovery of canonical projections from published ledger entries.

### Limitations

- Operators must configure the permanent GNA identity correctly before first
  production publication; rotating it later breaks identity continuity.
- Automatic publication depends on matching, evidence policy, and external
  integration availability.
- Policy changes require explicit review, tests, and a plan-only run.

## Public website and design

### Implemented

- Read-only landing page, archive index, archive item pages, vulnerability pages,
  publication API/dump, and `security.txt`.
- Human-readable GCVE sections plus raw JSON.
- Responsive basic layout with no external front-end dependency.

### Remaining product gap

The requested design configurator is not implemented. There is no web-managed
theme, logo upload, navigation editor, reusable content blocks, imprint, FAQ, or
link collection. Those should be built as a separate content/configuration layer
rather than mixed into publication records.

## Collections, sorting, grouping, and search

- Review observations use validated query objects and SQL `LIMIT/OFFSET`.
- Sorting is stable and includes confidence, title, and review state.
- Confidence min/max filters are interactive and server-validated.
- Public archive entries are grouped by month and paginated.
- Worker history is bounded before job files are loaded.
- FTS5 provides indexed search when SQLite supports it; installations without
  FTS5 use a slower but functional `LIKE` fallback.

Uniform collection components and cursor pagination remain future improvements,
especially for growing audit histories and administrative lists.

## Operations and deployment

- Hardened systemd units for public, review, sync, and timer workloads.
- Apache public/review virtual-host examples and atomic installer.
- Upgrade lock, clean-tree check, fast-forward pull, preflight tests, SQLite
  backup, package reinstall, migration plan, restart, and readiness probes.
- Source configuration validation before downtime.

See [Maintenance](MAINTENANCE.md) for recurring tasks and failure handling.
