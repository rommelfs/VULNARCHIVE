# Implementation review and completion plan

**Reviewed:** 2026-09-08
**Scope:** the eight requested end-product capabilities plus operational quality
**Meaning of status:** repository implementation, not production-host state

## Executive summary

The core ingestion, provenance, matching, review, audit, and GNA 1988 publication pipeline is implemented. The largest remaining product gap is a configurable website/content system. Collection behavior is scalable for the primary review and archive pages, but pagination and grouping are not yet uniform across every audit and administration view. Matching evaluation exists, but its labelled corpus must expand before broad automatic use.

| # | Requirement | Status | Main remaining work |
|---:|---|---|---|
| 1 | Multiple sources | Foundation complete | Adapter onboarding contract, more real sources, source health UI |
| 2 | Automatic GNA 1988 publication | Complete with policy controls | Production acceptance, monitoring, failure drills |
| 3 | Compare/enrich/link known CVEs, including LLM | Complete with safeguards | Larger labelled corpus, drift reports, operator metrics |
| 4 | Manual approval when ambiguous | Complete | SSO/MFA only if required; improve assignment/queues |
| 5 | Website design/content options | Partial | Theme/content model, logo, pages, navigation, admin editor |
| 6 | Sort tables by fields such as confidence | Main queue complete | Shared sortable collection component for remaining lists |
| 7 | Grouping and pagination everywhere | Partial | Audit/admin pagination, cursor strategy where needed |
| 8 | Full-text index | Complete with fallback | FTS health/rebuild tooling and relevance tuning |

## 1. Multiple sources

### Implemented

- A source-adapter registry isolates source identity, feed/month discovery, and parsing.
- Full Disclosure and Bugtraq are registered.
- Source selection is repeatable on the CLI and configurable through `VA_SOURCES`.
- Source ID and canonical key are persisted; deduplication is source-aware.
- Historical workers accept source selections and date ranges.

### Gap and completion work

Bugtraq is archive-only, and enabling it does not backfill history. There is no web page showing source health, last successful import, coverage, or parser error rate.

1. Formalize adapter contract tests with feed/month/message fixtures.
2. Add source status: capability, last run/success, counts, and latest message date.
3. Expose source status and safe default selection to administrators.
4. Add parser-change regression fixtures per source.

## 2. Automatic GNA 1988 publication

### Implemented

- Environment-driven publication policy and a plan-only command.
- Known-ID context records and new GNA 1988 allocations.
- Stable provider identity, year allocation, retry, canonical records, publication ledger, public API, dump, and vulnerability pages.
- Startup recovery of missing canonical projections from published ledger rows.

### Gap and completion work

Repository functionality cannot prove production authority, permanent identity, external availability, backup quality, or operational response.

1. Run a controlled production acceptance record end to end.
2. Alert on failed publication, stalled timer, allocation exhaustion, and public canonical-route failure.
3. Rehearse ledger reconciliation and pre-publication database restore.
4. Require reviewed policy/evaluation artifacts for automation changes.

## 3. Known-CVE comparison and enrichment

### Implemented

- Explicit identifier resolution, structured extraction, bounded candidate retrieval, deterministic contradictions, and confidence evidence.
- Optional LLM candidate comparison in `off`, `shadow`, `review`, and `automatic` modes.
- Versioned prompts and persisted analysis events including provider/output.
- Offline labelled-fixture evaluation with precision and recall gates.
- Automatic mode refuses to start without a passing current evaluation report.

### Gap and completion work

The initial fixture corpus is too small to represent decades of source formats, languages, vendor naming, forks, version syntax, and duplicate advisories. External lookup changes can cause retrieval drift.

1. Build stratified positive, negative, ambiguous, and no-candidate fixtures.
2. Split development and holdout fixtures; report per-source/per-era metrics.
3. Record retrieval snapshots or candidate-set hashes for reproducibility.
4. Add periodic drift reporting and automatic-mode revalidation.
5. Export reviewed analyst feedback without contaminating the holdout set.

## 4. Manual approval and multi-user review

### Implemented

- Pending/approved/rejected workflow with actor-attributed append-only events.
- Managed users, administrator/reviewer roles, PBKDF2 password storage, and activation controls in the web UI.
- Search, live confidence-range sliders, sorting, pagination, and bounded explicit-selection bulk actions.
- Optional four-eyes policy requiring a distinct second reviewer.
- Analysis and review history shown for each observation.

### Gap and completion work

Local authentication lacks SSO, MFA, account lockout/recovery, and granular permissions. There is no ownership/assignment or reviewer workload view.

1. Add optional assignment, saved queues, and “needs second review” filtering.
2. Add account controls or integrate an identity provider if required.
3. Add administrator audit views and paginated event export.
4. Add concurrency/version checks for simultaneous decisions.

## 5. Website design and managed content

### Implemented

The public service has a responsive baseline style, landing/archive/item/vulnerability pages, human-readable record sections, raw JSON, API/dump, and security contact route.

### Gap and completion design

There is no design configurator or content management system. Operators cannot manage a logo, colors, text blocks, imprint, FAQ, navigation, or curated links through the UI.

1. Add `site_settings`: title, description, logo reference, color tokens, footer.
2. Add `content_pages`: slug, title, ordered safe blocks, draft/published state, revision, actor, timestamps.
3. Add ordered navigation items and visibility.
4. Build an admin editor with preview, validation, audit events, and rollback.
5. Use a strict rendering allowlist; prohibit arbitrary script/style injection.
6. Define file policy for logo/assets, size/type checks, and caching.
7. Seed Home, About, FAQ, Imprint, and Links pages.

## 6. Sortable tables

The principal review table uses allowlisted sort keys, stable SQL ordering, and confidence/title/review sorting. Worker, administrative, and event lists do not all share this behavior. Introduce a reusable collection contract defining sort fields, direction, tie-breaker, filter serialization, and accessible sort state, then migrate growing lists one by one.

## 7. Grouping and pagination

Review observations are SQL paginated, public archive pages are grouped by month and paginated, and worker history is bounded before loading files. Audit histories and small administration lists are not uniformly pageable/groupable; offset pagination may become costly on deep pages.

1. Inventory every collection and define expected maximum size.
2. Add shared list metadata: items, total, page/cursor, filters, and sort.
3. Add audit/admin pagination before those tables become large.
4. Evaluate keyset pagination for archive and event streams.
5. Group only where it serves users: source, month, state, or actor.

## 8. Full-text index

SQLite FTS5-backed search is used when available, with a compatible `LIKE` fallback. Operators still need explicit FTS status, rebuild, drift, and performance tools.

1. Add a search-status and guarded rebuild/check command.
2. Report whether production uses FTS5 or fallback.
3. Test rebuild with representative database volume.
4. Add relevance fixtures for identifiers, vendors, products, and phrases.

## Cross-cutting gaps

- **Governance:** decide retention, RPO/RTO, and automation-policy ownership; the software license is AGPL-3.0.
- **Security:** prioritize login hardening/SSO from the threat model, CSRF protection, and dependency/environment scanning.
- **Observability:** measure source runs, extraction errors, candidate counts, review latency, second-review backlog, publication outcomes, worker duration, database size, and response latency.

## Conflict-minimizing delivery plan

### Phase A — production acceptance and observability

Add source/publication/matching health projections and alerts; run backup/restore and controlled-publication acceptance; expand evaluation fixtures without changing matcher behavior. Prefer new health/metrics modules over rewrites of the store or UI.

### Phase B — public content and design subsystem

Add an isolated content/settings schema and API, a safe renderer and defaults, then an administrator editor and preview. Keep site content separate from observations and GCVE records. Split schema/store, public rendering, and admin UI into separate commits.

### Phase C — collection consistency

Inventory and migrate event/admin/worker lists to a shared query contract. Add keyset pagination only after measurement. Add FTS status/rebuild tooling and relevance tests.

### Phase D — identity and workflow hardening

Add assignments and second-review queues; decide local-auth hardening versus SSO/MFA; add optimistic concurrency for review decisions.

### Phase E — end-to-end release gate

Test multi-source fixture import through extraction, retrieval, review, plan, publication, and canonical public URL. Verify audit completeness, accessibility, security, backup/restore, performance, and operator documentation.

## Definition of done

- Two sources demonstrably import with source health and provenance.
- GNA 1988 plan/publish/retry/canonical URL succeeds in production acceptance.
- Known-CVE matching meets a representative held-out gate and remains auditable.
- Ambiguity is reviewable by named users; optional four-eyes works end to end.
- Administrators can safely manage branding, navigation, and core content pages.
- Every growing table has appropriate stable sorting and bounded navigation.
- Meaningful collections support pagination/grouping appropriate to their use.
- FTS status, indexed search, fallback, and rebuild are operationally verified.
- Install, upgrade, backup, restore, monitoring, and handover are rehearsed.
