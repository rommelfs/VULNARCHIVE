# Architecture

## System context

VULNARCHIVE sits between mailing-list archives, Vulnerability-Lookup, optional
LLM infrastructure, analysts, and GCVE consumers.

```text
Full Disclosure / Bugtraq
           |
     source adapters
           |
   parser + extraction ---------> immutable source evidence
           |
 candidate lookup <------------> Vulnerability-Lookup
           |
 deterministic checks ---- optional bounded LLM comparison
           |                         |
           +------ analysis events --+
                         |
                       SQLite
                    /     |      \
             review UI  publisher  public UI/API
```

## Components

### Source adapters

`sources.py` owns registered source identity, current feed discovery, historical
month discovery, and source-specific parsing. The shared CLI and pipeline operate
on the adapter protocol rather than hard-coded source URLs.

### Parsing and extraction

Parsers retain message metadata and body text. Extraction converts unstructured
text into structured facts and signals. The extracted representation is derived
data: reprocessing may change it without changing the original source evidence.

### Candidate matching

`vulnerability_lookup.py` resolves explicit identifiers and retrieves a bounded
candidate set. Deterministic checks exclude contradictions and score supporting
evidence. The optional LLM sees the observation and those candidates only.

Every meaningful analysis run is recorded with method, inputs/results, model or
provider metadata, prompt version, and output/error details as applicable.

### Store

SQLite is the local system of record. Startup applies idempotent schema evolution
and compatibility repairs. Principal entities include:

- observations and extracted facts;
- sources and source-aware canonical keys;
- candidate matches and confidence evidence;
- append-only analysis events;
- append-only review events and their current-state projection;
- review users and settings;
- GCVE allocations, canonical records, and publication ledger entries.

FTS5 is used when available. Stable SQL ordering plus `LIMIT/OFFSET` prevents the
main collections from materializing the full archive in application memory.

### Review service

The review service is a private, state-changing HTTP process. It authenticates a
bootstrap environment account and managed database users. It validates trusted
proxy/network information, applies roles, writes review events, manages archive
workers, and can enforce an optional distinct-second-reviewer rule.

### Publisher

The publisher evaluates approved observations against publication policy,
resolves known identities, reserves GNA 1988 IDs where needed, writes canonical
records, and appends outcome information to the publication ledger. Planning and
publishing are separate commands.

### Public service

The public service is read-only from an HTTP perspective. It renders archive and
vulnerability pages and serves machine-readable publication output. It must not
expose review actions or credentials.

### Historical workers

Archive imports run as subprocess workers launched by the review service. Their
date ranges and source selections are validated and persisted. Historical
workers import and analyse; they do not implicitly publish.

## Identity and deduplication

The source ID and a source-local canonical key identify an imported message.
Message ID is preferred when available, with URL-based fallback. Content hashes
support stable archive-item URLs and duplicate-content detection, but content
similarity does not erase distinct source provenance.

GCVE identity is independent of observation identity. One observation may link
to an existing CVE, create contextual evidence, or support a new GNA allocation.

## Decision model

1. Import and preserve source evidence.
2. Extract structured facts.
3. Resolve explicit IDs and retrieve bounded candidates.
4. Apply deterministic exclusion/scoring.
5. Optionally ask the LLM to compare existing candidates.
6. Record analysis events.
7. Project a confidence and proposed action.
8. Route uncertain/policy-sensitive cases to review.
9. Record reviewer events; optionally require a distinct second reviewer.
10. Plan publication, then publish eligible records and record outcomes.

## Security boundaries

- **Untrusted:** source HTML/text, external API responses, LLM output, browser
  input, forwarding headers from non-trusted addresses.
- **Private:** review service, user administration, worker controls, database,
  environment secrets.
- **Public:** read-only web service, GCVE pages, archive pages, dump/API,
  `security.txt`.
- **Privileged:** installation and upgrade scripts, systemd/Apache configuration,
  database restore.

The reverse proxy terminates TLS and restricts `/review/`. The review backend
must also enforce authentication and allowed networks; proxy policy alone is not
the only control.

## Availability and scaling

The current architecture targets one host and one SQLite database. WAL mode
supports concurrent readers and a writer, but it is not a multi-node HA design.
Scale is achieved through indexed queries, bounded pages, worker limits, and
separate HTTP processes. If write concurrency or dataset size exceeds SQLite's
operational envelope, a database migration should preserve existing query/event
contracts rather than bypass them.

## Extension points

- Add a source by implementing and registering an adapter plus contract fixtures.
- Add extraction fields in the model, extractor, persistence, audit payload, and
  tests together.
- Change matching by adding labelled evaluation cases before raising automation.
- Add public content/design through a separate site-content model and renderer.
- Extend collections through the validated query contract and stable server-side
  pagination rather than custom in-memory filtering.
