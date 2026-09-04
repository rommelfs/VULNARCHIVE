# VULNARCHIVE GNA 1988 publication policy

Version: 1

## Scope

VULNARCHIVE archives public vulnerability-related mailing-list posts and publishes machine-readable observations and records derived from them. Full Disclosure is the first supported source.

VULNARCHIVE may issue `GCVE-1988-<publication-year>-<serial>` records for:

1. previously unidentified vulnerabilities described by an archived source; and
2. independent analysis, references, or context concerning an existing vulnerability identifier.

Routine mentions of an existing identifier may be represented only as Sightings. A single source may produce multiple Sightings and one contextual GCVE record related to multiple existing identifiers.

## Assertion and trust model

A publication is an assertion made by GNA 1988. It does not mean that VULNARCHIVE, GCVE, CIRCL, the affected vendor, or any third party has validated or endorsed the underlying report. Consumers decide independently whether to trust the GNA, the original source, or an individual assertion.

Automated publication is permitted. The deterministic evidence score controls whether enough material is present to produce a useful record; it is not a confidence, correctness, or severity score.

## Identifier year

The year component is the year in which the source mailing-list post was published. Historical backfills retain the original publication year rather than the ingestion or GCVE allocation year.

## Existing identifiers and relationships

Resolved CVE, GCVE, GHSA, or other supported identifiers are preserved. Contextual VULNARCHIVE records use explicit BCP-05 relationships. `related` is the default. Equivalence is not asserted automatically.

## Sightings

- `seen` means the archived source mentions or discusses the vulnerability.
- `published-proof-of-concept` means the source contains or links to publicly available reproduction or exploit material.
- PoC publication does not imply exploitation in the wild.

Sightings may be emitted for an existing identifier and for a newly published GCVE-1988 record.

## Source preservation and provenance

The collector stores the retrieved source representation, source URL, format, publication date, author, Message-ID when available, extracted text, links, and SHA-256 digest. Derived GCVE records include the source URL and digest in the `x_vulnarchive` namespace.

## Configuration

Minimum body length, evidence thresholds, product requirements, context-record creation, Sighting creation, maximum description length, and automatic year-range creation are deployment configuration. The active values are exposed by the `fd-sightings policy` command and the local publication dashboard.

## Removal

VULNARCHIVE may remove a record or Sighting when operationally necessary. This policy does not define a dispute-resolution workflow.
