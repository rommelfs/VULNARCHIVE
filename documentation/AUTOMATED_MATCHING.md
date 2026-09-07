# Automated mailing-list analysis and vulnerability matching

## Goal

For every relevant mailing-list post, VULNARCHIVE should preserve the source,
extract the available vulnerability facts, compare them with existing records,
and publish either:

1. a new GCVE-1988 advisory when no reliable existing record is found; or
2. a contextual GCVE-1988 record and Sighting referencing an existing CVE,
   GCVE, or GHSA identifier when the relationship is sufficiently supported.

The process must remain reproducible and auditable. A model score is evidence
for a decision, not proof that two vulnerabilities are identical.

## Available approaches

### 1. Deterministic static analysis

Static analysis is the safest first stage and works without external services.
It can extract explicit identifiers, vendor and product names, affected
versions, CWE and CVSS values, vulnerability classes, fixed versions, URLs,
PoC markers, and source dates. Explicit identifiers are the strongest signal:
when an identifier exists in Vulnerability-Lookup, it can be referenced without
semantic inference.

Advantages are low cost, reproducibility, explainability, and easy regression
testing. Its limitation is lower recall for prose, aliases, spelling variants,
and posts that omit identifiers.

### 2. Vulnerability-Lookup candidate retrieval

The extracted product and text can be used to retrieve a bounded candidate set
from the read-only Vulnerability-Lookup API. Candidate scoring can compare:

- vendor/product identity and aliases;
- affected and fixed version ranges;
- vulnerability class or CWE;
- title and description similarity;
- advisory URLs, commits, and publication dates;
- platform, component, and attack prerequisites.

Retrieval and decision-making should remain separate. An API search hit is only
a candidate and must not automatically become a relationship.

### 3. Optional LLM-assisted comparison

An LLM can normalize unstructured prose into a strict schema and compare the
post with the already retrieved candidates. It is most useful for explaining
which facts agree, conflict, or are missing. The model should return structured
JSON containing the selected candidate (or `no_match`), supporting facts,
contradictions, missing information, and a confidence value.

The LLM must not search an unbounded identifier space, allocate an identifier,
or publish directly. Its output must pass deterministic schema validation and
the same final policy gate as all other inferred evidence. Prompts, model and
version, input hashes, candidate IDs, raw structured output, and policy version
must be retained for audit. Mailing-list content is untrusted prompt input and
must be delimited; instructions contained in a post must never be treated as
system instructions. Before using a hosted model, deployment owners must also
approve data-protection, retention, and confidentiality implications.

## Implemented decision pipeline

The current pipeline now applies the following unattended-publication rules:

1. Resolve identifiers explicitly present in the post. All resolved explicit
   identifiers are eligible references and use the BCP-05 `related` type.
2. If no explicit identifier resolves, query Vulnerability-Lookup by the static
   product hint and score title overlap.
3. Retain every inferred result as a review candidate.
4. Accept an inferred reference only if the best supported candidate reaches
   `VA_MIN_INFERRED_MATCH_CONFIDENCE` (default `0.92`) and leads the runner-up by
   at least `VA_MIN_INFERRED_MATCH_MARGIN` (default `0.08`).
5. Publish an accepted inferred reference as `possibly_related`, never as
   equivalence. If the gate rejects every candidate, mark the post as requiring
   review. Do not create a potentially duplicate advisory merely because the
   candidate comparison is ambiguous.

An analyst-approved selection bypasses the unattended confidence gate and is
recorded as such; it is not misrepresented as a model or static-parser result.

The two thresholds are intentionally independent from the publication evidence
score: one answers “is there enough useful material for a record?”, while the
other answers “is this candidate unambiguous enough to reference?”. Operators
should begin with dry runs and tune thresholds against a labelled corpus rather
than lowering them to increase match volume.

## Recommended next increments

1. **Build a labelled evaluation set.** Sample matched and unmatched historic
   posts; have two reviewers label exact match, related, and no match. Measure
   precision first, especially false references.
2. **Improve structured extraction.** Add vendor, product, component, affected
   versions, fixed versions, vulnerability class, and commit/advisory fields to
   the stored extraction schema.
3. **Broaden candidate retrieval.** Query using aliases and multiple extracted
   terms, bound the number of results, cache responses, and record the API
   endpoint and retrieval time.
4. **Add contradiction-aware scoring.** Reject candidates with incompatible
   product, component, version, vulnerability class, or chronology even when
   their titles look similar.
5. **Pilot an LLM behind a feature flag.** Run it only on the bounded candidate
   set, require schema-valid output, store the audit material, and keep it in
   shadow mode until the labelled-set precision target is met.
6. **Introduce explicit operating modes.** Use `off`, `shadow`, `review`, and
   `automatic`; production should move to `automatic` only after threshold,
   privacy, cost, timeout, and fallback behaviour have been approved.
7. **Monitor and correct.** Track match method, evidence, reviewer overrides,
   false-reference rate, API/model failures, latency, and cost. Corrections must
   preserve the original decision trail rather than silently rewriting it.

## Safe rollout

Run `fd-sightings plan-auto` against a copy of production data and inspect every
inferred target before enabling unattended publication. Keep the analyst review
interface as the fallback for ambiguous candidates. API or model failure must
degrade to static analysis and review/archive-only processing; it must never
turn uncertainty into a positive match.
