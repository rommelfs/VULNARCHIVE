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

The OpenAI Responses API integration is implemented and disabled by default.
Configure `OPENAI_API_KEY` and `VA_LLM_MODEL`, then select one mode:

* `off`: no model request;
* `shadow`: retain the model decision and audit evidence without changing the
  deterministic candidate ranking;
* `review`: let the model select from the bounded candidates, but cap its score
  below the unattended threshold so an analyst must decide;
* `automatic`: allow the selected candidate to pass through the same confidence
  and runner-up gate as deterministic matches. Any reported contradiction caps
  confidence below the default unattended threshold.

`automatic` is also startup-gated by a machine-readable evaluation report. The
report must pass the configured precision/recall thresholds and match the current
prompt version. Generate it with:

```bash
fd-sightings evaluate tests/fixtures/matching \
  --output data/matching-evaluation.json
```

Then set `VA_MATCH_EVALUATION_REPORT` to that protected file. A missing, stale,
or failing report prevents automatic mode rather than silently downgrading the
assurance requirement.

Every request uses `store: false` and a strict JSON schema. Only up to ten
Vulnerability-Lookup candidates are sent. API errors or invalid model output
degrade to the deterministic result and do not fail the mailing-list import.

LLM comparison requires candidates. Configure `VL_URL` to a complete
Vulnerability-Lookup deployment that supports product search; the restricted
VULNARCHIVE public endpoint cannot be used as its own candidate source.

Import summaries distinguish observations from candidate matches: `matched` is
the number of observations with at least one candidate, while `match_candidates`
and `match_methods` count individual candidates. Consequently, the method counts
can legitimately add up to more than `matched`.

The LLM counters are observation-based rather than candidate-based:
`llm_evaluated` counts attempted comparisons, `llm_succeeded` counts completed
comparisons, and `llm_errors` counts observations whose comparison failed.
`llm_error_types` groups the exception classes. An LLM failure degrades to the
deterministic candidates, so it does not increment the top-level import
`failed` counter. For example, `llm_evaluated: 10`, `llm_succeeded: 0`, and
`llm_errors: 10` means all ten attempted comparisons failed but import continued.

## Implemented decision pipeline

The current pipeline now applies the following unattended-publication rules:

1. Resolve identifiers explicitly present in the post. All resolved explicit
   identifiers are eligible references and use the BCP-05 `related` type.
2. If no explicit identifier resolves, query Vulnerability-Lookup by the static
   product hint and score title, product, CWE, and version evidence. A conflicting
   CWE is retained as an explicit contradiction and caps the candidate below the
   default unattended-publication threshold.
3. Retain every inferred result, its supporting evidence, and contradictions as
   a review candidate.
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

## Remaining improvement plan

1. **Expand and stratify the labelled evaluation set.** The evaluation runner and
   initial fixtures exist. Add matched, unmatched, contradictory, and ambiguous
   examples from both sources and multiple eras; preserve a holdout split and
   measure false references first.
2. **Measure extraction quality.** Vendor, product, component, aliases, affected
   and fixed versions, commits, and advisory fields are represented. Add field-
   level fixtures and metrics rather than expanding the schema without evidence.
3. **Broaden candidate retrieval carefully.** Query using aliases and extracted
   terms, bound the number of results, cache responses, and record the API
   endpoint and retrieval time.
4. **Extend contradiction coverage.** Product/component/version/class exclusions
   exist; add chronology, rename/fork, and vendor-transfer fixtures.
5. **Pilot the implemented LLM modes.** Keep production in `shadow` until the
   holdout precision target, privacy, cost, timeout, and fallback behavior have
   been approved. Use `review` before `automatic`.
6. **Detect drift.** Bind reports to retrieval snapshots or candidate hashes,
   expire automatic approval after material matcher/provider changes, and show
   per-source/per-era metrics.
7. **Monitor and correct.** Track match method, evidence, reviewer overrides,
   false-reference rate, API/model failures, latency, and cost. Corrections must
   preserve the original decision trail rather than silently rewriting it.

## Safe rollout

Run `fd-sightings plan-auto` against a copy of production data and inspect every
inferred target before enabling unattended publication. Keep the analyst review
interface as the fallback for ambiguous candidates. API or model failure must
degrade to static analysis and review/archive-only processing; it must never
turn uncertainty into a positive match.
