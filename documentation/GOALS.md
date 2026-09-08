# Goals, principles, and scope

## Mission

VULNARCHIVE turns difficult-to-search historic security mailing-list evidence
into a durable, reviewable, and interoperable vulnerability archive. It helps
analysts connect primary disclosures to existing CVEs and allows GNA 1988 to
publish qualified records without hiding uncertainty or provenance.

## Product goals

1. **Preserve evidence.** Keep source identity, canonical keys, message IDs,
   URLs, hashes, dates, and raw content alongside derived data.
2. **Support multiple sources.** Sources are adapters selected independently;
   source-specific assumptions do not leak into the common pipeline.
3. **Enrich, do not rewrite history.** Extraction and matching add structured
   context while retaining the original evidence.
4. **Prefer known identities.** Explicit and high-confidence links to existing
   CVEs take priority over allocating a new record.
5. **Escalate ambiguity.** Unclear identity, weak evidence, or policy failure is
   routed to a reviewer rather than silently published.
6. **Make automation measurable.** Automatic matching is enabled only after a
   versioned evaluation meets explicit precision and recall gates.
7. **Make decisions attributable.** Analysis and review actions are append-only,
   actor-attributed events; the current state is a projection of that history.
8. **Publish interoperable output.** GNA 1988 output follows the repository BCPs
   and remains available through stable human and machine interfaces.
9. **Scale collections safely.** Search, sorting, grouping, and pagination happen
   server-side and use stable ordering.
10. **Remain operable by a small team.** Installation, backup, upgrade, recovery,
    and handover procedures must be explicit and reproducible.

## Design principles

### Provenance before convenience

Derived fields may be corrected or reprocessed. Original source evidence must
remain traceable. Deduplication is performed with source-aware canonical keys;
cross-source similarity alone must not erase provenance.

### Deterministic controls around probabilistic tools

LLM output is advisory evidence inside a bounded candidate set. Deterministic
exclusions, confidence/margin thresholds, evaluation gates, publication policy,
and optional human approval control the final action.

### Safe defaults

- LLM mode defaults to `off`.
- Review binds to loopback unless explicitly changed.
- Historical workers do not publish.
- New source enablement does not imply automatic historical backfill.
- The optional four-eyes policy is off unless an administrator enables it.
- Upgrade failures stop before destructive migration whenever possible.

### Separation of concerns

Import, review, publication, and public serving are separate workflows. The
public service is read-only. Publication is not an implicit side effect of
opening or approving a review page.

## Non-goals

- Crawling the entire web for vulnerability information.
- Treating an LLM as an authoritative source or autonomous identifier allocator.
- Replacing source archives, CVE authorities, or Vulnerability-Lookup.
- Guaranteeing that every historic message describes a vulnerability.
- Automatically merging records across sources solely because text is similar.
- Providing a general-purpose identity provider or enterprise authorization
  platform; managed local review users are deliberately scoped to this service.
- Offering high-availability database replication in the current SQLite-based
  architecture.

## Success criteria

- Every published record can be traced to source evidence and decision history.
- Known-CVE assignment precision meets the configured evaluation gate before
  automatic matching is enabled.
- Ambiguous cases stay pending and are visible to reviewers.
- Collection response time grows with page size, not total archive size.
- A new source can be added through an adapter and contract tests without
  rewriting the shared pipeline.
- An operator can install, upgrade, back up, restore, and validate the service
  using repository documentation alone.

## Governance decisions still required

- Define retention periods for raw source content, worker logs, and audit events.
- Define production recovery-time and recovery-point objectives.
- Define the authority and process for changing evaluation thresholds and
  publication policy.
- Decide whether external identity-provider integration is required beyond local
  managed accounts.

## Licensing

The VULNARCHIVE software is released under the GNU Affero General Public License
v3.0. The separately licensed GCVE BCP documents retain their stated Creative
Commons Attribution 4.0 terms. See the repository `LICENSE` and `NOTICE` files.
