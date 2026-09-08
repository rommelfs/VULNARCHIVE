# VULNARCHIVE documentation

This directory contains the product, architecture, operations, and GCVE
interoperability documentation for VULNARCHIVE.

## Start here

| Audience | Document | Purpose |
|---|---|---|
| Everyone | [Project README](../README.md) | Overview, quick start, workflows, and links |
| Product and governance | [Goals](GOALS.md) | Goals, non-goals, principles, and success criteria |
| Operators and reviewers | [Features](FEATURES.md) | Supported behavior, limitations, and maturity |
| Developers | [Architecture](ARCHITECTURE.md) | Components, data flow, persistence, and boundaries |
| Operators | [Configuration](CONFIGURATION.md) | Environment variables and safe defaults |
| Operators | [Deployment](../DEPLOYMENT.md) | Production installation and upgrade procedure |
| Operators | [Maintenance](MAINTENANCE.md) | Backups, health checks, recovery, and routine work |
| Matching owners | [Automated matching](AUTOMATED_MATCHING.md) | Candidate matching, LLM modes, evaluation gate |
| Project managers | [Implementation review](IMPLEMENTATION_REVIEW.md) | Requirement status, gaps, and delivery sequence |
| Successor maintainers | [Handover](../HANDOVER.md) | Operational acceptance checklist |
| Publishers | [Publication policy](../VULNARCHIVE_POLICY.md) | Evidence and publication rules |
| Distributors | [Software license](../LICENSE) and [notice](../NOTICE) | AGPL-3.0 terms and copyright attribution |

## Documentation conventions

- Commands are shown from the repository root unless stated otherwise.
- Production paths use `/opt/vulnarchive` for code and data and
  `/etc/vulnarchive/vulnarchive.env` for secrets and configuration.
- “Implemented” means the behavior exists in this repository and has automated
  coverage; it does not imply that a particular production host is configured.
- “Automatic” never means unaudited: matching and review events remain persisted.
- Documentation should be updated in the same commit as externally observable
  behavior.

## GCVE Best Current Practices

The BCP documents define the interoperability framework used by GCVE-compatible
participants. Project-specific decisions remain in the VULNARCHIVE publication
policy.

| BCP | Topic |
|---|---|
| [BCP-01](bcp-01.md) | Scope and terminology |
| [BCP-02](bcp-02.md) | Numbering authorities and identifiers |
| [BCP-03](bcp-03.md) | Record format |
| [BCP-04](bcp-04.md) | Publication and distribution |
| [BCP-05](bcp-05.md) | Allocation and lifecycle |
| [BCP-06](bcp-06.md) | Federation and discovery |
| [BCP-07](bcp-07.md) | Security considerations |
| [BCP-09](bcp-09.md) | References and relationships |
| [BCP-10](bcp-10.md) | Reserved |
| [BCP-12](bcp-12.md) | Reserved |

## Keeping documentation healthy

When changing the system:

1. Update the feature/status statement and configuration reference.
2. Update deployment or maintenance steps if operator action changes.
3. Add migration and rollback notes for persistent-data changes.
4. Add or update tests for documented commands and behavior.
5. Run the checks listed in the root README before committing.
