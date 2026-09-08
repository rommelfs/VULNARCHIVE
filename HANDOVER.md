# Operational handover

This checklist transfers responsibility for a VULNARCHIVE installation. Complete
it with the outgoing and incoming maintainers; do not store secrets in this file.

## System identity

- [ ] Production hostname, private review address, and canonical public URL known
- [ ] Current Git commit/tag and deployment date recorded
- [ ] GNA 1988 organization UUID and ownership confirmed
- [ ] Service account, repository, data, and environment paths confirmed
- [ ] DNS, TLS certificate renewal, and Apache ownership assigned

## Access

- [ ] At least two named active administrators exist
- [ ] Reviewer membership and departed-user deactivation reviewed
- [ ] Bootstrap environment credential transferred through a secure channel
- [ ] Host, backup, monitoring, and external-provider access transferred
- [ ] Allowed client networks and trusted proxy networks documented

## Data and sources

- [ ] Enabled `VA_SOURCES` recorded; archive-only Bugtraq behavior understood
- [ ] Latest successful Full Disclosure sync and historical worker state checked
- [ ] Database size, integrity, FTS capability, and free disk space checked
- [ ] Backup schedule, encryption, retention, off-host copy, and last restore test recorded
- [ ] Raw evidence and audit-event retention policy identified

## Matching and publication

- [ ] Current LLM mode, model, prompt version, and API owner recorded
- [ ] Current matching evaluation report and last fixture review identified
- [ ] Publication policy output (`fd-sightings policy`) archived
- [ ] Latest `fd-sightings plan-auto` reviewed
- [ ] Publication ledger, retry process, and external dependency contacts understood
- [ ] Optional four-eyes setting and reviewer coverage confirmed

## Services and operations

- [ ] Public, review, sync, and timer units pass health checks
- [ ] Internal `401` review challenge and authenticated proxy route both tested
- [ ] Public home, archive, vulnerability, API, dump, and `security.txt` routes tested
- [ ] Upgrade script and Apache installer procedure demonstrated
- [ ] Logs, alerts, escalation path, and maintenance window documented
- [ ] Incident stop-publication, preservation, restore, and reconciliation process rehearsed

## Required reading

- [Project overview](README.md)
- [Deployment](DEPLOYMENT.md)
- [Configuration](documentation/CONFIGURATION.md)
- [Maintenance](documentation/MAINTENANCE.md)
- [Architecture](documentation/ARCHITECTURE.md)
- [Automated matching](documentation/AUTOMATED_MATCHING.md)
- [Publication policy](VULNARCHIVE_POLICY.md)
- [Implementation status](documentation/IMPLEMENTATION_REVIEW.md)

## Open decisions to transfer

Record owners and due dates outside this repository for licensing, data
retention, recovery objectives, evaluation-threshold governance, design/content
management, and any SSO/MFA requirement.
