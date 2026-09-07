# GCVE Best Current Practices

For the VULNARCHIVE implementation and rollout plan that applies these BCPs to
mailing-list processing, see
[`AUTOMATED_MATCHING.md`](AUTOMATED_MATCHING.md).

This directory contains the individual GCVE Best Current Practice (BCP)
documents supplied in [`bcp_all.txt`](bcp_all.txt). Splitting the source bundle
into Markdown files makes each document directly discoverable, linkable, and
renderable while retaining the bundled source as received.

## Available documents

| BCP | Title | Version | Status | Date |
| --- | --- | --- | --- | --- |
| [BCP-01](bcp-01.md) | Signature Verification of the Directory File | 1.2 | Published | 2026-03-10 |
| [BCP-02](bcp-02.md) | Practical Guide to Vulnerability Handling and Disclosure | 1.7 | Published | 2026-05-02 |
| [BCP-03](bcp-03.md) | Decentralized Publication Standard | 1.5 | Published for public review | 2026-03-10 |
| [BCP-04](bcp-04.md) | Recommendations and Best Practices for ID Allocation | 1.4 | Published | 2026-03-10 |
| [BCP-05](bcp-05.md) | GCVE Vulnerability Format (Updated CVE Record Format) | 1.7 | Published for public review | 2026-03-10 |
| [BCP-06](bcp-06.md) | Requirements and Evaluation Criteria for GCVE Numbering Authorities (GNAs) | 1.1 | Draft for public review | 2026-03-10 |
| [BCP-07](bcp-07.md) | Known Exploited Vulnerability (KEV) Assertion Format | 2.2 | Published for public review | 2026-09-01 |
| [BCP-09](bcp-09.md) | Scope of a GCVE Record | 1.0 | Draft for public review | 2026-05-20 |
| [BCP-10](bcp-10.md) | Improved Common Platform Enumeration for GCVE | 1.1 | Draft for public review | 2026-04-29 |
| [BCP-12](bcp-12.md) | Sighting Format | 0.9 | Draft for public review | 2026-07-30 |

BCP-08 and BCP-11 are not listed because no documents with those identifiers
are present in `bcp_all.txt`. The status labels in the table are concise
renderings of the metadata in each document; the individual documents retain
the original metadata and public-review links verbatim.

## Source and maintenance

`bcp_all.txt` is the source bundle for this snapshot. Each `bcp-NN.md` file is
the corresponding complete section of that bundle, from its YAML front matter
up to (but not including) the next document's front matter. When the bundle is
updated, regenerate all individual files together and verify that their ordered
contents reproduce every BCP section in the bundle.
