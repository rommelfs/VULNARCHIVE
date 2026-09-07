# VULNARCHIVE handover

## Architecture

VULNARCHIVE imports and archives Full Disclosure messages, resolves known identifiers, and applies the configured publication policy. GCVE-1988 identifiers, BCP-05 records, reservations, and publication metadata live in one canonical SQLite database. Publication does not depend on an external write API.

The production boundary consists of:

- `vulnarchive-sync.service`: imports messages and writes eligible records to SQLite.
- `vulnarchive-web.service`: read-only public server on `127.0.0.1:8766`.
- `vulnarchive-review.service`: administrative UI on the configured private address
  `10.205.22.135:8765`; firewall-restricted and never publicly proxied.
- Apache: public TLS ingress with an explicit route allowlist and a static `security.txt`.

The public server exposes `/`, `/api/gcve/publication`, `/dumps/gna-1988.ndjson`, and `/archive/`. BCP-03 returns a bare JSON list. The dump contains exactly the canonical local publication set as compact NDJSON. `deploy/security.txt` advertises the public GCVE base and is mirrored by the direct application route.

Review decisions support zero, one, or multiple referenced vulnerability IDs. Approved selections override automated matches for local publication; an empty selection deliberately creates a new advisory.

## Configuration

Use `config/vulnarchive.env.example`. `VA_GNA_ORG_UUID` is the permanent publisher identity and must not change after publication. `VL_URL` is optional and only used for read-only lookup of foreign vulnerability identifiers; local GCVE publication requires no `VL_API_KEY`.

Runtime data belongs below `data/` and must be backed up with the matching deployed code. Keep `/etc/vulnarchive/vulnarchive.env` restricted to `root:vulnarchive`.

## Operations

```sh
fd-sightings policy
fd-sightings plan-auto --limit 20
fd-sightings sync --retry-failed
fd-sightings public --bind 127.0.0.1 --port 8766
```

Before rollout, run the unit suite, compile check, and hermetic BCP-03 acceptance suite documented in `README.md`. Then run `apachectl configtest`, confirm public GET routes, verify authentication and the IP allowlist at `/review/`, and confirm unprefixed administrative and write routes return 404/405.

Do not expose SQLite or port 8766 directly. Expose port 8765 only on the RFC1918 interface and only to the trusted operator subnet. Back up the SQLite database before upgrades and historical imports. Publication reservations are idempotent and must be reused after failures.
