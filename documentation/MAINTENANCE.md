# Maintenance and operations

## Service inventory

| Unit | Purpose | Expected mode |
|---|---|---|
| `vulnarchive-web.service` | Read-only public site/API | continuously running |
| `vulnarchive-review.service` | Private analyst UI and worker control | continuously running on private address |
| `vulnarchive-sync.timer` | Schedules current-feed ingestion/publication | active timer |
| `vulnarchive-sync.service` | One-shot sync run | inactive between runs |

## Routine health checks

```bash
sudo systemctl status vulnarchive-web.service vulnarchive-review.service \
  vulnarchive-sync.timer --no-pager --full
sudo systemctl list-timers vulnarchive-sync.timer --no-pager
sudo journalctl -u vulnarchive-sync.service -n 100 --no-pager
curl --fail --silent --show-error http://127.0.0.1:8766/ >/dev/null
```

Probe the review service with credentials from a protected operator context. A
request without credentials returning `401 Authentication required` proves the
listener and authentication challenge are working; it does not prove a valid
login or proxy route.

```bash
curl -i --max-time 5 http://PRIVATE_ADDRESS:8765/
curl --fail --user USER:PASSWORD --max-time 10 \
  http://PRIVATE_ADDRESS:8765/ >/dev/null
```

Also validate the external canonical routes:

```bash
curl --fail https://vuln.example/.well-known/security.txt
curl --fail https://vuln.example/api/gcve/publication >/dev/null
curl --fail --user USER:PASSWORD https://vuln.example/review/ >/dev/null
```

## Logs

```bash
sudo journalctl -u vulnarchive-web.service --since today
sudo journalctl -u vulnarchive-review.service --since today
sudo journalctl -u vulnarchive-sync.service --since today
sudo tail -n 100 /var/log/apache2/error.log
```

Do not paste environment files, authorization headers, API keys, password hashes,
or full sensitive source messages into tickets. Worker details are bounded in the
UI; use journal and persisted job metadata for deeper diagnosis.

## SQLite backup

Stop writers or use SQLite's online backup API. A raw copy of only the main file
while WAL writes are active can be incomplete.

Preferred online backup:

```bash
sudo -u vulnarchive sqlite3 /opt/vulnarchive/data/fd-sightings.sqlite \
  ".backup '/opt/vulnarchive/data/fd-sightings-$(date -u +%Y%m%dT%H%M%SZ).sqlite'"
```

Verify backups:

```bash
sqlite3 BACKUP.sqlite 'PRAGMA integrity_check;'
sqlite3 BACKUP.sqlite 'PRAGMA foreign_key_check;'
```

Copy verified backups to a separate failure domain and test restoration on a
non-production host. Define retention and encryption according to the data
policy; raw mailing-list evidence and account data may require protection.

## Restore

1. Announce downtime and stop review, sync, and public services.
2. Preserve the failed database and any `-wal`/`-shm` files for investigation.
3. Restore a verified database with correct owner and mode.
4. Start the application once in a controlled command so idempotent migrations
   can run.
5. Run integrity checks, `fd-sightings plan-auto`, and application tests.
6. Start public/review services and the timer, then execute internal and external
   health checks.
7. Record the restore point and any publication gap.

## Upgrade

Use the guarded script rather than an ad-hoc pull:

```bash
cd /opt/vulnarchive
sudo /opt/vulnarchive/deploy/upgrade.sh
```

The script locks upgrades, requires a clean tracked tree, fast-forwards Git,
runs tests/compile checks, validates source configuration, backs up SQLite,
reinstalls the package and units, runs a publication plan as migration/startup
validation, restores previously active services, and probes readiness.

Afterward:

```bash
git log -1 --oneline
sudo systemctl --failed
sudo journalctl -u vulnarchive-web.service -u vulnarchive-review.service \
  -u vulnarchive-sync.service --since '-10 minutes' --no-pager
```

Review release notes for environment, schema, Apache, or evaluation changes.
The upgrade script does not replace operator judgment about policy changes.

## Apache changes

Install repository-managed public configuration atomically with:

```bash
sudo ./deploy/install-apache-config.sh
```

The installer backs up the active site, runs `apachectl configtest`, restores on
failure, and reloads only valid configuration. Confirm required modules and both
public and authenticated review routes after every change.

## Matching-evaluation maintenance

Run evaluation whenever extraction, deterministic scoring, candidate selection,
prompt content, or model policy changes:

```bash
.venv/bin/fd-sightings evaluate tests/fixtures/matching \
  --output data/matching-evaluation.json
```

Review false positives and false negatives, add representative labelled cases,
and commit fixture changes. Production reports are deployment artifacts and may
contain environment-specific evidence; do not blindly commit them.

## Source maintenance

- Check current-feed sync logs at least daily.
- A source enabled in `VA_SOURCES` may still be archive-only.
- Test a small month with `--limit` before a large historical backfill.
- Watch source-side format/URL changes and update adapter fixtures.
- Use the review worker page for progress; avoid overlapping large backfills on
  the same single-host SQLite deployment.

## User and access maintenance

- Maintain at least two active administrators before enabling four-eyes policy.
- Deactivate departed users promptly.
- Rotate the bootstrap environment password after emergency use.
- Periodically inspect append-only review events for unexpected bulk actions.
- Keep proxy allowlists and trusted-proxy CIDRs as narrow as possible.

## Incident checklist

1. Stop automatic sync/publication if record integrity is in doubt.
2. Preserve database, WAL, logs, current commit ID, configuration checksum, and
   relevant evaluation report.
3. Distinguish proxy failure, service failure, database failure, and external
   dependency failure using direct internal probes.
4. Restore service from a verified backup or roll forward with a tested fix.
5. Reconcile publication ledger state before retrying failed publications.
6. Document impact, records affected, corrective action, and follow-up tests.

## Capacity signals

Investigate when page latency grows, WAL files remain large, worker queues overlap,
disk space approaches limits, or FTS5 fallback is active on a large dataset.
Before migrating away from SQLite, measure query plans and indexes and preserve
the existing query/event contracts in integration tests.
