# Production deployment

This guide describes a single-host Debian/Ubuntu deployment with Apache, systemd,
and SQLite. Adapt addresses and TLS paths to the target environment. Review the
[architecture](documentation/ARCHITECTURE.md),
[configuration](documentation/CONFIGURATION.md), and
[maintenance guide](documentation/MAINTENANCE.md) before production use.

## 1. Prerequisites

- Python 3.11+, `python3-venv`, Git, SQLite CLI
- Apache 2.4 with `proxy`, `proxy_http`, `headers`, `ssl`, and `rewrite`
- A DNS name and valid TLS certificate
- A private address reachable by the reverse proxy for the review service
- Network egress to configured sources and Vulnerability-Lookup
- Root access for account, systemd, Apache, and environment installation

Example packages:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv sqlite3 apache2
sudo a2enmod proxy proxy_http headers ssl rewrite
```

## 2. Service account and checkout

```bash
sudo useradd --system --home /opt/vulnarchive --shell /usr/sbin/nologin \
  vulnarchive 2>/dev/null || true
sudo install -d -o vulnarchive -g vulnarchive -m 0750 /opt/vulnarchive
sudo -u vulnarchive git clone <repository-url> /opt/vulnarchive
cd /opt/vulnarchive
sudo install -d -o vulnarchive -g vulnarchive -m 0750 /opt/vulnarchive/data
sudo -u vulnarchive python3 -m venv .venv
sudo -u vulnarchive .venv/bin/python -m pip install --upgrade pip
sudo -u vulnarchive .venv/bin/python -m pip install -e .
```

If `/opt/vulnarchive` already exists, verify that it is the intended clean
checkout instead of cloning over it. A fresh `git clone` requires the destination
not to exist (or to be empty).

## 3. Environment configuration

```bash
sudo install -d -o root -g root -m 0755 /etc/vulnarchive
sudo install -o root -g root -m 0600 config/vulnarchive.env.example \
  /etc/vulnarchive/vulnarchive.env
sudoedit /etc/vulnarchive/vulnarchive.env
```

At minimum, verify:

- canonical `VA_PUBLIC_BASE_URL`;
- permanent `VA_GNA_ORG_UUID` and GNA 1988 identity;
- `VA_SOURCES` (`bugtraq` is historical/archive-only);
- a private `VA_REVIEW_BIND`, correct `/review` prefix, narrow allowed/trusted
  networks, and a long random bootstrap password;
- a contact-bearing `FD_USER_AGENT`;
- publication thresholds and switches;
- LLM mode `off` or `shadow` initially.

Never source an untrusted environment file in a privileged shell. The systemd
units parse it as an environment file. Follow the complete
[configuration reference](documentation/CONFIGURATION.md).

## 4. Install systemd units

```bash
sudo install -o root -g root -m 0644 deploy/vulnarchive-web.service \
  deploy/vulnarchive-review.service deploy/vulnarchive-sync.service \
  deploy/vulnarchive-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

The review unit binds to `${VA_REVIEW_BIND}:8765`; the public unit binds to
`127.0.0.1:8766`. Inspect the unit files and host firewall before starting them.

## 5. Initialize and validate

Run startup/migration and planning commands as the service account with the same
environment used by systemd:

```bash
sudo -u vulnarchive env $(sudo awk '!/^($|#)/ {print}' \
  /etc/vulnarchive/vulnarchive.env) \
  /opt/vulnarchive/.venv/bin/fd-sightings policy
sudo -u vulnarchive env $(sudo awk '!/^($|#)/ {print}' \
  /etc/vulnarchive/vulnarchive.env) \
  /opt/vulnarchive/.venv/bin/fd-sightings plan-auto
```

For values containing shell metacharacters or whitespace, use a root-owned helper
or `systemd-run` rather than the illustrative `awk` expansion above. Do not print
secrets to shared logs.

Run repository checks before exposing the service:

```bash
sudo -u vulnarchive env PYTHONPATH=src .venv/bin/python \
  -m unittest discover -s tests -v
sudo -u vulnarchive .venv/bin/python -m compileall -q src
sqlite3 data/fd-sightings.sqlite 'PRAGMA integrity_check;'
```

## 6. Apache and TLS

Review `deploy/apache-vuln.freearchive.org.conf` and
`deploy/apache-review.vuln.freearchive.org.conf`, replace hostnames, addresses,
certificate paths, and network ACLs, then use the guarded installer:

```bash
sudo /opt/vulnarchive/deploy/install-apache-config.sh
```

The installer backs up an existing site, validates Apache configuration, restores
on failure, and reloads only after a successful config test. Ensure that:

- public paths proxy only to the read-only service;
- `/review/` proxies to the private review service and preserves the prefix;
- the review route is restricted to approved networks;
- forwarding headers are trusted only from configured proxy networks;
- `/.well-known/security.txt` is served at the canonical public origin;
- HTTP redirects to HTTPS.

## 7. Start services

```bash
sudo systemctl enable --now vulnarchive-web.service
sudo systemctl enable --now vulnarchive-review.service
sudo systemctl enable --now vulnarchive-sync.timer
```

The review service may remain disabled at boot if operational policy requires
manual activation, but document that choice. The sync service is a one-shot
invoked by its timer and normally appears inactive between runs.

## 8. Acceptance checks

```bash
sudo systemctl status vulnarchive-web.service vulnarchive-review.service \
  vulnarchive-sync.timer --no-pager --full
sudo ss -ltnp | grep -E ':8765|:8766'
curl --fail https://vuln.example/
curl --fail https://vuln.example/.well-known/security.txt
curl --fail https://vuln.example/api/gcve/publication >/dev/null
curl -i http://PRIVATE_ADDRESS:8765/
curl --fail --user USER:PASSWORD https://vuln.example/review/ >/dev/null
```

An unauthenticated direct review probe should return `401`; a connection refusal
means the process/address/firewall is wrong. Verify at least one archive page and,
after a controlled test publication, its canonical `/vulnerability/<ID>` route.

## 9. First operational run

1. Import a small historical sample with `--limit`.
2. Inspect extraction, candidates, analysis history, and provenance in review.
3. Create named reviewer accounts and verify roles.
4. Leave four-eyes disabled until two independent active reviewers are ready.
5. Run `plan-auto`; inspect every proposed action.
6. Test backup and restore before enabling unattended publication.
7. Enable only Full Disclosure for current sync; queue Bugtraq month ranges as
   historical workers.

## Upgrades

The current repository ships **VULNARCHIVE upgrade script 4**. Confirm the
deployed script version with `deploy/upgrade.sh --version` before relying on the
steps described below.

From a clean checkout:

```bash
cd /opt/vulnarchive
sudo /opt/vulnarchive/deploy/upgrade.sh
```

To install an already checked-out, operator-verified revision without contacting
the Git remote, use `sudo /opt/vulnarchive/deploy/upgrade.sh --no-pull`.

The upgrade script removes only disposable, untracked package artifacts before
checking the tree. If an older revision must be prepared manually, the equivalent
cleanup is `rm -rf -- build src/fd_sightings.egg-info`; verify with `git status`
first and never use this command for a path containing tracked files.

The script performs lock, Git, tests, source validation, database backup,
installation, startup/migration planning, service restoration, and readiness
checks. Read its output and complete the post-upgrade checks in the
[maintenance guide](documentation/MAINTENANCE.md). Environment or Apache changes
may still require explicit operator review.

## Rollback and recovery

Do not downgrade a migrated database blindly. Prefer rolling forward with a
tested fix. If restoration is necessary, stop all writers, preserve current
database/WAL/log evidence, restore the pre-upgrade verified backup, deploy its
matching code revision, and reconcile the publication ledger before resuming
sync. See [Maintenance](documentation/MAINTENANCE.md).

## Production checklist

- [ ] Permanent GNA identity and canonical URL confirmed
- [ ] Secrets root-owned and mode `0600`
- [ ] Review listener private; proxy/network trust lists narrow
- [ ] TLS, redirect, security headers, and `security.txt` verified
- [ ] Named administrators/reviewers created
- [ ] Source behavior tested with a small import
- [ ] LLM off/shadow unless a passing current evaluation exists
- [ ] Publication policy and plan reviewed
- [ ] Database backup and restore tested
- [ ] Timer, logs, disk monitoring, and alert ownership assigned
- [ ] External public and authenticated review routes validated
