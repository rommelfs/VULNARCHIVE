# VULNARCHIVE production deployment

## Architecture and trust boundary

VULNARCHIVE runs two separate HTTP processes:

- `vulnarchive-web.service` is the read-only public application on `127.0.0.1:8766`.
  It serves `/`, `/api/gcve/publication`, `/dumps/gna-1988.ndjson`,
  `/.well-known/security.txt`, and `/archive/`.
- `vulnarchive-review.service` is the administrative review and publication UI on
  the private RFC1918 address configured as `VA_REVIEW_BIND` (currently
  `10.205.22.135:8765`). Restrict it to the operator network; the public Apache
  virtual host never proxies it.
- `vulnarchive-sync.service` imports new messages and commits eligible GCVE records transactionally to the same local SQLite store.

There is no required local Vulnerability-Lookup installation and no dependency on port
10001. Apache is the only public ingress. The SQLite database and both application
ports must not be exposed directly.

## Installation

Create the service account, install the project and protected configuration, then
install the units and Apache virtual host:

```sh
sudo useradd --system --home /opt/vulnarchive --shell /usr/sbin/nologin vulnarchive
sudo install -d -o vulnarchive -g vulnarchive -m 0750 /opt/vulnarchive/data
python3 -m venv /opt/vulnarchive/.venv
/opt/vulnarchive/.venv/bin/pip install /opt/vulnarchive
sudo install -d -o root -g vulnarchive -m 0750 /etc/vulnarchive
sudo install -o root -g vulnarchive -m 0640 config/vulnarchive.env.example /etc/vulnarchive/vulnarchive.env
sudo install -m 0644 deploy/vulnarchive-{web,review,sync}.service deploy/vulnarchive-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vulnarchive-web
# Enable the review service only when operators need it.
sudo systemctl start vulnarchive-review
```

`VL_URL` is optional and is used by the importer only for read-only resolution of foreign identifiers. The review service has no Vulnerability-Lookup connection and performs no external writes. GCVE reservation and publication require no external account or API key. Set `VA_REVIEW_BIND=10.205.22.135` and allow TCP/8765 only from the trusted RFC1918 operator network. No credential is loaded by the public process, and its HTTP handler implements GET only. The static `deploy/security.txt` is the single discovery document served by Apache and mirrored by the application.

## Apache and public acceptance

Enable `proxy`, `proxy_http`, `headers`, and `ssl`, install
`deploy/apache-vuln.freearchive.org.conf`, and reload Apache after `apachectl configtest`.
The virtual host uses an explicit route allowlist to the public app. Although the app
also rejects unknown routes and every POST, do not add a catch-all to the review port.

```sh
apachectl configtest
curl --fail https://vuln.freearchive.org/
curl --fail 'https://vuln.freearchive.org/api/gcve/publication?per_page=1'
curl --fail https://vuln.freearchive.org/dumps/gna-1988.ndjson
curl --fail https://vuln.freearchive.org/archive/
curl --fail https://vuln.freearchive.org/.well-known/security.txt
curl --fail -X POST https://vuln.freearchive.org/api/gcve/publication && exit 1 || true
```

Confirm that the unprefixed `/connection`, `/publish`, and `/observation` paths return
404. `/review` redirects to the separately authenticated review backend at
`https://vuln.freearchive.org/review/`; TCP/8765 remains restricted to the proxy.

The `/vulnerability/` public route is part of the explicit Apache allowlist. When
deploying this route for the first time, install the updated
`deploy/apache-vuln.freearchive.org.conf`, run `apachectl configtest`, and reload
Apache. The application upgrade script deliberately does not overwrite an
operator-managed Apache virtual host.

## Publication and operation

Before enabling periodic publication, verify the local policy and run:

```sh
sudo -u vulnarchive /opt/vulnarchive/.venv/bin/fd-sightings plan-auto --limit 20
sudo systemctl enable --now vulnarchive-sync.timer
```

The authenticated review UI includes an **Archive imports** page. Operators can
queue a start month, end month, optional per-month limit, and whether candidate
matching is enabled. Historical workers execute sequentially to limit upstream
load and SQLite contention. Their JSON status and captured command output are
stored in `/opt/vulnarchive/data/workers/`. Starting an archive worker imports
observations only; publication remains a separate policy-controlled operation.

Back up `/opt/vulnarchive/data`, configuration, and the publication ledger. Monitor the
public and sync units separately.

## Upgrade

Run the supplied upgrade script from any directory; it operates on
`/opt/vulnarchive` by default:

```sh
sudo /opt/vulnarchive/deploy/upgrade.sh
```

Do not run `git pull` or `pip install` separately. The script removes disposable
`build/` and `src/*.egg-info/` artifacts and refuses modified tracked files,
performs a fast-forward-only pull, tests the target source before downtime, stops the
sync timer and application processes, creates a consistent SQLite backup, preserves the
configuration and previous Git revision, reinstalls the package, updates the systemd
units, applies store migrations through a non-publishing plan, restores only services
that were active, and checks the local public endpoint. Backups are stored below
`/var/backups/vulnarchive` by default.

When upgrading once from an older script that still rejects these generated
untracked directories, bootstrap the fixed script as follows:

```sh
cd /opt/vulnarchive
rm -rf -- build src/fd_sightings.egg-info
git pull --ff-only
sudo ./deploy/upgrade.sh --no-pull
```

This one-time sequence is only necessary for the affected older script. New versions
remove untracked build artifacts both before the Git check and after package installation.
Confirm that the fixed script is actually present before rerunning it:

```sh
/opt/vulnarchive/deploy/upgrade.sh --version
# VULNARCHIVE upgrade script 2
```

If `--version` is rejected, or the output still says `uncommitted changes` rather than
`modified tracked files`, the checkout is still on the old revision. Running that old
script again cannot install a fix which is not present on its configured Git branch.

If another deployment mechanism has already checked out the desired revision, use:

```sh
sudo /opt/vulnarchive/deploy/upgrade.sh --no-pull
```

Staging and nonstandard installations can override `VULNARCHIVE_APP_DIR`,
`VULNARCHIVE_VENV_DIR`, `VULNARCHIVE_ENV_FILE`, `VULNARCHIVE_BACKUP_DIR`, and
`VULNARCHIVE_DB_FILE`. On a failure after services have stopped, the script attempts to
start the previously active services again and prints the old revision and backup path.
For a full rollback, restore both that Git revision and its matching SQLite backup.

## Authenticated review reverse proxy

The review application requires HTTP Basic authentication and a client-IP allowlist. Set `VA_REVIEW_PREFIX=/review`, `VA_REVIEW_USERNAME`, and a long random `VA_REVIEW_PASSWORD`. Set `VA_REVIEW_ALLOWED_NETWORKS` to the operator/VPN CIDRs and `VA_REVIEW_TRUSTED_PROXIES` only to the reverse proxy CIDRs. Forwarded client addresses are ignored from every other peer, and absent credentials fail closed with HTTP 503.

The main Apache virtual host maps `/review/` to `10.205.22.135:8765` and overwrites `X-Forwarded-For` with the actual TCP peer before proxying. Install `deploy/apache-vuln.freearchive.org.conf`, run `apachectl configtest`, and restrict TCP/8765 so only the proxy can reach it.
