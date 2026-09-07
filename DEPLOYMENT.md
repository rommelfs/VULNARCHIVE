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

Confirm that `/review`, `/connection`, `/publish`, and `/observation` return 404 through
the public host. Reach the review UI directly at `http://10.205.22.135:8765/` only from
the firewall-restricted operator network; do not add it to the public virtual host.

## Publication and operation

Before enabling periodic publication, verify the local policy and run:

```sh
sudo -u vulnarchive /opt/vulnarchive/.venv/bin/fd-sightings plan-auto --limit 20
sudo systemctl enable --now vulnarchive-sync.timer
```

Back up `/opt/vulnarchive/data`, configuration, and the publication ledger. Monitor the
public and sync units separately. For upgrades, stop the timer, back up SQLite, deploy to
staging, validate BCP-03 pagination, `since` filtering, dump equivalence and archive
URLs, then atomically deploy and restart. Restore both code and the matching database
backup if rollback is required.
