# VULNARCHIVE production deployment

## Architecture and trust boundary

VULNARCHIVE runs two separate HTTP processes:

- `vulnarchive-web.service` is the read-only public application on `127.0.0.1:8766`.
  It serves `/`, `/api/gcve/publication`, `/dumps/gna-1988.ndjson`,
  `/.well-known/security.txt`, and `/archive/`.
- `vulnarchive-review.service` is the administrative review and publication UI on
  `127.0.0.1:8765`. It must only be reached locally or through a separately secured
  operator channel; the public Apache virtual host never proxies it.
- `vulnarchive-sync.service` performs writes to the configured external publication
  target (`VL_URL`) with the API key from the protected environment file.

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

Set `VL_URL` to the independently operated publication target. Put `VL_API_KEY` only in
`/etc/vulnarchive/vulnarchive.env` (mode 0640, `root:vulnarchive`). Use a dedicated,
least-privileged publisher credential. No credential is loaded by the public process for
handling requests, and its HTTP handler implements GET only.

Configure `VA_SECURITY_CONTACT` and refresh `VA_SECURITY_EXPIRES` before it expires.

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
the public host. The review UI remains at `127.0.0.1:8765` for an SSH tunnel or another
authenticated operator-only ingress.

## Publication and operation

Before enabling periodic publication, verify the independently managed target and run:

```sh
sudo -u vulnarchive /opt/vulnarchive/.venv/bin/fd-sightings plan-auto --limit 20
sudo systemctl enable --now vulnarchive-sync.timer
```

Back up `/opt/vulnarchive/data`, configuration, and the publication ledger. Monitor the
public and sync units separately. For upgrades, stop the timer, back up SQLite, deploy to
staging, validate BCP-03 pagination, `since` filtering, dump equivalence and archive
URLs, then atomically deploy and restart. Restore both code and the matching database
backup if rollback is required.
