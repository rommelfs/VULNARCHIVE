# VULNARCHIVE production deployment

The public host consists of two local services behind Apache:

- Vulnerability-Lookup on `127.0.0.1:10001` is the canonical website, GCVE publication store, BCP-03 API, Sighting API, and dump publisher.
- This repository on `127.0.0.1:8765` collects mailing-list posts and serves stable `/archive/` copies. Its review and publication UI should remain reachable only locally or through an authenticated administration path.

## 1. Install the collector

Copy the project to `/opt/vulnarchive`, create the service account, and ensure only that account can read the environment file:

```sh
sudo useradd --system --home /opt/vulnarchive --shell /usr/sbin/nologin vulnarchive
sudo python3 -m venv /opt/vulnarchive/.venv
sudo /opt/vulnarchive/.venv/bin/python -m pip install -e /opt/vulnarchive
sudo install -d -o vulnarchive -g vulnarchive -m 0750 /opt/vulnarchive/data /etc/vulnarchive
sudo install -o root -g vulnarchive -m 0640 config/vulnarchive.env.example /etc/vulnarchive/vulnarchive.env
```

Replace `VL_API_KEY` and confirm that `VA_GNA_ORG_UUID` is identical to the stable `local_instance_uuid` used by the Vulnerability-Lookup instance.

## 2. Configure Vulnerability-Lookup

Merge `config/vulnerability-lookup.generic.json.example` into its `config/generic.json`. Required values include:

```json
{
  "public_domain": "vuln.freearchive.org",
  "local_instance_name": "gna-1988",
  "local_instance_vulnid_pattern": "^GCVE-1988-[0-9]{4}-[0-9]{4,19}$",
  "local_instance_vulnid_example": "GCVE-1988-yyyy-nnnn"
}
```

Create an API user with permissions for Sightings, vulnerability-ID ranges, vulnerability-ID reservation, and vulnerability publication. Keep the instance UUID stable and backed up.

## 3. Install services

```sh
sudo install -o root -g root -m 0644 deploy/vulnarchive-web.service /etc/systemd/system/
sudo install -o root -g root -m 0644 deploy/vulnarchive-sync.service /etc/systemd/system/
sudo install -o root -g root -m 0644 deploy/vulnarchive-sync.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vulnarchive-web.service
```

Run one controlled dry plan before the first publication:

```sh
sudo -u vulnarchive /opt/vulnarchive/.venv/bin/fd-sightings plan-auto --limit 20
```

## 4. Configure Apache

Enable the required modules, install the supplied virtual host, and reload Apache:

```sh
sudo a2enmod proxy proxy_http headers ssl
sudo install -o root -g root -m 0644 deploy/apache-vuln.freearchive.org.conf /etc/apache2/sites-available/vuln.freearchive.org.conf
sudo a2dissite 000-default
sudo a2ensite vuln.freearchive.org
sudo apachectl configtest
sudo systemctl reload apache2
```

The certificate paths in the template assume Certbot/Let's Encrypt and must match the host.

## 5. Initial archive and continuous operation

Phase 1 imports historical months without publishing during collection:

```sh
fd-sightings archive --from-period 2002-07 --to-period 2026-09
fd-sightings plan-auto --limit 20
fd-sightings publish-auto
```

Phase 2 is handled by `vulnarchive-sync.timer`, which imports the current RSS feed and applies the automatic policy every 15 minutes.

## 6. Public verification

All checks must succeed before updating or relying on the GNA directory entry:

```sh
curl -f https://vuln.freearchive.org/
curl -f https://vuln.freearchive.org/.well-known/api-policy.json
curl -f 'https://vuln.freearchive.org/api/gcve/publication?per_page=1'
curl -f https://vuln.freearchive.org/dumps/gna-1988.ndjson
curl -f https://vuln.freearchive.org/.well-known/security.txt
```

Run the separate, destructive acceptance check against a prepared test instance
(not production). The instance must contain at least three seed records, have a
1999 ID range for GNA 1988, expose its generated dump, and use credentials with
reservation and publication permissions:

```sh
VL_URL=https://test-vuln.example \
VL_API_KEY=replace-with-test-publication-key \
VA_GNA_ORG_UUID=4e2abfbf-4a2a-4b76-a4e0-d77c18ba156c \
python3 deploy/verify-bcp03.py --allow-write
```

This check validates the BCP-03 envelope and records, invalid parameters and
limits, two-page continuity, historical-ID backfill using current publication
time, both sides of the `since` boundary, and consistency with
`dumps/gna-1988.ndjson`. The static publication fixture is in
`tests/bcp03/historical-record.json`. A successful run, in addition to the
public checks above and the official BCP-05 validator, is a mandatory prerequisite
for enabling the production timer:

```sh
sudo systemctl enable --now vulnarchive-sync.timer
```

The `security.txt` response should declare the GCVE endpoint, and the GCVE directory should expose `https://vuln.freearchive.org` as the GNA 1988 pull API.
