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
sudo systemctl enable --now vulnarchive-web.service vulnarchive-sync.timer
```

Run one controlled dry plan before the first publication:

```sh
sudo -u vulnarchive /opt/vulnarchive/.venv/bin/fd-sightings plan-auto --limit 20
```

Before any controlled single publication, the read-only deployment preflight is
mandatory. Pass the `generic.json` actually used by Vulnerability-Lookup; the
script compares it with the checked-in reference and
`/etc/vulnarchive/vulnarchive.env`, then performs unauthenticated `GET` requests
against the public API policy, GCVE publication endpoint, and expected
`gna-1988.ndjson` dump:

```sh
cd /opt/vulnarchive
sudo -u vulnarchive ./deploy/check-vulnerability-lookup.py \
  --lookup-config /opt/vulnerability-lookup/config/generic.json
```

The command must finish with `READY` before proceeding. It does not read or send
`VL_API_KEY`, reserve vulnerability IDs, or publish records. If the effective
configuration file is not locally accessible, omit `--lookup-config` to run the
reduced public-metadata and endpoint checks; that reduced check does not replace
the mandatory full check before publication.

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

The `security.txt` response should declare the GCVE endpoint, and the GCVE directory should expose `https://vuln.freearchive.org` as the GNA 1988 pull API. Validate the public BCP-03 response with the official BCP-05 validator before enabling the timer.
