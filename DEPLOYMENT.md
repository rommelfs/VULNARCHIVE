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

Do not start or enable `vulnarchive-sync.timer` yet. The timer remains disabled
until every rollout gate in section 5 has passed.

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

## 5. Mandatory rollout gates and timer activation

The following gates are ordered and mandatory. Stop at the first failure. Keep
the timer disabled throughout, and run collector commands with the production
environment:

```sh
test "$(systemctl is-enabled vulnarchive-sync.timer 2>/dev/null || true)" = disabled
run_collector() {
  sudo -u vulnarchive sh -c \
    'set -a; . /etc/vulnarchive/vulnarchive.env; set +a; exec /opt/vulnarchive/.venv/bin/fd-sightings "$@"' \
    sh "$@"
}
```

Run all gates in the same root shell so that the `run_collector` function and
the IDs captured below remain available. The environment file must use
shell-compatible `KEY=value` syntax as well as systemd `EnvironmentFile=`
syntax; otherwise invoke the command with an equivalent, securely loaded
environment.

### Gate 1: local Vulnerability-Lookup connection

Test the local instance, including authentication by the publication account.
Both requests must return HTTP 2xx, and `/api/user/me` must identify the intended
account:

```sh
curl --fail --silent --show-error http://127.0.0.1:10001/.well-known/api-policy.json | jq .
VL_API_KEY=$(sudo sed -n 's/^VL_API_KEY=//p' /etc/vulnarchive/vulnarchive.env)
curl --fail --silent --show-error -H "X-API-KEY: ${VL_API_KEY}" \
  http://127.0.0.1:10001/api/user/me | jq .
unset VL_API_KEY
```

### Gate 2: non-writing automatic plan

This command is a dry plan and must complete successfully. Review all 20 results
and their proposed operations before continuing:

```sh
run_collector plan-auto --limit 20 | tee /tmp/vulnarchive-plan.json
jq -e '.count <= 20 and (.outcomes | type == "array")' /tmp/vulnarchive-plan.json
```

### Gate 3: stable instance UUID

Set `VL_GENERIC_JSON` to the active Vulnerability-Lookup configuration file.
The configured `VA_GNA_ORG_UUID` must be a UUID, must equal
`local_instance_uuid`, and must equal the value backed up during the first
deployment. Never replace the backup after publication merely to make this gate
pass.

```sh
VL_GENERIC_JSON=/opt/vulnerability-lookup/config/generic.json
ENV_UUID=$(sudo sed -n 's/^VA_GNA_ORG_UUID=//p' /etc/vulnarchive/vulnarchive.env)
INSTANCE_UUID=$(sudo jq -er '.local_instance_uuid' "$VL_GENERIC_JSON")
printf '%s\n' "$ENV_UUID" | grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
test "$ENV_UUID" = "$INSTANCE_UUID"
sudo test -s /etc/vulnarchive/local_instance_uuid || \
  printf '%s\n' "$INSTANCE_UUID" | sudo tee /etc/vulnarchive/local_instance_uuid >/dev/null
test "$INSTANCE_UUID" = "$(sudo cat /etc/vulnarchive/local_instance_uuid)"
unset ENV_UUID INSTANCE_UUID
```

### Gate 4: publish exactly one approved test record

Choose one archived candidate from the plan that creates a `new-advisory` or
`context-and-sightings` record. An analyst must inspect its source, extracted
content, relationships, record type, and archive rendering in the local review
UI and explicitly approve it for this rollout. Ensure that this approved
candidate is the first actionable, not-yet-published item shown by `plan-auto`.
Then publish with a hard limit of one and capture the allocated ID:

```sh
run_collector publish-auto --limit 1 | tee /tmp/vulnarchive-test-publication.json
GCVE_ID=$(jq -er '[.outcomes[].operations[] | select(.kind == "gcve" and (.status == 200 or .status == 201)) | .id] | select(length == 1) | .[0]' /tmp/vulnarchive-test-publication.json)
test -n "$GCVE_ID"
```

Do not run `publish-auto` again during the rollout. The gate passes only when
exactly one newly published GCVE ID was captured.

### Gate 5: BCP-03 and dump

The same ID and its VULNARCHIVE archive URL must occur in the public BCP-03
response and in the published NDJSON dump:

```sh
curl --fail --silent --show-error 'https://vuln.freearchive.org/api/gcve/publication?per_page=100' -o /tmp/bcp03.json
jq -e --arg id "$GCVE_ID" '.. | objects | select(.cveMetadata.vulnId? == $id or .cveMetadata.cveId? == $id)' /tmp/bcp03.json >/dev/null
curl --fail --silent --show-error https://vuln.freearchive.org/dumps/gna-1988.ndjson -o /tmp/gna-1988.ndjson
jq -e --arg id "$GCVE_ID" 'select(.cveMetadata.vulnId? == $id or .cveMetadata.cveId? == $id)' /tmp/gna-1988.ndjson >/dev/null
```

### Gate 6: BCP-05 validation

Extract the one published record from BCP-03 and validate it with the current
official GCVE BCP-05 validator. Warnings are failures for this rollout:

```sh
jq --arg id "$GCVE_ID" '.. | objects | select(.cveMetadata.vulnId? == $id or .cveMetadata.cveId? == $id)' /tmp/bcp03.json > /tmp/vulnarchive-test-record.json
gcve-bcp-05-validator --fail-on-warning /tmp/vulnarchive-test-record.json
```

Use the executable name documented by the installed official validator if it
differs; `--fail-on-warning` (or its exact equivalent) remains mandatory.

### Gate 7: Sighting and archive URL

Obtain the expected archive URL from the validated record. Confirm that it is an
HTTPS URL below `/archive/`, is reachable, and that the Sighting API returns a
Sighting for the test ID whose source is that URL:

```sh
ARCHIVE_URL=$(jq -er '[.. | objects | .url? | select(type == "string" and startswith("https://vuln.freearchive.org/archive/"))][0]' /tmp/vulnarchive-test-record.json)
curl --fail --silent --show-error "$ARCHIVE_URL" >/dev/null
curl --fail --silent --show-error \
  "https://vuln.freearchive.org/api/sighting/?vulnerability=${GCVE_ID}" \
  -o /tmp/vulnarchive-test-sightings.json
jq -e --arg id "$GCVE_ID" --arg source "$ARCHIVE_URL" \
  '.. | objects | select(.vulnerability? == $id and .source? == $source)' \
  /tmp/vulnarchive-test-sightings.json >/dev/null
```

Also check the public site metadata before activation:

```sh
curl --fail https://vuln.freearchive.org/
curl --fail https://vuln.freearchive.org/.well-known/security.txt
```

Only after gates 1 through 7 have succeeded, reject the shipped example API key
and enable continuous operation:

```sh
sudo grep -Fq 'replace-with-publication-account-api-key' /etc/vulnarchive/vulnarchive.env && {
  echo 'Refusing to enable timer: example API key is still configured.' >&2
  exit 1
}
sudo systemctl enable --now vulnarchive-sync.timer
systemctl is-enabled vulnarchive-sync.timer
systemctl is-active vulnarchive-sync.timer
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
