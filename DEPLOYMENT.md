# VULNARCHIVE production deployment

## 1. Verbindliche Kompatibilitätsbasis

Für Produktion ist **Vulnerability-Lookup v2.13.0** aus dem offiziellen Repository
`https://github.com/cve-search/vulnerability-lookup.git` festgelegt. Die maschinenlesbare
Sperre steht in `deploy/vulnerability-lookup.version`; weder `main` noch `latest` darf
installiert werden. Das Installationsskript prüft den exakten Tag und schreibt den dabei
aufgelösten Git-Commit nach `/opt/vulnerability-lookup/INSTALLED_COMMIT`. Dieser Wert muss
im Betriebsprotokoll und Backup festgehalten werden. Ein verschobener Tag ist gegenüber
dem gesicherten Commit als Supply-Chain-Abweichung zu behandeln.

**Nur diese Basis ist für VULNARCHIVE freigegeben:** In v2.13.0 stellt
`/api/gcve/publication` BCP-03 bereit, einschließlich `since`-basierter inkrementeller
Synchronisation und Pagination. Dieselbe Version erzeugt die GNA-Dumps unter `/dumps/`
und liefert die API-Policy unter `/.well-known/api-policy.json`. Eine neuere Version gilt
nicht automatisch als kompatibel, selbst wenn ihre API antwortet.

## 2. Dienste und Datenflüsse

Der Host benötigt PostgreSQL (Benutzer, Veröffentlichungsmetadaten und Webdaten),
Kvrocks auf `127.0.0.1:10002` (persistenter Vulnerability-Keyspace), Redis/Valkey auf
`127.0.0.1:6379` (Cache und Worker-Koordination), den Web/API-Prozess auf
`127.0.0.1:10001` sowie die Vulnerability-Lookup-Hintergrund-/Feed-Worker. PostgreSQL,
Redis und Kvrocks dürfen nicht öffentlich lauschen. Apache ist der einzige öffentliche
Ingress. Der Collector auf `127.0.0.1:8765` bedient ausschließlich `/archive/`.

Installiere versionsgebundene Distribution-Pakete aus dem internen Paket-Snapshot und
halte deren Versionen im Betriebsprotokoll fest:

```sh
sudo apt-get install postgresql redis-server kvrocks git python3 poetry
sudo systemctl disable --now redis-server kvrocks postgresql
sudoedit /etc/redis/redis.conf       # bind 127.0.0.1; protected-mode yes
sudoedit /etc/kvrocks/kvrocks.conf  # bind 127.0.0.1; port 10002; persistente dir
sudo systemctl enable --now postgresql redis-server kvrocks
```

## 3. Installation der festgelegten Version

```sh
sudo useradd --system --home /opt/vulnerability-lookup --shell /usr/sbin/nologin vulnerability-lookup
chmod +x deploy/install-vulnerability-lookup.sh
sudo ./deploy/install-vulnerability-lookup.sh
cat /opt/vulnerability-lookup/INSTALLED_COMMIT
```

Das Release bringt sein Dependency-Lockfile mit; `poetry install --sync` verwendet dieses.
Repository, Release und installierter Commit gehören gemeinsam in Change-Ticket und
Backup-Manifest.

## 4. Datenbankinitialisierung und Migration

```sh
sudo -u postgres psql --set ON_ERROR_STOP=1 -f deploy/postgresql-init.sql
sudo -u vulnerability-lookup env \
  VULNERABILITYLOOKUP_CONFIG=/etc/vulnerability-lookup/generic.json \
  /opt/vulnerability-lookup/.venv/bin/flask --app website.app db upgrade
```

Die Migration ist vor dem Start der Web- und Worker-Prozesse auszuführen. Vor jedem
erneuten `db upgrade` sind konsistente PostgreSQL- und Kvrocks-Snapshots erforderlich.
Nicht einzelne Migrationen überspringen oder Tabellen per Hand erzeugen.

## 5. Vollständige Instanzkonfiguration

`config/vulnerability-lookup.generic.json.example` ist ein vollständiger, bewusst
kleiner Override über den unveränderten Upstream-Defaults von v2.13.0. Jeder Wert ist
verbindlich zugeordnet:

| Schlüssel | Produktionswert | Zweck |
|---|---|---|
| `public_domain` | `vuln.freearchive.org` | kanonischer externer Host |
| `user_accounts` | `true` | separates Publikationskonto ermöglichen |
| `fulltextsearch` | `true` | Suche/Resolver des Collectors |
| `local_instance_name` | `gna-1988` | Dump- und lokale Quellenbezeichnung |
| `local_instance_uuid` | dokumentierte UUID im Beispiel | stabile Herausgeberidentität; niemals regenerieren |
| `local_instance_vulnid_pattern` | `^GCVE-1988-[0-9]{4}-[0-9]{4,19}$` | ausschließlich GNA-1988-IDs |
| `local_instance_vulnid_example` | `GCVE-1988-yyyy-nnnn` | UI/API-Beispiel |
| `local_instance_vulnid_max_serial` | `50000000` | oberes Reservierungslimit |
| `local_instance_vulnid_priority_bound` | `20000` | Upstream-Prioritätsgrenze |

```sh
sudo install -d -o root -g vulnerability-lookup -m 0750 /etc/vulnerability-lookup
sudo install -o root -g vulnerability-lookup -m 0640 \
  config/vulnerability-lookup.generic.json.example /etc/vulnerability-lookup/generic.json
sudo install -o root -g vulnerability-lookup -m 0640 \
  deploy/vulnerability-lookup.env.example /etc/vulnerability-lookup/service.env
```

Keine UUID, Grenze oder Regex darf durch Umgebungsvariablen abweichend überschrieben
werden. Passwörter/API-Secrets kommen ausschließlich in `secrets.env` (Modus 0640).

## 6. Web- und Hintergrunddienste

```sh
sudo install -m 0644 deploy/vulnerability-lookup-{web,workers}.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vulnerability-lookup-workers vulnerability-lookup-web
ss -ltn | grep -E '127.0.0.1:(6379|10001|10002)'
curl --fail http://127.0.0.1:10001/.well-known/api-policy.json
```

`vulnerability-lookup-web.service` bindet ausdrücklich nur an `127.0.0.1:10001`.
Anschließend werden die vorhandenen `vulnarchive-*`-Units installiert und Apache mit
`deploy/apache-vuln.freearchive.org.conf` vorgeschaltet.

## 7. Minimales Publikationskonto

Lege in der Vulnerability-Lookup-Administration ein dediziertes Konto
`vulnarchive-publisher` ohne Administrator-, Benutzerverwaltungs-, Import-/Feed- oder
Konfigurationsrechte an. Erteile nur diese API-Fähigkeiten:

1. **Sightings erstellen**,
2. **Vulnerability-ID-Ranges lesen und für GNA 1988 erstellen**,
3. **IDs ausschließlich aus GNA-1988-Ranges reservieren**, und
4. **lokale Vulnerabilities/GCVE-Publikationen erstellen**.

Kein Lösch-, Änderungs-, Rollenverwaltungs- oder Fremd-GNA-Recht ist erforderlich.
Wenn die installierte Rollenmaske eine Fähigkeit nur als breiteres Recht anbietet, ist
das als Ausnahme zu dokumentieren und durch einen Integrationstest auf GNA 1988 zu
begrenzen. Der API-Key liegt nur in `/etc/vulnarchive/vulnarchive.env` (0640,
`root:vulnarchive`). `/api/user/me` muss das Konto bestätigen.

## 8. Collector und öffentlicher Abnahmetest

Installiere den Collector wie in `README.md`, danach dessen systemd-Units, aber aktiviere
den Timer erst nach einem Dry Run:

```sh
sudo -u vulnarchive /opt/vulnarchive/.venv/bin/fd-sightings plan-auto --limit 20
curl --fail https://vuln.freearchive.org/.well-known/api-policy.json
curl --fail 'https://vuln.freearchive.org/api/gcve/publication?per_page=1'
curl --fail 'https://vuln.freearchive.org/api/gcve/publication?since=2026-09-01T00:00:00Z&per_page=1'
curl --fail https://vuln.freearchive.org/dumps/gna-1988.ndjson
```

Pagination muss anhand des von der Antwort gelieferten Next-Links/Cursors bis zur
letzten Seite getestet werden; keine URL-Konvention erraten. Prüfe einen nach dem
`since`-Zeitpunkt publizierten historischen Backfill und validiere einen Record mit dem
offiziellen BCP-05-Validator. Erst dann `vulnarchive-sync.timer` aktivieren.

## 9. Backup und Betrieb

Täglich zu sichern sind PostgreSQL, die persistente Kvrocks-Datenablage, Konfiguration,
Instanz-UUID, `INSTALLED_COMMIT`, Secrets getrennt verschlüsselt sowie das Collector-
Ledger. Redis ist Cache/Koordination, muss aber vor Wartung sauber beendet werden.
Web und Worker werden gemeinsam überwacht; fehlende Worker können zu veralteten Dumps
führen, obwohl HTTP noch 200 liefert.

## 10. Kontrolliertes Upgrade und Rollback (BCP-03)

1. Timer und Publisher stoppen; aktuellen Commit, API-Policy und repräsentative
   paginierte sowie `since`-Antworten als Test-Fixtures sichern.
2. PostgreSQL, Kvrocks, Konfiguration und Ledger konsistent sichern.
3. Kandidatenversion in einer Staging-Kopie **explizit** pinnen; niemals die
   Produktions-Lockdatei vor erfolgreicher Abnahme ändern.
4. Migration auf einer Backup-Kopie ausführen. Schema, BCP-03-Form, Sortierung,
   `since`-Grenzverhalten, Pagination, Dumps, Well-known-Policy und BCP-05 validieren.
5. Erst nach Review Lockdatei und Dokumentation im selben Commit ändern und ein kurzes
   Wartungsfenster für Migration/Neustart nutzen.

Rollback: Publisher stoppen, beide Dienste anhalten, **PostgreSQL und Kvrocks gemeinsam**
auf den Vor-Upgrade-Snapshot zurücksetzen, den in `INSTALLED_COMMIT` gesicherten Commit
v2.13.0 auschecken, dessen Lock-Dependencies installieren, alte Konfiguration einspielen
und die Abnahmetests wiederholen. Ein Code-Downgrade gegen ein vorwärts migriertes Schema
ist verboten. Bei jeder Abweichung bleibt Publikation deaktiviert; so kann ein Update das
BCP-03-Verhalten nicht unkontrolliert ändern.
