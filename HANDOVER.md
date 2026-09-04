# VULNARCHIVE – Handover

Stand: 4. September 2026
Projektversion: 0.2.0
Verbindliche Vulnerability-Lookup-Version: **v2.13.0** (offizieller Release; aufgelösten
Produktions-Commit zusätzlich aus `INSTALLED_COMMIT` sichern)
GCVE Numbering Authority: GNA 1988 – VULNARCHIVE
Öffentliche Zieladresse: <https://vuln.freearchive.org>

## Startprompt für den neuen ChatGPT-Account

> Übernimm das Projekt VULNARCHIVE aus dem bereitgestellten Git-Repository. Lies zuerst `HANDOVER.md`, `VULNARCHIVE_POLICY.md`, `DEPLOYMENT.md` und `README.md`. Prüfe anschließend den lokalen Stand mit den vorhandenen Tests. Der Collector und Publisher sind lokal implementiert; als nächster Hauptschritt muss die öffentliche Instanz auf `vuln.freearchive.org` ausgerollt werden. Veröffentliche nichts, bevor Zielinstanz, API-Schlüssel, GNA-Konfiguration und ein Dry Run überprüft wurden. Bewahre die getroffenen fachlichen Entscheidungen aus dem Handover bei.

## Ziel des Projekts

VULNARCHIVE archiviert öffentliche Security-Mailinglisten und überführt darin enthaltene Schwachstelleninformationen in maschinenlesbare GCVE-Daten. Der Startpunkt ist die Full-Disclosure-Mailingliste.

Das System soll zwei Phasen unterstützen:

1. Historischer Backfill der Mailinglistenarchive.
2. Kontinuierlicher Import neuer Beiträge und automatische Publikation.

VULNARCHIVE ist als GNA 1988 registriert:

- <https://gcve.eu/gna/1988/>
- Short Name: `VULNARCHIVE`
- Full Name: `Vulnerability Disclosure Archive`

## Verbindliche fachliche Entscheidungen

### Veröffentlichungsmodell

VULNARCHIVE darf sowohl neue Schwachstellen als auch eigenständige Kontext-, Referenz- und Analysedatensätze zu bestehenden Schwachstellen veröffentlichen.

- Beitrag mit bestehender CVE/GCVE/GHSA:
  - Sighting auf die bestehende ID.
  - Bei ausreichendem Inhalt zusätzlich eigener `GCVE-1988-*`-Record vom Typ `analysis` oder `reference`.
- Beitrag ohne explizite ID, aber mit automatisch gefundenem Kandidaten:
  - automatische Publikation ist erlaubt;
  - die Zuordnung wird transparent als `possibly_related` gekennzeichnet;
  - Match-Methode und Konfidenz werden im Sighting erwähnt.
- Beitrag ohne bekannte oder gefundene ID:
  - bei Erreichen der konfigurierten Mindestanforderungen neuer `GCVE-1988-*`-Record vom Typ `advisory`.
- Nicht ausreichender Beitrag:
  - wird archiviert, aber erzeugt keinen GCVE-Record.

### Trust-Modell

Es gibt ausdrücklich keinen manuellen Validierungszwang. Eine Publikation ist eine Behauptung von GNA 1988 und kein Gütesiegel. Andere Instanzen und Nutzer müssen VULNARCHIVE nicht vertrauen.

Die automatische Evidenzbewertung misst nur, ob genügend strukturierter Inhalt für eine nützliche Publikation vorhanden ist. Sie ist keine Wahrheits-, Vertrauens- oder Severity-Bewertung.

### ID- und Zeitregeln

- Format: `GCVE-1988-<YEAR>-<SERIAL>`.
- Das Jahr der ID ist das Veröffentlichungsjahr des ursprünglichen Mailinglistenbeitrags.
- `cveMetadata.datePublished` ist der tatsächliche Publikationszeitpunkt des VULNARCHIVE-Records.
- Der ursprüngliche Veröffentlichungszeitpunkt steht separat in `x_vulnarchive.sourcePublishedAt`.
- Dadurch bleiben historische IDs sinnvoll, während `since`-basierte BCP-03-Synchronisation neue Backfills erkennen kann.

### Beziehungen

- explizit im Beitrag enthaltene und aufgelöste ID: `related`;
- automatisch aus Produkt/Titel gefundener Kandidat: `possibly_related`;
- `equal` wird nicht automatisch behauptet.

### Sightings

- `seen`: Schwachstelle wurde im archivierten Beitrag erwähnt oder behandelt.
- `published-proof-of-concept`: Der Beitrag enthält oder verlinkt öffentliches Reproduktions- beziehungsweise Exploitmaterial.
- Ein PoC impliziert niemals automatisch `exploited`.

### Quellenarchiv

Gespeichert werden:

- Original-URL;
- abgerufene HTML-Quelle;
- extrahierter Text;
- Titel, Autor und Veröffentlichungsdatum;
- Message-ID, falls vorhanden;
- Links;
- SHA-256 der abgerufenen Quelle.

Stabile Archiv-URLs folgen dem Schema:

`https://vuln.freearchive.org/archive/full-disclosure/<YEAR>/<MONTH>/<NUMBER>`

## Architektur

```text
Full Disclosure Archive / RSS
              │
              ▼
      VULNARCHIVE Collector
      Parser + Extraktion
              │
              ▼
    Vulnerability-ID Resolver
  explizit oder Produkt/Titel-Match
              │
              ▼
   konfigurierbarer Policy-Entscheider
       ┌──────┼────────┐
       ▼      ▼        ▼
    Archiv  Sighting  GCVE-1988 Record
                  │
                  ▼
       Vulnerability-Lookup
    API · BCP-03 · Dumps · Website
```

## Festgelegte Vulnerability-Lookup-Basis

Die freigegebene Produktionsbasis ist ausschließlich Vulnerability-Lookup **v2.13.0**.
Sie ist in `deploy/vulnerability-lookup.version` gesperrt und wird mit
`deploy/install-vulnerability-lookup.sh` installiert. Für genau diese Version werden
`/api/gcve/publication`, `since`-Synchronisation, Pagination, GNA-Dumps und
`/.well-known/api-policy.json` vorausgesetzt und abgenommen. „Aktuell“ in älteren
Notizen bedeutet ausdrücklich nicht, ungeprüft den neuesten Upstream-Stand einzusetzen.

Web/API (`127.0.0.1:10001`) und Hintergrund-Worker haben getrennte systemd-Units; sie
benötigen PostgreSQL, Redis/Valkey und Kvrocks. Initialisierung, vollständiges Mapping
der acht Generic-Config-Werte, Least-Privilege-Publikationskonto sowie verpflichtende
Upgrade-/Rollback-Prüfungen stehen in `DEPLOYMENT.md`. Ein Versionswechsel darf erst
nach Staging-Abnahme des BCP-03-Verhaltens erfolgen.

Produktionsaufteilung:

- Vulnerability-Lookup auf `127.0.0.1:10001` ist kanonischer GCVE- und Sighting-Store und stellt BCP-03 bereit.
- Der VULNARCHIVE-Collector läuft auf `127.0.0.1:8765`.
- Apache veröffentlicht Vulnerability-Lookup unter `/` und leitet nur `/archive/` an den Collector weiter.
- Die lokale Review-/Publikationsoberfläche wird nicht öffentlich exponiert.

## Projektpfad und wichtige Dateien

Wichtige Dateien:

- `README.md` – Nutzung und Befehle
- `VULNARCHIVE_POLICY.md` – öffentlich dokumentierbares GNA-Modell
- `DEPLOYMENT.md` – Produktions-Rollout
- `config/vulnarchive.env.example` – Collector-/Policy-Konfiguration
- `config/vulnerability-lookup.generic.json.example` – Einstellungen der Zielinstanz
- `deploy/apache-vuln.freearchive.org.conf` – Apache Reverse Proxy
- `deploy/vulnarchive-web.service` – lokaler Archivdienst
- `deploy/vulnarchive-sync.service` – kontinuierlicher Import und Publisher
- `deploy/vulnarchive-sync.timer` – 15-Minuten-Timer
- `src/fd_sightings/policy.py` – Entscheidungsmodell
- `src/fd_sightings/publication.py` – Sighting-/GCVE-Payloads und idempotente Publikation
- `src/fd_sightings/vulnerability_lookup.py` – API-Client
- `src/fd_sightings/store.py` – SQLite-Archiv und Publikationsledger
- `src/fd_sightings/review_ui.py` – lokale Oberfläche und öffentliche Archivansicht
- `tests/test_pipeline.py` – automatisierte Tests

## Implementierter Stand

- Historischer Import nach Monat und Zeitraum.
- RSS-Import für neue Full-Disclosure-Beiträge.
- Rohquellenarchiv und SHA-256.
- Extraktion von CVE, GCVE, GHSA, CWE und CVSS.
- Erkennung von PoC-Indikatoren.
- Auflösung expliziter IDs über Vulnerability-Lookup.
- Kandidatensuche über Produkt und Titel.
- Konfigurierbare automatische Publikationspolicy.
- Automatische Sightings.
- Reservierung von `GCVE-1988-*` über die Vulnerability-Lookup-GNA-API.
- Automatische Erstellung fehlender Jahresbereiche, sofern aktiviert und berechtigt.
- BCP-05-Records mit `advisory`, `analysis` oder `reference`.
- `x_vulnarchive`-Provenienzfelder.
- Idempotentes SQLite-Publikationsledger.
- Wiederverwendung bereits reservierter IDs nach temporären Fehlern.
- SQLite-WAL und Busy Timeout für parallelen Web-/Sync-Betrieb.
- Lokale Review- und automatische Publikationsoberfläche.
- `sync`-Befehl für Import und direkte automatische Publikation.
- Produktionsvorlagen für Apache und systemd.

## Aktueller lokaler Datenstand

- Ein Full-Disclosure-Testbeitrag ist importiert:
  - `https://seclists.org/fulldisclosure/2026/Sep/27`
  - Flextype RCE / PoC
  - automatisch gefundener Kandidat: `CVE-2026-77939`
  - Match-Methode: Produkt-/Titelüberschneidung
  - Beziehung deshalb: `possibly_related`
- Die vollständige abgerufene HTML-Quelle ist gespeichert.
- Es wurden keine externen automatischen Publikationen durchgeführt.
- Das automatische Publikationsledger enthält derzeit null Einträge.

## Lokaler Betrieb

```sh
git clone <repository-url> VULNARCHIVE
cd VULNARCHIVE
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
fd-sightings policy
fd-sightings plan-auto --limit 20
fd-sightings review --port 8766
```

Die korrigierte Oberfläche wurde zuletzt unter folgender Adresse gestartet:

<http://127.0.0.1:8766/publish>

Auf Port 8765 lief zuletzt noch ein älterer Prozess, der außerhalb der Codex-Sandbox gestartet worden war. Er sollte vor dem nächsten regulären Start beendet werden.

## Zentrale Befehle

Einzelnen Beitrag importieren:

```sh
fd-sightings url https://seclists.org/fulldisclosure/2026/Sep/27
```

Historischen Zeitraum importieren:

```sh
fd-sightings archive --from-period 2002-07 --to-period 2026-09
```

Automatischen Plan ohne Publikation anzeigen:

```sh
fd-sightings plan-auto --limit 20
```

Alle geeigneten archivierten Beiträge publizieren:

```sh
fd-sightings publish-auto
```

Fehler erneut versuchen:

```sh
fd-sightings publish-auto --retry-failed
```

Kontinuierlicher RSS-Import plus Publikation:

```sh
fd-sightings sync --retry-failed
```

Publikationsledger exportieren:

```sh
fd-sightings export-publications --output publications.jsonl
```

## Konfigurierbare Policy

Die produktiven Werte kommen aus der Umgebung:

- `VL_URL=https://vuln.freearchive.org`
- `VL_API_KEY=<secret>`
- `VA_GNA_ID=1988`
- `VA_GNA_SHORT_NAME=VULNARCHIVE`
- `VA_PUBLIC_BASE_URL=https://vuln.freearchive.org`
- `VA_GNA_ORG_UUID=<stable UUIDv4>`
- `VA_PUBLISH_SIGHTINGS=true`
- `VA_PUBLISH_CONTEXT_RECORDS=true`
- `VA_MIN_NEW_RECORD_SCORE=5`
- `VA_MIN_CONTEXT_RECORD_SCORE=3`
- `VA_MIN_BODY_CHARS=160`
- `VA_REQUIRE_PRODUCT_FOR_NEW=true`
- `VA_AUTO_CREATE_YEAR_RANGE=true`
- `VA_MAX_DESCRIPTION_CHARS=12000`

Der API-Schlüssel ist nicht im Projekt und nicht im Handover enthalten.

`VA_GNA_ORG_UUID` muss mit der dauerhaft verwendeten `local_instance_uuid` der Vulnerability-Lookup-Instanz abgestimmt werden. Nach erster Publikation darf diese UUID nicht mehr geändert werden.

## Tests und Verifikation

Letzter lokaler Teststand:

- 15 Tests erfolgreich.
- Python-Kompilierungsprüfung erfolgreich.
- Editable-Installation in `.venv` erfolgreich.
- Ein real erzeugter Beispielrecord bestand den offiziellen GCVE-BCP-05-Validator mit `--fail-on-warning`.

Tests erneut ausführen:

```sh
cd VULNARCHIVE
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m compileall -q src tests
```

## Öffentlicher Ist-Zustand

Am 4. September 2026 wurde read-only geprüft:

- `https://vuln.freearchive.org/` liefert HTTP 200, zeigt jedoch nur die Apache2-Ubuntu-Standardseite.
- `/.well-known/api-policy.json` liefert 404.
- `/api/gcve/publication` liefert 404.
- `/dumps/` liefert 404.
- `/dumps/gna-1988.ndjson` liefert 404.
- `/.well-known/security.txt` liefert 404.

Die GNA-Registrierung selbst ist online und nennt Website sowie Dump-URL. Der eigentliche Server-Rollout ist daher der nächste Hauptschritt.

## Nächste Schritte in empfohlener Reihenfolge

1. Zugriff auf den Server von `vuln.freearchive.org` herstellen.
2. Apache-Standardseite deaktivieren.
3. Die festgelegte Vulnerability-Lookup-Version v2.13.0 mit den Artefakten unter
   `deploy/` installieren und konfigurieren (nicht `main`/`latest`).
4. `local_instance_name` auf `gna-1988` setzen.
5. Stabile Instanz-/GNA-UUID festlegen und sichern.
6. Publikationskonto mit minimal erforderlichen API-Rechten erstellen.
7. Collector nach `/opt/vulnarchive` übertragen.
8. `/etc/vulnarchive/vulnarchive.env` mit echtem API-Schlüssel erstellen.
9. systemd-Dienste und Apache-VHost installieren.
10. Noch keinen Timer aktivieren; zuerst Verbindung und Dry Run prüfen.
11. Einen einzelnen kontrollierten Testrecord publizieren.
12. BCP-03, BCP-05, Archiv-URL, Sighting und Dump öffentlich prüfen.
13. GCVE-GNA-Verzeichnis um `gcve_pull_api` ergänzen beziehungsweise korrigieren.
14. Erst danach historischen Backfill und den 15-Minuten-Timer aktivieren.

## Bekannte Grenzen

- Der Parser behandelt aktuell einen Mailinglistenbeitrag als ein Finding. Beiträge mit mehreren unabhängigen Schwachstellen sollten künftig aufgeteilt werden.
- Die Produkt-/Titel-Kandidatensuche ist bewusst einfach und darf falsche Beziehungen erzeugen. Diese werden als `possibly_related` und mit Konfidenz offengelegt.
- Weitere Mailinglisten benötigen jeweils einen Source-Adapter und stabile kanonische Archiv-URLs.
- Das öffentliche Deployment ist noch nicht erfolgt.

## Sicherheits- und Betriebsregeln

- Keine API-Schlüssel in Git, SQLite, Chat oder Browser Storage speichern.
- Environment-Datei auf dem Server mit restriktiven Rechten schützen.
- Vor Massenpublikation PostgreSQL, Kvrocks, Valkey, Vulnerability-Lookup-Konfiguration und Instanz-UUID sichern.
- Dry Runs ändern keinen externen Zustand.
- Das automatische Ledger vor und nach Publikationsläufen exportieren.
- Reservierte GCVE-IDs nach Fehlern nicht neu reservieren; der Publisher verwendet die im Ledger gespeicherte ID erneut.
- Ein fremder oder unerwarteter reservierter ID-Präfix wird abgelehnt.

## Übergabeumfang

Das Git-Repository enthält Quellcode, Tests, Konfigurationsbeispiele, Deployment-Vorlagen und Dokumentation. Laufzeitdaten unter `data/`, virtuelle Python-Umgebungen, Caches, Exporte und Zugangsdaten werden durch `.gitignore` ausgeschlossen. Die oben beschriebene lokale Testbeobachtung ist deshalb dokumentiert, aber ihre SQLite-Datenbank wird nicht veröffentlicht.
