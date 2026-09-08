# Implementierungsreview und konfliktarmer Ausbauplan

Stand der Prüfung: 8. September 2026. Bewertet wurden Implementierung, Tests und
Betriebsdokumentation im Repository. Die Statusangaben bedeuten:

- **Erfüllt**: der geforderte Kern ist implementiert und automatisiert getestet.
- **Teilweise**: ein nutzbarer Teil ist vorhanden, der Anspruch für das Endprodukt
  wird aber noch nicht vollständig erreicht.
- **Offen**: es gibt noch keine tragfähige Implementierung des geforderten Kerns.

## Kurzfazit

| Nr. | Anforderung | Status | Wesentliche Lücke |
|---:|---|---|---|
| 1 | Mehrere Quellen | **Teilweise** | Full Disclosure und Bugtraq sind auswählbar; weitere Adapter und quellenübergreifende Provenienz bleiben offen. |
| 2 | Automatische Publikation als GNA 1988 | **Erfüllt** | Vor Produktion bleiben Policy-Abnahme und Ende-zu-Ende-Abnahmetest erforderlich. |
| 3 | CVE-Abgleich und LLM-Aufwertung | **Teilweise** | Pipeline existiert, aber Extraktion, Retrieval, Audit-Trail und Evaluation sind noch zu schmal. |
| 4 | Manuelles Approval bei Mehrdeutigkeit | **Teilweise** | Fachlicher Workflow existiert; Queue-Betrieb, Historie und Zustandsmodell müssen gehärtet werden. |
| 5 | Gestaltbare Website | **Offen** | Inhalte, Navigation und CSS sind fest im Python-Code eingebettet; CMS-/Theme-/Asset-Konzept fehlt. |
| 6 | Sortierbare Tabellen | **Teilweise** | Die Publikations-API sortiert Datumsfelder; UI-Tabellen und `confidence` sind nicht sortierbar. |
| 7 | Gruppierung und Pagination überall | **Teilweise** | Öffentliches Archiv und API können paginieren; Review-, Publish- und Worker-Tabellen nicht. |
| 8 | Fulltext-Index | **Teilweise** | FTS5 für Beobachtungen ist vorhanden; Abdeckung, zwingende Verfügbarkeit und DB-seitige Pagination fehlen. |

## Detailprüfung

### 1. Mehrere Quellen — teilweise

Ein Source-Adapter-Vertrag und eine Registry für Full Disclosure und Bugtraq sind
inzwischen vorhanden. RSS-, Sync- und Monatsimport akzeptieren wiederholbare
`--source`-Optionen. Beobachtungen speichern `source_id` und einen kanonischen,
pro Quelle eindeutigen Schlüssel; Message-ID verhindert Duplikate desselben
Beitrags unter einer zweiten URL. Generische, hashbasierte Archivdetailseiten
entfernen die frühere Full-Disclosure-Annahme aus öffentlichen Links.

Noch fehlen Adapter für Archive außerhalb des gemeinsamen Seclists-HTML-Formats,
quellenübergreifende Provenienz für denselben Beitrag, Checkpoints pro Quelle und
Source-Filter/Gruppierung in allen Collections. Bestehende Daten werden
rückwärtskompatibel auf `source_id='full-disclosure'` migriert.

### 2. Automatische Publikation als GNA 1988 — erfüllt

`sync` verbindet Import und Policy-gesteuerte automatische Publikation. Die
Implementierung reserviert `GCVE-1988-<Jahr>-<Sequenz>` transaktional in SQLite,
führt ein dauerhaftes Publikations-Ledger und erzeugt BCP-05-Datensätze. Bereits
publizierte Operationen werden idempotent übersprungen; fehlgeschlagene werden
nur explizit erneut versucht. BCP-03-API und NDJSON-Dump lesen denselben
kanonischen lokalen Datensatz.

Wichtig ist die fachliche Grenze: „automatisch“ bedeutet nicht, dass jeder
importierte Text publiziert wird. Policy, Relevanz, Evidenzscore, Match-Schwellen
und Mehrdeutigkeit bestimmen `archive-only`, `review-required`, Sighting,
Kontextdatensatz oder neues Advisory. Das entspricht dem dokumentierten
Vorsichtsprinzip. Vor Produktivfreigabe müssen die dauerhafte GNA-UUID, Backup/
Restore, Parallelitätsverhalten und BCP-03/BCP-05-Abnahme gegen eine realistische
Datenbank geprüft werden.

### 3. CVE-Abgleich, LLM und Aufwertung — teilweise

Vorhanden sind:

1. statische Extraktion von CVE, GCVE, GHSA, CWE, CVSS, Versionen,
   Schwachstellenklassen und PoC-Indikatoren;
2. exakte Auflösung expliziter IDs über Vulnerability-Lookup;
3. begrenztes Kandidaten-Retrieval nach Produkt sowie deterministisches Scoring
   von Titel-, Produkt-, CWE- und Versionssignalen;
4. optionaler LLM-Vergleich von höchstens zehn vorgegebenen Kandidaten mit
   strengem JSON-Schema, `store: false`, Prompt-Injection-Hinweis und den Modi
   `off`, `shadow`, `review`, `automatic`;
5. Confidence-/Margin-Gates und konservative `possibly_related`-Beziehungen für
   inferierte Treffer.

Ein append-only Analyseprotokoll speichert inzwischen Retrieval-Zeitpunkt,
vollständigen begrenzten Kandidatensatz, deterministische und finale Matches,
Provider, Modell, Promptversion, Input-Hash, Response-ID, strukturierten
LLM-Output und Fehler pro Import beziehungsweise Reprocessing. Gelabelte
Vendor-, Produkt-, Komponenten-, Alias-, Versionsbereich-, Fixed-Version- und
Commit-Angaben werden strukturiert extrahiert. Kandidaten mit deterministischen
Produkt-, Vendor-, Komponenten- oder Versionswidersprüchen werden vor dem LLM
ausgeschlossen und mit Begründung protokolliert; chronologisch spätere
Kandidaten werden als Widerspruch markiert. Noch offen sind unstrukturierte
Aliasauflösung, semantisch belastbare Versionsbereichsvergleiche, breiteres
Retrieval sowie ein ausreichend großer produktionsnaher Label-Korpus. Ein
Offline-Evaluator berechnet Precision/Recall und liefert maschinenlesbare
Einzelergebnisse; `automatic` verlangt nun einen bestandenen Report für die
aktuelle Promptversion mit mindestens 0,98 Precision und 0,80 Recall. Die
Datenschutzfreigabe und der Ausbau des Label-Korpus bleiben Produktions-Gates.

### 4. Manueller Approval-Prozess — teilweise

Die geschützte Review-Oberfläche bietet Filter, Volltextsuche, Kandidatenauswahl,
Mehrfachzuordnung, explizite Zuordnung, Notiz, Approval und Rejection. Null
ausgewählte IDs führen bewusst zu einem neuen Advisory; analystisch bestätigte
IDs werden als `analyst-approved` in die Publikationsplanung übernommen.
Approval publiziert nicht implizit, sondern erfordert eine nachgelagerte lokale
Publikationsaktion. Netzwerk-Allowlist, Basic Auth und CSRF-Schutz sind vorhanden.

Eine append-only Entscheidungshistorie speichert inzwischen Einzel- und
Batch-Entscheidungen einschließlich authentifiziertem Reviewer, IDs, Sighting-Typ
und Notiz; die Detailansicht zeigt diese Historie. Batch-Aktionen und eine
paginierte Queue sind ebenfalls vorhanden. Reviewer- und Administrator-Konten
können über die geschützte Web-UI verwaltet
werden; ein optionales Vier-Augen-Prinzip verlangt zwei unterschiedliche
Reviewer. Für ein Endprodukt fehlen weiterhin Claiming/Zuweisung und eine
feinere Berechtigungsmatrix.
Außerdem sollte ein expliziter Zustandsautomat verhindern, dass Reprocessing,
Approval und automatische Jobs einander semantisch überschreiben. Ein
unveränderliches Match-/LLM-Ereignisprotokoll muss neben der finalen Entscheidung
erhalten bleiben.

### 5. Gestaltbare Website — offen

Öffentliche Startseite, Navigation, Texte und CSS werden als Stringliterale in
`public_ui.py` erzeugt. Es gibt weder Seitenmodell noch Templates, Asset-Pipeline,
Logo-Konfiguration, Impressum, FAQ oder verwaltbare Linkblöcke. Die vorhandene
kleine responsive Oberfläche ist ein funktionaler Prototyp, keine
Gestaltungsplattform.

Benötigt wird ein bewusst kleines Content-/Theme-System: versionierte Templates,
statische Assets, eine validierte Site-Konfiguration und Markdown-Seiten für
Info, FAQ, Impressum und Datenschutz. Redaktionelle Inhalte sollten deploybar
sein, ohne Import-, Matching- oder Publikationslogik zu ändern. Sicherheitsheader
und Escaping dürfen durch die Umstellung nicht geschwächt werden.

### 6. Sortierbare Tabellen — teilweise

Die öffentliche Publikations-API unterstützt `date_sort` und `sort_order` mit
stabiler ID als Tie-Breaker. Die Archivliste ist dagegen fest absteigend nach
Publikationsdatum sortiert. Review-, automatische Publikations- und Worker-
Tabellen haben keine klickbaren Spalten oder validierten Sortierparameter.
`confidence` wird in der Review-Liste lediglich als Maximum der Matches
berechnet.

Alle Listen brauchen serverseitige, erlaubnislistenbasierte Sortierung mit
stabilem sekundärem Schlüssel. Mindestens Datum, Quelle, Status, Review-Status,
Titel und maximale Confidence sollten unterstützt werden. SQL-Spalten dürfen
nur aus einer internen Allowlist gewählt und niemals direkt aus Query-Strings
interpoliert werden.

### 7. Gruppierung und Pagination überall — teilweise

Das öffentliche Archiv gruppiert nach Monat und paginiert nach dem Laden und
Sortieren aller Treffer. Die BCP-03-Abfrage kennt `page`/`per_page`. Für Review-
Queue, Publikationsdashboard und Worker-Liste fehlen Pagination und frei wählbare
Gruppierung. Die Detailseiten benötigen naturgemäß keine Pagination; „überall“
sollte deshalb als „jede potenziell unbeschränkte Collection“ präzisiert werden.

Die gemeinsame Lösung sollte Filter, Sortierung, Gruppierung, `page` und
`per_page` in einem `ListQuery`-Objekt validieren. Count und Seitenauswahl müssen
in SQL stattfinden, statt zunächst die gesamte Collection in Python zu laden.
Gruppierungen sollten zunächst Quelle, Monat, Status und Review-Status umfassen.

### 8. Fulltext-Index — teilweise

SQLite FTS5 indexiert URL, Titel, Autor, Body und Extraktionsmetadaten. Trigger
halten den Index synchron; beim Start wird eine abweichende Zeilenzahl neu
aufgebaut. Öffentliches Archiv und Review-Queue verwenden die Suche. Wenn FTS5
nicht verfügbar ist, fällt die Anwendung jedoch still auf eine langsamere
`LIKE`-Suche zurück. GCVE-Datensätze, redaktionelle Seiten, Review-Notizen und
vollständig normalisierte Identifikatoren sind nicht als eigener Suchkorpus
modelliert.

Für den Produktionsanspruch muss definiert werden, welche Entitäten durchsuchbar
sind. FTS5 sollte beim Deployment als Capability geprüft und überwacht werden;
Rebuild/Integrity-Check benötigen ein Operator-Kommando. Trefferzahl,
SQL-Pagination, Ranking und sichere Behandlung ungültiger FTS-Syntax gehören in
die Abnahmetests.

## Übergreifende Abweichungen und Risiken

1. **Quellenspezifische Annahmen durchdringen alle Schichten.** Ein einzelner
   Bugtraq-Parser reicht nicht; Modell, Routing, Publikationsreferenzen, Worker,
   UI und Tests müssen gemeinsam abstrahiert werden.
2. **Listen werden häufig vollständig materialisiert.** Das funktioniert für den
   Pilot, skaliert aber nicht für ein Vollarchiv und verhindert konsistente
   DB-seitige Pagination.
3. **Aktueller Zustand ersetzt Historie.** Review und Match-Reprocessing brauchen
   immutable Events, damit Entscheidungen später erklärbar bleiben.
4. **Dokumentation und Audit-Schema sind nicht deckungsgleich.** Insbesondere der
   versprochene vollständige LLM-/Retrieval-Audit-Trail ist noch nicht vorhanden.
5. **Ein Post entspricht einem Finding.** Beiträge mit mehreren unabhängigen
   Schwachstellen werden nicht aufgeteilt; Multi-Source-Import erhöht dieses
   Fehlzuordnungsrisiko.

## Konfliktarmer Umsetzungsplan

### Begonnene Umsetzung

Der erste vertikale Schnitt aus Phase 1 und Phase 4 ist umgesetzt: Ein
validiertes `ListQuery` kapselt Filter, Sortierung, Richtung und Seitengröße. Die
Review-Queue verwendet DB-seitiges Counting und Pagination, stabile Sortierung
mit Allowlist sowie sortierbare Spalten für Titel, Confidence und Review-Status.
Review-Entscheidungen werden zusätzlich append-only mit Reviewer und fachlichen
Entscheidungsdaten protokolliert; der aktuelle Zustand bleibt als performante
Projektion auf der Beobachtung bestehen.
Auch Import und Reprocessing erzeugen nun append-only Analyseereignisse mit dem
vollständigen Matching- und LLM-Auditkontext.
Der erste Schnitt aus Phase 2 ist ebenfalls umgesetzt: Source-Registry,
Full-Disclosure-/Bugtraq-Adapter, wiederholbare CLI-Quellenauswahl, additive
Source-Migration, Message-ID-Deduplizierung und generische Archivdetailrouten.
Die bestehenden Store-Methoden bleiben vorerst kompatibel, damit die weiteren
Collections einzeln und ohne Big-Bang-Umstellung migriert werden können.

Die Arbeit wird entlang stabiler Schnittstellen geschnitten. Jede Phase beginnt
mit Vertragstests und endet mit einer Migration/Abnahme. Parallele Änderungen an
`store.py`, `public_ui.py` und `review_ui.py` werden vermieden; diese Dateien sind
derzeit zentrale Konfliktherde.

### Phase 0 — Verträge und Sicherheitsnetz (kurzfristig)

- Decision Records für `SourceAdapter`, `ListQuery`, Audit Events und
  Finding-vs.-Message-Modell festlegen.
- Bestehendes Verhalten durch Contract-Tests für FD-Import, Review-Zustände,
  automatische Publikation, BCP-03 und FTS einfrieren.
- Eine repräsentative Testdatenbank und anonymisierte, gelabelte Match-Stichprobe
  anlegen; Präzisionsziel und Freigabekriterien definieren.
- GNA-Identität, Policy, Datenschutz, Backup/Restore und Rollback als
  Produktions-Gates dokumentieren.

### Phase 1 — Datenmodell und gemeinsame Query-Schicht

- Additive Migrationen: `sources`, `source_items`, `findings`,
  `analysis_events`, `review_events`; bestehende Beobachtungen auf
  `full-disclosure` zurückfüllen. Alte Lesepfade bleiben während der Migration
  kompatibel.
- Ein getestetes Repository-Modul für Filter, erlaubte Sortierfelder, stabile
  Tie-Breaker, Count und SQL-Pagination einführen.
- Review-/LLM-Events append-only speichern; finalen Zustand weiterhin als
  Projektion für schnelle Abfragen anbieten.

**Konfliktregel:** Ein Arbeitspaket besitzt Migration und Repository. UI-Teams
verwenden nur die neue Schnittstelle und ändern das Schema nicht parallel.

### Phase 2 — Quellenadapter

- `SourceAdapter` mit `discover`, `fetch`, `parse`, `canonical_key` und
  `public_path` definieren; den aktuellen FD-Code ohne Verhaltensänderung in den
  ersten Adapter verschieben.
- Bugtraq als zweiten Adapter mit gespeicherten Fixtures, Message-ID-basierter
  Deduplizierung und Herkunftsmetadaten implementieren.
- CLI/Worker auf wiederholbare `--source`-Angaben beziehungsweise konfigurierte
  Quellen umstellen. Fehler und Checkpoints pro Quelle isolieren.
- Generische öffentliche Detailroute über opaque Item-ID anbieten und alte
  Full-Disclosure-URLs dauerhaft weiterleiten oder kompatibel bedienen.

### Phase 3 — Matching und kontrolliertes Approval

- Vendor, Komponente, Aliase, Fixed-Version, Commit und Chronologie strukturiert
  extrahieren; Kandidatenretrieval cachen und als Event protokollieren.
- Deterministische harte Widersprüche vor dem LLM anwenden. Vollständigen
  strukturierten LLM-Output, Prompt-/Provider-Version, Kandidaten und Policy-
  Version revisionssicher speichern.
- Gelabelten Datensatz offline auswerten. `automatic` erst nach bestandenem
  Präzisions-, Margin-, Datenschutz-, Kosten- und Ausfalltest freigeben.
- Review-State-Machine, Reviewer-Identität, Historie, Claiming und optionales
  Vier-Augen-Prinzip ergänzen. Reprocessing erzeugt neue Analyse-Events und
  überschreibt keine Entscheidungshistorie.

### Phase 4 — Collections: Sortierung, Gruppierung, Pagination, Suche

- Zuerst Review-Queue, danach Publish-Dashboard, Worker-Liste, öffentliches
  Archiv und Publikationsansicht auf `ListQuery` migrieren.
- UI-Links für erlaubte Sortierspalten (einschließlich Confidence), Gruppen und
  Seitengröße hinzufügen; Filterzustand in allen Links erhalten.
- FTS-Capability-Check, Operator-Rebuild, Integritätsprüfung, Ranking und
  DB-seitige Pagination ergänzen. Danach entscheiden, ob GCVE-Datensätze und
  redaktionelle Inhalte in getrennte FTS-Indizes aufgenommen werden.

**Konfliktregel:** Pro Collection ein eigenes, kleines Change-Set. Änderungen an
gemeinsamen Query-Verträgen werden vorher separat integriert; öffentliche und
administrative UI werden nicht gleichzeitig in derselben Datei bearbeitet.

### Phase 5 — Design- und Content-System

- Python-Stringtemplates in ein kleines Template-Paket verschieben; gemeinsame
  Layout-, Navigations- und Komponentenverträge definieren.
- Validierte Site-Konfiguration, versionierte Markdown-Seiten und statische
  Assets für Logo/Favicon einführen. Startseite, Info, FAQ, Impressum,
  Datenschutz und Links über Konfiguration/Inhalt pflegen.
- Accessibility-, CSP-, Escaping-, Responsive- und Screenshot-Regressionstests
  ergänzen. Content-Deploy und Anwendungscode getrennt versionieren, soweit der
  Betriebsprozess dies erlaubt.

### Phase 6 — Ende-zu-Ende-Abnahme

- Zwei Quellen parallel importieren; Spiegelduplikat, Multi-Finding-Post,
  eindeutige CVE, mehrdeutige Kandidaten, LLM-Ausfall und Reprocessing prüfen.
- Nachweisen, dass Mehrdeutigkeit in Review landet, Approval nachvollziehbar ist
  und genau einmal als GNA 1988 publiziert wird.
- Lasttest für Millionen Beobachtungen mit begrenzten Query-Zeiten und konstantem
  Speicherbedarf; Backup/Restore und Upgrade/Rollback testen.
- Öffentliche API, Dump, Archiv, Inhaltsseiten und administrative Collections
  gegen Pagination-, Sortier-, Gruppierungs- und Suchvertrag abnehmen.

## Empfohlene Reihenfolge der nächsten Changes

1. Contract-Tests und ADRs, ohne Produktionsverhalten zu ändern.
2. `ListQuery` plus DB-seitige Review-Pagination als erster vertikaler Schnitt.
3. Additives Source-/Event-Schema mit FD-Backfill.
4. FD-Adapter-Extraktion; erst danach Bugtraq hinzufügen.
5. Audit-Events und gelabelte Matching-Evaluation vor weiterer Automatisierung.
6. Übrige Collections migrieren.
7. Template-/Content-System zuletzt auf den dann stabilen Routen und Queries
   aufbauen.

Diese Reihenfolge reduziert Merge-Konflikte und, wichtiger, verhindert, dass
eine optisch neue Oberfläche oder ein zusätzlicher Parser auf dem derzeit noch
quellenspezifischen und nicht historisierten Datenmodell verfestigt wird.
