# Findings: Beobachtung, Verdacht und bestätigte Auswirkung

## Messkontext

Die [lokale Verifikation](evidence/local-verification-2026-09-11.json) hält die finalen Scan-Zusammenfassungen, Zeitpunkte, Implementierungs- und Report-Hashes fest. Sie ist ein Prüfprotokoll, keine signierte Attestierung.

Die ursprünglichen Zahlen stammen aus Scans mit veränderlichen Tags. Der [GitHub-Referenzlauf vom 11.09.2026](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/runs/34605150362) wurde vor der Härtung geprüft. Die folgenden neuen Messungen sind **lokale Docker-Läufe vom 11.09.2026**, nicht bereits ein GitHub-Lauf der neuen Fassung.

Festgelegtes Ziel:
- Image: `bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`
- Quellcode: `5658473cf8814459bf89000ce373b20ed0b4eb37`
- Image-Label: Juice Shop 20.2.0; Referenzplattform linux/amd64
- Scanner-Digests und Regel-Commit: [scan-lock.json](../config/scan-lock.json)

Scanner-Zahlen zählen je nach Format Regeln, Alert-Typen, Fundstellen oder Paket-/Advisory-Kombinationen. Sie sind keine Anzahl voneinander unabhängiger, bestätigter Angriffe.

## Trivy: ein OS-only-Gate übersieht Anwendungspakete

Trivy 0.74.0, Debian 13.6, Datenbank `UpdatedAt: 2026-09-11T07:00:51.617232631Z`:

| Ebene | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Gesamt |
|---|---:|---:|---:|---:|---:|---:|
| OS-Pakete | 0 | 1 | 16 | 13 | 1 | 31 |
| npm-Pakete | 8 | 44 | 38 | 7 | 0 | 97 |
| **Gesamt** | **8** | **45** | **54** | **20** | **1** | **128** |

Der frühere Workflow filterte auf CRITICAL/HIGH/MEDIUM/LOW und meldete deshalb **127**. Der neue Aufruf lässt auch UNKNOWN sichtbar. Die zusätzliche Zeile ist hier eine Änderung des Filters, nicht der Nachweis einer neu entstandenen Schwachstelle.

Im historischen Workflow stand:

```bash
trivy image --pkg-types os --severity CRITICAL --ignore-unfixed --exit-code 1
```

Auf diese Messung angewendet würde die Kontrolle keine kritischen npm-Findings blockieren: `--pkg-types os` schließt diese Ebene aus. Ein weiterer Dependency-Scanner kann ergänzen, aber seine bloße Existenz beweist noch nicht die vollständige Abdeckung oder eine wirksame Gate-Policy.

Das Lab dokumentiert die Findings statt Juice Shop bei jeder bekannten Schwachstelle zu blockieren. Für eigene releasbare Software braucht es dagegen eine begründete Policy inklusive Anwendungspaketen, Ausnahmen und Zuständigkeit.

Die acht kritischen Einträge sind zudem keine acht eindeutigen CVEs: Ein Advisory kann mehrere Paketversionen treffen. Die Scanner-Severity und eine angebotene Fix-Version allein belegen weder Erreichbarkeit noch Ausnutzbarkeit im Anwendungskontext.

## Semgrep: Scope und Einordnung

Der neue lokale Lauf mit Semgrep **1.176.0** meldete **76 Findings**, davon **37 in routes/**, bei **865 gemeldeten gescannten Dateien**. Im SARIF stehen 212 Regeldefinitionen; die CLI nennt 211 ausgeführte Regeln. JSON und SARIF enthalten keine technischen Scanfehler.

Die früheren „11 Findings in routes/“ bezogen sich auf andere, veränderliche Registry-Packs. Sie sind nicht direkt mit diesem neuen Regelstand vergleichbar. Hier werden die Verzeichnisse `javascript` und `typescript` aus `semgrep/semgrep-rules` am Commit `40b8c63f75dc7c22c8a77482d73bfb864b146f7e` verwendet. Die Regeln werden nicht als eigener Code vendort oder neu lizenziert.

Explizit außerhalb des SAST-Scopes:
- `data/static/codefixes`: Schulungs-Codefragmente, teils absichtlich unvollständige Syntax.
- `test`, `tests`, `.git`, `node_modules`: Tests, Versionsdaten und installierte Fremdabhängigkeiten.
- `frontend/src/assets/private/three.js`: große vendorte Drittbibliothek. Ein erster strikter Lauf meldete dort drei Regel-Timeouts und wurde korrekt als fehlgeschlagen behandelt. Die bewusste Scope-Entscheidung ist kein Fix dieser Datei und kein Nachweis, dass Trivy alle ihre Risiken abdeckt.

Zusätzlich gelten Semgreps Größenlimit und Ignore-Regeln aus dem festgelegten Zielstand. Der lokale Lauf meldete zwei zu große Dateien und zwei durch Semgrepignore ausgeschlossene Dateien. `--no-git-ignore` deaktiviert nicht alle anderen Filter. „Keine technischen Fehler“ bedeutet nicht „jede Zeile der Anwendung wurde geprüft“.

### Beispiel: res.sendFile ist zunächst ein Prüfauftrag

Vier Findings betreffen:
- `routes/fileServer.ts:32`
- `routes/keyServer.ts:14`
- `routes/logfileServer.ts:14`
- `routes/quarantineServer.ts:14`

Der Ausdruck `res.sendFile(path.resolve('ftp/', file))` verdient eine Prüfung. Vorher gibt es im [File-Server des festgelegten Zielstands](https://github.com/juice-shop/juice-shop/blob/5658473cf8814459bf89000ce373b20ed0b4eb37/routes/fileServer.ts) aber bereits eine Slash-Prüfung und Einschränkungen zulässiger Dateinamen beziehungsweise Endungen.

**Status: SAST-Verdacht, keine in diesem Repo bestätigte beliebige Dateileselücke.** Für einen belastbaren Befund müssten Parameterherkunft, Routing/Decoding, Filter, Betriebssystem und erreichbarer Dateizugriff geprüft werden. Ein reproduzierbarer Request/Response-Beleg fehlt hier bewusst noch.

PortSwigger-Übungen zur gleichen Schwachstellenklasse helfen beim Verständnis. Ein anderswo gelöster Path-Traversal-Lab ist aber kein Beleg dafür, dass dieser konkrete Endpunkt mit derselben Eingabe ausnutzbar ist.

## ZAP: passive Baseline, kein Exploit-Nachweis

Der neue lokale Lauf mit ZAP 2.17.0 meldete:
- 88 besuchte URLs im CLI-Lauf
- `FAIL-NEW: 0, WARN-NEW: 8, PASS: 59`
- 11 Alert-Objekte im JSON, weil einzelne Regeln mehrere Alert-Untertypen erzeugen

Beispiele sind fehlende CSP-/Cross-Origin-Header, Hinweise auf JavaScript-Funktionen und Cache-Verhalten. `WARN` ist die konfigurierte Baseline-Behandlung, nicht automatisch eine hohe Vulnerability-Severity. `PASS` bedeutet nicht, dass die gesamte betreffende Schwachstellenklasse ausgeschlossen ist.

Eine URL wie `/juice-shop/build/routes/fileServer.js:68:18` taucht im Report auf. Der konkrete Eintrag betrifft fehlende Header beziehungsweise die Erkennung einer modernen Webanwendung. Das ist **kein Nachweis für einen erfolgreichen Traversal-Angriff**. Auch ein vermuteter Stacktrace-Leak sollte mit der auslösenden Response belegt werden, bevor daraus eine bestätigte Auswirkung wird.

Die Baseline ist unauthentifiziert, nutzt den traditionellen Spider und greift nicht aktiv an. Login-Bereiche, viele SPA-/API-Pfade, Geschäftslogik und aktive Exploit-Verifikation bleiben außerhalb dieses Nachweises.

## Der belastbare Schluss

Die Scanner liefern unterschiedliche Hinweise zum selben festgelegten Ziel. Korrelation hilft bei der Untersuchung, ersetzt sie aber nicht. Die verifizierte eigene Verbesserung in diesem Repo ist die [Fehlerbehandlung der Pipeline](case-study-fail-closed.md), nicht eine behauptete Ausnutzung oder Reparatur von Juice Shop.
