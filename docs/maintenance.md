# Wartung und GitHub-Einrichtung

## Versionen bewusst aktualisieren

Alle Runtime-Pins stehen in [config/scan-lock.json](../config/scan-lock.json). Eine feste Version verhindert Drift, ersetzt aber keine Updates. Die wöchentliche Pipeline aktualisiert **nicht** automatisch Scanner oder Regeln; nur Trivys Advisory-Datenbank wird beim Lauf frisch geladen.

1. Releases und Änderungen beim jeweiligen offiziellen Upstream prüfen.
2. Gewünschten Image-Tag mit `docker buildx imagetools inspect <image:version>` auflösen; Digest prüfen und eintragen. Keine zufälligen Digests aus Drittquellen übernehmen.
3. Bei einem Zielupdate auch den vollständigen Juice-Shop-Commit festlegen. Das Image-Label `org.opencontainers.image.revision` muss dazu passen; der Runner prüft dies. Ein Label beweist nicht, dass ein Image tatsächlich aus unverändertem Quellcode gebaut wurde.
4. Den Semgrep-Regel-Commit unabhängig aktualisieren. Die Auswahl `javascript`/`typescript` sowie Scope-Ausschlüsse prüfen. Neue Regeln können Syntax-/Performance-Probleme sichtbar machen; nicht pauschal ignorieren.
5. `python -m unittest discover -s tests -v`, `python scripts/lint_workflows.py` und alle vier lokalen Scans ausführen.
6. Neue Zahlen nur zusammen mit Datum, Ziel-Digest, Source-/Regel-Commit und Scanner-/DB-Stand dokumentieren. Frühere Messungen nicht stillschweigend überschreiben.
7. Änderung als PR prüfen und den GitHub-Lauf abwarten.

Dependabot ist für GitHub Actions konfiguriert. Es aktualisiert **nicht** das eigene JSON-Lockfile. Die Actions bleiben auf vollständige SHAs festgelegt; Versionskommentare erleichtern die Zuordnung.

## Pflichtcheck für main

**Noch nicht durch Code aktiviert:** Der Workflow definiert `Security checks`, ein GitHub-Ruleset muss aber separat eingerichtet werden.

Nach dem ersten erfolgreichen Lauf der neuen Fassung:
- Ruleset für `main` aktivieren.
- Pull Request vor dem Merge verlangen.
- `Security checks` als erforderlichen Statuscheck auswählen.
- Bypass-Rechte bewusst begrenzen; alte Scanner-Checknamen gegebenenfalls ersetzen.

Danach einen Test-PR verwenden: Eine absichtlich fehlschlagende Regression darf nicht mergebar sein. Ein grüner lokaler Test beweist nicht, dass die Repository-Regel korrekt eingerichtet ist. Die genauen Möglichkeiten hängen von Repository-Sichtbarkeit, GitHub-Plan und Berechtigungen ab. [GitHub: Rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)

## Artefakte und Grenzen der Reproduktion

`run.json` enthält Lockfile, UTC-Zeit, Repository-Commit, Dirty-Flag, Hashes der Scan-Implementierung und Ergebnisstatus. Die SHA-256-Hashes identifizieren lokale Scriptstände, archivieren aber nicht deren Inhalt; für eine spätere Reproduktion müssen Änderungen auch versioniert werden.

Trivy speichert den verwendeten Datenbankstand als `trivy-db.json`. Die DB selbst wird nicht dauerhaft archiviert. Deshalb sind historische CVE-Zahlen nicht bitgenau aus dem Repo allein rekonstruierbar. ZAP-Crawl-Ergebnisse können ebenfalls variieren.

Artefakte laufen nach 30 Tagen ab und sind keine vertrauliche Ablage. Dauerhafte Portfolio-Belege sind kleine manuell geprüfte Auswertungen mit Kontext, keine eingecheckten Secret-Reports.

## Ressourcen und Sicherheit

Die Scans benötigen Netzwerkzugriff zu den öffentlichen Registries und Git-Repositories. Semgrep bekommt Ziel und Regeln read-only gemountet. Kein Scanner bekommt den Docker-Socket, privilegierten Modus oder ein schreibberechtigtes GitHub-Token.

Alle Container laufen mit `--cap-drop ALL`. Damit verliert auch uid 0 `CAP_DAC_OVERRIDE` und unterliegt den normalen Dateirechten. Gemountete Eingaben brauchen deshalb `0750`, Report-Verzeichnisse `0770`, jeweils passend zur mit `--group-add` ergänzten Host-Gruppe (`scripts/scan.py`: `container_inputs`, `report_directory`). Zwei Fallen dabei: `tempfile.TemporaryDirectory()` legt `0700` an, und ein an `mkdir` übergebener Modus wird von der umask reduziert (`0770` → `0750`). Beides fällt lokal unter Docker Desktop nicht auf, weil Windows- und macOS-Bind-Mounts andere Rechte melden als ein Linux-Runner.

Das Docker-Netz hat keinen veröffentlichten Ziel-Port, ist aber keine vollständige Netzwerk-Sandbox: ausgehender Verkehr ist nicht generell gesperrt. Das Lab ersetzt keine Härtung für fremde untrusted Workloads auf gemeinsam genutzten oder produktiven Runnern.

Bei einem hart abgebrochenen lokalen Lauf nur die dazugehörigen Ressourcen mit Präfix `devsecops-lab-<run-id>` prüfen und gezielt entfernen. Keine globalen Cleanup-Befehle verwenden.
