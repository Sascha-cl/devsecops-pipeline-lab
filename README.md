# devsecops-pipeline-lab

[![Security Pipeline](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/workflows/security-pipeline.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Security-CI mit Gitleaks, Semgrep, Trivy und OWASP ZAP — inklusive Tests dafür, wann ein Scan rot werden muss.** Das Referenzziel ist der absichtlich verwundbare OWASP Juice Shop. Keine eigene VM, keine Deployment-Secrets, keine öffentlich exponierte Testanwendung.

> **Was „grün“ bedeutet:** Scanner und Report-Prüfungen sind erfolgreich durchgelaufen; Gitleaks hat keine Secrets erkannt. Die Findings des absichtlich unsicheren Ziels sind erlaubt. Grün ist **keine Sicherheitsfreigabe** für Juice Shop und kein Nachweis eines vollständigen Pentests.

## In zwei Minuten orientieren

- [Workflow](.github/workflows/security-pipeline.yml) und [gemeinsamer Scan-Runner](scripts/scan.py)
- [Fallstudie: ein grüner Job trotz kaputtem Scanner](docs/case-study-fail-closed.md)
- [Findings einordnen: OS-Gate, SAST-Verdacht und DAST-Grenzen](docs/findings.md)
- Prüfprotokolle mit Report-Hashes: [lokal](docs/evidence/local-verification-2026-09-11.json), [CI](docs/evidence/ci-verification-2026-09-12.json), [Merge-Gate](docs/evidence/merge-gate-proof-2026-09-12.json)
- [Portierung von GitLab CI](docs/portierung-gitlab-zu-github-actions.md)
- [Versionen aktualisieren und Merge-Regeln einrichten](docs/maintenance.md)

## Selbst ausprobieren

Voraussetzungen: Python **3.10+**, Git und Docker mit Linux-Containern; Internetzugriff für öffentliche Images, Quellcode, Regeln und Vulnerability-Datenbank. Keine Python-Pakete, Scanner-Konten oder selbst hinterlegten Secrets erforderlich. Referenzplattform: **linux/amd64**; ARM benötigt Docker-Emulation.

```bash
git clone https://github.com/Sascha-cl/devsecops-pipeline-lab.git
cd devsecops-pipeline-lab

# Schnell, offline und ohne Docker: Report- und Fehlerbehandlung testen.
python -m unittest discover -s tests -v

# Dieselben Aufrufe wie in der CI; unter Linux ggf. python3 verwenden.
python scripts/scan.py gitleaks
python scripts/scan.py semgrep
python scripts/scan.py trivy
python scripts/scan.py zap
```

Der erste Scan lädt Images und kann einige Minuten dauern. Auf Windows funktioniert der Python-Aufruf aus PowerShell mit Docker Desktop im Linux-Modus.

Jeder Lauf erhält ein **neues** Verzeichnis unter `reports/<scanner>/<run-id>/`: Reports, Zusammenfassung und `run.json` mit Version-Pins, UTC-Zeit, Status, Repository-Commit und Kennzeichnung lokaler Änderungen. Trivy ergänzt seinen Datenbankstand; SAST, Trivy und ZAP prüfen die Revision des Zielimages. Alte Ergebnisse können einen neuen fehlgeschlagenen Lauf nicht grün machen.

Auf GitHub: Fork erstellen, Actions bei Bedarf aktivieren, **Security Pipeline → Run workflow**. Ergebnisse stehen in der Job-Zusammenfassung und den Artefakten. Die gehärtete Fassung lief am 11.09.2026 als [Run 34616453058](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/runs/34616453058) grün durch: sechs Jobs, vier Artefakte, [Protokoll](docs/evidence/ci-verification-2026-09-11.json). Der [Lauf davor](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/runs/34615142596) war rot, obwohl lokal alles grün war; die Ursache steht in der [Fallstudie](docs/case-study-fail-closed.md).

## Architektur und Fehlerpolitik

```text
push / pull_request / Wochenplan / manuell
   ├─ Pipeline regression tests
   └─ Scan-Matrix (unabhängig, fail-fast: false)
        ├─ Gitleaks → Repo-Historie + aktuelle Dateien
        ├─ Semgrep  → festgelegter Juice-Shop-Quellcode + feste Regeln
        ├─ Trivy    → festgelegtes Juice-Shop-Image
        └─ ZAP      → dasselbe Image im temporären Docker-Netz
                         └─ http://juice-shop:3000 (kein Host-Port)
   └─ Security checks → Tests UND alle vier Scanner müssen erfolgreich sein
```

| Situation | Ergebnis |
|---|---|
| Secret-Fund im eigenen Repo | **Fehler**; Gitleaks ist hier ein Gate |
| Erwartetes SAST-/SCA-/Baseline-Finding im Lab-Ziel | Report, kein blockierendes Vulnerability-Gate |
| Scanner-Absturz, Downloadfehler, ungültige Regeln oder Prozess-Timeout | **Fehler** |
| Semgrep-Parsefehler, Regel-Timeout oder null gescannte Dateien | **Fehler**, keine vorgetäuschte Abdeckung |
| Fehlender, leerer oder strukturell unvollständiger Pflichtreport | **Fehler** |
| Zielcontainer nicht erreichbar | **Fehler** vor ZAP |
| Fehlgeschlagener oder übersprungener Scanner/Testjob | Sammelcheck **nicht erfolgreich** |

Die Matrix und die Tests laufen parallel. Nur der abschließende Check wartet auf beide. Ein tatsächlich verpflichtender Merge-Check erfordert zusätzlich ein GitHub-Ruleset; die YAML allein schützt `main` nicht. Für dieses Repository ist das Ruleset aktiv und mit einem absichtlich fehlschlagenden [Test-PR](https://github.com/Sascha-cl/devsecops-pipeline-lab/pull/4) geprüft: Semgrep meldete Erfolg bei null gescannten Dateien, die Report-Prüfung lehnte ab, der Merge war blockiert. Einzelheiten in [maintenance.md](docs/maintenance.md) und der [Fallstudie](docs/case-study-fail-closed.md).

## Was festgelegt ist — und was sich weiterhin ändert

[config/scan-lock.json](config/scan-lock.json) fixiert alle Container per Digest sowie Zielquellcode und Semgrep-Regeln per vollständigem Commit-SHA. Actions sind ebenfalls per SHA gepinnt. Das Zielimage meldet eine passende Quellcode-Revision; das ist ein Konsistenzcheck anhand eines Upstream-Labels, **kein kryptografischer Build-Provenance-Nachweis**.

Semgrep verwendet die JavaScript-/TypeScript-Regeln eines festen `semgrep-rules`-Commits statt veränderlicher Registry-Packs. Schulungs-Codefragmente, Tests und eine große vendorte Bibliothek sind explizit außerhalb dieses SAST-Scopes. Einzelheiten und Grenzen stehen in der [Auswertung](docs/findings.md).

Die Trivy-Datenbank wird bewusst aktualisiert. Neue Advisories können deshalb trotz identischem Image andere Zahlen liefern. DB-Metadaten werden archiviert, die gesamte Datenbank nicht: Ein historisches Ergebnis lässt sich nachvollziehen, aber nicht allein mit diesem Repo bitgenau nachrechnen. Auch zeitbegrenztes Crawling und das Runner-Image können variieren.

## Herkunft und Eigenanteil

Die Grundlage ist ein Teamprojekt aus dem 4. Semester an der TH Aschaffenburg (IT-Sicherheit, SoSe 2026). Wir haben zu fünft GitLab-Pipelines für eine Spring-Boot-Anwendung und Juice Shop sowie ein Findings-Dashboard gebaut.

Mein Anteil im Hochschulprojekt war die DAST-Stage mit OWASP ZAP für beide Anwendungen, die Container-Scan-Auswertung und das Patchen kritischer CVEs. Dieses Repo zeigt den neu aufgebauten Security-CI-Ausschnitt, nicht den fremden Anwendungscode oder das Team-Dashboard. Der frühere CVE-Patch ist hier **noch nicht als öffentliche Vorher/Nachher-Fallstudie belegt**. Die neue Fallstudie dokumentiert stattdessen die überprüfbare Fehlerbehandlung dieser Pipeline.

Die Hochschul-VM und ihre SSH-Zugangsdaten wurden durch einen kurzlebigen Zielcontainer ersetzt. Das macht den Scan unabhängig vom Hochschulnetz. Es ist bewusst **keine vollständige Build-/Deploy-Pipeline**.

## Reports sind keine Secret-Ablage

Gitleaks scannt die verfügbare Git-Historie mit `fetch-depth: 0` und zusätzlich den aktuellen Arbeitsstand. Beide Aufrufe verwenden `--redact`; ein Muster-Treffer blockiert. Das Entfernen eines Secrets aus der aktuellen Datei entfernt es nicht aus der Historie. Ein echter Fund erfordert insbesondere Widerruf beziehungsweise Rotation.

Reports bleiben außerhalb der Versionskontrolle und werden 30 Tage als CI-Artefakte aufbewahrt. Artefakte eines öffentlichen Repos sind **nicht vertraulich**. Nur redigierte Reports beziehungsweise Ergebnisse des öffentlichen Lab-Ziels gehören hierhin. Ein grüner Gitleaks-Scan besagt weiterhin nur, dass seine Regeln nichts erkannt haben.

## Bewusste Grenzen und nächste Schritte

- ZAP: unauthentifizierte passive Baseline mit traditionellem Spider; keine vollständige SPA-, API-, Login- oder aktive Angriffstest-Abdeckung.
- Ein SAST-Finding ist ein Prüfauftrag, kein bestätigter Exploit. PortSwigger-Übungserfahrung ersetzt keine Verifikation am konkreten Ziel.
- Lokale Regressionstests simulieren Fehlerfälle; sie sind kein vollständiger Test aller Scanner-Interna.
- Ein grüner Lauf auf einem Windows-Host beweist nichts über einen Linux-Runner: Bind-Mount-Rechte unterscheiden sich, ein echter Fehler daraus ist in der [Fallstudie](docs/case-study-fail-closed.md) dokumentiert.
- Die Report-Prüfung blockiert den Totalausfall der Abdeckung, nicht deren schleichenden Verlust: ein Exclude, das nur noch wenige Dateien übrig lässt, gilt weiterhin als gültiger Scan.
- Offen: eine separate Anwendungs-Fallstudie mit reproduziertem Finding, Fix und erneutem Scan.

## Lizenz

MIT für den eigenen Code, siehe [LICENSE](LICENSE). Juice Shop und Semgrep-Regeln werden zur Laufzeit aus ihren öffentlichen Upstream-Repositories geladen und behalten ihre jeweiligen Lizenzen; sie werden hier nicht als eigener Code ausgegeben.
