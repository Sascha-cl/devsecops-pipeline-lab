# Von GitLab CI zu GitHub Actions

Das Hochschulprojekt lief in einem selbst gehosteten GitLab. Der [redigierte historische Workflow](gitlab-ci.original.redacted.yml) ist ein Herkunftsbeleg, **keine Vorlage für eine gehärtete Produktionspipeline**. Platzhalter verbergen Betriebsadressen und Konten; `$SSH_PRIVATE_KEY` ist lediglich der Variablenname, kein veröffentlichter Schlüssel.

## Was sich geändert hat

| Hochschulprojekt | Öffentliche Lab-Fassung |
|---|---|
| `stages` und `stage:` | unabhängige Scan-Matrix; Abhängigkeiten nur beim abschließenden Check |
| Scanner-Aufrufe in `script:` | derselbe kleine Python-Runner lokal und in GitHub Actions |
| selbst gebautes `image.tar` | öffentliches Zielimage per Digest, passender Quellcode per Commit |
| Deployment per SSH auf Hochschul-VM | kurzlebiger Zielcontainer ohne veröffentlichten Host-Port |
| DAST nach Deployment | Baseline direkt im temporären Docker-Netz |
| `artifacts:` | gepinntes `actions/upload-artifact`, auch bei Fehlern |
| teilweise `allow_failure` und `|| true` | Findings und technische Ausfälle getrennt behandeln |
| veränderliche Image-Tags und Regeln | [Version-Lock](../config/scan-lock.json), geprüfte Updates |
| grüne Jobs als einziges Signal | Negativtests, Pflichtreports, Scan-Metadaten und Sammelcheck |

Die grundlegenden Aufgaben der Scanner bleiben gleich. Ihre Argumente und ihre Fehlerpolitik sind aber **nicht unverändert**: Gitleaks redigiert und blockiert, Semgrep läuft strikt mit lokalen gepinnten Regeln, Trivy berichtet statt das Lab-Ziel zu blockieren und ZAP ignoriert nur die erwarteten Warnungs-Exitcodes über `-I`.

## Warum das Deployment entfällt

Ein öffentliches Projekt kann durchaus mit eigenen Secrets deployen. Dieses Lab soll aber gerade ohne individuelle Infrastruktur und ohne Zugang zum Hochschulnetz nutzbar sein. Deshalb werden VM, SSH-Schlüssel und Deployment nicht durch neue Zugangsdaten ersetzt, sondern aus dem Scan-Aufbau entfernt.

Das zeigt Security-CI an einem Referenzziel. Es zeigt keinen produktiven Releaseprozess und keine Absicherung einer realen Deployment-Umgebung.

## Container-Netzwerk: die tatsächliche Grenze

GitHub-Service-Container sind **auch vom Host-Runner erreichbar**, wenn ihre Ports auf den Host gemappt werden. Läuft der Job selbst in einem Container, können Service-Namen direkt im gemeinsamen Netz verwendet werden. Ein zusätzlich per `docker run` gestarteter Scanner gehört aber nicht automatisch zu diesem Netz.

Hier werden Ziel und ZAP explizit demselben temporären Netz zugeordnet. Der Zielcontainer erhält den Alias `juice-shop`; kein Port wird auf den Host veröffentlicht. Das vereinfacht lokale Reproduktion und Cleanup, ist aber nicht die einzige mögliche Actions-Bauform. [GitHub-Dokumentation](https://docs.github.com/en/actions/tutorials/use-containerized-services/use-docker-service-containers)

## Dateirechte und Aufräumen

ZAP behält seinen unprivilegierten Image-Benutzer. Das Report-Verzeichnis bekommt unter Linux Modus `0770`; der Container erhält die Host-Gruppe als zusätzliche Gruppe. So kann ZAP schreiben, ohne das Verzeichnis für alle Benutzer mit `0777` zu öffnen. Docker Desktop bildet Windows-Bind-Mount-Rechte anders ab; beide Laufumgebungen müssen geprüft werden.

Container, Netzwerke und Trivy-Cache-Volumes haben pro Lauf eindeutige Namen. Der Runner räumt nur diese Ressourcen im `finally`-Block auf, auch bei Scanfehlern und Prozess-Timeouts. Ein hart beendeter lokaler Python-Prozess kann trotzdem Ressourcen hinterlassen. Es gibt bewusst kein globales `docker system prune`.

## Warum ein Health-Check sinnvoll bleibt

ZAP hat eigene technische Fehlercodes. Die Behauptung „ein unerreichbares Ziel führt automatisch zu einem erfolgreichen leeren Scan“ wäre falsch. Der zusätzliche HTTP-Check liefert stattdessen eine frühere, klarere Fehlermeldung.

Connect-Timeout, Request-Timeout, Retry-Zeitbudget und Prozess-Timeout begrenzen das Warten. ZAP hat zusätzlich ein Start-/Passive-Scan-Zeitlimit und ein Prozesslimit; der Actions-Job ist ebenfalls begrenzt. [ZAP-Exitcodes und Optionen](https://www.zaproxy.org/docs/docker/baseline-scan/)

## Historische Muster nicht übernehmen

Im redigierten Original bleiben beispielsweise `allow_failure: true`, `|| true`, `sleep 15`, ein OS-only-Gate und das VM-Deployment sichtbar. Diese Zeilen dokumentieren den damaligen Aufbau. Insbesondere pauschales Ignorieren von Scannerfehlern ist nicht die heutige Fehlerpolitik.

Der nächste Qualitätsnachweis ist nicht ein fünfter Scanner, sondern der [Regressionstest für einen ausgefallenen Scanner](case-study-fail-closed.md).
