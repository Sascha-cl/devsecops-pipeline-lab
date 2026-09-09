# devsecops-pipeline-lab

[![Secret Detection](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/workflows/secret-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Eine CI-Pipeline, die Security-Scanner über den kompletten Durchlauf einbindet: Secret Detection, statische Analyse, Abhängigkeits- und Container-Scan, dynamischer Test gegen die laufende Anwendung. Alles läuft ohne eigene Infrastruktur direkt in der CI.

## Woher das kommt

Die Grundlage ist ein Teamprojekt aus dem 4. Semester an der TH Aschaffenburg (Modul IT-Sicherheit, SoSe 2026). Dort haben wir zu fünft zwei GitLab-Pipelines gebaut, eine für eine Spring-Boot-Anwendung und eine für den OWASP Juice Shop, dazu ein Dashboard, das die Findings der einzelnen Scanner zusammenführt.

Mein Anteil daran war die DAST-Stage mit OWASP ZAP für beide Anwendungen, die Auswertung der Container-Scans und das Patchen der gefundenen kritischen CVEs. Dieses Repo enthält ausschließlich diesen Teil, neu aufgebaut und portiert. Das Dashboard und der Anwendungscode meiner Kommilitonen sind nicht enthalten, weil sie mir nicht gehören.

## Das Problem, das den Nachbau nötig gemacht hat

Die Original-Pipeline läuft außerhalb des Hochschulnetzes nicht. Sie deployt per SSH auf eine VM und scannt danach deren interne Adresse:

```yaml
deploy_vm:
  - echo "$SSH_PRIVATE_KEY" | base64 -d > ~/.ssh/agilesec.key
  - scp image.tar $VM_USER@$VM_IP:~/image.tar

dast_zap_baseline:
  needs: [deploy_vm]
  DAST_TARGET: "$DAST_TARGET_URL_JUICESHOP"
```

Ein öffentliches Repo kann weder den Key noch die VM haben. Eine Pipeline, die bei jedem Klon rot läuft, belegt gar nichts.

Die Lösung steckte schon im eigenen Fuzzing-Job: die zu testende Anwendung als Service-Container im CI-Netz starten, statt sie irgendwohin zu deployen. Damit fällt der komplette Deploy-Schritt weg, mit ihm der SSH-Key, die VM und jede Variable, die ein Geheimnis enthält. Der Scan läuft gegen `http://juice-shop-app:3000` im selben Netzwerk wie der Job.

## Architektur

```
push / pull_request / cron
        │
        ├─ secret detection ....... Gitleaks über die volle Git-Historie
        ├─ sast ................... Semgrep                    (geplant)
        ├─ dependency scan ........ OWASP Dependency-Check      (geplant)
        ├─ container scan ......... Trivy gegen das Image       (geplant)
        └─ dast ................... ZAP gegen Service-Container (geplant)
                                          │
                                    juice-shop:3000
                                    (öffentliches Upstream-Image,
                                     wird referenziert, nicht kopiert)
```

## Was aktuell läuft

Secret Detection mit Gitleaks, bei jedem Push und zusätzlich montags früh. Der geplante Lauf ist Absicht. Ein Scanner, der nur bei Änderungen anspringt, findet nichts in einem Repo, das gerade niemand anfasst, und genau dort liegen alte Secrets am längsten.

Gescannt wird die vollständige Historie, nicht der Arbeitsstand:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Ohne diese Zeile sieht Gitleaks nur den letzten Commit. Ein Zugangsdatum, das vor zehn Commits entfernt wurde, steht weiterhin in der Historie und lässt sich weiterhin abrufen. Das Entfernen einer Datei löscht sie nicht aus Git.

## Warum die Reports nicht im Repo liegen

Im Uni-Projekt wurden die Scanner-Reports als Dateien eingecheckt, damit das Dashboard sie lesen konnte. Der Gitleaks-Report enthielt dabei die gefundenen Treffer im Klartext. Der Scanner, der Secrets finden soll, hat sie dadurch selbst wieder in die Versionskontrolle geschrieben.

Hier laufen die Reports deshalb als CI-Artefakt mit begrenzter Aufbewahrung, `reports/` steht im `.gitignore`, und Gitleaks läuft mit `--redact`:

```yaml
--report-path /repo/reports/gitleaks-report.json
--redact
--exit-code 1
```

Der Fundort bleibt im Report, der Wert nicht. Für die Behebung reicht das, denn wer die Stelle kennt, kann rotieren.

## Ein Detail aus der DAST-Stage

Der ZAP-Job wartet nicht blind, sondern prüft, ob das Ziel tatsächlich antwortet:

```bash
for i in $(seq 1 30); do
  if curl -sf -o /dev/null "$DAST_TARGET"; then
    echo "Ziel erreichbar nach $((i*10))s"
    break
  fi
  ...
done
```

Ein `sleep 15` hätte die Pipeline ebenfalls grün gemacht. Startet der Container aber nicht, scannt ZAP ins Leere, findet nichts und meldet Erfolg. Das Ergebnis wäre ein grüner Haken ohne Aussage, und das ist schlechter als ein roter Job, weil niemand mehr nachsieht. Der Job bricht in dem Fall ab.

## Fahrplan

- [x] Repo, Lizenz, Secret Detection mit Gitleaks
- [ ] Semgrep und OWASP Dependency-Check
- [ ] Trivy gegen das Container-Image, mit Gate auf behebbare kritische OS-Findings
- [ ] ZAP-Baseline gegen den Service-Container
- [ ] Auswertung der Scan-Ergebnisse und Vergleich GitLab CI gegen GitHub Actions

## Lizenz

MIT, siehe [LICENSE](LICENSE). Der OWASP Juice Shop wird als öffentliches Image referenziert und steht unter der MIT-Lizenz des Projekts.
