# devsecops-pipeline-lab

[![Security Pipeline](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/workflows/security-pipeline.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Eine CI-Pipeline, die Security-Scanner über den kompletten Durchlauf einbindet: Secret Detection, statische Analyse, Container-Scan und ein dynamischer Test gegen die laufende Anwendung. Alles läuft ohne eigene Infrastruktur direkt in der CI.

## Woher das kommt

Die Grundlage ist ein Teamprojekt aus dem 4. Semester an der TH Aschaffenburg (Modul IT-Sicherheit, SoSe 2026). Dort haben wir zu fünft zwei GitLab-Pipelines gebaut, eine für eine Spring-Boot-Anwendung und eine für den OWASP Juice Shop, dazu ein Dashboard, das die Findings der einzelnen Scanner zusammenführt.

Mein Anteil war die DAST-Stage mit OWASP ZAP für beide Anwendungen, die Auswertung der Container-Scans und das Patchen der gefundenen kritischen CVEs. Dieses Repo enthält ausschließlich diesen Teil, neu aufgebaut und nach GitHub Actions portiert. Das Dashboard und der Anwendungscode meiner Kommilitonen sind nicht enthalten, weil sie mir nicht gehören.

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

Die Lösung steckte schon im eigenen Fuzzing-Job: die zu testende Anwendung als Service-Container im CI-Netz starten, statt sie irgendwohin zu deployen. Damit fällt der Deploy-Schritt weg, mit ihm der SSH-Key, die VM und jede Variable, die ein Geheimnis enthält.

## Architektur

```
push / pull_request / cron
        │
        ├─ secret detection ....... Gitleaks über die volle Git-Historie
        ├─ sast ................... Semgrep gegen den Quellcode des Ziels
        ├─ container scan ......... Trivy gegen das Image des Ziels
        └─ dast ................... ZAP gegen den laufenden Container
                                          │
                                    juice-shop:3000
                                    (öffentliches Upstream-Image,
                                     wird referenziert, nicht kopiert)
```

Die vier Jobs laufen parallel und ohne `needs`. GitHub Actions kennt keine Stages wie GitLab, eine Reihenfolge entsteht nur über Abhängigkeiten. Hier ist keine nötig, denn die Scanner sind unabhängig und sollen sich nicht gegenseitig blockieren, wenn einer rot wird.

## Secret Detection

Gitleaks bei jedem Push, zusätzlich montags früh. Der geplante Lauf ist Absicht. Ein Scanner, der nur bei Änderungen anspringt, findet nichts in einem Repo, das gerade niemand anfasst, und genau dort liegen alte Secrets am längsten.

Gescannt wird die vollständige Historie, nicht der Arbeitsstand:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Ohne diese Zeile sieht Gitleaks nur den letzten Commit. Ein Zugangsdatum, das vor zehn Commits entfernt wurde, steht weiterhin in der Historie und lässt sich weiterhin abrufen. Das Entfernen einer Datei löscht sie nicht aus Git.

**Was der Scanner nicht findet**, habe ich separat getestet: von vier eingebauten Testwerten hat er einen gemeldet. Ein AWS-Beispielschlüssel steht auf der Allowlist, zwei menschliche Passwörter liegen unter der Entropie-Schwelle. Ein grüner Secret-Scan heißt „kein bekanntes Muster hat gematcht", nicht „hier liegen keine Zugangsdaten".

## Warum die Reports nicht im Repo liegen

Im Uni-Projekt wurden die Scanner-Reports als Dateien eingecheckt, damit das Dashboard sie lesen konnte. Der Gitleaks-Report enthielt dabei die Treffer im Klartext. Der Scanner, der Secrets finden soll, hat sie dadurch selbst wieder in die Versionskontrolle geschrieben.

Hier laufen die Reports als CI-Artefakt mit begrenzter Aufbewahrung, `reports/` steht im `.gitignore`, und Gitleaks läuft mit `--redact`. Der Fundort bleibt im Report, der Wert nicht. Für die Behebung reicht das, denn wer die Stelle kennt, kann rotieren.

## Was der Container-Scan zeigt

Trivy gegen `bkimminich/juice-shop:latest`, Basis Debian 13.6, Stand 10.09.2026:

| Ebene | CRITICAL | HIGH | MEDIUM | LOW | Gesamt |
|---|---:|---:|---:|---:|---:|
| OS-Pakete (Debian) | 0 | 1 | 16 | 13 | 30 |
| Anwendungspakete (npm) | 8 | 44 | 38 | 7 | 97 |
| **Gesamt** | **8** | **45** | **54** | **20** | **127** |

Die kritischen Findings liegen vollständig auf der Anwendungsebene:

```
CVE-2023-46233       crypto-js      3.3.0    fix: 4.2.0
CVE-2026-71851       crypto-js      3.3.0    fix: 4.0.0
CVE-2026-53486       decompress     4.2.1    fix: KEIN FIX
CVE-2015-9235        jsonwebtoken   0.1.0    fix: 4.2.2
CVE-2015-9235        jsonwebtoken   0.4.0    fix: 4.2.2
CVE-2019-10744       lodash         2.4.2    fix: 4.17.12
GHSA-5mrr-rgp6-x4gr  marsdb         0.6.11   fix: KEIN FIX
CVE-2026-59873       tar            6.2.1    fix: 7.5.19
```

### Warum hier kein Gate steht

In der ursprünglichen Pipeline blockierte diese Zeile den Build:

```bash
trivy image --pkg-types os --severity CRITICAL --ignore-unfixed --exit-code 1
```

Auf die Zahlen oben angewendet läuft dieses Gate **grün durch**. Es prüft mit `--pkg-types os` ausschließlich Betriebssystempakete, und dort stehen null kritische Findings. Die acht kritischen liegen in den npm-Abhängigkeiten, also genau in der Schicht, die das Gate nicht ansieht.

Das war im Uni-Projekt kein Loch, weil ein separater Dependency-Check die Quellcode-Ebene abgedeckt hat. Als alleinige Kontrolle wäre es aber eine falsche Sicherheit, und ein grünes Gate liest sich nun einmal wie eine Freigabe.

Auf dem Scan-Ziel steht hier bewusst gar kein Gate. Der Juice Shop ist absichtlich verwundbar, ein Gate würde dauerhaft auslösen, ohne dass jemand etwas daran ändern kann. Ein Gate, das immer rot ist, wird ignoriert und ist damit schlechter als keins. Die Trennung zwischen absichtlich unsicher und unabsichtlich angreifbar muss die Pipeline abbilden.

### Dieselbe Messung, drei Monate später

Im Uni-Projekt kam derselbe Scan im Juni 2026 auf 118 Findings bei Debian 13.5. Jetzt sind es 127 bei Debian 13.6. Gleicher Tag, anderes Ergebnis. `:latest` ist keine Version, und eine Scan-Zahl ohne Datum und Image-Digest ist nicht reproduzierbar.

## Was die statische Analyse zeigt

Semgrep mit den Regelsätzen `p/security-audit` und `p/javascript` gegen den Quellcode des Ziels. Allein im Verzeichnis `routes/` (61 Dateien, 89 angewandte Regeln) stehen 11 Findings:

| Anzahl | Regel | Fundstellen |
|---:|---|---|
| 4 | `express-res-sendfile` | fileServer.ts:33, keyServer.ts:14, logfileServer.ts:14, quarantineServer.ts:14 |
| 2 | `unknown-value-with-script-tag` | videoHandler.ts:58, videoHandler.ts:71 |
| 1 | `express-sequelize-injection` | search.ts:23 |
| 1 | `express-open-redirect` | redirect.ts:19 |
| 1 | `unknown-value-in-redirect` | redirect.ts:19 |
| 1 | `raw-html-format` | chatbot.ts:205 |
| 1 | `code-string-concat` | userProfile.ts:62 |

### Vom Finding zum Angriff

Die vier `express-res-sendfile`-Treffer sehen im Code harmlos aus:

```ts
res.sendFile(path.resolve('ftp/', file))
```

`path.resolve` verarbeitet `..` aber genau so, wie es dasteht. Wer `file` kontrolliert, verlässt das vorgesehene Verzeichnis. Das ist Path Traversal, und es ist dieselbe Schwachstellenklasse, die ich in der PortSwigger Web Security Academy von Hand ausgenutzt habe, dort über `filename=../../../etc/passwd` in einem Bild-Endpunkt.

Der Zusammenhang ist der eigentliche Punkt dieses Repos. Ein Scanner liefert eine Zeilennummer und eine Regel-ID. Ob daraus ein Angriff wird, hängt davon ab, ob der Parameter erreichbar ist, ob davor gefiltert wird und was im Zielverzeichnis liegt. Wer nur die Liste abarbeitet, kann nicht priorisieren. Wer die Klasse einmal selbst ausgenutzt hat, sieht der Zeile an, was sie wert ist.

Auch `express-sequelize-injection` in `search.ts:23` und die beiden XSS-Regeln im `videoHandler` lassen sich direkt in eine Angriffskette übersetzen.

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

### Was der DAST-Lauf meldet

ZAP Baseline gegen den laufenden Container, ohne aktive Angriffe, nur Crawl und passive Prüfung:

```
FAIL-NEW: 0    WARN-NEW: 9    PASS: 58
```

Die neun Warnungen sind überwiegend fehlende Sicherheitsheader: keine Content Security Policy, fehlende Cross-Origin-Header, eine verwundbare JS-Bibliothek. Nichts davon ist spektakulär, und genau das ist der Punkt einer Baseline. Sie prüft, was ein Angreifer ohne einen einzigen Angriff schon sieht.

## Wenn drei Scanner auf dieselbe Datei zeigen

Beim Crawlen ist ZAP über diese URL gestolpert:

```
http://juice-shop:3000/juice-shop/build/routes/fileServer.js:59:18
```

Das ist kein normaler Pfad, das ist ein interner Dateipfad, den die Anwendung in einer Fehlermeldung preisgegeben hat. Interessant wird er im Zusammenhang mit der statischen Analyse. Semgrep hatte `fileServer.ts` als Path-Traversal-Stelle markiert. Derselbe Dateiname taucht jetzt im laufenden Betrieb wieder auf, diesmal weil ein Stacktrace nach außen dringt.

Drei Blickwinkel auf dieselbe Komponente:

| Quelle | Aussage über `fileServer` |
|---|---|
| SAST (Semgrep) | im Quellcode steckt eine Path-Traversal-Lücke |
| DAST (ZAP) | die laufende App verrät den internen Pfad der Datei über eine Fehlermeldung |
| eigene Praxis (PortSwigger) | dieselbe Schwachstellenklasse von Hand ausgenutzt, `../../../etc/passwd` |

Ein Scanner allein liefert eine Zeile. Erst die Kombination ergibt eine Spur: eine Datei, die statisch verdächtig ist, im Betrieb Interna leakt und zu einer Angriffsklasse gehört, die ich selbst durchgespielt habe. Diese Findings zu verbinden ist die Arbeit, die kein einzelnes Werkzeug abnimmt.

## Fahrplan

- [x] Repo, Lizenz, Secret Detection mit Gitleaks
- [x] Semgrep gegen den Quellcode des Scan-Ziels
- [x] Trivy gegen das Container-Image, mit Auswertung statt Gate
- [x] ZAP-Baseline gegen den laufenden Container
- [ ] Vergleich GitLab CI gegen GitHub Actions als eigener Abschnitt

## Lizenz

MIT, siehe [LICENSE](LICENSE). Der OWASP Juice Shop wird als öffentliches Image und öffentliches Repository referenziert und steht unter der MIT-Lizenz des Projekts.
