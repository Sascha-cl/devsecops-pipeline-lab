# Von GitLab CI zu GitHub Actions

Das Original dieser Pipeline lief in einem selbst gehosteten GitLab an der Hochschule. Dieses Repo ist die nach GitHub Actions portierte Fassung. Die Notizen hier halten fest, was sich beim Umzug geändert hat und warum.

> Der ursprüngliche `.gitlab-ci.yml` liegt redigiert unter [`gitlab-ci.original.redacted.yml`](gitlab-ci.original.redacted.yml). Interne IP-Adressen, der SSH-Schlüssel und die VM-Zugangsdaten sind durch Platzhalter ersetzt. Der Ablauf bleibt lesbar, die Betriebsinterna der Hochschule stehen nicht im Netz.

## Die Begriffe zeigen auf dasselbe, heißen aber anders

| GitLab CI | GitHub Actions | Anmerkung |
|---|---|---|
| `stages` mit `stage:` je Job | `jobs`, standardmäßig parallel | Actions kennt keine Stages. Reihenfolge entsteht nur über `needs`. |
| `script:` | `steps:` mit `run:` | In Actions ist ein Schritt entweder ein `run` oder ein `uses`. |
| eingebauter Docker-Executor, `image:` je Job | `runs-on: ubuntu-latest`, Container per `docker run` oder `uses` | Der GitLab-Runner startet den Job selbst im angegebenen Image. Der Actions-Runner ist eine volle Linux-VM, in der Docker bereitsteht. |
| `artifacts:` | `actions/upload-artifact` | In GitLab reicht ein Schlüssel, in Actions ist es ein eigener Schritt. |
| `only: - main` | `on: push: branches: [main]` | Auslöser stehen in Actions zentral oben, nicht pro Job. |
| CI/CD-Variablen im Projekt | Secrets und Variablen im Repo | Konzeptgleich, andere Oberfläche. |

## Was komplett wegfiel

Die Original-Pipeline hatte zwei Stufen, die dieses Repo nicht mehr braucht: `deploy_vm` und ein davon abhängiges `dast_zap_baseline`.

```yaml
# Original, redigiert
deploy_vm:
  stage: deploy
  script:
    - echo "$SSH_PRIVATE_KEY" | base64 -d > ~/.ssh/deploy.key
    - scp image.tar $VM_USER@$VM_IP:~/image.tar
    - ssh $VM_USER@$VM_IP "docker load -i ~/image.tar && docker run -d ..."
  only:
    - main

dast_zap_baseline:
  stage: dast-scan
  needs: [deploy_vm]
  variables:
    DAST_TARGET: "$DAST_TARGET_URL"   # zeigte auf eine interne VM-Adresse
```

Der Grund für den Wegfall steht im Haupt-README: ein öffentliches Repo hat keinen SSH-Schlüssel und keine Hochschul-VM. Statt die Anwendung irgendwohin zu deployen und dann deren Adresse zu scannen, startet der DAST-Job sie als eigenen Container im selben Docker-Netz und scannt sie dort. Damit verschwinden der Deploy-Schritt, der Schlüssel, die VM und jede Variable, die ein Geheimnis enthielt.

Das ist keine Notlösung für GitHub. Es ist die sauberere Bauform, weil der Scan nichts über die Hochschulinfrastruktur mehr voraussetzt und bei jedem Fork ohne Einrichtung läuft.

## Was fast unverändert blieb

Die eigentlichen Scanner-Aufrufe. Trivy, Semgrep und ZAP werden in beiden Welten als Container gestartet und bekommen dieselben Argumente. Beispiel Trivy:

```yaml
# GitLab
container-scan-trivy:
  image:
    name: aquasec/trivy:latest
    entrypoint: [""]
  script:
    - trivy image --input image.tar --format json --output reports/trivy-report.json ...
```

```yaml
# GitHub Actions
- name: Trivy gegen das Zielimage
  run: |
    docker run --rm -v "$PWD/reports:/out" aquasec/trivy:latest \
      image "$TARGET_IMAGE" --format json --output /out/trivy-report.json ...
```

Der Unterschied ist der Rahmen, nicht der Scan. GitLab hängt den Runner-Prozess direkt ins Trivy-Image, unter Actions ruft ein Schritt Trivy per `docker run` auf. Das Ergebnis ist dasselbe.

## Zwei Fallen, die erst auf dem Runner auffallen

**Der Service-Container hängt nicht automatisch im richtigen Netz.** GitHub Actions bietet einen `services:`-Block für Begleitcontainer. Der ist aber nur aus Schritten erreichbar, die selbst im Job-Container laufen. Die Schritte hier laufen direkt auf der Runner-VM, und ein per `docker run` gestarteter ZAP-Container liegt dann in einem anderen Netz als der Service. Deshalb erstellt der DAST-Job Netz, Ziel und Scanner von Hand, statt `services:` zu benutzen.

**ZAP läuft als non-root.** Das offizielle Image schreibt seine Reports nach `/zap/wrk` unter einem unprivilegierten Benutzer. Ohne Schreibrechte auf dem gemounteten Verzeichnis bricht der Scan beim Speichern ab, und zwar erst am Ende, nachdem er schon gelaufen ist. Ein `chmod 777` auf das Report-Verzeichnis vor dem Lauf löst das.

Beide Punkte kosten auf einem echten Runner sonst einen roten Lauf pro Erkenntnis. Deshalb wurde die komplette Kette vor dem ersten Push lokal mit Docker durchgespielt.

## Was ich dabei gelernt habe

Eine Pipeline zu portieren ist nicht Suchen und Ersetzen. Die Scanner-Aufrufe sind das Einfache. Die Arbeit steckt im Ausführungsmodell: wie ein Runner an Container kommt, in welchem Netz die stehen und unter welchem Benutzer sie schreiben. Wer das versteht, kann eine Pipeline zwischen den Systemen bewegen, ohne blind Vorlagen zu kopieren.
