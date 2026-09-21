# Fallstudie: ein grüner Job trotz kaputtem Scanner

## Finding

Im [Workflow vor der Härtung](https://github.com/Sascha-cl/devsecops-pipeline-lab/blob/c87252d/.github/workflows/security-pipeline.yml#L81-L115) stand `continue-on-error: true` am Semgrep-Schritt. Wenn der Report fehlte, wurde lediglich eine Meldung ausgegeben; der Upload warnte nur.

Die Absicht war sinnvoll: bekannte Findings des absichtlich unsicheren Ziels sollten keinen dauerroten Job erzeugen. Die Implementierung unterschied aber nicht zwischen **„Schwachstelle gefunden“** und **„Scanner konnte nicht arbeiten“**.

`semgrep scan` meldet Findings ohne `--error` standardmäßig mit Exit 0. Ein pauschales `continue-on-error` ist dafür nicht erforderlich und schluckt zusätzlich technische Fehlschläge. [Semgrep-CLI](https://docs.semgrep.dev/cli-reference#exit-codes)

**Auswirkung:** Ein grüner Job konnte trotz fehlender statischer Prüfung entstehen. Das ist ein Fehler in der Aussagekraft der Sicherheitskontrolle. Hier wird kein Vorfall oder nachgewiesener Angriff auf das Repository behauptet; die alte Fehlerbehandlung wurde statisch nachvollzogen, nicht durch einen absichtlich kaputten öffentlichen Workflow demonstriert.

## Änderung

Der gemeinsame [Scan-Runner](../scripts/scan.py) behandelt jeden nicht erfolgreichen Prozessstatus als Fehler. Semgrep bekommt `--strict`, aber weiterhin kein `--error`:

- Findings am Lab-Ziel bleiben erlaubt.
- Ungültige Regeln, Parsefehler und Regel-Timeouts werden nicht ignoriert.
- Fehlende Reports, null gescannte Dateien und fehlerhafte SARIF-Invocations blockieren zusätzlich.
- JSON und SARIF müssen bei der Finding-Zahl übereinstimmen.
- Jeder Lauf schreibt in ein frisches Verzeichnis; alte Reports können keinen aktuellen Erfolg vortäuschen.
- Fehlgeschlagene Läufe speichern `status: failed` mit ihrem Kontext.

Der Upload sichert auch Fehlerartefakte. Er ersetzt die Report-Prüfung nicht.

## Verifikation mit einem echten Scanner

Der [Integrationstest](../scripts/verify_semgrep_contract.py) verwendet das festgelegte Semgrep-Image und eine winzige eigene JavaScript-Regel mit synthetischen Eingaben. Er greift kein externes Ziel an und verwendet keine Zugangsdaten.

Lokal am **11.09.2026**, Semgrep **1.176.0**:

| Testfall | Gemessener Scanner-Exit | Erwartetes Verhalten des Runners |
|---|---:|---|
| synthetisches `eval(userInput)`-Finding | 0, ein Finding | gültigen Report akzeptieren |
| unauffällige synthetische Datei | 0, null Findings | gültigen Report mit tatsächlich gescannter Datei akzeptieren |
| ungültige YAML-Regel | 7 | Prozessfehler weiterreichen, keinen erfolgreichen Scan behaupten |

Der Test selbst ist erfolgreich, **weil** der absichtlich kaputte Scanner-Aufruf abgewiesen wurde. Er fängt diese Ausnahme nur als Test-Assertion ab; der normale Scanpfad ignoriert sie nicht.

Reproduktion:

```bash
python scripts/verify_semgrep_contract.py
```

Das Ergebnis landet als `contract.json` unter `reports/semgrep/contract-<id>/`. Derselbe Integrationstest läuft vor dem eigentlichen SAST-Scan in GitHub Actions.

## Ein echter Fehler beim ersten gehärteten Lauf

Ein erster Scan des festgelegten Juice-Shop-Stands meldete 76 Findings **und drei Regel-Timeouts** in der vendorten Datei `frontend/src/assets/private/three.js`. Die CLI zeigte trotzdem eine freundliche Scan-Zusammenfassung; der tatsächliche Prozess-Exit war **2**.

Der neue Runner beendete sich daraufhin mit **Exit 1** und speicherte den Lauf als fehlgeschlagen. Das ist der konkrete Unterschied zu einer pauschal tolerierten Scanner-Panne.

Die große Drittbibliothek wurde anschließend als explizite, dokumentierte SAST-Scope-Ausnahme eingeordnet. Der erneute Lauf meldete 76 Findings, 865 gescannte Dateien und keine technischen Fehler. Das ist **keine Reparatur der Bibliothek** und keine Behauptung vollständiger Anwendungsabdeckung. Die Entscheidung steht in [findings.md](findings.md).

## Lokal grün ist kein CI-Beweis

Vor dem Push waren alle vier Scans, der Semgrep-Vertragstest und 20 Regressionstests lokal erfolgreich. Der erste GitHub-Lauf der gehärteten Fassung ([Run 34615142596](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/runs/34615142596)) scheiterte trotzdem, und zwar im Vertragstest vor dem eigentlichen Scan:

```text
Semgrep failed to set the safe.directory Git config option: [Errno 13] Permission denied: '/src'
PermissionError: [Errno 13] Permission denied: '/src/rule.yml'
```

Prozess-Exit **2**, der Runner beendete sich mit **1**. Ursache war keine Scanner-Änderung, sondern das Zusammenspiel zweier eigener Entscheidungen:

- Die Container laufen mit `--cap-drop ALL`. Damit verliert auch uid 0 `CAP_DAC_OVERRIDE` und unterliegt den normalen Dateirechten. Das Semgrep-Image setzt kein `USER`, arbeitete also als root ohne DAC-Umgehung.
- `tempfile.TemporaryDirectory()` legt das gemountete Eingabeverzeichnis mit `0700` an, Eigentümer ist der Runner-User. Die per `--group-add` ergänzte Host-Gruppe hilft dort nicht, weil `0700` der Gruppe keine Rechte gibt.

Nachgestellt mit einem Docker-Volume und einem Verzeichnis `1001:1001`:

| Verzeichnis | Container | Zugriff | Ergebnis |
|---|---|---|---|
| `0700` | root, `--cap-drop ALL` | lesen | `Permission denied` |
| `0750` | dito, `--group-add 1001` | lesen | erfolgreich |
| `0750` | dito, `--group-add 1001` | schreiben | `Permission denied` |
| `0770` | dito, `--group-add 1001` | schreiben | erfolgreich |

Die letzten zwei Zeilen betreffen einen zweiten, noch unentdeckten Fehler derselben Klasse: Ein an `mkdir` übergebener Modus wird von der umask reduziert, `0770` also zu `0750`. Das Ausgabeverzeichnis des Vertragstests wäre damit unbeschreibbar gewesen — der nächste Fehlschlag direkt hinter dem ersten. In Python geprüft: `mkdir(mode=0o770)` ergibt `0o750`, `mkdir()` plus `chmod(0o770)` ergibt `0o770`.

`container_inputs()` und `report_directory()` in [scan.py](../scripts/scan.py) setzen die Modi jetzt zentral per `chmod`, passend zur ergänzten Host-Gruppe. Der [Folgelauf](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/runs/34616453058) war grün: sechs Jobs, vier Artefakte, [Protokoll](evidence/ci-verification-2026-09-11.json).

**Warum lokal nichts auffiel:** Bind-Mounts von Docker Desktop unter Windows und macOS melden andere Eigentümer und Rechte als ein Linux-Runner. Diese Fehlerklasse ist dort strukturell unsichtbar, nicht bloß unwahrscheinlich. Das [lokale Prüfprotokoll](evidence/local-verification-2026-09-11.json) enthält genau eine Rechteprobe, und die betraf die Schreibseite von ZAP; die Leseseite der gemounteten Eingaben war nicht geprüft.

Zwei Regressionstests decken das jetzt ab: einer prüft die Modi unter erzwungener `umask 077`, der andere, dass der Runner die Capability-Flags überhaupt noch setzt. Der zweite Test existiert, weil die naheliegende Abkürzung gewesen wäre, `--cap-drop ALL` zu entfernen — das hätte das Symptom beseitigt und die Härtung aufgegeben. Die Suite wuchs damit von 20 auf 22 Tests. Ein Modus-Test auf einem Windows-Host bleibt allerdings wirkungslos und wird dort übersprungen; der belastbare Nachweis ist der grüne Runner-Lauf.

## Automatisierte Regression

Am 11.09.2026 bestanden alle **20 Unit-/Regressionstests** des damaligen Stands; die finalen vier lokalen Scannerläufe waren erfolgreich. Das [Prüfprotokoll](evidence/local-verification-2026-09-11.json) enthält die zugehörigen Fingerprints und die Ergebnisse des echten Semgrep-Vertragstests.

**actionlint** prüfte den Workflow zunächst nur lokal in Version 1.7.12. Inzwischen läuft der Linter als Pipeline-Schritt mit einem per Digest festgelegten Image ([lint_workflows.py](../scripts/lint_workflows.py)), also unter derselben Regel wie die Scanner: eine einmalige lokale Prüfung ist keine laufende Kontrolle.

[tests/test_pipeline.py](../tests/test_pipeline.py) prüft unter anderem:
- echte nicht erfolgreiche Kindprozesse und Prozess-Timeouts,
- gültige Findings versus technische Scanfehler,
- fehlende, leere, ungültige und widersprüchliche Reports,
- fehlende Regeln und null gescannte Dateien,
- Secret-Funde als Blocker,
- falsches ZAP-Ziel oder falschen Trivy-Image-Digest,
- inkonsistente Quellcode-/Image-Revisionen,
- alte erfolgreiche Reports neben einem neuen gescheiterten Lauf,
- Mutable-Tags und zentrale Workflow-Schutzregeln,
- Dateimodi gemounteter Ein- und Ausgaben unter erzwungener umask,
- die Capability- und Platform-Flags des Container-Aufrufs.

```bash
python -m unittest discover -s tests -v
```

Diese Tests verwenden bewusst synthetische Reports und Prozesse; sie simulieren nicht alle internen Scannerfehler. Der zusätzliche Container-Integrationstest prüft den tatsächlichen Exit-/Report-Vertrag des gepinnten Semgrep-Images.

## Nachweis, dass der Merge wirklich blockiert

Ein grüner Sammelcheck beweist nur, dass er berichtet. Ob er auch blockiert, wurde am 12.09.2026 mit [PR #4](https://github.com/Sascha-cl/devsecops-pipeline-lab/pull/4) geprüft. Die Änderung war ein einziges zusätzliches Exclude-Pattern `"*"` in `config/scan-lock.json`.

[Run 34689611041](https://github.com/Sascha-cl/devsecops-pipeline-lab/actions/runs/34689611041):

```text
Scanning 0 files with 212 Code rules:
  Nothing to scan.
✅ Scan completed successfully.
 • Targets scanned: 0
SCAN FAILED: Semgrep scanned zero files
##[error]Process completed with exit code 1.
```

Semgrep hielt diesen Lauf für erfolgreich, inklusive grünem Häkchen. Die Report-Prüfung nicht.

| Check | Ergebnis |
|---|---|
| Pipeline regression tests | grün |
| Scan (gitleaks), Scan (trivy), Scan (zap) | grün |
| Scan (semgrep) | rot |
| Security checks | rot, `TEST_RESULT: success`, `SCAN_RESULT: failure` |

Der Merge war anschließend in der Oberfläche blockiert, obwohl der Autor Repo-Admin ist und das Ruleset keine Bypass-Actors hat. Der PR wurde geschlossen, nicht gemergt. Belege in [merge-gate-proof-2026-09-12.json](evidence/merge-gate-proof-2026-09-12.json), Konfiguration in [maintenance.md](maintenance.md).

Zwei Punkte daran sind wichtiger als das rote Kreuz:

- Das Lockfile war syntaktisch gültig, `load_lock()` akzeptierte es, und alle 22 Regressionstests blieben grün. Synthetische Tests können diesen Fehler nicht fangen; erkennbar war er nur am echten Report.
- Der Fehler ist realistisch. Ein zu breites Exclude beim Ausschließen einer einzelnen störenden Datei kostet die gesamte SAST-Abdeckung, ohne eine einzige Fehlermeldung zu erzeugen.

**Grenze:** Geprüft ist ein Muster, das *alle* Zieldateien entfernt. Ein Exclude, das die Abdeckung nur stark reduziert, bleibt unauffällig, solange mindestens eine Datei gescannt wird. Gegen schleichenden Scope-Verlust hilft diese Prüfung nicht; dafür wäre eine begründete Untergrenze für die Dateizahl nötig.

## Aussage und Grenze

Nachgewiesen ist lokal, auf einem GitHub-Runner und am Merge-Gate: **erwartete Findings dürfen passieren, technische Scanfehler und stillschweigend verlorene Abdeckung dürfen keinen Erfolg vortäuschen**. Der Runner-Nachweis ist dabei der wertvollere von den ersten beiden, weil er nicht geplant war: Ein echter Konfigurationsfehler wurde rot gemeldet statt durchgelassen.

Der gemeinsame `Security checks`-Status **verhindert** einen Merge inzwischen nachweislich, weil zusätzlich ein Ruleset auf `main` greift. Das gilt für dieses Repository und seinen aktuellen Regelstand, nicht automatisch für einen Fork: dort muss das Ruleset erneut eingerichtet und erneut mit einem fehlschlagenden PR geprüft werden.

Diese Fallstudie belegt eine Verbesserung am eigenen Pipeline-Code. Die dazu ergänzende Anwendungs-Fallstudie mit manuell reproduzierter Schwachstelle, Fix und Nachtest steht in [was der `res.sendFile`-Verdacht am File-Server wirklich hergibt](case-study-fileserver.md).
