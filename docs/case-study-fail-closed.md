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

## Automatisierte Regression

Am 11.09.2026 bestanden alle **20 Unit-/Regressionstests**; der Workflow war mit **actionlint 1.7.12** fehlerfrei. Die finalen vier lokalen Scannerläufe waren erfolgreich. Das [Prüfprotokoll](evidence/local-verification-2026-09-11.json) enthält die zugehörigen Fingerprints und die Ergebnisse des echten Semgrep-Vertragstests.

[tests/test_pipeline.py](../tests/test_pipeline.py) prüft unter anderem:
- echte nicht erfolgreiche Kindprozesse und Prozess-Timeouts,
- gültige Findings versus technische Scanfehler,
- fehlende, leere, ungültige und widersprüchliche Reports,
- fehlende Regeln und null gescannte Dateien,
- Secret-Funde als Blocker,
- falsches ZAP-Ziel oder falschen Trivy-Image-Digest,
- inkonsistente Quellcode-/Image-Revisionen,
- alte erfolgreiche Reports neben einem neuen gescheiterten Lauf,
- Mutable-Tags und zentrale Workflow-Schutzregeln.

```bash
python -m unittest discover -s tests -v
```

Diese Tests verwenden bewusst synthetische Reports und Prozesse; sie simulieren nicht alle internen Scannerfehler. Der zusätzliche Container-Integrationstest prüft den tatsächlichen Exit-/Report-Vertrag des gepinnten Semgrep-Images.

## Aussage und Grenze

Nachgewiesen ist lokal: **erwartete Findings dürfen passieren, technische Scanfehler dürfen keinen Erfolg vortäuschen**. Der Workflow hat zusätzlich einen gemeinsamen `Security checks`-Status. Ob dieser Merges tatsächlich verhindert, muss nach dem Push mit einem GitHub-Ruleset und einem Test-PR verifiziert werden.

Diese Fallstudie belegt eine Verbesserung am eigenen Pipeline-Code. Sie ersetzt nicht die noch ausstehende Anwendungs-Fallstudie mit manuell reproduzierter Schwachstelle und Patch.
