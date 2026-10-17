# Symcon MCP Werkstatt

MCP-Zugang für Symcon ab 8.1: Objektstruktur lesen, Kategorien und Variablen anlegen,
PHP-Skripte bearbeiten und ausführen sowie zyklische Ereignisse konfigurieren.
Version 0.2.0 ergänzt zusätzliche Lesebereiche, gesperrte Kategorien und getrennte Freigaben für Quelltexte und Medien. Medienobjekte können zur Untersuchung von IPSView-Dateien gelesen werden.
IPSView-Seiten können damit noch nicht bearbeitet werden.

## Installation

Repository-URL in der Symcon-Modulverwaltung hinzufügen. Instanz „Symcon MCP Werkstatt“
anlegen und eine freigegebene Kategorie auswählen. Instanz außerhalb dieser Kategorie ablegen.
Bei Wechsel von einer manuellen Installation den alten Werkstatt-Ordner zuvor außerhalb
des modules-Verzeichnisses sichern/entfernen, damit dieselben Modul-IDs nicht doppelt geladen werden.
Instanz nicht löschen: Bibliotheks- und Modul-ID bleiben identisch.

## Zugang

Token im Modul erzeugen und mit „Änderungen übernehmen“ speichern. Zugang aktivieren.
Schreib- und Ausführungsrechte sind separat und standardmäßig aus.
RootID 0 bedeutet: kein Arbeitsbereich; ein Zugang mit ausschließlich Lesebereichen ist möglich.

Endpunkt: `/hook/symcon-mcp-INSTANZID` mit `Authorization: Bearer TOKEN`.
Optional „Token auch in der Adresse“ aktivieren. Mit aktivem Symcon Connect erzeugt
„ChatGPT-Adresse anzeigen / kopieren“ die vollständige HTTPS-Adresse inklusive Token.
Im Kopierfeld Strg+A und Strg+C verwenden. In ChatGPT diese Adresse als MCP-Verbindung
mit Anmeldung „Keine Anmeldung“ eintragen. Die Token-Prüfung übernimmt das Modul.
Die vollständige Adresse ist ein Kennwort und kann in Client-/Proxy-Logs erscheinen.
Der Modul-Debug schreibt keine Tokens, URLs, Quelltexte oder Variablenwerte.
Ein Tokenwechsel trennt bestehende Clients nach dem Übernehmen.

## Werkzeuge

- workspace_info: Kategorie-ID, Name und Freigaben.
- objects_list: root_id, parent_id, objects (direkte Kinder).
- object_read: gefilterte Metadaten und Werte; Skript-/Ereigniscode nur mit separater Quelltextfreigabe. Verknüpfungen liefern nur zugängliche Ziel-IDs und werden nicht automatisch verfolgt.
- media_read: nur mit separater Medieninhaltsfreigabe, Text-/Base64-Abschnitte und SHA256; bis 32 MiB pro Datei,
  maximal 64 KiB pro Antwort, standardmäßig 8 KiB. Liest intern die gesamte Datei.
- category_create / variable_create / variable_set: Objekte anlegen und Werte schreiben.
- script_put: Skript anlegen/ersetzen, vorhandene Skripte mit expected_sha256 schützen.
- script_run: asynchron starten; Annahme ist keine Rückmeldung über den Skripterfolg.
- event_interval: zyklische Ereignisse anlegen/ändern, active explizit angeben.

parent_id kann beim Anlegen entfallen; dann wird die freigegebene Kategorie verwendet.
Neue Werkzeuge erfordern gegebenenfalls eine Aktualisierung der ChatGPT-Werkzeugliste.

## Grenzen

PHP-Ausführung ist keine Sandbox: Skripte haben volle Symcon-Rechte auch außerhalb
des freigegebenen Bereichs. Deshalb benötigt das Ändern vorhandener Skripte ebenfalls
die Ausführungsfreigabe. Bereits eingerichtete Ereignisse laufen nach Abschalten der
Modulfreigaben weiter; bei Bedarf separat in Symcon deaktivieren.
Keine Löschfunktionen, Archivabfragen oder Modulinstallationen. Keine Transaktionen.
Tokens liegen in der Symcon-Konfiguration. Die Maskierung ist keine Verschlüsselung.
Stateless MCP mit JSON-Antworten, keine SSE-Streams und kein OAuth.

## Tests

Außerhalb von Symcon mit PHP ausführen:

```sh
php tests/token_auth.php
php tests/workspace.php
php tests/access.php
```

`python3 test_connection.py` führt einen lesenden Verbindungstest durch.
Tests arbeiten mit Symcon-Testdoubles. Version 0.1.7 wurde vom Anwender in Symcon
bestätigt; Medienzugriff in 0.1.8 ist lokal getestet, Live-Prüfung steht noch aus.

## Lese-, Schreib- und Sperrbereiche (0.2.0)

Im Formular stehen drei Bereiche zur Verfügung:

| Einstellung | Bedeutung |
| --- | --- |
| Arbeitsbereich | Bisherige Kategorie für Erstellen/Bearbeiten/Ausführen, jeweils mit den passenden globalen Freigaben. 0 deaktiviert diesen Bereich. |
| Zusätzliche Kategorien – nur lesen | Mehrere Kategorien mit Unterobjekten. Objektstruktur und Variablenwerte lesbar, kein Erstellen, Schreiben, Skriptstart oder Ereignisänderung. |
| Gesperrte Kategorien | Mehrere Kategorien mit Unterobjekten. Keine direkten Lese-, Schreib- oder Ausführungszugriffe und keine Einträge in Objektlisten. |

Priorität bei Überschneidungen: **gesperrt > nur lesen > Arbeitsbereich**.
Eine als Lesebereich eingetragene Kategorie bleibt also auch innerhalb des Arbeitsbereichs
schreibgeschützt. Ein Lesebereich über dem Arbeitsbereich macht diesen ebenfalls nur lesbar.
Deshalb bevorzugt getrennte Kategorien für Arbeits- und Lesebereiche auswählen.
Sperren gelten auch für ausdrücklich freigegebene Unterkategorien. Die Werkstatt-Instanz
und ihre Unterobjekte sind immer gesperrt. Root 0 kann nicht als Lesebereich eingetragen werden.
Leere oder nicht mehr existierende Kategorie-Auswahlen müssen korrigiert/entfernt werden;
fehlerhafte Einstellungen sperren den Datenzugriff statt die Freigabe zu erweitern.

workspace_info nennt alle tatsächlich lesbaren Wurzelkategorien und ihre effektiven Rechte.
objects_list zeigt nur erlaubte Kinder, markiert sie mit read/write und filtert auch
ChildrenIDs/HasChildren in object_read. Nicht freigegebene Eltern und gesperrte Link-Ziele
werden nicht offengelegt. Links verleihen niemals Rechte auf das Ziel.
Instanz-Konfigurationen werden nicht ausgelesen.

### Quelltexte und Medien separat freigeben

- „Skriptquelltexte und Ereignis-Code … freigeben“ erlaubt Quelltexte in allen lesbaren Bereichen.
  Ohne Freigabe werden auch eingebettete Ereignisskripte und Aktionsparameter nicht ausgegeben.
- „Medieninhalte … freigeben“ erlaubt media_read in allen lesbaren Bereichen. Ohne Freigabe
  bleibt nur ungefährliche Medienmetadaten-Ausgabe ohne Dateipfad/Stream-URL; media_read fehlt
  in der Werkzeugliste und wird auch bei veralteter Werkzeugliste abgewiesen.

Beide neuen Freigaben sind **standardmäßig aus, auch nach einem Update von 0.1.8**.
Für weiteres Bearbeiten vorhandener Skripte sollte die Quelltextfreigabe eingeschaltet sein,
damit der aktuelle SHA256 gelesen werden kann. Für IPSView-Untersuchungen ist die
Medieninhaltsfreigabe erforderlich. Tokens und bisherige Kategorie-IDs bleiben unverändert.
Nach dem Übernehmen die ChatGPT-Werkzeugliste aktualisieren.

### Grenze der Schutzwirkung

Diese Regeln schützen direkte MCP-Werkzeuge. Beliebiges PHP bleibt ein privilegierter
Zugang und kann die Kategorienregeln umgehen, Dateien lesen oder Secrets abrufen.
Skriptstart sowie Änderung bestehender PHP-Skripte benötigen deshalb die separate
Ausführungsfreigabe und sind Administratorfunktionen. Wer eine harte Lesegrenze benötigt,
muss die PHP-Ausführung abgeschaltet lassen. Bereits aktive Ereignisse separat beachten.
Der Inhalt eines zulässigen Variablenwertes, einer Beschreibung, eines freigegebenen Skripts
oder einer freigegebenen IPSView kann seinerseits Zugangsdaten enthalten. Das Modul erkennt
solche Geheimnisse nicht automatisch. Sensible Inhalte konsequent aus Lesebereichen herausnehmen.
Die Vault-Anbindung ist nicht Bestandteil dieser Version.
