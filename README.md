# Symcon MCP Werkstatt

MCP-Zugang für Symcon ab 8.1: Objektstruktur lesen, Kategorien und Variablen anlegen,
PHP-Skripte bearbeiten und ausführen sowie zyklische Ereignisse konfigurieren.
Version 0.1.8 ergänzt das Lesen von Medienobjekten zur Untersuchung von IPSView-Dateien.
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
RootID 0 sperrt den Zugang.

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
- object_read: Metadaten, Werte, Skriptquelltext, Ereignis- oder Medieninformationen.
- media_read: Text-/Base64-Abschnitte und SHA256; bis 32 MiB pro Datei,
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
```

`python3 test_connection.py` führt einen lesenden Verbindungstest durch.
Tests arbeiten mit Symcon-Testdoubles. Version 0.1.7 wurde vom Anwender in Symcon
bestätigt; Medienzugriff in 0.1.8 ist lokal getestet, Live-Prüfung steht noch aus.
