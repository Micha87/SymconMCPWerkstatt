# Änderungen

## 0.4.0

- Kategorien und Instanzen mit Rechteauswahl: kein Zugriff, nur lesen, lesen und schreiben.
- Bestehende Einträge ohne Rechtefeld bleiben nur lesbar, einschließlich Formularanzeige.
- Schreibwerkzeuge berücksichtigen alle freigegebenen Schreibbereiche, auch ohne Standard-Arbeitsbereich.
- workspace_info liefert writable_roots zusätzlich zu den lesbaren Bereichen.
- Rechte gelten rekursiv; Sperren vor Nur-Lesen vor Schreibfreigaben, globale Freigaben bleiben erforderlich.
- Variablen unter schreibbaren Kategorien, Instanzen und Skripten anlegen; Skripte/Kategorien auch unter Instanzen.
- Instanz-Konfigurationslesefreigabe und Eigenschaftenfilter bleiben separat; keine neuen Gerätekonfigurationsbefehle.
- Rücksetzen auf Nur-Lesen beim Instanzwechsel im Editor und zusätzliche Grenz-/Migrationstests.

## 0.3.2

- Pro Instanz „Alle Eigenschaften erlauben“ oder einzelne Eigenschaften per Checkbox auswählen.
- Bearbeitungsdialog ermittelt Eigenschaftsnamen automatisch, einschließlich verschachtelter JSON-Felder.
- Altes Textfeld erscheint nicht mehr im Dialog; vorhandene alte Freigaben bleiben kompatibel.
- Leere Einzelauswahl gewährt keinerlei Konfigurationszugriff, gesperrte Werte sind nicht auswählbar.
- Instanzwechsel im Dialog setzt die Konfigurationsfreigabe zurück; Speichern erst beim Übernehmen.

## 0.3.1

- Checkbox „Konfiguration lesen“ pro ausgewählter Instanz statt manueller Eigenschaftsliste.
- Ohne Haken keine Konfigurationsabfrage; leere Instanzauswahl erteilt keine Freigaben.
- Konfiguration mit rekursiver Filterung bekannter Zugangsfelder, JSON-Listen/-Objekte eingeschlossen.
- URLs mit Anmeldedaten/Tokenparametern, Auth-Header und Schlüsselmaterial werden zurückgehalten.
- 0.3.0-Eigenschaftsfreigaben bleiben bis zum Speichern der neuen Checkbox eingeschränkt erhalten.
- Keine automatische Erweiterung bestehender Rechte und keine Instanz-Schreibfunktionen.

## 0.3.0

- Einzelne Instanzen einschließlich Kerninstanzen und ihrer Unterobjekte nur lesend freigeben.
- Neue Werkzeuge instances_list (optional nach Modul-GUID) und instance_read.
- object_read ergänzt um Status, Modulidentität und gefilterte Verbindungs-ID.
- Eigenschaften nur über explizite Namensliste; ausschließlich Zahlen und Bool-Werte.
- JSON-Felder gezielt lesbar, z. B. Location.latitude und Location.longitude.
- Gesperrte Kategorien und eigene Modulinstanz behalten Vorrang; keine Instanz-Schreibfunktionen.
- Standardmäßig leere Instanzfreigabe, bestehende Kategorie-Rechte bleiben bestehen.

## 0.2.0

- Mehrere zusätzliche Lesekategorien und mehrere rekursive Sperrkategorien.
- Sperren und Nur-Lesen haben Vorrang bei überlappenden Freigaben.
- Zugriffskontrolle für jeden Lese-, Schreib-, Ausführungs- und Ereignispfad.
- Gefilterte Objektlisten, Kind-IDs, Eltern-IDs und Verknüpfungsziele.
- Eigene Freigaben für Skript-/Ereigniscode und Medieninhalte, standardmäßig deaktiviert.
- Betrieb ohne Arbeitsbereich mit ausschließlich Lesekategorien.
- Fail-closed bei fehlerhafter Kategorie-Konfiguration; Modulinstanz immer gesperrt.
- Dokumentierte Grenze: frei ausgeführtes PHP ist nicht sandboxfähig.

## 0.1.8

Erste GitHub-Version mit Medien-Lesezugriff, Token-Erzeugung und Kopierdialogen,
Workspace-Erkennung, Debug-Ausgaben und Skript-/Variablen-/Ereigniswerkzeugen.
