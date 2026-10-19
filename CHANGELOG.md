# Änderungen

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
