# Änderungen

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
