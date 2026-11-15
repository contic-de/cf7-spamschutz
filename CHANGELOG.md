# Änderungsverlauf

Nur die Versionen mit dokumentierter Änderung; frühere Stände (bis 1.4.x) sind nicht einzeln dokumentiert.

## 1.6.1
- Selbsttest hält der Burst-Drosselung stand: ein gescheiterter zweiter Abruf zählt nicht als Defekt, der Abruf wird einmal nach zwei Sekunden wiederholt.

## 1.6.0
- Der Alarm prüft den Mechanismus statt Opfer zu zählen: täglicher Selbsttest (Erreichbarkeit, Signatur, Alter, Cache-Freiheit über zwei Abrufe). Die Hinweiszeile nennt nur den gemessenen Befund. Die Bot-Zahl steht als Information auf der Log-Seite.

## 1.5.1
- Das „24 Stunden“-Fenster der Fehlerzählung wanderte mit; ersetzt durch Stundenkörbe.

## 1.5.0
- Log mit zeitlicher Obergrenze: höchstens 200 Einträge **und** höchstens 30 Tage (bei jedem neuen Eintrag, beim Öffnen der Log-Seite und per täglichem Cron-Job).
