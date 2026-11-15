# CF7 Spamschutz (selbst gehostet, ohne Cookies)

Mehrstufiger Spamschutz für [Contact Form 7](https://wordpress.org/plugins/contact-form-7/) ohne externe
Dienste: kein reCAPTCHA, keine Cookies, kein Consent-Banner nötig. Entwickelt und im Betrieb bei CONTIC
(Gengenbach), Version 1.6.1, Lizenz GPL-2.0-or-later.

> **English in short:** Self-hosted, cookie-free, multi-stage spam protection for Contact Form 7
> (honeypot, minimum fill time, content score, optional rate limit). Check data lives in a REST endpoint,
> not in the page HTML, so page caches do not break it. No external services. Companion plugin for
> Spectra (UAGB) forms included. GPL-2.0-or-later. Documentation below is in German.

## Was es tut

| Stufe | Prüfung |
|---|---|
| 1 Token | Signierter Zeitstempel-Token, vom Browser per `fetch` aus einem eigenen REST-Endpunkt geholt; fehlt er oder ist er abgelaufen oder zu jung (3 s), wird die Einsendung abgewiesen |
| 2 Honigtopf | Verstecktes Feld mit wechselndem Namen |
| 3 Duplikate | Gleiche Einsendung (Hash) innerhalb 24 h wird abgewiesen |
| 4 Rate-Limit | höchstens 3 Einsendungen je 10 Minuten und 10 je 24 h je Absender (nur Hash der IP) — **ab Werk aus** (`CS_STAGE_RATE = false`), erst einschalten, wenn `REMOTE_ADDR` hinter Ihrem Reverse Proxy stimmt |
| 5 Inhalts-Score | Schlüsselwörter, Links, Zufallstext-Erkennung (Vokal- und Groß/Klein-Anteil), Telefonnummern; ab Punktzahl 4 Betreff-Präfix `[Prüfen]`, ab 7 abweisen |

**Cache-fest:** Die Prüfdaten stehen nie im HTML, sondern kommen per JavaScript aus
`/wp-json/contic-spam/v1/token`. Eine Page-Cache-Schicht kann deshalb keinen veralteten Token ausliefern.

**Selbsttest:** Ein täglicher Cron-Job ruft den Token-Endpunkt selbst auf und prüft Erreichbarkeit,
Signatur, Alter und Cache-Freiheit. Schlägt das fehl, erscheint eine Hinweiszeile im Dashboard mit dem
gemessenen Befund. Grenze: Der Aufruf läuft über die Server-Schleife und sieht daher keine Firewall,
die nur externe Browser abweist.

**Beobachtungsmodus:** `CS_ENFORCE = false` schreibt nur ins Log und weist nicht ab.

## Installation

1. `cf7-spamschutz.php` als *Must-Use-Plugin* nach `wp-content/mu-plugins/` kopieren (oder als normales Plugin).
2. Voraussetzung: PHP-Erweiterung `mbstring` (ohne sie lädt sich die Datei nicht, das Formular bleibt ungeschützt, aber funktionsfähig).
3. Formular einmal absenden und unter *Werkzeuge → Spam-Log* prüfen.
4. Für **Spectra-Formulare** (UAGB) zusätzlich `spectra-spamschutz.php` ablegen: CF7-Hooks greifen dort nicht.

Die Datei ist site-agnostisch und greift automatisch auf jedes CF7-Formular der Site.

## Datenschutz (Fakten aus dem Code, keine Rechtsberatung)

- **Gespeichert** wird nur, wenn eine Einsendung abgewiesen oder markiert wird: Zeit, Formularkennung, **Absenderadresse**, Grund, Punktzahl, Textauszug. Im Ringpuffer (Option `cs_log`, höchstens 200 Einträge) und höchstens **30 Tage** (täglicher Löschjob).
- **Rate-Limit und Duplikate:** nur Hashes (HMAC der IP, SHA-256 der Einsendung) als kurzlebige Transients, keine Klartext-IP.
- **Keine Cookies**, keine Verbindung nach außen. Der Selbsttest ruft nur den eigenen REST-Endpunkt auf (Server-Schleife).
- Ob und wie das in Ihre Datenschutzerklärung gehört (Rechtsgrundlage, Löschfrist), prüfen Sie für Ihre Site selbst oder mit Ihrer Rechtsberatung.

## Tests

```bash
php tests/run.php
```

172 Prüfungen ohne WordPress (mit Stubs): Token, Honigtopf, Score, Rate-Limit, Duplikate, Log, Selbsttest,
Escaping der Admin-Ausgabe. **Nicht** getestet: Zusammenspiel mit anderen Plugins, jeder Contact-Form-7-Stand,
echte Mailzustellung. Der Code läuft produktiv auf den Websites von CONTIC.

## Grenzen

- Kein Schutz gegen gezielte, menschliche Einsendungen.
- Der REST-Namensraum `contic-spam/v1` und die Optionsnamen bleiben bestehen (Rückwärtskompatibilität).
- Das Rate-Limit braucht eine verifizierte Absenderadresse (siehe oben).

## Lizenz

GPL-2.0-or-later, siehe `LICENSE`. © CONTIC, Gengenbach.
