<?php
/**
 * Plugin Name: CF7 Spamschutz (self-hosted, DSGVO)
 * Plugin URI:  https://github.com/contic-de/cf7-spamschutz
 * Description: Mehrstufiger Spamschutz für Contact Form 7 — Honeypot, Zeitprüfung,
 *              Rate-Limit und Inhalts-Score. Cache-fest: Prüfdaten stehen nie im HTML,
 *              sondern kommen per JS aus einem eigenen REST-Endpoint. Keine externen
 *              Dienste, keine Cookies, kein Consent nötig.
 * Version:     1.6.1
 * Author:      CONTIC
 * Author URI:  https://contic.de
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * Deployment: als mu-plugin ablegen -> wp-content/mu-plugins/cf7-spamschutz.php
 * Site-agnostisch: greift automatisch auf JEDES CF7-Formular der Site.
 *
 * Änderungsverlauf: CHANGELOG.md · Tests: php tests/run.php
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

// I8: Neudeklaration (z. B. weil derselbe Code zusaetzlich als „Code Snippets"-Snippet
// existiert) oder ein abgebrochener FTP-Upload darf keinen weissen Bildschirm ergeben.
if ( defined( 'CS_VERSION' ) ) { return; } // schon geladen

// M-mb: mb_strtolower/mb_strpos/mb_substr/mb_strlen haben in WP-Core keinen
// vollstaendigen Fallback. Fehlt mbstring, lieber die ganze Datei nicht laden
// (Kontaktformular bleibt ungeschuetzt, aber funktionsfaehig) als im Filter zu fataln
// und die Einreichung zu verlieren. Die PHP-Erweiterungen sind vor dem Einsatz
// je Site zu pruefen.
if ( ! function_exists( 'mb_strtolower' ) ) { return; } // ohne mbstring nicht lauffaehig

/* --- Stellschrauben ------------------------------------------------------ */

const CS_VERSION      = '1.6.1';
const CS_TOKEN_TTL    = 3600;  // Sekunden, danach Token abgelaufen
const CS_MIN_SECONDS  = 3;     // Mindestalter zwischen Token-Abruf und Absenden
const CS_SCORE_MARK   = 4;     // ab hier Betreff-Präfix [Prüfen]
const CS_SCORE_BLOCK  = 7;     // ab hier abweisen
const CS_RL_SHORT     = 3;     // Absendungen pro CS_RL_SHORT_TTL
const CS_RL_SHORT_TTL = 600;
const CS_RL_DAY       = 10;    // Absendungen pro 24 h
const CS_LOG_MAX      = 200;   // Einträge im Ringpuffer
const CS_LOG_RETENTION_DAYS = 30; // zusätzliche Zeitgrenze, unabhängig von CS_LOG_MAX (v1.5.0)
const CS_RANDOM_MIN_LEN   = 8;    // Feld muss mindestens so viele Buchstaben haben,
                                   // um auf Zufallstoken geprueft zu werden (2026-07-28)
const CS_RANDOM_MAX_VOWEL = 0.20; // Vokalanteil darunter = Zeichenwirrwarr, kein Wort
const CS_RANDOM_MAX_CASE_FLIP = 0.35; // Gross-/Klein-Wechselrate darueber = Zeichenwirrwarr

/* --- Stufen-Schalter (Spec §3.1) ----------------------------------------- */

/**
 * Jede Prüfstufe ist einzeln abschaltbar, und CS_ENFORCE schaltet den gesamten
 * Spamschutz in den Beobachtungsmodus: protokollieren, aber nichts abweisen.
 *
 * CS_STAGE_RATE ist bewusst auf false vorbelegt (Entscheidung 2026-07-26).
 * Grund: steht auf dem Server nginx als Reverse Proxy vor PHP — bei KeyHelp eine
 * übliche Konstellation —, dann liefert $_SERVER['REMOTE_ADDR'] für JEDEN Besucher
 * dieselbe Adresse (127.0.0.1). Alle Besucher teilten sich dann ein Kontingent, und
 * die vierte Anfrage von irgendwem binnen zehn Minuten würde abgewiesen. Erst
 * einschalten, wenn REMOTE_ADDR je Site verifiziert ist.
 */
const CS_ENFORCE        = true;  // false = Beobachtungsmodus (nur Log, keine Abweisung)
const CS_STAGE_TOKEN    = true;
const CS_STAGE_HONEYPOT = true;
// I3 (2026-07-26): eigener Schalter, unabhängig von CS_STAGE_RATE. cs_dup_hit() braucht
// keine IP — der Schlüssel ist hash(email + text) — und darf daher nicht mit abgeschaltet
// sein, nur weil REMOTE_ADDR hinter dem Reverse Proxy noch nicht verifiziert ist.
const CS_STAGE_DUP      = true;
const CS_STAGE_RATE     = false; // erst nach REMOTE_ADDR-Prüfung auf true
const CS_STAGE_SCORE    = true;

/* --- Token --------------------------------------------------------------- */

/**
 * Signiert einen Unix-Zeitstempel fälschungssicher.
 */
function cs_sign( $ts, $salt ) {
	$ts = (int) $ts;
	return $ts . '.' . hash_hmac( 'sha256', (string) $ts, $salt );
}

/**
 * Prüft ein Token und liefert den enthaltenen Zeitstempel — oder false.
 */
function cs_verify( $token, $salt ) {
	$token = (string) $token;
	$parts = explode( '.', $token, 2 );
	if ( 2 !== count( $parts ) || '' === $parts[0] || ! ctype_digit( $parts[0] ) ) {
		return false;
	}
	$ts = (int) $parts[0];
	if ( ! hash_equals( cs_sign( $ts, $salt ), $token ) ) {
		return false;
	}
	return $ts;
}

/**
 * Leitet den Honeypot-Feldnamen deterministisch aus dem Token ab — pro Besucher
 * verschieden, ohne serverseitigen Zustand.
 */
function cs_honeypot_name( $token, $salt ) {
	return 'f' . substr( hash_hmac( 'sha256', 'hp|' . $token, $salt ), 0, 11 );
}

/* --- Inhalts-Score ------------------------------------------------------- */

/**
 * Keyword-Startliste, bewusst konservativ. Erweitern nach Auswertung des Spam-Logs.
 *
 * Bewusst NICHT enthalten: 'seo', 'traffic', 'ranking' (Entscheidung 2026-07-26).
 * Für eine Technologie- und Prozessberatung ist das normales Kundenvokabular:
 * "wir suchen Beratung zu SEO und mehr Traffic" erreichte damit 4 Punkte und wäre
 * markiert worden, ein Websitevergleich mit drei Referenzlinks und dem Wort
 * "Ranking" sogar 8 Punkte und damit geblockt. Nicht wieder aufnehmen, ohne die
 * beiden Regressionstests in tests/run.php zu prüfen.
 */
const CS_KEYWORDS = array(
	'backlink', 'guest post', 'crypto', 'bitcoin', 'casino', 'loan', 'viagra',
	'web design services', 'increase your sales',
);

/**
 * Häufige deutsche/englische Funktionswörter — ihr Fehlen ist ein Spam-Signal.
 * Bewusst breit gehalten: eine zu knappe Liste bestraft kurze echte Anfragen
 * ("Guten Tag, wie in … beschrieben, bitte um Rückruf.") mit einem False Positive.
 */
const CS_FUNCTION_WORDS = array(
	' der ', ' die ', ' das ', ' und ', ' ich ', ' wir ', ' sie ', ' ist ', ' für ',
	' mit ', ' eine ', ' einen ', ' nicht ', ' auf ', ' zu ', ' von ', ' in ', ' im ',
	' um ', ' wie ', ' an ', ' bei ', ' aus ', ' dem ', ' den ', ' es ', ' auch ',
	' nach ', ' bitte ', ' habe ', ' haben ', ' uns ', ' mir ',
	' the ', ' and ', ' you ', ' we ', ' is ', ' for ', ' with ', ' to ', ' of ',
	' on ', ' at ', ' this ', ' our ', ' have ', ' are ', ' would ', ' please ',
);

/** Zählt echte Links (http/https/www) — E-Mail-Adressen zählen nicht mit. */
function cs_count_urls( $s ) {
	return (int) preg_match_all( '#(?:https?://|\bwww\.)\S+#i', (string) $s );
}

/** Anteil kyrillischer/CJK-/arabischer Zeichen an allen Buchstaben (0.0–1.0). */
function cs_foreign_ratio( $s ) {
	$letters = (int) preg_match_all( '/\p{L}/u', (string) $s );
	if ( 0 === $letters ) {
		return 0.0;
	}
	$foreign = (int) preg_match_all(
		'/[\p{Cyrillic}\p{Han}\p{Hiragana}\p{Katakana}\p{Hangul}\p{Arabic}]/u',
		(string) $s
	);
	return $foreign / $letters;
}

/**
 * Anzahl der Treffer aus CS_KEYWORDS — mit Wortgrenzen, nicht als Teilstring.
 * Teilstring-Suche träfe 'crypto' in "cryptography" und 'loan' in Eigennamen.
 */
function cs_keyword_hits( $s ) {
	$s    = (string) $s;
	$hits = 0;
	foreach ( CS_KEYWORDS as $kw ) {
		if ( preg_match( '/\b' . preg_quote( $kw, '/' ) . '\b/iu', $s ) ) {
			$hits++;
		}
	}
	return $hits;
}

/** Enthält der Text mindestens ein deutsches/englisches Funktionswort? */
function cs_has_function_word( $s ) {
	$s = ' ' . mb_strtolower( preg_replace( '/\s+/u', ' ', (string) $s ) ) . ' ';
	foreach ( CS_FUNCTION_WORDS as $w ) {
		if ( false !== mb_strpos( $s, $w ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Enthält der Text irgendwo ein Leerzeichen?
 *
 * Belegter Spam-Fall (eilige-edv.de, 2026-07-28): Betreff `zdcyHHVHPHkCHExn`,
 * Nachricht `yhKXSOsCGLhdLEudb` — je ein zufälliges Einzeltoken ohne Link, ohne
 * Keyword, ohne Fremdschrift. cs_extract() verbindet die Felder nur mit `\n`, ein
 * echtes Leerzeichen kommt ausschließlich aus mehrwortigem Inhalt (Name mit
 * Vor-/Nachname, ein ganzer Satz). Reines Zufallstoken-Spam hat keins.
 */
function cs_has_whitespace( $s ) {
	return false !== strpos( (string) $s, ' ' );
}

/**
 * Vokalanteil an allen Buchstaben eines Feldes (0.0–1.0), oder null ohne Buchstaben.
 * Ohne y: im Deutschen kaum vokalisch, aber in Zufallstoken haeufiger Fuellbuchstabe
 * ("yhKXSOsCGLhdLEudb") — mitgezaehlt haette es den Ausschlag genau dort verwaschen,
 * wo er zaehlt (2026-07-28, Testbefund).
 */
function cs_vowel_ratio( $s ) {
	$letters = (int) preg_match_all( '/\p{L}/u', (string) $s );
	if ( 0 === $letters ) {
		return null;
	}
	$vowels = (int) preg_match_all( '/[aeiouäöüAEIOUÄÖÜ]/u', (string) $s );
	return $vowels / $letters;
}

/**
 * Anteil der Gross-/Klein-Wechsel zwischen aufeinanderfolgenden Buchstaben (0.0–1.0).
 *
 * I10 (2026-07-29, belegter Spam-Fall contic.de): reiner Zufallstext ueber dem
 * lateinischen Alphabet hat im Erwartungswert ~19 % Vokale (5 von 26 Buchstaben) —
 * fast identisch mit CS_RANDOM_MAX_VOWEL. Individuelle Zufallstoken streuen dadurch
 * um die Schwelle herum und rutschen bei zufaellig hoeherem Vokalanteil durch
 * ("LDTIhlaLPqQijIBX" 25 %, "qsXkRjVEJqPusMFNPIIgAvjd" ~21 %,
 * "UdhwMGKVjoKHuBviZ" ~24 % — alle drei knapp über CS_RANDOM_MAX_VOWEL, kamen nur
 * markiert statt blockiert durch). Die Gross-/Klein-Wechselrate ist dagegen ein
 * deutlich trennschärferes Signal fuer genau dieses Bot-Muster (zufällige
 * Zeichenfolgen über [a-zA-Z]): echte Woerter/Namen wechseln so gut wie nie mitten
 * im Wort die Schreibung (max. 1 Wechsel bei Titel-Schreibung), waehrend
 * "LDTIhlaLPqQijIBX" 6 von 15 moeglichen Wechseln hat (40 %).
 */
function cs_case_flip_ratio( $s ) {
	preg_match_all( '/\p{L}/u', (string) $s, $m );
	$letters = $m[0];
	$n       = count( $letters );
	if ( $n < 2 ) {
		return 0.0;
	}
	$flips = 0;
	$prev  = ( $letters[0] === mb_strtoupper( $letters[0] ) && $letters[0] !== mb_strtolower( $letters[0] ) );
	for ( $i = 1; $i < $n; $i++ ) {
		$cur = ( $letters[ $i ] === mb_strtoupper( $letters[ $i ] ) && $letters[ $i ] !== mb_strtolower( $letters[ $i ] ) );
		if ( $cur !== $prev ) {
			$flips++;
		}
		$prev = $cur;
	}
	return $flips / ( $n - 1 );
}

/**
 * Enthält der Text ein Feld, das wie zusammenhangloses Zeichenwirrwarr aussieht?
 *
 * Ergänzung zu cs_has_whitespace() (2026-07-28, Entscheidung: reine
 * Zufallstoken-Spam-Faelle sollen blockiert statt nur markiert werden). Zwei
 * unabhaengige Pruefungen je Feld (ODER-verknuepft — reicht, wenn eine anschlaegt):
 *
 * 1. Vokalanteil (cs_vowel_ratio): "zdcyHHVHPHkCHExn" 1/16 (~6 %). Faengt auch
 *    einheitlich klein/gross geschriebene Zufallsfolgen, wo Signal 2 nichts hat.
 * 2. Gross-/Klein-Wechselrate (cs_case_flip_ratio, I10): faengt Faelle, in denen der
 *    Vokalanteil zufaellig ueber der Schwelle liegt (s. Docblock dort).
 *
 * Auch lange echte deutsche Komposita bleiben bei beiden Pruefungen unauffaellig:
 * "Nachhaltigkeitsstrategieberatung" hat 37 % Vokalanteil und 0 % Wechselrate (nur
 * Grossbuchstabe am Wortanfang) — waere bei einer reinen Laengen-Schwelle faelschlich
 * als Zufallstoken durchgefallen.
 *
 * Je FELD geprüft (cs_extract() trennt mit "\n"), nicht über den ganzen Text
 * gemittelt: ein plausibler Name neben einem Zufallsbetreff darf dessen Ausschlag
 * nicht verwaschen. CS_RANDOM_MIN_LEN filtert kurze echte Antworten heraus ("Max",
 * "Rückruf", "Danke!" bleiben alle unter der Mindestlänge) — sonst waere jede kurze
 * aber echte Anfrage ohne Leerzeichen ebenfalls betroffen.
 *
 * Bekannter Restfall (nicht behoben, Risiko akzeptiert): ein einzelnes Feld, dessen
 * gesamter Inhalt ein einwortiger Marken-/Eigenname mit binnengrossem Buchstaben ist
 * ("McDonald", "PayPal") kann die Wechselrate-Schwelle vereinzelt erreichen. Setzt
 * zusaetzlich voraus, dass *kein* anderes Feld der Einreichung ein Leerzeichen enthält
 * — bei einer eingebetteten Erwaehnung in einem ganzen Satz greift die Pruefung gar
 * nicht erst (cs_has_whitespace() waere dann schon wahr).
 */
function cs_has_random_token( $text ) {
	foreach ( preg_split( '/\n/', (string) $text ) as $field ) {
		$letters = (int) preg_match_all( '/\p{L}/u', $field );
		if ( $letters < CS_RANDOM_MIN_LEN ) {
			continue;
		}
		$ratio = cs_vowel_ratio( $field );
		if ( null !== $ratio && $ratio < CS_RANDOM_MAX_VOWEL ) {
			return true;
		}
		if ( cs_case_flip_ratio( $field ) > CS_RANDOM_MAX_CASE_FLIP ) {
			return true;
		}
	}
	return false;
}

/**
 * Additive Bewertung. Additiv statt harter Einzelregeln, damit eine echte Anfrage
 * mit einem Link nicht durchfällt. Schwellen: CS_SCORE_MARK / CS_SCORE_BLOCK.
 *
 * @param string $name
 * @param string $text
 * @param int    $parts_count Anzahl der Freitextteile, die cs_extract() zu $text
 *                             zusammengefügt hat (Default 2 für Aufrufer mit nur
 *                             zwei Argumenten — entspricht dem bisherigen Verhalten,
 *                             s. M-name).
 * @return array{score:int,signals:string[]}
 */
function cs_score( $name, $text, $parts_count = 2 ) {
	$score   = 0;
	$signals = array();

	$urls = cs_count_urls( $text );
	if ( $urls >= 3 ) {
		$score += 4;
		$signals[] = 'urls>=3';
	} elseif ( 2 === $urls ) {
		$score += 2;
		$signals[] = 'urls=2';
	} elseif ( 1 === $urls ) {
		$score += 1;
		$signals[] = 'urls=1';
	}

	if ( preg_match( '/\[(?:url|link)\s*=|<a\s+href/i', (string) $text ) ) {
		$score += 4;
		$signals[] = 'markup_link';
	}

	$foreign = cs_foreign_ratio( $text ) > 0.10;
	if ( $foreign ) {
		$score += 4;
		$signals[] = 'foreign_script';
	}

	$kw = cs_keyword_hits( $text );
	if ( $kw > 0 ) {
		$score += min( 4, 2 * $kw );
		$signals[] = 'keywords=' . $kw;
	}

	$name_t = trim( (string) $name );
	$text_t = trim( (string) $text );
	if ( cs_count_urls( $name_t ) > 0 ) {
		$score += 3;
		$signals[] = 'url_in_name';
	} elseif ( $parts_count > 1 && '' !== $name_t && mb_strtolower( $name_t ) === mb_strtolower( $text_t ) ) {
		// M-name: bei nur einem Freitextfeld (z. B. Name + E-Mail, sonst nichts) ist
		// Text === Name zwangsläufig und kein Spam-Signal — sonst markiert jede
		// Rückruf-/Newsletter-Anmeldung automatisch (2026-07-26).
		$score += 3;
		$signals[] = 'name_eq_text';
	}

	// Kein Füllwort-Signal bei Fremdschrift: beides misst dieselbe Ursache, und die
	// Doppelzählung ließ eine echte Anfrage in nicht-lateinischer Schrift mit einem
	// Link exakt die Blockschwelle erreichen (Entscheidung 2026-07-26, I2).
	if ( '' !== $text_t && ! $foreign && ! cs_has_function_word( $text_t ) ) {
		$score += 2;
		$signals[] = 'no_function_word';
	}

	// Unabhaengig vom Fuellwort-Signal: reines Zufallstoken-Spam (kein Link, kein
	// Keyword, keine Fremdschrift) hatte sonst nur no_function_word (+2) und blieb
	// unter CS_SCORE_MARK.
	//
	// Zwei Stufen (Entscheidung, 2026-07-28, nach zwei belegten Live-Faellen
	// auf eilige-edv.de): enthaelt zusaetzlich ein Feld, das wie zusammenhangloses
	// Zeichenwirrwarr aussieht (cs_has_random_token(), Vokalanteil-Pruefung je Feld),
	// zusammen mit no_function_word +7 = Blockschwelle erreicht. Fehlt dieses Merkmal
	// (z. B. eine kurze aber echte Antwort wie Name "Max", Betreff "Rückruf",
	// Nachricht "Danke!" — alle Felder unter CS_RANDOM_MIN_LEN), bleibt es bei +2,
	// zusammen mit no_function_word nur Markierung — bewusst so gestaffelt, damit eine
	// kurze echte Anfrage ohne Leerzeichen nicht denselben Ausschlag bekommt wie ein
	// langes Zufallstoken.
	if ( '' !== $text_t && ! cs_has_whitespace( $text_t ) ) {
		if ( cs_has_random_token( $text_t ) ) {
			$score += 5;
			$signals[] = 'no_whitespace_random_token';
		} else {
			$score += 2;
			$signals[] = 'no_whitespace';
		}
	}

	return array( 'score' => $score, 'signals' => $signals );
}

/* --- Rate-Limit und Duplikate -------------------------------------------- */

/** Felder, die nie in die Inhaltsbewertung einfließen (Metadaten, keine Nutzereingabe). */
// I11 (2026-07-29): lead_consent/form_version/lead_lang ergaenzt — seit der
// Formular-Vereinheitlichung auf das lead_*-Schema (alle vier Sites) sind das die
// neuen Metadaten-Felder anstelle von datenschutz/acceptance (bleiben als Fallback
// fuer noch nicht umgestellte Kopien stehen).
const CS_SKIP_FIELDS = array(
	'source_site', 'form_type', 'datenschutz', 'acceptance',
	'lead_consent', 'form_version', 'lead_lang',
);

/** IP ausschließlich gehasht — nie im Klartext gespeichert (DSGVO, Spec §3.7). */
function cs_ip_hash( $ip, $salt ) {
	return substr( hash_hmac( 'sha256', (string) $ip, $salt ), 0, 32 );
}

/** Zählt die Absendung und meldet, ob ein Limit überschritten wurde. */
function cs_rate_hit( $ip_hash ) {
	$k_short = 'cs_rl_' . $ip_hash;
	$n_short = (int) get_transient( $k_short );
	if ( $n_short >= CS_RL_SHORT ) {
		return 'rate_short';
	}

	$k_day = 'cs_rl24_' . $ip_hash;
	$n_day = (int) get_transient( $k_day );
	if ( $n_day >= CS_RL_DAY ) {
		return 'rate_day';
	}

	set_transient( $k_short, $n_short + 1, CS_RL_SHORT_TTL );
	set_transient( $k_day, $n_day + 1, DAY_IN_SECONDS );
	return '';
}

/**
 * Identische Nachricht derselben Adresse innerhalb von 24 h.
 *
 * Die beiden Werte werden über `wp_json_encode` verbunden, nicht per `.'|'.`:
 * sonst ergeben ('a@b.de', 'hallo|welt') und ('a@b.de|hallo', 'welt') denselben
 * Schlüssel, und die zweite Einreichung würde fälschlich als Duplikat abgewiesen
 * (Review 2026-07-26).
 */
function cs_dup_hit( $email, $text ) {
	$key = 'cs_dup_' . substr(
		hash( 'sha256', wp_json_encode( array(
			mb_strtolower( trim( (string) $email ) ),
			trim( (string) $text ),
		) ) ),
		0,
		32
	);
	if ( get_transient( $key ) ) {
		return 'duplicate';
	}
	set_transient( $key, 1, DAY_IN_SECONDS );
	return '';
}

/**
 * Wählt das Namensfeld gezielt aus, statt per Teilstring-Regex `/name/i`.
 *
 * Grund (Review 2026-07-26, belegt): `/name/i` greift auch auf
 * `firmenname` und `username` und nimmt den ersten Treffer — bei einem Formular
 * mit `firmenname` VOR `name` landete die Firma im Namensfeld. Und bei
 * edu-space.de (`vorname` + `nachname`) ergab es nur die Hälfte des Namens.
 *
 * Kein Treffer heißt bewusst leerer Name statt falscher Name: `cs_score`
 * behandelt einen leeren Namen sauber, ein falscher Name verfälscht die
 * Signale `url_in_name` und `name_eq_text`.
 */
function cs_pick_name( $named ) {
	// I11 (2026-07-29): lead_name ergaenzt — einheitliches Feldschema seit der
	// Formular-Vereinheitlichung auf allen vier Sites (contic.de, eilige-edv.de,
	// gseilheimer.de, edu-space.de).
	foreach ( array( 'lead_name', 'name', 'your-name', 'ihr-name', 'full-name', 'fullname' ) as $k ) {
		if ( isset( $named[ $k ] ) ) {
			return $named[ $k ];
		}
	}

	$first = '';
	$last  = '';
	foreach ( array( 'vorname', 'first-name', 'firstname' ) as $k ) {
		if ( isset( $named[ $k ] ) ) {
			$first = $named[ $k ];
			break;
		}
	}
	foreach ( array( 'nachname', 'last-name', 'lastname' ) as $k ) {
		if ( isset( $named[ $k ] ) ) {
			$last = $named[ $k ];
			break;
		}
	}

	return trim( $first . ' ' . $last );
}

/**
 * Zieht E-Mail, Name und Freitext aus beliebigen CF7-Formularen — die Feldnamen
 * unterscheiden sich je Site (name/nachricht vs. vorname/bemerkungen vs. message).
 *
 * @return array{email:string,name:string,text:string,parts_count:int}
 */
function cs_extract( $data ) {
	$email = '';
	$parts = array();
	$named = array();

	foreach ( (array) $data as $key => $value ) {
		if ( 0 === strpos( (string) $key, '_' ) ) {
			continue;
		}
		// M-skip: Rohschlüssel case-sensitiv gegen CS_SKIP_FIELDS zu vergleichen, während
		// $named weiter unten kleingeschrieben wird, ließ ein Feld wie „Datenschutz"
		// (Groß-/Kleinschreibung je nach Formularbau) durchrutschen statt übersprungen
		// zu werden (2026-07-26).
		if ( in_array( strtolower( (string) $key ), CS_SKIP_FIELDS, true ) ) {
			continue;
		}
		if ( is_array( $value ) ) {
			$value = implode( ' ', array_map( 'strval', $value ) );
		}
		$value = trim( (string) $value );
		if ( '' === $value ) {
			continue;
		}
		if ( '' === $email && is_email( $value ) ) {
			$email = $value;
			continue;
		}
		$named[ strtolower( (string) $key ) ] = $value;
		$parts[] = $value;
	}

	return array(
		'email'       => $email,
		'name'        => cs_pick_name( $named ),
		'text'        => implode( "\n", $parts ),
		'parts_count' => count( $parts ), // M-name: s. cs_score()
	);
}

/* --- Spam-Log ------------------------------------------------------------ */

/**
 * Ringpuffer der letzten CS_LOG_MAX Fälle. Ohne diese Ansicht ließe sich der
 * Inhalts-Score nicht nachjustieren — man würde blind tunen.
 *
 * Enthält bewusst keine IP, auch nicht gehasht. Enthält seit der C1-Korrektur
 * (Abschluss-Review 2026-07-26) die Absenderadresse der abgewiesenen Einreichung —
 * ohne sie war ein Fehlalarm im Log nicht beantwortbar. Retention (seit v1.5.0,
 * 2026-08-03): maximal CS_LOG_MAX Einträge UND höchstens CS_LOG_RETENTION_DAYS Tage —
 * je nachdem, was zuerst greift (s. cs_log_apply_retention()). Für die
 * Datenschutzerklärung relevant, s. README.md, Abschnitt Datenschutz.
 */
function cs_log_add( $entry ) {
	$log = cs_log_get();
	array_unshift( $log, $entry );
	$log = cs_log_apply_retention( $log );
	update_option( 'cs_log', array_slice( $log, 0, CS_LOG_MAX ), false );
}

function cs_log_get() {
	$log = get_option( 'cs_log', array() );
	return is_array( $log ) ? $log : array();
}

/**
 * Reine Filterfunktion: entfernt Eintraege, deren 'time'-Feld aelter als
 * CS_LOG_RETENTION_DAYS ist. Kein Options-Zugriff hier — leicht testbar, wiederverwendet
 * von cs_log_add() (Schreibpfad) und cs_log_purge_expired() (Lesepfad ohne neuen Eintrag).
 *
 * Fail-safe: Eintraege ohne lesbares 'time'-Feld (leer oder von strtotime() nicht
 * geparst) werden NICHT entfernt — ein Parsing-Fehler soll eher zu einem Eintrag zu viel
 * fuehren als zu einem unbemerkten Datenverlust.
 */
function cs_log_apply_retention( $log ) {
	$cutoff = time() - ( CS_LOG_RETENTION_DAYS * DAY_IN_SECONDS );
	return array_values( array_filter( (array) $log, function ( $row ) use ( $cutoff ) {
		if ( empty( $row['time'] ) ) {
			return true;
		}
		$ts = strtotime( (string) $row['time'] );
		return false === $ts ? true : $ts >= $cutoff;
	} ) );
}

/**
 * Wendet die Retention-Frist auf den bestehenden Bestand an, ohne dass ein neuer
 * Log-Eintrag vorliegt — Aufrufer: cs_render_log_page() (Admin-Seite geoeffnet) und der
 * taegliche Cron-Job cs_daily_log_purge (Sicherheitsnetz fuer stille Perioden). Schreibt
 * nur, wenn sich der Bestand tatsaechlich veraendert hat (kein Leerlauf-Write).
 */
function cs_log_purge_expired() {
	$log  = cs_log_get();
	$kept = cs_log_apply_retention( $log );
	if ( count( $kept ) !== count( $log ) ) {
		update_option( 'cs_log', $kept, false );
	}
	return $kept;
}

/**
 * Taeglicher Cron-Job als Sicherheitsnetz: loescht abgelaufene Log-Eintraege auch dann,
 * wenn weder eine neue Einreichung eintrifft noch jemand Werkzeuge -> Spam-Log oeffnet
 * (z. B. eine ruhige Site in einer spamarmen Woche). Ohne dieses Netz blieben abgelaufene
 * Eintraege bis zum naechsten Log-Zugriff liegen — bei wenig Traffic potenziell Monate.
 */
add_action( 'cs_daily_log_purge', 'cs_log_purge_expired' );

if ( ! wp_next_scheduled( 'cs_daily_log_purge' ) ) {
	wp_schedule_event( time(), 'daily', 'cs_daily_log_purge' );
}

add_action( 'admin_menu', function () {
	add_management_page(
		'Spam-Log',
		'Spam-Log',
		'manage_options',
		'cs-log',
		'cs_render_log_page'
	);
} );

function cs_render_log_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	if ( isset( $_POST['cs_clear'] ) && check_admin_referer( 'cs_clear_log' ) ) {
		update_option( 'cs_log', array(), false );
		echo '<div class="notice notice-success"><p>Log geleert.</p></div>';
	}

	$log = cs_log_purge_expired();

	echo '<div class="wrap"><h1>Spam-Log</h1>';
	echo '<p>Die letzten ' . (int) CS_LOG_MAX . ' abgewiesenen oder markierten Einreichungen, '
		. 'höchstens ' . (int) CS_LOG_RETENTION_DAYS . ' Tage alt — ältere Einträge werden '
		. 'automatisch gelöscht. Grundlage für das Nachjustieren der Schwellen (aktuell: '
		. 'markieren ab ' . (int) CS_SCORE_MARK . ', blocken ab ' . (int) CS_SCORE_BLOCK . ').</p>';

	// M10: die Tokenfehler-Zahl steht hier als Information — sie loest keinen Alarm mehr
	// aus, weil sie ueberwiegend abgewehrte Bots zaehlt (s. cs_selftest_check()).
	$stand = get_option( CS_SELFTEST_OPT, false );
	echo '<p><strong>Token-Endpunkt:</strong> ';
	if ( is_array( $stand ) && isset( $stand['time'] ) ) {
		echo ( empty( $stand['ok'] ) ? '<span style="color:#b32d2e">gestört</span>' : 'in Ordnung' )
			. ' — ' . esc_html( (string) $stand['msg'] )
			. ' (geprüft am ' . esc_html( date_i18n( 'd.m.Y H:i', (int) $stand['time'] ) ) . ')';
	} else {
		echo 'noch nicht geprüft — der tägliche Selbsttest läuft spätestens morgen.';
	}
	echo '<br><strong>Einreichungen ohne gültiges Token, letzte 24 h:</strong> '
		. (int) cs_fail_count() . ' — normalerweise Bots, die kein JavaScript ausführen.</p>';

	echo '<form method="post" style="margin:1em 0">';
	wp_nonce_field( 'cs_clear_log' );
	echo '<button class="button" name="cs_clear" value="1">Log leeren</button></form>';

	if ( empty( $log ) ) {
		echo '<p>Keine Einträge.</p></div>';
		return;
	}

	echo '<table class="widefat striped"><thead><tr>'
		. '<th>Zeit</th><th>Formular</th><th>E-Mail</th><th>Grund</th><th>Score</th>'
		. '<th>Signale</th><th>Auszug</th>'
		. '</tr></thead><tbody>';

	foreach ( $log as $row ) {
		$signals = isset( $row['signals'] ) && is_array( $row['signals'] )
			? implode( ', ', $row['signals'] )
			: '';
		echo '<tr>'
			. '<td>' . esc_html( isset( $row['time'] ) ? $row['time'] : '' ) . '</td>'
			. '<td>' . esc_html( isset( $row['form'] ) ? $row['form'] : '' ) . '</td>'
			. '<td>' . esc_html( isset( $row['email'] ) ? $row['email'] : '' ) . '</td>'
			. '<td>' . esc_html( isset( $row['reason'] ) ? $row['reason'] : '' ) . '</td>'
			. '<td>' . esc_html( isset( $row['score'] ) ? $row['score'] : '' ) . '</td>'
			. '<td>' . esc_html( $signals ) . '</td>'
			. '<td>' . esc_html( isset( $row['excerpt'] ) ? $row['excerpt'] : '' ) . '</td>'
			. '</tr>';
	}

	echo '</tbody></table></div>';
}

/* --- REST-Endpoint: Token ------------------------------------------------ */

add_action( 'rest_api_init', function () {
	register_rest_route( 'contic-spam/v1', '/token', array(
		'methods'             => 'GET',
		'permission_callback' => '__return_true', // öffentlich; gibt nichts Geheimes heraus
		'callback'            => function () {
			$salt  = wp_salt( 'contic-spam' );
			$token = cs_sign( time(), $salt );
			nocache_headers();
			return array(
				't' => $token,
				'f' => cs_honeypot_name( $token, $salt ),
			);
		},
	) );
} );

/* --- Client-JS ----------------------------------------------------------- */

/**
 * Holt das signierte Token per REST und injiziert Token- und Honeypot-Feld in jedes
 * CF7-Formular. Im HTML steht nur dieses statische Skript — deshalb ist der Schutz
 * unabhängig von jedem Page-Cache (der Fehler des Vorgängers, s. Spec §1.3).
 *
 * Fünf Eigenschaften, die in drei Review-Runden erarbeitet wurden und nicht
 * wegoptimiert werden dürfen:
 *
 * 1. Abruf beim Seitenaufbau, NICHT bei der ersten Interaktion. Sonst ist der Klick
 *    auf „Senden" selbst die erste Interaktion, und der fetch kommt garantiert zu
 *    spät — jede autogefüllte Anfrage wäre verloren.
 * 2. Token- und Honeypot-Wert werden als Property UND als Attribut gesetzt. CF7 ruft
 *    nach erfolgreichem Versand `form.reset()` auf, und `reset()` stellt jedes Feld
 *    auf sein `defaultValue` zurück — also auf das value-Attribut. Ohne das Attribut
 *    wäre das Token danach leer, und eine zweite Anfrage von derselben Seite würde
 *    als `no_token` abgewiesen.
 * 3. Das Sicherheitsnetz am submit-Ereignis prüft, ob GENAU DIESES Formular ein
 *    gefülltes Token trägt — nicht bloß, ob global eines geholt wurde. Ein
 *    nachträglich ins DOM eingefügtes Formular (Popup, AJAX-Sektion) hat keines,
 *    während die globale Frische noch gilt; ohne diese Unterscheidung würde dort
 *    tokenlos abgesendet und alles als `no_token` abgewiesen.
 * 4. Aufgehaltenes Absenden wird immer freigegeben: Token-Abruf gegen 4 s gekappt,
 *    Abruf-Coalescing gegen 5 s gekappt. Schlimmster Fall ist Kappung plus
 *    Mindestalter, also rund 7 s — danach geht die Anfrage in jedem Fall raus, im
 *    Zweifel ohne Token und damit serverseitig abgewiesen, aber MIT Auszug im Log.
 *    Ein tot wirkender Senden-Button ist schlimmer als eine geloggte Ablehnung.
 * 5. Auffrischen bei `pageshow` und `visibilitychange` — ein über Nacht schlafender
 *    Laptop hätte sonst ein abgelaufenes Token im Formular.
 *
 * Die URL wird relativ eingesetzt: `rest_url()` baut sie aus `home_url`, und bei
 * www-/non-www- oder http-/https-Abweichung würde der fetch sonst cross-origin und
 * von WordPress abgelehnt — was 100 % der Anfragen abweisen würde.
 */
function cs_inline_js() {
	$url         = wp_json_encode( wp_make_link_relative( rest_url( 'contic-spam/v1/token' ) ) );
	$min_ms      = CS_MIN_SECONDS * 1000;
	$refresh_ms  = 3000000; // 50 min — innerhalb der Server-TTL von CS_TOKEN_TTL (3600 s)
	$hold_cap_ms = 4000;    // so lange wird ein Absenden höchstens aufgehalten
	$grab_cap_ms = 5000;    // so lange gilt ein laufender Abruf als „läuft noch"

	return <<<JS
(function(){
	// CF7 6.x sendet selbst per fetch ab — ohne fetch ist das Formular ohnehin nicht
	// nutzbar. Der Test verhindert nur einen Fehler, der die Listener-Registrierung
	// abbrechen würde.
	if(typeof fetch !== 'function' || typeof Promise !== 'function'){ return; }

	var url = {$url}, minAge = {$min_ms}, tokenAt = 0, inflight = null, last = null;

	// Felder setzen, ohne die Frische-Uhr anzufassen.
	function inject(d){
		if(!d || !d.t || !d.f){ return false; }
		var forms = document.querySelectorAll('form.wpcf7-form');
		for(var i=0;i<forms.length;i++){
			var f = forms[i];
			var t = f.querySelector('input[name="_cs_t"]');
			if(!t){
				t = document.createElement('input');
				t.type = 'hidden';
				t.name = '_cs_t';
				f.appendChild(t);
			}
			t.value = d.t;
			t.setAttribute('value', d.t);
			var old = f.querySelector('input[data-cs-hp]');
			if(old){ old.parentNode.removeChild(old); }
			var hp = document.createElement('input');
			hp.type = 'text';
			hp.name = d.f;
			hp.value = '';
			hp.setAttribute('value','');
			hp.tabIndex = -1;
			hp.autocomplete = 'off';
			hp.setAttribute('data-cs-hp','1');
			hp.setAttribute('aria-hidden','true');
			hp.style.cssText = 'position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden';
			f.appendChild(hp);
		}
		return true;
	}

	// Neues Token übernehmen: Felder setzen, merken, Uhr stellen.
	function apply(d){
		if(!inject(d)){ return false; }
		last = d;
		tokenAt = Date.now();
		return true;
	}

	function once(retry){
		return fetch(url,{credentials:'omit',cache:'no-store'})
			.then(function(r){ if(!r.ok){ throw new Error('http '+r.status); } return r.json(); })
			.then(apply)
			.catch(function(){ return retry ? once(false) : false; });
	}

	// Gekappt, damit ein hängender Request nicht dauerhaft jeden weiteren Abruf blockt.
	function grab(){
		if(inflight){ return inflight; }
		inflight = Promise.race([
			once(true),
			new Promise(function(res){ setTimeout(function(){ res(false); }, {$grab_cap_ms}); })
		]).then(function(ok){ inflight = null; return ok; });
		return inflight;
	}

	function fresh(){ return tokenAt > 0 && (Date.now() - tokenAt) < {$refresh_ms}; }

	// M1: prueft nicht nur, ob ueberhaupt ein Wert im Feld steht, sondern ob er mit dem
	// zuletzt geholten Token identisch ist. Ein abgekoppeltes oder geklontes Formular
	// (Popup-Builder) kann sonst ein aelteres Token tragen, waehrend fresh() bereits das
	// neuere meint -> token_expired serverseitig.
	function hasToken(f){
		var t = f.querySelector('input[name="_cs_t"]');
		return !!(t && t.value && last && t.value === last.t);
	}

	grab();
	setInterval(grab, {$refresh_ms});
	window.addEventListener('pageshow', function(){ if(!fresh()){ grab(); } });
	document.addEventListener('visibilitychange', function(){
		if(document.visibilityState === 'visible' && !fresh()){ grab(); }
	});

	document.addEventListener('submit', function(ev){
		var f = ev.target;
		if(!f || !f.classList || !f.classList.contains('wpcf7-form')){ return; }
		if(f.getAttribute('data-cs-ok') === '1'){ f.removeAttribute('data-cs-ok'); return; }
		if(hasToken(f) && fresh() && (Date.now() - tokenAt) >= minAge){ return; }

		ev.preventDefault();
		ev.stopPropagation();

		if(f.getAttribute('data-cs-wait') === '1'){ return; }
		f.setAttribute('data-cs-wait','1');

		var btn = ev.submitter;
		// M5: Astra setzt background-color/color explizit auf Buttons, der
		// UA-Graustich beim disabled-Attribut entfaellt also womoeglich — zusaetzlich
		// inline sichtbar machen, damit ein aufgehaltenes Absenden nicht wie ein toter
		// Button aussieht.
		if(btn){ btn.setAttribute('disabled','disabled'); btn.style.opacity = '0.6'; btn.style.cursor = 'progress'; }

		var ready;
		if(fresh() && last){
			// Token noch gültig, aber dieses Formular hat es nicht (nachträglich
			// eingefügt oder DOM ersetzt): nachtragen statt neu holen. Die Uhr bleibt
			// stehen, sonst gälte ein altes Token clientseitig länger als die
			// Server-TTL und liefe auf token_expired.
			inject(last);
			ready = Promise.resolve(true);
		} else {
			ready = Promise.race([
				grab(),
				new Promise(function(res){ setTimeout(function(){ res(false); }, {$hold_cap_ms}); })
			]);
		}

		ready.then(function(){
			// M3: springt die Systemuhr rueckwaerts, wuerde Date.now() - tokenAt negativ
			// und Math.max(0, ...) liesse minAge unveraendert dastehen — das Halten
			// dauerte dann bis zur Sprungdauer, das Formular wirkte tot. Nach oben auf
			// minAge gekappt, damit das Warten nie laenger als das Mindestalter selbst ist.
			var wait = tokenAt ? Math.min(minAge, Math.max(0, minAge - (Date.now() - tokenAt))) : 0;
			setTimeout(function(){
				f.removeAttribute('data-cs-wait');
				if(btn){ btn.removeAttribute('disabled'); btn.style.opacity = ''; btn.style.cursor = ''; }
				f.setAttribute('data-cs-ok','1');
				// Aufräumen VOR dem Auslösen einplanen: wirft requestSubmit (etwa weil
				// der Button während des Haltens ersetzt wurde), bliebe die Markierung
				// sonst stehen und der naechste echte Klick käme ungeprüft durch.
				setTimeout(function(){ f.removeAttribute('data-cs-ok'); }, 0);
				// M-try: requestSubmit() kann werfen (z. B. Button waehrend des Haltens
				// ausgetauscht) — ohne try/catch bliebe die Anfrage dann still unversendet.
				try {
					if(typeof f.requestSubmit === 'function'){ f.requestSubmit(btn || undefined); }
					else { f.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})); }
				} catch(e) {
					f.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
				}
			}, wait);
		});
	}, true);
})();
JS;
}

// CF7 lädt seine Frontend-Assets standardmäßig auf jeder Seite, dieser Hook feuert
// also nicht nur auf Formularseiten. Ein DOM-Test beim Start würde nachträglich
// eingefügte Formulare (Popups, AJAX-Sektionen) dauerhaft ungeschützt lassen — das
// Skript läuft deshalb immer, und Punkt 3 des Docblocks oben trägt das Token bei
// solchen Formularen spätestens beim Absenden nach. Preis: ein REST-Aufruf auch auf
// Seiten ohne Formular.
add_action( 'wpcf7_enqueue_scripts', function () {
	wp_register_script( 'cs-guard', '', array(), CS_VERSION, true );
	wp_enqueue_script( 'cs-guard' );
	wp_add_inline_script( 'cs-guard', cs_inline_js() );
} );

/* --- Hilfsfunktionen für den Filter -------------------------------------- */

/**
 * Prüft gegen WP → Einstellungen → Diskussion → „Liste unerwünschter Inhalte"
 * (Option `disallowed_keys`). Damit lassen sich eigene Begriffe ohne Codeänderung
 * pflegen (Spec §3.5) — ein Treffer ist sofort Spam, unabhängig vom Score.
 *
 * Teilstring-Suche wie in WordPress selbst, damit ein dort eingetragenes Wort sich
 * hier genauso verhält wie bei Kommentaren.
 */
function cs_disallowed_hit( $text ) {
	$list = (string) get_option( 'disallowed_keys', '' );
	if ( '' === trim( $list ) ) {
		return false;
	}

	$text = mb_strtolower( (string) $text );
	foreach ( preg_split( '/\r\n|\r|\n/', $list ) as $word ) {
		$word = trim( $word );
		if ( '' === $word ) {
			continue;
		}
		if ( false !== mb_strpos( $text, mb_strtolower( $word ) ) ) {
			return true;
		}
	}

	return false;
}

/**
 * Formular-Kennung für den Log, z. B. „1734 — Kontakt CONTIC".
 *
 * Vier Sites mit je mehreren Formularen: ohne diese Angabe ließe sich ein Log-Eintrag
 * beim Nachjustieren keinem Formular zuordnen (Spec §3.6 verlangt Formular-ID/-Titel).
 * Durchgehend defensiv geprüft — ein API-Wechsel in CF7 darf den Kontaktkanal nicht
 * mit einem Fatal Error lahmlegen, im Zweifel bleibt das Label leer.
 */
function cs_form_label( $submission ) {
	if ( ! is_object( $submission ) || ! method_exists( $submission, 'get_contact_form' ) ) {
		return '';
	}
	$form = $submission->get_contact_form();
	if ( ! is_object( $form ) || ! method_exists( $form, 'id' ) || ! method_exists( $form, 'title' ) ) {
		return '';
	}
	return $form->id() . ' — ' . $form->title();
}

/**
 * Einheitliche Ablehnung: immer protokollieren, abweisen nur wenn CS_ENFORCE.
 *
 * Der Auszug wird mitgeführt, wo er vorliegt: bei `rate_short`, `rate_day` und
 * `duplicate` sind Fehlalarme am wahrscheinlichsten (geteilte Firmen-IP, ungeduldiges
 * Doppelklicken), und ohne den Nachrichtentext kann niemand beurteilen, ob eine echte
 * Anfrage getroffen wurde.
 *
 * C1 (2026-07-26): ohne Flamingo speichert CF7 bei abgewiesenen Einreichungen nichts,
 * und ein Sende-Plugin (z. B. fuer Webhooks) feuert bei Spam gar nicht — der Log-Auszug ist die einzige
 * verbleibende Kopie. Ohne Absender-E-Mail ist ein Fehlalarm nicht beantwortbar, daher
 * bekommt jeder Aufruf die E-Mail explizit mit.
 *
 * @return bool true = Spam (abweisen), false = durchlassen
 */
function cs_reject( $submission, $reason, $score, $signals, $excerpt = '', $email = '' ) {
	if ( is_object( $submission ) && method_exists( $submission, 'add_spam_log' ) ) {
		$submission->add_spam_log( array(
			'agent'  => 'contic-spamschutz',
			'reason' => $reason . ( CS_ENFORCE ? '' : ' (Beobachtungsmodus)' ),
		) );
	}

	cs_log_add( array(
		'time'    => current_time( 'mysql' ),
		'form'    => cs_form_label( $submission ),
		'email'   => $email,
		'reason'  => $reason . ( CS_ENFORCE ? '' : ' (nur beobachtet)' ),
		'score'   => (int) $score,
		'signals' => $signals,
		'excerpt' => mb_substr( (string) $excerpt, 0, 300 ),
	) );

	// I5: systematischer Tokenausfall (blockierte REST-Route, gecachte Token-Antwort,
	// zerlegtes Inline-Skript) faellt sonst nur auf, wenn jemand die Log-Seite oeffnet.
	if ( 'no_token' === $reason || 'token_expired' === $reason ) {
		cs_fail_note();
	}

	return CS_ENFORCE;
}

/**
 * I5/M9 (2026-08-24): Tokenfehler in Stundenkoerben statt in einem einzelnen Zaehler.
 *
 * Anlass: der Vorgaenger schrieb `set_transient( 'cs_fail_24h', $n + 1, DAY_IN_SECONDS )`.
 * Jeder neue Fehlschlag setzte die Restlaufzeit wieder auf volle 24 h — das Fenster
 * wanderte also mit. Zurueckgelaufen waere der Zaehler nur nach 24 h voellig ohne
 * Tokenfehler; bei laufendem Bot-Verkehr kommt das nie vor. Die Meldung „in den letzten
 * 24 Stunden" nannte damit eine Summe ueber einen unbestimmt langen Zeitraum.
 *
 * Jetzt: ein Korb je Stunde, Koerbe aelter als 24 h fallen weg. Die Zahl in der Meldung
 * entspricht dadurch dem, was sie behauptet (stundengenau, also 23–24 h).
 */
const CS_FAIL_BUCKET_KEY = 'cs_fail_buckets';
const CS_FAIL_WINDOW_H   = 24;

/** Aktuelle Stunde als ganzzahliger Korbschluessel. */
function cs_fail_hour() {
	return (int) floor( time() / HOUR_IN_SECONDS );
}

/** Wirft Koerbe ausserhalb des 24-h-Fensters weg. */
function cs_fail_prune( $buckets, $now_hour ) {
	if ( ! is_array( $buckets ) ) {
		return array();
	}
	$out = array();
	foreach ( $buckets as $h => $n ) {
		$h = (int) $h;
		if ( $h > $now_hour - CS_FAIL_WINDOW_H && $h <= $now_hour ) {
			$out[ $h ] = (int) $n;
		}
	}
	return $out;
}

/** Verbucht einen Tokenfehlschlag in der laufenden Stunde. */
function cs_fail_note() {
	$hour    = cs_fail_hour();
	$buckets = cs_fail_prune( get_transient( CS_FAIL_BUCKET_KEY ), $hour );

	$buckets[ $hour ] = ( isset( $buckets[ $hour ] ) ? (int) $buckets[ $hour ] : 0 ) + 1;

	// TTL grosszuegig: das Fenster bestimmt cs_fail_prune(), nicht der Transient-Ablauf.
	set_transient( CS_FAIL_BUCKET_KEY, $buckets, 2 * DAY_IN_SECONDS );
}

/** Tokenfehlschlaege der letzten 24 Stunden. */
function cs_fail_count() {
	$buckets = cs_fail_prune( get_transient( CS_FAIL_BUCKET_KEY ), cs_fail_hour() );
	return array_sum( $buckets );
}

/* --- Selbsttest des Token-Endpunkts ------------------------------------- */

/**
 * M10 (2026-08-24): der Alarm prueft jetzt den Mechanismus statt die Opfer zu zaehlen.
 *
 * Anlass: die Notice schlug an, sobald 5 Einreichungen ohne gueltiges Token eintrafen —
 * und behauptete dabei, die REST-Route sei blockiert oder ein Cache liefere altes Token.
 * Beides war beim ersten echten Auftreten falsch. Der Tokentest ist Stufe 2 und laeuft vor
 * Honigtopf, Blockliste und Score; jeder Bot ohne JavaScript erzeugt zwangslaeufig
 * `no_token`. Der Alarm meldete damit den Normalbetrieb des Schutzes als Stoerung —
 * am Livelog belegt: acht gemeldete Faelle, acht Spam-Einreichungen, kein Besucher.
 *
 * Stattdessen ruft ein taeglicher Cron-Job den Endpunkt selbst auf und prueft, was die
 * alte Notice nur vermutet hat: Erreichbarkeit, gueltige Signatur, plausibles Alter und —
 * ueber zwei aufeinanderfolgende Abrufe — dass nicht zweimal dasselbe Token kommt.
 *
 * Grenze, bewusst in Kauf genommen: der Aufruf laeuft ueber die Server-Schleife. Eine WAF
 * oder ein CDN, das nur externe Browser abweist, sieht dieser Test nicht. Er deckt ab:
 * entfernte/umbenannte Route, geaenderte permission_callback, PHP-Fatal, Plugin-Konflikt,
 * falsches Salt und eine cachende Zwischenschicht innerhalb von WordPress.
 */
const CS_SELFTEST_OPT     = 'cs_selftest';
const CS_SELFTEST_MAX_AGE = 60;  // Sekunden zwischen Ausstellung und Empfang
const CS_SELFTEST_STALE_D = 3;   // Tage ohne Testlauf -> Cron laeuft vermutlich nicht

/**
 * Bewertet zwei Endpunkt-Antworten. Rein rechnend, damit die Testsuite jeden Fall
 * durchspielen kann, ohne HTTP zu sprechen.
 *
 * $resp je: array( 'error' => string|null, 'code' => int, 'body' => string )
 */
function cs_selftest_check( $resp1, $resp2, $salt, $now ) {
	$fehler = function ( $msg ) { return array( 'ok' => false, 'msg' => $msg ); };

	if ( ! empty( $resp1['error'] ) ) {
		return $fehler( 'Endpunkt nicht erreichbar: ' . $resp1['error'] );
	}
	$code = (int) ( $resp1['code'] ?? 0 );
	if ( 200 !== $code ) {
		return $fehler( 'Endpunkt antwortet mit HTTP ' . $code . ' statt 200.' );
	}

	$daten = json_decode( (string) ( $resp1['body'] ?? '' ), true );
	if ( ! is_array( $daten ) || ! isset( $daten['t'] ) || ! is_string( $daten['t'] ) ) {
		return $fehler( 'Antwort enthaelt kein Token-Feld.' );
	}

	$ts = cs_verify( $daten['t'], $salt );
	if ( false === $ts ) {
		return $fehler( 'Token traegt keine gueltige Signatur.' );
	}

	$alter = (int) $now - (int) $ts;
	if ( $alter > CS_SELFTEST_MAX_AGE || $alter < -CS_SELFTEST_MAX_AGE ) {
		return $fehler( 'Token ist bei Empfang bereits ' . $alter . ' s alt — '
			. 'eine Zwischenschicht liefert vermutlich eine gespeicherte Antwort.' );
	}

	// Zweiter Abruf dient allein der Cache-Pruefung. Scheitert er (z. B. weil die
	// Burst-Drosselung zuschlaegt), bleibt der Befund des ersten Abrufs stehen — ein
	// misslungener Zweitabruf ist kein Defekt und darf keinen Alarm ausloesen.
	$daten2 = json_decode( (string) ( $resp2['body'] ?? '' ), true );
	if ( is_array( $daten2 ) && isset( $daten2['t'] ) && $daten2['t'] === $daten['t'] ) {
		return $fehler( 'Zwei Abrufe liefern dasselbe Token — '
			. 'die Antwort wird zwischengespeichert.' );
	}

	return array( 'ok' => true, 'msg' => 'Endpunkt liefert frische, gueltig signierte Token.' );
}

/** Ein einzelner Abruf, in der von cs_selftest_check() erwarteten Form. */
function cs_selftest_fetch_once() {
	$antwort = wp_remote_get( rest_url( 'contic-spam/v1/token' ), array(
		'timeout'   => 10,
		'sslverify' => false, // Schleifenaufruf auf den eigenen Host
	) );
	if ( is_wp_error( $antwort ) ) {
		return array( 'error' => $antwort->get_error_message(), 'code' => 0, 'body' => '' );
	}
	return array(
		'error' => null,
		'code'  => (int) wp_remote_retrieve_response_code( $antwort ),
		'body'  => (string) wp_remote_retrieve_body( $antwort ),
	);
}

/**
 * Holt eine Antwort und wiederholt den Versuch einmal, wenn die Verbindung scheitert
 * oder der Status nicht 200 ist.
 *
 * Grund (2026-08-24, an contic.de gemessen): zehn Abrufe ohne Pause ergaben vier
 * abgerissene Verbindungen, zehn Abrufe mit zwei Sekunden Abstand keine einzige. Vor dem
 * Endpunkt sitzt also eine Drosselung gegen Anfrage-Bursts. Fuer Besucher ist das
 * belanglos — ein Formular loest genau einen Abruf aus —, aber der Selbsttest feuert
 * zweimal kurz hintereinander. Ohne diesen zweiten Versuch wuerde er die Drosselung als
 * Endpunkt-Defekt melden, also genau die Sorte Fehlalarm erzeugen, die er abloesen soll.
 */
function cs_selftest_fetch() {
	$erste = cs_selftest_fetch_once();
	if ( null === $erste['error'] && 200 === (int) $erste['code'] ) {
		return $erste;
	}
	sleep( 2 );
	return cs_selftest_fetch_once();
}

/** Cron-Einsprung: testet und schreibt das Ergebnis weg. */
function cs_run_selftest() {
	$erste  = cs_selftest_fetch();
	$zweite = cs_selftest_fetch();
	$e      = cs_selftest_check( $erste, $zweite, wp_salt( 'contic-spam' ), time() );

	update_option( CS_SELFTEST_OPT, array(
		'time' => time(),
		'ok'   => (bool) $e['ok'],
		'msg'  => (string) $e['msg'],
	), false );

	return $e;
}

add_action( 'cs_daily_selftest', 'cs_run_selftest' );

if ( ! wp_next_scheduled( 'cs_daily_selftest' ) ) {
	wp_schedule_event( time(), 'daily', 'cs_daily_selftest' );
}

/**
 * M10: Notice nur noch bei nachgewiesenem Defekt am Endpunkt — oder wenn der Test
 * selbst seit Tagen nicht mehr gelaufen ist (dann sagt niemand mehr etwas, und genau
 * das soll nicht unbemerkt bleiben).
 */
add_action( 'admin_notices', function () {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$stand = get_option( CS_SELFTEST_OPT, false );

	// Noch nie gelaufen: kein Alarm — der Cron-Job startet spaetestens morgen.
	if ( ! is_array( $stand ) || ! isset( $stand['time'] ) ) {
		return;
	}

	$alter_tage = ( time() - (int) $stand['time'] ) / DAY_IN_SECONDS;

	if ( $alter_tage > CS_SELFTEST_STALE_D ) {
		echo '<div class="notice notice-warning"><p>'
			. '<strong>Spamschutz:</strong> Der Selbsttest des Token-Endpunkts lief zuletzt vor '
			. esc_html( (string) (int) $alter_tage ) . ' Tagen. Vermutlich sind die '
			. 'wp-cron-Aufgaben angehalten — der Schutz selbst ist davon nicht betroffen.'
			. '</p></div>';
		return;
	}

	if ( empty( $stand['ok'] ) ) {
		echo '<div class="notice notice-error"><p>'
			. '<strong>Spamschutz:</strong> Der Token-Endpunkt <code>'
			. esc_html( '/wp-json/contic-spam/v1/token' ) . '</code> hat den Selbsttest nicht '
			. 'bestanden. Befund: ' . esc_html( (string) $stand['msg'] ) . ' '
			. 'Solange das gilt, werden echte Anfragen abgewiesen. Geprüft am '
			. esc_html( date_i18n( 'd.m.Y H:i', (int) $stand['time'] ) ) . '.'
			. '</p></div>';
	}
} );

/** Score der laufenden Einreichung; 0, wenn der Filter nicht bis Stufe 4 kam. */
function cs_get_score() {
	return isset( $GLOBALS['cs_score'] ) ? (int) $GLOBALS['cs_score'] : 0;
}

/** Liest ein POST-Feld als Zeichenkette. Arrays ergeben '' statt einer PHP-Warnung. */
function cs_post( $key ) {
	if ( ! isset( $_POST[ $key ] ) || ! is_scalar( $_POST[ $key ] ) ) {
		return '';
	}
	return (string) wp_unslash( $_POST[ $key ] );
}

/* --- Prüffilter ---------------------------------------------------------- */

add_filter( 'wpcf7_spam', function ( $spam, $submission ) {
	if ( $spam ) {
		return $spam; // bereits von anderer Instanz als Spam markiert
	}

	$GLOBALS['cs_score'] = 0;
	$GLOBALS['cs_mark']  = false;

	// M-guard: einzige CF7-Aufrufstelle im Filter, die bislang ungeprüft blieb, während
	// cs_form_label() und cs_reject() durchgehend defensiv sind. Ein API-Wechsel in CF7
	// darf den Kontaktkanal nicht mit einem Fatal Error lahmlegen — im Zweifel durchlassen.
	if ( ! is_object( $submission ) || ! method_exists( $submission, 'get_posted_data' ) ) {
		return false;
	}

	$salt   = wp_salt( 'contic-spam' );
	$token  = cs_post( '_cs_t' );
	$fields = cs_extract( $submission->get_posted_data() );
	$text   = $fields['text'];
	$email  = $fields['email'];

	// Stufe 2 — Token und Zeit.
	if ( CS_STAGE_TOKEN ) {
		$ts = cs_verify( $token, $salt );

		if ( false === $ts ) {
			// Kein JS ausgeführt, oder der REST-Endpoint ist nicht erreichbar.
			return cs_reject( $submission, 'no_token', 0, array(), $text, $email );
		}

		$age = time() - $ts;

		if ( $age > CS_TOKEN_TTL ) {
			return cs_reject( $submission, 'token_expired', 0, array(), $text, $email );
		}
		if ( $age < CS_MIN_SECONDS ) {
			return cs_reject( $submission, 'too_fast', 0, array(), $text, $email );
		}
	}

	// Stufe 1 — Honeypot. Nur prüfbar, wenn ein gültiges Token den Feldnamen liefert.
	if ( CS_STAGE_HONEYPOT && '' !== $token ) {
		$hp_name = cs_honeypot_name( $token, $salt );
		if ( '' !== trim( cs_post( $hp_name ) ) ) {
			return cs_reject( $submission, 'honeypot', 0, array(), $text, $email );
		}
	}

	// Blockliste aus den WP-Einstellungen — sofort Spam, unabhängig vom Score.
	if ( CS_STAGE_SCORE && cs_disallowed_hit( $text ) ) {
		return cs_reject( $submission, 'disallowed_keys', 0, array( 'disallowed' ), $text, $email );
	}

	// Stufe 3 — Duplikate VOR dem Rate-Limit: sonst verbraucht ein ungeduldiger
	// Doppelklick zwei der drei Kurzfrist-Absendungen. I3 (2026-07-26): eigener Schalter,
	// unabhängig von CS_STAGE_RATE — cs_dup_hit() braucht keine IP.
	if ( CS_STAGE_DUP ) {
		$hit = cs_dup_hit( $email, $text );
		if ( '' !== $hit ) {
			return cs_reject( $submission, $hit, 0, array(), $text, $email );
		}
	}

	if ( CS_STAGE_RATE ) {
		$ip  = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		$hit = cs_rate_hit( cs_ip_hash( $ip, $salt ) );
		if ( '' !== $hit ) {
			return cs_reject( $submission, $hit, 0, array(), $text, $email );
		}
	}

	// Stufe 4 — Inhalts-Score.
	if ( CS_STAGE_SCORE ) {
		$result = cs_score( $fields['name'], $text, $fields['parts_count'] );
		$GLOBALS['cs_score'] = $result['score'];

		if ( $result['score'] >= CS_SCORE_BLOCK ) {
			return cs_reject( $submission, 'score_block', $result['score'], $result['signals'], $text, $email );
		}

		if ( $result['score'] >= CS_SCORE_MARK ) {
			$GLOBALS['cs_mark'] = true;
			cs_log_add( array(
				'time'    => current_time( 'mysql' ),
				'form'    => cs_form_label( $submission ),
				'email'   => $email,
				'reason'  => 'score_mark',
				'score'   => $result['score'],
				'signals' => $result['signals'],
				'excerpt' => mb_substr( $text, 0, 300 ),
			) );
		}
	}

	return false;
}, 20, 2 );

/**
 * Graubereich 4–6: im Betreff kennzeichnen — aber nur in der Mail an uns.
 *
 * CF7 ruft diesen Filter je Mail-Vorlage auf. Ohne die Namensprüfung bekäme ein
 * echter Interessent eine Bestätigungsmail mit „[Prüfen]" im Betreff, also die
 * Mitteilung, er sehe wie Spam aus — schlimmer als die Markierung selbst.
 */
add_filter( 'wpcf7_mail_components', function ( $components, $form, $mail ) {
	if ( empty( $GLOBALS['cs_mark'] ) || ! isset( $components['subject'] ) ) {
		return $components;
	}
	if ( is_object( $mail ) && method_exists( $mail, 'name' ) && 'mail' !== $mail->name() ) {
		return $components; // Autoresponder an den Absender — nicht kennzeichnen
	}
	// I9 (2026-07-26): '[SPAM?] ' im Betreff lud Microsoft 365/Google-Workspace-Filter
	// und lokale Postfach-Regeln ("SPAM" im Betreff) dazu ein, das Band 4–6 — das
	// bewusst echte Anfragen enthalten soll — selbst in den Junk-Ordner zu legen. Der
	// maschinenlesbare Marker bleibt der Log-Eintrag `score_mark`.
	$components['subject'] = '[Prüfen] ' . $components['subject'];
	return $components;
}, 10, 3 );
