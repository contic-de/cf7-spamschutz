<?php
require __DIR__ . '/wp-stubs.php';
require dirname( __DIR__ ) . '/cf7-spamschutz.php';

$GLOBALS['t_pass'] = 0;
$GLOBALS['t_fail'] = 0;

function t( $label, $actual, $expected ) {
    if ( $actual === $expected ) {
        $GLOBALS['t_pass']++;
        echo "  ok   $label\n";
    } else {
        $GLOBALS['t_fail']++;
        echo "  FAIL $label\n";
        echo "       erwartet: " . var_export( $expected, true ) . "\n";
        echo "       erhalten: " . var_export( $actual, true ) . "\n";
    }
}

$salt = wp_salt( 'contic-spam' );

echo "\nToken\n";
$ts    = 1750000000;
$token = cs_sign( $ts, $salt );
t( 'Signatur enthaelt Zeitstempel', strstr( $token, '.', true ), '1750000000' );
t( 'Verify liefert Zeitstempel',    cs_verify( $token, $salt ), $ts );
t( 'Verify lehnt manipuliert ab',   cs_verify( '1750000001.' . substr( $token, 11 ), $salt ), false );
t( 'Verify lehnt fremden Salt ab',  cs_verify( $token, 'anderer-salt' ), false );
t( 'Verify lehnt Muell ab',         cs_verify( 'abc', $salt ), false );
t( 'Verify lehnt leer ab',          cs_verify( '', $salt ), false );

echo "\nHoneypot-Feldname\n";
$hp = cs_honeypot_name( $token, $salt );
t( 'Laenge 12',            strlen( $hp ), 12 );
t( 'beginnt mit Buchstabe', (bool) preg_match( '/^[a-z]/', $hp ), true );
t( 'stabil je Token',       cs_honeypot_name( $token, $salt ), $hp );
t( 'anders bei anderem Token',
   cs_honeypot_name( cs_sign( $ts + 1, $salt ), $salt ) !== $hp, true );

echo "\nInhalts-Score — Einzelsignale\n";
t( 'keine URL',  cs_count_urls( 'Guten Tag, bitte um Rueckruf.' ), 0 );
t( 'eine URL',   cs_count_urls( 'Siehe https://beispiel.de/x' ), 1 );
t( 'zwei URLs',  cs_count_urls( 'https://a.de und www.b.de' ), 2 );
t( 'E-Mail ist keine URL', cs_count_urls( 'info@contic.de' ), 0 );
t( 'kyrillisch erkannt', cs_foreign_ratio( 'Привет' ) > 0.5, true );
t( 'deutsch nicht fremd', cs_foreign_ratio( 'Guten Tag' ) < 0.01, true );
t( 'Umlaute nicht fremd', cs_foreign_ratio( 'Grüße für Sie' ) < 0.01, true );
t( 'Keyword-Treffer', cs_keyword_hits( 'We offer guest post and backlink services' ), 2 );
t( 'kein Keyword',   cs_keyword_hits( 'Anfrage zur Prozessberatung' ), 0 );
t( 'Branchenwort zaehlt nicht', cs_keyword_hits( 'Beratung zu SEO und mehr Traffic, besseres Ranking' ), 0 );
t( 'Wortgrenze: cryptography kein Treffer', cs_keyword_hits( 'We need advice on cryptography standards' ), 0 );
t( 'Funktionswort da',   cs_has_function_word( 'Ich habe eine Frage' ), true );
t( 'kein Funktionswort', cs_has_function_word( 'Ranking Traffic Boost' ), false );
t( 'Leerzeichen erkannt',     cs_has_whitespace( 'Guten Tag, bitte um Rueckruf.' ), true );
t( 'kein Leerzeichen erkannt', cs_has_whitespace( 'zdcyHHVHPHkCHExn' ), false );

echo "\nVokalanteil / Zufallstoken-Erkennung (2026-07-28)\n";
t( 'Zufallstoken 1 hat niedrigen Vokalanteil', cs_vowel_ratio( 'zdcyHHVHPHkCHExn' ) < CS_RANDOM_MAX_VOWEL, true );
t( 'Zufallstoken 2 hat niedrigen Vokalanteil', cs_vowel_ratio( 'yhKXSOsCGLhdLEudb' ) < CS_RANDOM_MAX_VOWEL, true );
t( 'echtes Wort hat hohen Vokalanteil', cs_vowel_ratio( 'Rueckruf' ) >= CS_RANDOM_MAX_VOWEL, true );
t( 'langes deutsches Kompositum hat hohen Vokalanteil',
   cs_vowel_ratio( 'Nachhaltigkeitsstrategieberatung' ) >= CS_RANDOM_MAX_VOWEL, true );
t( 'keine Buchstaben liefert null', cs_vowel_ratio( '9117619477' ), null );

t( 'erkennt Zufallstoken im mehrfeldigen Text',
   cs_has_random_token( "barfieldconstruction\n9117619477\nzdcyHHVHPHkCHExn\nyhKXSOsCGLhdLEudb" ), true );
t( 'kurze echte Felder bleiben unter der Mindestlaenge',
   cs_has_random_token( "Max\nRueckruf\nDanke!" ), false );
t( 'langes Kompositum wird nicht als Zufallstoken erkannt',
   cs_has_random_token( "Schmidt\nAnfrage\nNachhaltigkeitsstrategieberatung" ), false );

// I10 (2026-07-29, belegter Spam-Fall contic.de): Vokalanteil allein reichte nicht,
// weil reiner Zufall im Mittel ~19 % Vokale hat und einzelne Token darueber liegen
// koennen. Gross-/Klein-Wechselrate faengt genau diese Faelle zusaetzlich.
t( 'Gross/Klein-Wechsel bei Zufallstoken hoch (contic.de-Fall)',
   cs_case_flip_ratio( 'LDTIhlaLPqQijIBX' ) > CS_RANDOM_MAX_CASE_FLIP, true );
t( 'Vokalanteil dieses Tokens liegt UEBER der reinen Vokalschwelle (Beleg fuer I10)',
   cs_vowel_ratio( 'LDTIhlaLPqQijIBX' ) >= CS_RANDOM_MAX_VOWEL, true );
t( 'Gross/Klein-Wechsel bei echtem Wort niedrig', cs_case_flip_ratio( 'unternehmensberatung' ), 0 );
t( 'Gross/Klein-Wechsel bei Titel-Schreibung niedrig', cs_case_flip_ratio( 'Nachhaltigkeitsstrategieberatung' ) <= CS_RANDOM_MAX_CASE_FLIP, true );
t( 'erkennt Zufallstoken jetzt auch ueber die Wechselrate (contic.de-Fall)',
   cs_has_random_token( "LDTIhlaLPqQijIBX\n6607533394\nunternehmensberatung\nqsXkRjVEJqPusMFNPIIgAvjd\nUdhwMGKVjoKHuBviZ" ), true );

echo "\nInhalts-Score — Gesamtbewertung\n";
$r = cs_score( 'Maria Braun', 'Guten Tag, wir möchten eine Prozessberatung anfragen. Bitte melden Sie sich.' );
t( 'echte Anfrage = 0', $r['score'], 0 );

$r = cs_score( 'Maria Braun', 'Guten Tag, wie in https://beispiel.de/projekt beschrieben, bitte um Rückruf.' );
t( 'echte Anfrage mit 1 Link = 1', $r['score'], 1 );
t( 'bleibt unter Markierung', $r['score'] < CS_SCORE_MARK, true );

$r = cs_score( 'SEO Team', 'Buy backlink packages and increase your sales: https://a.com https://b.com https://c.com' );
t( 'Werbemail wird geblockt', $r['score'] >= CS_SCORE_BLOCK, true );
t( 'Werbemail Score exakt', $r['score'], 8 );

// I2 (2026-07-26): foreign_script und no_function_word massen dieselbe Ursache doppelt —
// wer kyrillisch/CJK/arabisch schreibt, hat zwangslaeufig kein deutsches/englisches
// Funktionswort. cs_score() unterdrueckt no_function_word jetzt, wenn foreign_script
// bereits gezaehlt hat. Dieser Fall faellt dadurch von 8 auf 6 und landet nur noch im
// Markierungsband, nicht mehr im Block — das ist die bewusst akzeptierte Folge.
$r = cs_score( 'Иван', 'Здравствуйте, https://spam.ru и https://spam2.ru предлагаем услуги' );
t( 'kyrillischer Spam Score exakt (I2: 8 -> 6)', $r['score'], 6 );
t( 'kyrillischer Spam: mindestens Markierung', $r['score'] >= CS_SCORE_MARK, true );
t( 'kyrillischer Spam: nicht mehr geblockt (I2)', $r['score'] < CS_SCORE_BLOCK, true );

// Abschluss-Review, Coverage-Luecke: die I2-Korrektur darf Fremdschrift-Spam nicht
// grundsaetzlich unblockbar machen. Mit einem dritten Link bleibt er blockiert.
$r = cs_score( 'Иван', 'Здравствуйте, https://spam.ru https://spam2.ru https://spam3.ru предлагаем услуги' );
t( 'kyrillischer Spam mit 3 Links bleibt blockbar (I2-Regression)', $r['score'] >= CS_SCORE_BLOCK, true );

// I2, neuer Regressionstest: eine echte russischsprachige Anfrage mit einem Link darf
// nicht geblockt werden. Reiner Text ohne deutsche/englische Woerter, damit kein
// Funktionswort das Ergebnis verfaelscht.
$r = cs_score( 'Иван Петров', 'Здравствуйте, мы хотели бы обсудить проект: https://beispiel.ru/projekt' );
t( 'echte russische Anfrage mit Link nicht geblockt (I2)', $r['score'] < CS_SCORE_BLOCK, true );
t( 'echte russische Anfrage mit Link Score exakt (I2)', $r['score'], 5 );

$r = cs_score( 'https://spam.de', 'Hallo, ich habe eine kurze Frage an Sie.' );
t( 'URL im Namen zaehlt', in_array( 'url_in_name', $r['signals'], true ), true );

$r = cs_score( 'Max', 'Kontakt bitte [url=https://spam.de]hier[/url] aufnehmen und melden.' );
t( 'BBCode zaehlt', in_array( 'markup_link', $r['signals'], true ), true );

// Regressionstests zur Entscheidung 2026-07-26: Branchenvokabular darf echte Anfragen
// nicht bestrafen. Beide Fälle stammen aus belegten False Positives im Task-3-Review.
$r = cs_score( 'Anna Schmidt', 'Guten Tag, wir suchen Beratung zu SEO und mehr Traffic für unsere Website. Bitte um Rückruf.' );
t( 'SEO-Lead kommt durch', $r['score'] < CS_SCORE_MARK, true );
t( 'SEO-Lead Score exakt', $r['score'], 0 );

$r = cs_score( 'Peter Klein', 'Vergleich Websites: https://firma-a.de https://firma-b.de https://firma-c.de Ranking soll verbessert werden.' );
t( 'Websitevergleich wird nicht geblockt', $r['score'] < CS_SCORE_BLOCK, true );
t( 'Websitevergleich Score exakt', $r['score'], 6 );

// Belegte Spam-Faelle eilige-edv.de, 2026-07-28 — drei echte Live-Einreichungen nach
// Rollout, alle Zufallstoken ohne Link, ohne Keyword, ohne Fremdschrift. Der erste kam
// vor dem no_whitespace-Signal mit Score 2 unmarkiert durch (Grund fuer dessen Einfuehrung).
// Nach Entscheidung (2026-07-28, nach dem zweiten/dritten Fall): dieses Muster
// soll geblockt statt nur markiert werden -> cs_has_random_token() als zweite Stufe.
// R3-Bereinigung 2026-08-02: E-Mail und Telefonnummer der drei Original-Faelle waren reale
// Drittdaten (Bot-Absender) und wurden durch synthetische Platzhalter ersetzt. Unkritisch
// fuer die Testaussage, da cs_extract() jede erkannte E-Mail-Adresse vor der Score-Bildung
// aus $text herauszieht (s. cf7-spamschutz.php cs_extract()) und Telefonnummern ohne
// Buchstaben die CS_RANDOM_MIN_LEN-Schwelle in cs_has_random_token() nie erreichen — beide
// Felder sind fuer Vokalanteil/Case-Flip-Erkennung folgenlos. name/subject/message bleiben
// unveraendert, das sind bereits algorithmische Zufallstoken, keine echten Namen.
foreach ( array(
	array( 'barfieldconstruction', 'kqztpdvswrand01@beispiel-mail.de', '5550100001', 'zdcyHHVHPHkCHExn', 'yhKXSOsCGLhdLEudb' ),
	array( 'PZhkSTDLFHhmfSiY', 'mplxjfghnq02@beispiel-mail.de', '5550100002', 'SxbWFckJVSRoUXVR', 'DzzjycTMHMZbqAgsqWROOWN' ),
	array( 'xDNrRNOlPMdrJqUOjtp', 'wvbcnrshtq03@beispiel-mail.de', '5550100003', 'nJZUpifSgoZnmcMmXoEQZ', 'ptzLKADQBaqQGGpRRgdHMj' ),
) as $i => $case ) {
	list( $name, $email, $telno, $subject, $message ) = $case;
	$e = cs_extract( array(
		'your-name' => $name, 'your-email' => $email, 'your-telno' => $telno,
		'your-subject' => $subject, 'your-message' => $message,
	) );
	$r = cs_score( $e['name'], $e['text'], $e['parts_count'] );
	t( "Zufallstoken-Spam #$i (eilige-edv.de) wird geblockt", $r['score'] >= CS_SCORE_BLOCK, true );
	t( "Zufallstoken-Spam #$i: random-token-Signal gesetzt",
	   in_array( 'no_whitespace_random_token', $r['signals'], true ), true );
}

// Belegter Spam-Fall contic.de, 2026-07-29 (I10) — aktuelles Live-Formular nutzt
// lead_*-Feldnamen (nicht your-*), inkl. echtem "lead_inquiry_type"-Feld
// ("unternehmensberatung") neben den drei Zufallstoken-Feldern. Kam mit v1.2.0 nur
// auf Score 4 (nur no_function_word + no_whitespace, OHNE random-token-Signal) durch,
// weil der Vokalanteil aller drei Felder zufaellig ueber CS_RANDOM_MAX_VOWEL lag —
// Grund fuer die Case-Flip-Ergaenzung oben.
// R3-Bereinigung 2026-08-02: lead_email/lead_phone waren eine reale Drittadresse, s. Hinweis
// beim Fall-Array oben — hier durch Platzhalter ersetzt, ohne Einfluss auf das Testergebnis.
$e5 = cs_extract( array(
	'lead_name' => 'LDTIhlaLPqQijIBX', 'lead_email' => 'nzqwyktr04@beispiel-mail.de',
	'lead_phone' => '5550100004', 'lead_inquiry_type' => 'unternehmensberatung',
	'lead_subject' => 'qsXkRjVEJqPusMFNPIIgAvjd', 'lead_message' => 'UdhwMGKVjoKHuBviZ',
	'lead_consent' => '1', 'source_site' => 'contic.de', 'form_type' => 'kontakt',
	'form_version' => '1.0', 'lead_lang' => 'de',
) );
t( 'contic.de-Zufallstoken-Fall: lead_name jetzt erkannt (I11)', $e5['name'], 'LDTIhlaLPqQijIBX' );
$r5 = cs_score( $e5['name'], $e5['text'], $e5['parts_count'] );
t( 'contic.de-Zufallstoken-Fall wird jetzt geblockt', $r5['score'] >= CS_SCORE_BLOCK, true );
t( 'contic.de-Zufallstoken-Fall: random-token-Signal gesetzt',
   in_array( 'no_whitespace_random_token', $r5['signals'], true ), true );

// Gegenprobe A: kurze aber echte Anfrage mit einwortigen Betreff/Nachricht-Feldern bleibt
// unmarkiert, weil der Name (zwei Woerter) dem Gesamttext ein Leerzeichen liefert.
$e2 = cs_extract( array(
	'your-name' => 'Jan Weber', 'your-email' => 'jan.weber@beispiel.de',
	'your-subject' => 'Rueckruf', 'your-message' => 'Danke.',
) );
$r2 = cs_score( $e2['name'], $e2['text'], $e2['parts_count'] );
t( 'kurze echte Anfrage (Leerzeichen im Namen) nicht markiert', $r2['score'] < CS_SCORE_MARK, true );

// Gegenprobe B, die eigentlich kritische: auch OHNE jedes Leerzeichen (einwortiger Name)
// darf eine kurze echte Anfrage nur markiert, nicht geblockt werden — alle Felder liegen
// unter CS_RANDOM_MIN_LEN, cs_has_random_token() darf hier nicht anschlagen.
$e3 = cs_extract( array(
	'your-name' => 'Max', 'your-email' => 'max@beispiel.de',
	'your-subject' => 'Rueckruf', 'your-message' => 'Danke!',
) );
$r3 = cs_score( $e3['name'], $e3['text'], $e3['parts_count'] );
t( 'kurze echte Anfrage ohne jedes Leerzeichen wird NICHT geblockt', $r3['score'] < CS_SCORE_BLOCK, true );
t( 'kurze echte Anfrage ohne jedes Leerzeichen: kein random-token-Signal',
   in_array( 'no_whitespace_random_token', $r3['signals'], true ), false );

// Gegenprobe C: eine echte Anfrage, deren einziger Inhalt ein langes deutsches Kompositum
// ist (z. B. eine der eigenen Leistungsbezeichnungen), darf trotz Laenge nicht als
// Zufallstoken durchgehen.
$e4 = cs_extract( array(
	'your-name' => 'Schmidt', 'your-email' => 'schmidt@beispiel.de',
	'your-subject' => 'Anfrage', 'your-message' => 'Nachhaltigkeitsstrategieberatung',
) );
$r4 = cs_score( $e4['name'], $e4['text'], $e4['parts_count'] );
t( 'langes echtes Kompositum wird NICHT geblockt', $r4['score'] < CS_SCORE_BLOCK, true );

echo "\nRate-Limit\n";
$GLOBALS['stub_transients'] = array();
$ip = cs_ip_hash( '203.0.113.9', $salt );
t( 'IP-Hash 32 Zeichen', strlen( $ip ), 32 );
t( 'IP nicht im Klartext', false === strpos( $ip, '203' ), true );
t( '1. Absendung ok', cs_rate_hit( $ip ), '' );
t( '2. Absendung ok', cs_rate_hit( $ip ), '' );
t( '3. Absendung ok', cs_rate_hit( $ip ), '' );
t( '4. Absendung blockt', cs_rate_hit( $ip ), 'rate_short' );
t( 'andere IP unbetroffen', cs_rate_hit( cs_ip_hash( '198.51.100.4', $salt ) ), '' );

echo "\nDuplikate\n";
$GLOBALS['stub_transients'] = array();
t( 'erste Nachricht ok',  cs_dup_hit( 'a@b.de', 'Hallo' ), '' );
t( 'gleiche blockt',      cs_dup_hit( 'a@b.de', 'Hallo' ), 'duplicate' );
t( 'Gross/Klein egal',    cs_dup_hit( 'A@B.de', 'Hallo' ), 'duplicate' );
t( 'andere Nachricht ok', cs_dup_hit( 'a@b.de', 'Anderer Text' ), '' );

echo "\nFeldextraktion\n";
$e = cs_extract( array(
	'_wpcf7'      => '17',
	'source_site' => 'contic.de',
	'form_type'   => 'kontakt',
	'name'        => 'Maria Braun',
	'email'       => 'maria@beispiel.de',
	'telefon'     => '0781 1234',
	'nachricht'   => 'Bitte um Rückruf.',
	'datenschutz' => array( '1' ),
) );
t( 'E-Mail erkannt', $e['email'], 'maria@beispiel.de' );
t( 'Name erkannt',   $e['name'],  'Maria Braun' );
t( 'Meta nicht im Text', false === strpos( $e['text'], 'contic.de' ), true );
t( 'Nachricht im Text',  false !== strpos( $e['text'], 'Rückruf' ), true );

echo "\nFeldextraktion — die realen Formularformen der vier Sites\n";
// Regressionstests aus dem Task-4-Review 2026-07-26. Jede Site hat andere
// Feldnamen; der Spamschutz läuft überall als dieselbe Datei.
$e = cs_extract( array(
	'_wpcf7' => '1734', 'your-name' => 'Maria Braun', 'your-email' => 'm@beispiel.de',
	'your-telno' => '0781 1', 'your-subject' => 'Beratung', 'your-message' => 'Bitte um Rückruf.',
) );
t( 'contic.de LIVE (your-*): Name',   $e['name'],  'Maria Braun' );
t( 'contic.de LIVE (your-*): E-Mail', $e['email'], 'm@beispiel.de' );

$e = cs_extract( array(
	'source_site' => 'gseilheimer.de', 'form_type' => 'kontakt', 'name' => 'John Doe',
	'email' => 'j@example.com', 'phone' => '+49 1', 'message' => 'Please call back.',
) );
t( 'gseilheimer.de (EN): Name', $e['name'], 'John Doe' );

$e = cs_extract( array(
	'source_site' => 'edu-space.de', 'form_type' => 'anmeldung', 'vorname' => 'Anna',
	'nachname' => 'Klein', 'email' => 'a@amt.ch', 'telefon' => '031 1',
	'themenschwerpunkte' => array( 'KI', 'Recht' ), 'bemerkungen' => 'Bitte Unterlagen.',
) );
t( 'edu-space.de: Vor- UND Nachname', $e['name'], 'Anna Klein' );

$e = cs_extract( array(
	'firmenname' => 'Muster GmbH', 'name' => 'Max Mustermann',
	'email' => 'max@muster.de', 'nachricht' => 'Anfrage.',
) );
t( 'firmenname verdraengt Namen nicht', $e['name'], 'Max Mustermann' );

$e = cs_extract( array(
	'firmenname' => 'Muster GmbH', 'email' => 'max@muster.de', 'nachricht' => 'Anfrage.',
) );
t( 'ohne Namensfeld leer statt falsch', $e['name'], '' );

// I11 (2026-07-29): alle vier Sites auf ein einheitliches lead_*-Feldschema umgestellt
// (contic.de, eilige-edv.de, gseilheimer.de, edu-space.de — per Live-Check bestätigt,
// ersetzt your-*/name-Schema oben). lead_consent/form_version/lead_lang sind Metadaten
// und duerfen nicht in die Bewertung einfliessen; lead_inquiry_type/lead_institution
// sind echte Nutzerangaben und muessen im Text bleiben.
$e = cs_extract( array(
	'_wpcf7' => '939', 'lead_name' => 'Maria Braun', 'lead_email' => 'm@beispiel.de',
	'lead_phone' => '0781 1', 'lead_subject' => 'Beratung', 'lead_message' => 'Bitte um Rückruf.',
	'lead_consent' => '1', 'lead_inquiry_type' => 'unternehmensberatung',
	'source_site' => 'contic.de', 'form_type' => 'kontakt', 'form_version' => '1.0',
	'lead_lang' => 'de',
) );
t( 'einheitliches lead_*-Schema: Name erkannt', $e['name'], 'Maria Braun' );
t( 'einheitliches lead_*-Schema: E-Mail erkannt', $e['email'], 'm@beispiel.de' );
// Erwartete Teile: lead_name, lead_phone, lead_subject, lead_message, lead_inquiry_type
// (5) — lead_consent/form_version/lead_lang duerfen NICHT mitzaehlen, sonst waeren es 8.
t( 'einheitliches lead_*-Schema: Metadaten nicht in parts_count', $e['parts_count'], 5 );
t( 'einheitliches lead_*-Schema: lead_inquiry_type bleibt im Text', false !== strpos( $e['text'], 'unternehmensberatung' ), true );

// edu-space.de hat zusaetzlich lead_institution statt/neben lead_inquiry_type.
$e = cs_extract( array(
	'lead_name' => 'Anna Klein', 'lead_email' => 'a@amt.ch', 'lead_phone' => '031 1',
	'lead_institution' => 'Stadt Musterhausen', 'lead_message' => 'Bitte Unterlagen.',
	'lead_consent' => '1', 'source_site' => 'edu-space.de', 'form_type' => 'anmeldung',
	'form_version' => '1.0', 'lead_lang' => 'de',
) );
t( 'edu-space.de lead_*-Schema: Name erkannt', $e['name'], 'Anna Klein' );
t( 'edu-space.de lead_*-Schema: lead_institution bleibt im Text', false !== strpos( $e['text'], 'Musterhausen' ), true );

echo "\nInhalts-Score — parts_count unterdrueckt name_eq_text bei nur einem Feld (M-name)\n";
// Ein Formular aus nur Name und E-Mail (Rueckruf, Newsletter) ergab vorher text===name,
// also name_eq_text (+3) plus no_function_word (+2) = 5 -> jede Einreichung markiert.
// cs_extract() liefert jetzt parts_count mit; cs_score() wendet name_eq_text nur an,
// wenn mehr als ein Freitextteil vorlag (2026-07-26).
$e = cs_extract( array( 'name' => 'Max Mustermann', 'email' => 'max@mustermann.de' ) );
t( 'M-name: nur ein Freitextteil (cs_extract)', $e['parts_count'], 1 );
$r = cs_score( $e['name'], $e['text'], $e['parts_count'] );
t( 'M-name: kein name_eq_text bei einem Feld', in_array( 'name_eq_text', $r['signals'], true ), false );
t( 'M-name: bleibt unter Markierung', $r['score'] < CS_SCORE_MARK, true );

// Gegenprobe direkt auf cs_score(): mit parts_count > 1 (Default bzw. explizit gesetzt)
// feuert das Signal weiterhin — bestehende zweistellige Aufrufer im Rest dieser Suite
// laufen unveraendert ueber den Default (2) weiter.
$r = cs_score( 'Max Mustermann', 'Max Mustermann' );
t( 'M-name: name_eq_text feuert weiter beim Default (parts_count=2)', in_array( 'name_eq_text', $r['signals'], true ), true );
$r = cs_score( 'Max Mustermann', 'Max Mustermann', 1 );
t( 'M-name: name_eq_text unterdrueckt bei explizitem parts_count=1', in_array( 'name_eq_text', $r['signals'], true ), false );

echo "\nRate-Limit — Tageslimit\n";
$GLOBALS['stub_transients'] = array();
$ip_day = cs_ip_hash( '192.0.2.7', $salt );
// Das Kurzfristlimit würde nach 3 Absendungen greifen — für den Test des
// Tageslimits wird nur dessen Zähler zwischendurch geleert.
for ( $i = 0; $i < CS_RL_DAY; $i++ ) {
	if ( $i > 0 && 0 === $i % CS_RL_SHORT ) {
		delete_transient( 'cs_rl_' . $ip_day );
	}
	cs_rate_hit( $ip_day );
}
delete_transient( 'cs_rl_' . $ip_day );
t( 'Tageslimit blockt nach 10', cs_rate_hit( $ip_day ), 'rate_day' );

echo "\nDuplikat-Schluessel\n";
$GLOBALS['stub_transients'] = array();
t( 'Trennzeichen im Text kollidiert nicht A', cs_dup_hit( 'a@b.de', 'hallo|welt' ), '' );
t( 'Trennzeichen im Text kollidiert nicht B', cs_dup_hit( 'a@b.de|hallo', 'welt' ), '' );

echo "\nSpam-Log\n";
// Relative Zeitstempel: feste Daten verfallen an der Loeschfrist (CS_LOG_RETENTION_DAYS)
// und machen den Test mit der Zeit rot, ohne dass der Code kaputt ist.
$GLOBALS['stub_options'] = array();
cs_log_add( array( 'time' => date( 'Y-m-d H:i:s', time() - 120 ), 'reason' => 'honeypot', 'score' => 0 ) );
cs_log_add( array( 'time' => date( 'Y-m-d H:i:s', time() - 60 ), 'reason' => 'too_fast', 'score' => 0 ) );
$log = cs_log_get();
t( 'zwei Eintraege', count( $log ), 2 );
t( 'neuester zuerst', $log[0]['reason'], 'too_fast' );

for ( $i = 0; $i < CS_LOG_MAX + 20; $i++ ) {
	cs_log_add( array( 'time' => date( 'Y-m-d H:i:s', time() - 30 ), 'reason' => 'x', 'score' => 0 ) );
}
t( 'Ringpuffer begrenzt', count( cs_log_get() ), CS_LOG_MAX );

echo "\nSpam-Log — zeitbasierte Loeschfrist (v1.5.0)\n";
// Relative Zeitstempel (statt fester Datumsangaben), damit die Tests unabhaengig vom
// tatsaechlichen Ausfuehrungsdatum immer dieselbe Alters-Konstellation pruefen.
$old_ts    = time() - ( ( CS_LOG_RETENTION_DAYS + 1 ) * DAY_IN_SECONDS );
$recent_ts = time() - DAY_IN_SECONDS;

// A. cs_log_apply_retention() isoliert als reine Funktion — kein Options-Zugriff noetig.
$filtered = cs_log_apply_retention( array(
	array( 'time' => date( 'Y-m-d H:i:s', $old_ts ),    'reason' => 'old' ),
	array( 'time' => date( 'Y-m-d H:i:s', $recent_ts ), 'reason' => 'recent' ),
) );
t( 'cs_log_apply_retention entfernt den abgelaufenen Eintrag', count( $filtered ), 1 );
t( 'cs_log_apply_retention behaelt den juengeren Eintrag', $filtered[0]['reason'], 'recent' );

// B. cs_log_add() purgt beim Schreiben auch laengst vorhandene, mittlerweile abgelaufene
// Bestandseintraege — nicht nur den gerade neu hinzugefuegten.
$GLOBALS['stub_options']['cs_log'] = array(
	array( 'time' => date( 'Y-m-d H:i:s', $old_ts ), 'reason' => 'stale_from_before', 'score' => 0 ),
);
cs_log_add( array( 'time' => date( 'Y-m-d H:i:s', time() ), 'reason' => 'brandneu', 'score' => 0 ) );
$log = cs_log_get();
t( 'cs_log_add purgt abgelaufene Bestandseintraege mit', count( $log ), 1 );
t( 'verbleibender Eintrag ist der neue', $log[0]['reason'], 'brandneu' );

// C. cs_log_purge_expired() direkt, ohne neuen Eintrag (Admin-Seite / Cron-Aufrufer).
$GLOBALS['stub_options']['cs_log'] = array(
	array( 'time' => date( 'Y-m-d H:i:s', $old_ts ),    'reason' => 'a', 'score' => 0 ),
	array( 'time' => date( 'Y-m-d H:i:s', $recent_ts ), 'reason' => 'b', 'score' => 0 ),
);
$kept = cs_log_purge_expired();
t( 'cs_log_purge_expired entfernt abgelaufenen Eintrag', count( $kept ), 1 );
t( 'cs_log_purge_expired schreibt bereinigten Bestand zurueck', count( cs_log_get() ), 1 );

// D. Grenzfall mit Sicherheitsabstand statt exakter Gleichheit (vermeidet einen
// flakigen Test, da cs_log_apply_retention() bei jedem Aufruf selbst time() neu zieht):
// deutlich innerhalb der Frist bleibt, deutlich darueber hinaus fliegt raus.
$GLOBALS['stub_options']['cs_log'] = array(
	array(
		'time'   => date( 'Y-m-d H:i:s', time() - ( CS_LOG_RETENTION_DAYS * DAY_IN_SECONDS ) + 300 ),
		'reason' => 'knapp_innerhalb', 'score' => 0,
	),
	array(
		'time'   => date( 'Y-m-d H:i:s', time() - ( CS_LOG_RETENTION_DAYS * DAY_IN_SECONDS ) - 300 ),
		'reason' => 'knapp_ausserhalb', 'score' => 0,
	),
);
$kept = cs_log_purge_expired();
t( 'Eintrag knapp innerhalb der Frist bleibt', count( $kept ), 1 );
t( 'verbleibender Eintrag ist der knapp innerhalb liegende', $kept[0]['reason'], 'knapp_innerhalb' );

// Fail-safe: kein lesbares time-Feld -> nicht loeschen, auch wenn es laengst faellig waere.
$GLOBALS['stub_options']['cs_log'] = array(
	array( 'time' => '', 'reason' => 'leeres_zeitfeld', 'score' => 0 ),
	array( 'reason' => 'ganz_ohne_zeitfeld', 'score' => 0 ),
	array( 'time' => 'kein-gueltiges-datum-xyz', 'reason' => 'kaputtes_datum', 'score' => 0 ),
);
$kept = cs_log_purge_expired();
t( 'Fail-safe: Eintraege ohne lesbare Zeit bleiben alle drei', count( $kept ), 3 );

echo "\nSpam-Log — Cron-Registrierung (v1.5.0)\n";
t( 'cs_daily_log_purge wurde beim Laden geplant', isset( $GLOBALS['stub_cron']['cs_daily_log_purge'] ), true );

echo "\nBlockliste (WP-Einstellungen)\n";
$GLOBALS['stub_options'] = array();
t( 'leere Liste kein Treffer', cs_disallowed_hit( 'Guten Tag, bitte um Rückruf.' ), false );

update_option( 'disallowed_keys', "kasino\nSchneeballsystem" );
t( 'Treffer aus der Liste',   cs_disallowed_hit( 'Werbung für ein kasino' ), true );
t( 'Gross-/Kleinschreibung',  cs_disallowed_hit( 'Grosses SCHNEEBALLSYSTEM' ), true );
t( 'kein Treffer',            cs_disallowed_hit( 'Anfrage zur Prozessberatung' ), false );

/*
 * T1 — der Filter selbst war ungetestet. Minimales Fake-Objekt, gerade genug Oberflaeche
 * fuer die sechs Faelle unten (get_posted_data(), add_spam_log(), get_contact_form()) —
 * kein allgemeiner Mock.
 */
class CS_Fake_Form {
	private $id_val;
	private $title_val;
	function __construct( $id, $title ) { $this->id_val = $id; $this->title_val = $title; }
	function id() { return $this->id_val; }
	function title() { return $this->title_val; }
}

class CS_Fake_Submission {
	public $posted;
	public $spam_logs = array();
	private $form;
	function __construct( $posted, $form_id = 1, $form_title = 'Testformular' ) {
		$this->posted = $posted;
		$this->form   = new CS_Fake_Form( $form_id, $form_title );
	}
	function get_posted_data() { return $this->posted; }
	function add_spam_log( $entry ) { $this->spam_logs[] = $entry; }
	function get_contact_form() { return $this->form; }
}

echo "\nFilter wpcf7_spam — End-to-End (T1)\n";
$cb = $GLOBALS['stub_hooks']['wpcf7_spam'][0];

// 1. kein Token -> true zurueck, Log-Eintrag no_token.
$GLOBALS['stub_options']    = array();
$GLOBALS['stub_transients'] = array();
$_POST = array();
$sub = new CS_Fake_Submission( array(
	'name' => 'Max', 'email' => 'max@beispiel.de', 'nachricht' => 'Hallo, ich habe eine Frage.',
) );
$result = call_user_func( $cb, false, $sub );
t( 'T1.1: kein Token -> Spam', $result, true );
$log = cs_log_get();
t( 'T1.1: Log-Grund no_token', $log[0]['reason'], 'no_token' );
// 2. C1: der Log-Eintrag einer abgewiesenen Einreichung enthaelt eine Kontaktmoeglichkeit.
t( 'T1.2 (C1): Log-Eintrag enthaelt E-Mail', $log[0]['email'], 'max@beispiel.de' );

// 3. gueltiges Token, Alter > CS_MIN_SECONDS, sauberer Text -> false, kein Log-Eintrag.
$GLOBALS['stub_options']['cs_log'] = array();
$ts_ok    = time() - CS_MIN_SECONDS - 5;
$token_ok = cs_sign( $ts_ok, $salt );
$_POST    = array( '_cs_t' => $token_ok );
$sub_ok   = new CS_Fake_Submission( array(
	'name' => 'Maria Braun', 'email' => 'maria@beispiel.de',
	'nachricht' => 'Guten Tag, wir möchten eine Beratung anfragen. Bitte melden Sie sich.',
) );
$result_ok = call_user_func( $cb, false, $sub_ok );
t( 'T1.3: gueltiges Token + sauberer Text laesst durch', $result_ok, false );
t( 'T1.3: kein Log-Eintrag bei Durchlass', count( cs_log_get() ), 0 );

// 4. Honeypot gefuellt -> true, Log-Eintrag honeypot.
$GLOBALS['stub_options']['cs_log'] = array();
$ts_hp    = time() - CS_MIN_SECONDS - 5;
$token_hp = cs_sign( $ts_hp, $salt );
$hp_name  = cs_honeypot_name( $token_hp, $salt );
$_POST    = array( '_cs_t' => $token_hp, $hp_name => 'i-am-a-bot' );
$sub_hp   = new CS_Fake_Submission( array(
	'name' => 'Bot', 'email' => 'bot@spam.de', 'nachricht' => 'Hallo Welt.',
) );
$result_hp = call_user_func( $cb, false, $sub_hp );
t( 'T1.4: Honeypot -> Spam', $result_hp, true );
$log = cs_log_get();
t( 'T1.4: Log-Grund honeypot', $log[0]['reason'], 'honeypot' );

// 5. Score >= CS_SCORE_BLOCK -> true, Log-Eintrag score_block mit Auszug.
$GLOBALS['stub_options']['cs_log'] = array();
$ts_sp     = time() - CS_MIN_SECONDS - 5;
$token_sp  = cs_sign( $ts_sp, $salt );
$_POST     = array( '_cs_t' => $token_sp );
$spam_text = 'Buy backlink packages and increase your sales: https://a.com https://b.com https://c.com';
$sub_sp    = new CS_Fake_Submission( array(
	'name' => 'SEO Team', 'email' => 'seo@spam.de', 'nachricht' => $spam_text,
) );
$result_sp = call_user_func( $cb, false, $sub_sp );
t( 'T1.5: Score-Block -> Spam', $result_sp, true );
$log = cs_log_get();
t( 'T1.5: Log-Grund score_block', $log[0]['reason'], 'score_block' );
t( 'T1.5: Auszug enthaelt Text', false !== strpos( $log[0]['excerpt'], 'backlink' ), true );

// 6. Score im Band 4–6 -> false zurueck, $GLOBALS['cs_mark'] true, Log-Eintrag score_mark.
$GLOBALS['stub_options']['cs_log'] = array();
$ts_mk    = time() - CS_MIN_SECONDS - 5;
$token_mk = cs_sign( $ts_mk, $salt );
$_POST    = array( '_cs_t' => $token_mk );
$ru_text  = 'Здравствуйте, мы хотели бы обсудить проект: https://beispiel.ru/projekt';
$sub_mk   = new CS_Fake_Submission( array(
	'name' => 'Иван Петров', 'email' => 'ivan@beispiel.ru', 'nachricht' => $ru_text,
) );
$result_mk = call_user_func( $cb, false, $sub_mk );
t( 'T1.6: Score im Markierungsband laesst durch', $result_mk, false );
t( 'T1.6: cs_mark gesetzt', $GLOBALS['cs_mark'], true );
$log = cs_log_get();
t( 'T1.6: Log-Grund score_mark', $log[0]['reason'], 'score_mark' );

echo "\nAuslieferungskonfiguration (T2)\n";
t( 'CS_ENFORCE ist aktiv',      CS_ENFORCE, true );
t( 'CS_STAGE_TOKEN aktiv',      CS_STAGE_TOKEN, true );
t( 'CS_STAGE_HONEYPOT aktiv',   CS_STAGE_HONEYPOT, true );
t( 'CS_STAGE_SCORE aktiv',      CS_STAGE_SCORE, true );
t( 'CS_STAGE_DUP aktiv',        CS_STAGE_DUP, true );
echo '  Hinweis: CS_STAGE_RATE bleibt je Site nach der REMOTE_ADDR-Pruefung ohne Assert '
	. '(aktuell ' . ( CS_STAGE_RATE ? 'true' : 'false' ) . ").\n";

echo "\ncs_inline_js (T3)\n";
$js = cs_inline_js();
// wp_json_encode() (wie das echte WP-Pendant) escaped Schraegstriche als \/ — fuer den
// Inhaltsvergleich normalisiert, geprueft wird trotzdem die tatsaechlich erzeugte
// Zeichenkette aus cs_inline_js(), nicht ein Attrappentext.
$js_normalized = str_replace( '\\/', '/', $js );
t( 'JS enthaelt relative Token-URL', false !== strpos( $js_normalized, 'var url = "/wp-json/contic-spam/v1/token"' ), true );
t( 'JS enthaelt minAge=3000',        false !== strpos( $js, 'minAge = 3000' ), true );

$node_path = trim( (string) @shell_exec( 'command -v node 2>/dev/null' ) );
if ( '' !== $node_path ) {
	$tmp_js = tempnam( sys_get_temp_dir(), 'cs_js_' ) . '.js';
	file_put_contents( $tmp_js, $js );
	exec( 'node --check ' . escapeshellarg( $tmp_js ) . ' 2>&1', $node_out, $node_code );
	@unlink( $tmp_js );
	t( 'generiertes JS besteht node --check', 0 === $node_code, true );
} else {
	echo "  uebersprungen: node nicht verfuegbar\n";
}

echo "\nAdmin-Renderer Escaping (T4)\n";
// Capability- und Nonce-Guards sind mit Immer-true-Stubs (current_user_can(),
// check_admin_referer()) nicht beweisbar — hier wird nur das Escaping der Ausgabe
// geprueft, das ist mit den Stubs tatsaechlich pruefbar.
unset( $_POST['cs_clear'] );
$GLOBALS['stub_options']['cs_log'] = array(
	array(
		'time'    => date( 'Y-m-d H:i:s', time() - 30 ),
		'form'    => '1 — Testformular',
		'email'   => '<script>alert(1)</script>',
		'reason'  => 'honeypot',
		'score'   => 0,
		'signals' => array(),
		'excerpt' => '<script>alert(1)</script>',
	),
);
ob_start();
cs_render_log_page();
$html = ob_get_clean();
t( 'T4: kein unescaptes <script> in Ausgabe', false !== strpos( $html, '<script>alert(1)</script>' ), false );
t( 'T4: escapetes <script> vorhanden',        false !== strpos( $html, '&lt;script&gt;' ), true );

echo "\nTokenfehler-Fenster (M9)\n";

// Sauberer Start.
$GLOBALS['stub_transients'] = array();
t( 'M9: leeres Fenster zaehlt 0', cs_fail_count(), 0 );

cs_fail_note();
cs_fail_note();
t( 'M9: zwei Fehlschlaege zaehlen 2', cs_fail_count(), 2 );

// Kern des Defekts: ein neuer Fehlschlag darf alte NICHT wiederbeleben und das
// Fenster nicht mitziehen. Drei Koerbe kuenstlich altern lassen.
$h = cs_fail_hour();
set_transient( CS_FAIL_BUCKET_KEY, array(
    $h - 30 => 7,   // 30 h alt -> ausserhalb
    $h - 25 => 5,   // 25 h alt -> ausserhalb
    $h - 2  => 3,   // 2 h alt  -> drin
), 2 * DAY_IN_SECONDS );
t( 'M9: nur Koerbe innerhalb 24 h zaehlen', cs_fail_count(), 3 );

cs_fail_note();
t( 'M9: neuer Fehlschlag belebt alte nicht', cs_fail_count(), 4 );

$b = get_transient( CS_FAIL_BUCKET_KEY );
t( 'M9: alte Koerbe sind entfernt', isset( $b[ $h - 25 ] ) || isset( $b[ $h - 30 ] ), false );

// Randfall: genau 24 h alt faellt heraus, 23 h alt bleibt.
set_transient( CS_FAIL_BUCKET_KEY, array( $h - 24 => 9, $h - 23 => 1 ), 2 * DAY_IN_SECONDS );
t( 'M9: Korb bei genau 24 h faellt heraus', cs_fail_count(), 1 );

echo "\nSelbsttest des Token-Endpunkts (M10)\n";

$jetzt = 1750000000;
$gut   = function ( $ts ) use ( $salt ) {
    return array( 'error' => null, 'code' => 200,
                  'body'  => json_encode( array( 't' => cs_sign( $ts, $salt ) ) ) );
};

// Gutfall: zwei Abrufe, zwei verschiedene frische Token.
$e = cs_selftest_check( $gut( $jetzt ), $gut( $jetzt - 1 ), $salt, $jetzt );
t( 'M10: frische, verschiedene Token -> ok', $e['ok'], true );

// Verbindungsfehler.
$e = cs_selftest_check( array( 'error' => 'cURL 7', 'code' => 0, 'body' => '' ),
                        $gut( $jetzt ), $salt, $jetzt );
t( 'M10: Verbindungsfehler -> Defekt', $e['ok'], false );
t( 'M10: Fehlermeldung nennt die Ursache', false !== strpos( $e['msg'], 'cURL 7' ), true );

// Falscher HTTP-Status (z. B. Route blockiert).
$e = cs_selftest_check( array( 'error' => null, 'code' => 403, 'body' => '' ),
                        $gut( $jetzt ), $salt, $jetzt );
t( 'M10: HTTP 403 -> Defekt', $e['ok'], false );
t( 'M10: Status steht in der Meldung', false !== strpos( $e['msg'], '403' ), true );

// Antwort ohne Token-Feld.
$e = cs_selftest_check( array( 'error' => null, 'code' => 200, 'body' => '{"x":1}' ),
                        $gut( $jetzt ), $salt, $jetzt );
t( 'M10: Antwort ohne Token -> Defekt', $e['ok'], false );

// Gefaelschte Signatur.
$e = cs_selftest_check(
    array( 'error' => null, 'code' => 200,
           'body'  => json_encode( array( 't' => $jetzt . '.' . str_repeat( 'a', 64 ) ) ) ),
    $gut( $jetzt ), $salt, $jetzt );
t( 'M10: ungueltige Signatur -> Defekt', $e['ok'], false );

// Ueberaltertes Token -> gespeicherte Antwort.
$e = cs_selftest_check( $gut( $jetzt - 600 ), $gut( $jetzt - 601 ), $salt, $jetzt );
t( 'M10: ueberaltertes Token -> Defekt', $e['ok'], false );

// Zweimal dasselbe Token -> cachende Schicht. Genau der Fall, den die alte Notice
// nur vermutet hat und der live gerade NICHT vorlag.
$eins = $gut( $jetzt );
$e = cs_selftest_check( $eins, $eins, $salt, $jetzt );
t( 'M10: identische Token -> Defekt', $e['ok'], false );
t( 'M10: Cache-Befund benannt', false !== strpos( $e['msg'], 'zwischengespeichert' ), true );

// Drosselung: der zweite Abruf scheitert. Das darf KEINEN Alarm ausloesen, weil er
// allein der Cache-Pruefung dient — der erste Abruf hat den Endpunkt schon belegt.
$e = cs_selftest_check( $gut( $jetzt ),
                        array( 'error' => 'Connection reset', 'code' => 0, 'body' => '' ),
                        $salt, $jetzt );
t( 'M10: gescheiterter Zweitabruf ist kein Defekt', $e['ok'], true );

// Wiederholversuch: erster Abruf abgerissen, zweiter Versuch klappt -> kein Alarm.
$GLOBALS['stub_http'] = array(
    new WP_Error( 'http', 'Connection reset by peer' ),   // Drosselung
    array( 'response' => array( 'code' => 200 ),
           'body' => json_encode( array( 't' => cs_sign( time(), $salt ) ) ) ),
);
$r = cs_selftest_fetch();
t( 'M10: Wiederholversuch faengt abgerissene Verbindung auf', $r['error'], null );
t( 'M10: Wiederholversuch liefert Status 200', $r['code'], 200 );

// Bleibt es dabei, wird es gemeldet.
$GLOBALS['stub_http'] = array(
    new WP_Error( 'http', 'Connection reset by peer' ),
    new WP_Error( 'http', 'Connection reset by peer' ),
);
$r = cs_selftest_fetch();
t( 'M10: dauerhafter Ausfall wird durchgereicht', $r['error'], 'Connection reset by peer' );

// Der Cron-Einsprung schreibt das Ergebnis weg.
$GLOBALS['stub_options'] = array();
$GLOBALS['stub_http'] = array(
    array( 'response' => array( 'code' => 200 ),
           'body' => json_encode( array( 't' => cs_sign( time(), $salt ) ) ) ),
    array( 'response' => array( 'code' => 200 ),
           'body' => json_encode( array( 't' => cs_sign( time() - 1, $salt ) ) ) ),
);
$e = cs_run_selftest();
t( 'M10: Cron-Lauf besteht bei gesundem Endpunkt', $e['ok'], true );
$gespeichert = get_option( CS_SELFTEST_OPT );
t( 'M10: Ergebnis wird gespeichert', is_array( $gespeichert ) && true === $gespeichert['ok'], true );

echo "\nAdmin-Notice haengt am Testergebnis, nicht an der Bot-Zahl (M10)\n";

$notice = function () {
    ob_start();
    foreach ( $GLOBALS['stub_hooks']['admin_notices'] as $cb ) { call_user_func( $cb ); }
    return ob_get_clean();
};

// Kern der Aenderung: viele abgewehrte Bots, Endpunkt gesund -> keine Meldung.
$GLOBALS['stub_transients'] = array();
set_transient( CS_FAIL_BUCKET_KEY, array( cs_fail_hour() => 40 ), 2 * DAY_IN_SECONDS );
update_option( CS_SELFTEST_OPT, array( 'time' => time(), 'ok' => true, 'msg' => 'ok' ), false );
t( 'M10: 40 abgewehrte Bots loesen keinen Alarm aus', '' === trim( $notice() ), true );
t( 'M10: die Zahl ist trotzdem abrufbar', cs_fail_count(), 40 );

// Defekter Endpunkt, gar keine Bots -> Meldung.
$GLOBALS['stub_transients'] = array();
update_option( CS_SELFTEST_OPT,
    array( 'time' => time(), 'ok' => false, 'msg' => 'Endpunkt antwortet mit HTTP 403 statt 200.' ), false );
$html = $notice();
t( 'M10: defekter Endpunkt loest Alarm aus', false !== strpos( $html, 'nicht bestanden' ), true );
t( 'M10: Alarm nennt den gemessenen Befund', false !== strpos( $html, 'HTTP 403' ), true );
t( 'M10: Alarm behauptet keine Ursache mehr', false !== strpos( $html, 'Verdacht' ), false );

// Test laeuft nicht mehr -> eigener Hinweis.
update_option( CS_SELFTEST_OPT,
    array( 'time' => time() - 5 * DAY_IN_SECONDS, 'ok' => true, 'msg' => 'ok' ), false );
t( 'M10: veralteter Selbsttest wird gemeldet',
   false !== strpos( $notice(), 'wp-cron' ), true );

// Noch nie gelaufen -> kein Alarm.
$GLOBALS['stub_options'] = array();
t( 'M10: ohne Testlauf keine Meldung', '' === trim( $notice() ), true );

echo "\n" . $GLOBALS['t_pass'] . " ok, " . $GLOBALS['t_fail'] . " fehlgeschlagen\n";
exit( $GLOBALS['t_fail'] > 0 ? 1 : 0 );
