<?php
/**
 * Plugin Name: CONTIC Spamschutz — Spectra/UAGB-Formulare
 * Description: Ergänzt cf7-spamschutz.php um einen Prüfpfad für Spectra-Formulare (uagb/forms).
 * Version:     1.1.0
 * Author:      CONTIC
 * Author URI:  https://contic.de
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * ---------------------------------------------------------------------------
 * WARUM ES DIESE DATEI GIBT
 * ---------------------------------------------------------------------------
 * `cf7-spamschutz.php` hakt ausschliesslich in Contact Form 7 ein
 * (`wpcf7_spam`, `wpcf7_mail_components`, `wpcf7_enqueue_scripts`). Sites, deren
 * Kontaktformular ein Spectra-Formular ist, waren dadurch faktisch ungeschuetzt —
 * belegt am 2026-07-30 auf einer Live-Site: eine Einreichung kam per blankem
 * `curl` durch, ohne Token, ohne Browser, ohne Zeitverzoegerung.
 *
 * Verschaerfend kommt hinzu: Das Guard-Skript von cf7-spamschutz injiziert `_cs_t`
 * zwar in JEDES Formular im DOM — Spectras `forms.min.js` baut den POST-Body aber
 * selbst zusammen und uebernimmt nur Felder, zu denen ein Label-Element mit
 * passender id existiert. `_cs_t` wird dabei verworfen. Das Feld steht also im
 * Markup und suggeriert Schutz, ohne je beim Server anzukommen.
 *
 * Deshalb zwei Teile:
 *   1. Client: `window.fetch` wird umhuellt und `_cs_t` an genau die Requests
 *      angehaengt, die `action=uagb_process_forms` tragen.
 *   2. Server: eigener Handler auf `wp_ajax_nopriv_uagb_process_forms` mit
 *      Prioritaet 0 — laeuft vor UAGBs eigenem Handler und bricht bei Spam ab.
 *
 * ---------------------------------------------------------------------------
 * BEWUSSTE ABWEICHUNGEN VOM CF7-PFAD
 * ---------------------------------------------------------------------------
 * - **Kein Honeypot.** Ein zusaetzliches Eingabefeld wuerde von Spectras
 *   Serialisierung genauso verworfen wie `_cs_t` — es waere reine Zierde. Der
 *   Token- und Zeitpfad traegt den Schutz hier allein.
 * - **Eigenstaendige Datei statt Aenderung an cf7-spamschutz.php.** Die
 *   CF7-Datei laeuft unveraendert auf vier weiteren Sites; ein Eingriff dort
 *   waere ein Risiko fuer alle. Diese Datei laedt danach (mu-plugins laden
 *   alphabetisch, `cf7-` vor `spectra-`) und nutzt deren Funktionen mit.
 *
 * Voraussetzung: cf7-spamschutz.php >= 1.4.0 ist aktiv. Fehlt sie, tut diese
 * Datei nichts (siehe Guard unten) — sie erfindet keinen zweiten Schutz.
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }
if ( defined( 'CSX_VERSION' ) ) { return; } // schon geladen

const CSX_VERSION = '1.1.0';

/**
 * Eigener Scharfschalter, absichtlich getrennt von CS_ENFORCE.
 *
 * Der Schutz steht und faellt damit, dass `_cs_t` clientseitig im POST-Body
 * landet — und genau das ist der neue, noch unbewiesene Teil. Traegt die
 * fetch-Umhuellung aus irgendeinem Grund nicht (Optimierungs-Plugin, das
 * Inline-Skripte zusammenfasst; ein anderes Skript, das `window.fetch`
 * spaeter erneut umhuellt; Browser ohne URLSearchParams-Body), dann kaeme
 * JEDE echte Anfrage ohne Token an und wuerde als `no_token` abgewiesen.
 * Der Schaden waere derselbe stille Lead-Verlust, den dieses Projekt gerade
 * auf zwei anderen Sites aufgearbeitet hat.
 *
 * Deshalb: erst mitlaufen lassen, im Spam-Log pruefen, dass echte
 * Einreichungen NICHT als `no_token` auftauchen — dann auf true stellen.
 * Vorbild ist CS_STAGE_RATE, das aus demselben Grund false vorbelegt ist.
 *
 * SCHARF SEIT 2026-08-23 (v1.1.0). Die Beobachtung lief 24 Tage, vom Deploy
 * am 30.07.2026 bis zum 23.08.2026. Das Spam-Log enthielt in dieser Zeit
 * genau zwei Eintraege, beide `no_token`, beide die eigenen Tests vom
 * 30.07. — keine einzige echte Anfrage. Zusammen mit der Browser-Probe vom
 * 30.07., die das Anhaengen des Tokens durch die fetch-Umhuellung belegt
 * hat, war die Vorbedingung erfuellt.
 */
const CSX_ENFORCE = true;

/**
 * Ohne den CF7-Spamschutz fehlen cs_verify(), cs_score(), cs_log_add() und die
 * REST-Route, die das Token ausgibt. Dann ist Nichtstun richtig: ein halber,
 * selbstgebauter Schutz waere schlechter als ein klar erkennbar fehlender.
 */
function csx_ready() {
	return function_exists( 'cs_verify' )
		&& function_exists( 'cs_score' )
		&& function_exists( 'cs_log_add' )
		&& defined( 'CS_MIN_SECONDS' );
}

/* --- Client-JS ------------------------------------------------------------ */

/**
 * Holt dasselbe signierte Token wie der CF7-Pfad und haengt es an Spectra-POSTs.
 *
 * Die Eigenschaften aus cs_inline_js() gelten hier sinngemaess weiter:
 * Abruf beim Seitenaufbau (nicht bei der ersten Interaktion), Auffrischen bei
 * `pageshow`/`visibilitychange`, und im Zweifel wird abgesendet — ein tot
 * wirkender Senden-Button ist schlimmer als eine protokollierte Ablehnung.
 */
function csx_inline_js() {
	$url = wp_make_link_relative( rest_url( 'contic-spam/v1/token' ) );

	return <<<JS
(function () {
	var TOKEN = '';
	var fetching = null;

	function refresh() {
		if (fetching) { return fetching; }
		fetching = fetch('{$url}', { credentials: 'same-origin', cache: 'no-store' })
			.then(function (r) { return r.ok ? r.json() : null; })
			.then(function (d) { if (d && d.t) { TOKEN = d.t; } })
			.catch(function () {})
			.then(function () { fetching = null; });
		return fetching;
	}

	refresh();
	window.addEventListener('pageshow', function (e) { if (e.persisted) { refresh(); } });
	document.addEventListener('visibilitychange', function () {
		if (document.visibilityState === 'visible') { refresh(); }
	});

	/* Nur Spectra-Formular-Requests anfassen. Alles andere geht unveraendert
	   durch — diese Umhuellung darf fuer keinen fremden fetch spuerbar sein. */
	var nativeFetch = window.fetch;
	window.fetch = function (input, init) {
		try {
			if (init && init.body && TOKEN) {
				if (init.body instanceof URLSearchParams) {
					if (init.body.get('action') === 'uagb_process_forms' && !init.body.get('_cs_t')) {
						init.body.append('_cs_t', TOKEN);
					}
				} else if (typeof init.body === 'string'
					&& init.body.indexOf('action=uagb_process_forms') !== -1
					&& init.body.indexOf('_cs_t=') === -1) {
					init.body += '&_cs_t=' + encodeURIComponent(TOKEN);
				}
			}
		} catch (e) { /* niemals den Versand blockieren */ }
		return nativeFetch.apply(this, arguments);
	};
})();
JS;
}

add_action( 'wp_enqueue_scripts', function () {
	if ( is_admin() || ! csx_ready() ) {
		return;
	}
	wp_register_script( 'csx-guard', '', array(), CSX_VERSION, true );
	wp_enqueue_script( 'csx-guard' );
	wp_add_inline_script( 'csx-guard', csx_inline_js() );
} );

/* --- Serverseitige Pruefung ---------------------------------------------- */

/**
 * Zieht alle Nutzereingaben aus dem Spectra-Payload.
 *
 * Spectra sendet `form_data` als JSON, dessen SCHLUESSEL die Label-Texte sind
 * ("Vorname", "E-Mail", "Ihre Nachricht") — nicht die Feldnamen. Deshalb kann
 * hier nicht wie im CF7-Pfad ueber CS_SKIP_FIELDS nach Feldnamen gefiltert
 * werden; gefiltert wird stattdessen nach Schluessel-Semantik.
 */
function csx_extract( $raw ) {
	/* wp_unslash() ist hier Pflicht, nicht Kosmetik: WordPress legt in
	 * wp_magic_quotes() (Hook `sanitize_comment_cookies`, laeuft vor jedem
	 * AJAX-Handler) addslashes() auf $_POST. `form_data` kommt hier also als
	 * escapetes JSON an — `{\"Vorname\":\"...\"}` —, und json_decode() gibt
	 * darauf null zurueck. Ohne diese Zeile waeren `name`, `text` und `email`
	 * immer leer: die Inhaltsbewertung liefe auf dem leeren String und faende
	 * nie etwas, und im Spam-Log stuende bei jedem Eintrag ein leerer Auszug.
	 * Genau daran ist der Fehler am 2026-07-30 aufgefallen. Vgl. die
	 * verwandte wp_slash()-Falle in der Bridge (Commit e2f753e). */
	$data = json_decode( (string) wp_unslash( $raw ), true );
	if ( ! is_array( $data ) ) {
		return array( 'name' => '', 'text' => '', 'email' => '' );
	}

	$name = '';
	$mail = '';
	$parts = array();

	foreach ( $data as $key => $value ) {
		if ( 'id' === $key || is_array( $value ) ) {
			continue;
		}
		$value = trim( (string) $value );
		if ( '' === $value ) {
			continue;
		}
		$k = mb_strtolower( (string) $key );

		if ( '' === $mail && ( false !== mb_strpos( $k, 'mail' ) || is_email( $value ) ) ) {
			$mail = $value;
			continue; // E-Mail nicht in die Inhaltsbewertung — sonst zaehlt jede Adresse als Signal
		}
		if ( '' === $name && ( false !== mb_strpos( $k, 'name' ) || false !== mb_strpos( $k, 'vorname' ) ) ) {
			$name = $value;
		}
		$parts[] = $value;
	}

	return array(
		'name'  => $name,
		'text'  => implode( "\n", $parts ),
		'email' => $mail,
	);
}

/** Protokolliert im selben Ringpuffer wie der CF7-Pfad (Werkzeuge → Spam-Log). */
function csx_reject( $reason, $score = 0, $signals = array(), $excerpt = '', $email = '' ) {
	cs_log_add( array(
		'time'    => current_time( 'mysql' ),
		'form'    => 'Spectra: ' . sanitize_text_field( (string) ( $_POST['block_id'] ?? '?' ) ),
		'email'   => $email,
		'reason'  => $reason . ( ( CS_ENFORCE && CSX_ENFORCE ) ? '' : ' (nur beobachtet)' ),
		'score'   => (int) $score,
		'signals' => $signals,
		'excerpt' => mb_substr( (string) $excerpt, 0, 300 ),
	) );

	if ( 'no_token' === $reason || 'token_expired' === $reason ) {
		$n = (int) get_transient( 'cs_fail_24h' );
		set_transient( 'cs_fail_24h', $n + 1, DAY_IN_SECONDS );
	}

	if ( ! CS_ENFORCE || ! CSX_ENFORCE ) {
		return; // Beobachtungsmodus: protokollieren, aber durchlassen
	}

	/* Spectras JS wertet `data` aus: 200 = Erfolgsmeldung, alles andere = die
	   normale Fehlermeldung des Formulars. Absichtlich dieselbe Meldung wie bei
	   jedem anderen Fehler — ein Bot soll nicht erfahren, woran er gescheitert
	   ist, und ein faelschlich geblockter Mensch sieht nichts Kryptisches. */
	wp_send_json_success( 400 );
}

add_action( 'wp_ajax_nopriv_uagb_process_forms', function () {
	if ( ! csx_ready() ) {
		return;
	}

	$salt    = wp_salt( 'contic-spam' );
	$fields  = csx_extract( $_POST['form_data'] ?? '' );
	$excerpt = $fields['text'];

	/* Stufe 1+2: Token vorhanden und echt. */
	if ( defined( 'CS_STAGE_TOKEN' ) && CS_STAGE_TOKEN ) {
		$token = isset( $_POST['_cs_t'] ) ? (string) wp_unslash( $_POST['_cs_t'] ) : '';
		if ( '' === $token ) {
			csx_reject( 'no_token', 0, array(), $excerpt, $fields['email'] );
			return;
		}
		$ts = cs_verify( $token, $salt );
		if ( false === $ts ) {
			csx_reject( 'bad_token', 0, array(), $excerpt, $fields['email'] );
			return;
		}

		/* Stufe 3: Zeitfalle. Ein Mensch braucht laenger als CS_MIN_SECONDS, um
		   ein Formular auszufuellen; ein Skript ist sofort fertig. */
		$age = time() - (int) $ts;
		if ( $age < CS_MIN_SECONDS ) {
			csx_reject( 'too_fast', 0, array( 'age=' . $age ), $excerpt, $fields['email'] );
			return;
		}
		if ( $age > CS_TOKEN_TTL ) {
			csx_reject( 'token_expired', 0, array( 'age=' . $age ), $excerpt, $fields['email'] );
			return;
		}
	}

	/* Stufe 4: Duplikate — gleicher Text, gleiche Adresse, mehrfach. */
	if ( defined( 'CS_STAGE_DUP' ) && CS_STAGE_DUP && function_exists( 'cs_dup_hit' ) ) {
		if ( cs_dup_hit( $fields['email'], $fields['text'] ) ) {
			csx_reject( 'duplicate', 0, array(), $excerpt, $fields['email'] );
			return;
		}
	}

	/* Stufe 5: Rate-Limit. Standardmaessig aus — hinter einem Reverse Proxy ist
	   REMOTE_ADDR fuer alle Besucher gleich (vgl. Kommentar zu CS_STAGE_RATE). */
	if ( defined( 'CS_STAGE_RATE' ) && CS_STAGE_RATE
		&& function_exists( 'cs_rate_hit' ) && function_exists( 'cs_ip_hash' ) ) {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		if ( cs_rate_hit( cs_ip_hash( $ip, $salt ) ) ) {
			csx_reject( 'rate_limit', 0, array(), $excerpt, $fields['email'] );
			return;
		}
	}

	/* Stufe 6: Inhaltsbewertung mit derselben Logik wie im CF7-Pfad. */
	if ( defined( 'CS_STAGE_SCORE' ) && CS_STAGE_SCORE ) {
		$result = cs_score( $fields['name'], $fields['text'] );
		if ( $result['score'] >= CS_SCORE_BLOCK ) {
			csx_reject( 'score', $result['score'], $result['signals'], $excerpt, $fields['email'] );
			return;
		}
	}

	/* Kein Abbruch: UAGBs eigener Handler laeuft anschliessend normal weiter. */
}, 0 );
