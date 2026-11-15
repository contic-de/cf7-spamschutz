<?php
/**
 * Minimal-Stubs der WordPress-Funktionen, die cf7-spamschutz.php nutzt.
 * Nur für den lokalen Testlauf (php tests/run.php) — nie ausliefern.
 */

define( 'ABSPATH', __DIR__ );
define( 'DAY_IN_SECONDS', 86400 );
define( 'HOUR_IN_SECONDS', 3600 );

$GLOBALS['stub_transients'] = array();
$GLOBALS['stub_options']    = array();
$GLOBALS['stub_hooks']      = array();

function wp_salt( $scheme = 'auth' ) { return 'test-salt-' . $scheme; }

// T1: Callbacks werden je Tag aufgezeichnet (nicht nur der Tag-Name), damit die
// Testsuite den registrierten wpcf7_spam-Filter greifen und selbst aufrufen kann.
function add_filter( $tag, $cb, $prio = 10, $args = 1 ) { $GLOBALS['stub_hooks'][ $tag ][] = $cb; return true; }
function add_action( $tag, $cb, $prio = 10, $args = 1 ) { $GLOBALS['stub_hooks'][ $tag ][] = $cb; return true; }
function register_rest_route( $ns, $route, $args ) { return true; }
function add_management_page( $a, $b, $c, $d, $e = null ) { return true; }
function wp_register_script( $h, $s = '', $d = array(), $v = false, $f = false ) { return true; }
function wp_enqueue_script( $h ) { return true; }
function wp_add_inline_script( $h, $js, $pos = 'after' ) { return true; }
function rest_url( $path = '' ) { return 'https://example.test/wp-json/' . ltrim( $path, '/' ); }
function wp_make_link_relative( $link ) { return preg_replace( '#^(https?:)?//[^/]+(/?.*)#i', '$2', $link ); }
function nocache_headers() {}
function wp_json_encode( $v ) { return json_encode( $v ); }
function wp_unslash( $v ) { return $v; }
function esc_html( $v ) { return htmlspecialchars( (string) $v, ENT_QUOTES ); }
function esc_attr( $v ) { return htmlspecialchars( (string) $v, ENT_QUOTES ); }
function current_time( $type ) { return date( 'Y-m-d H:i:s' ); }
function is_email( $v ) { return (bool) filter_var( $v, FILTER_VALIDATE_EMAIL ); }
function current_user_can( $cap ) { return true; }

function get_transient( $k ) {
    if ( ! isset( $GLOBALS['stub_transients'][ $k ] ) ) { return false; }
    $e = $GLOBALS['stub_transients'][ $k ];
    if ( $e['exp'] < time() ) { unset( $GLOBALS['stub_transients'][ $k ] ); return false; }
    return $e['val'];
}
function set_transient( $k, $v, $ttl ) {
    $GLOBALS['stub_transients'][ $k ] = array( 'val' => $v, 'exp' => time() + $ttl );
    return true;
}
function delete_transient( $k ) { unset( $GLOBALS['stub_transients'][ $k ] ); return true; }

function get_option( $k, $default = false ) {
    return isset( $GLOBALS['stub_options'][ $k ] ) ? $GLOBALS['stub_options'][ $k ] : $default;
}
function update_option( $k, $v, $autoload = null ) { $GLOBALS['stub_options'][ $k ] = $v; return true; }
function check_admin_referer( $action = -1, $arg = '_wpnonce' ) { return true; }
function wp_nonce_field( $action = -1, $name = '_wpnonce', $referer = true, $display = true ) { return ''; }

// Minimal-Stub des wp-cron-Systems, nur fuer den Registrierungsaufruf beim Laden der
// Plugin-Datei (cs_daily_log_purge) — kein echter Scheduler, nur Buchfuehrung.
$GLOBALS['stub_cron'] = array();
function wp_next_scheduled( $hook ) {
    return isset( $GLOBALS['stub_cron'][ $hook ] ) ? $GLOBALS['stub_cron'][ $hook ] : false;
}
function wp_schedule_event( $timestamp, $recurrence, $hook ) {
    $GLOBALS['stub_cron'][ $hook ] = $timestamp;
    return true;
}

// M10: HTTP-Schicht und Datumsformat fuer den Selbsttest des Token-Endpunkts.
// $GLOBALS['stub_http'] ist eine Warteschlange: jeder wp_remote_get()-Aufruf nimmt den
// naechsten Eintrag. Ein WP_Error-Objekt darin simuliert einen Verbindungsfehler.
class WP_Error {
    private $msg;
    function __construct( $code = '', $msg = '' ) { $this->msg = $msg; }
    function get_error_message() { return $this->msg; }
}
$GLOBALS['stub_http'] = array();
function is_wp_error( $t ) { return $t instanceof WP_Error; }
function wp_remote_get( $url, $args = array() ) {
    if ( empty( $GLOBALS['stub_http'] ) ) {
        return new WP_Error( 'leer', 'keine Antwort vorbereitet' );
    }
    return array_shift( $GLOBALS['stub_http'] );
}
function wp_remote_retrieve_response_code( $r ) { return isset( $r['response']['code'] ) ? $r['response']['code'] : 0; }
function wp_remote_retrieve_body( $r ) { return isset( $r['body'] ) ? $r['body'] : ''; }
function date_i18n( $fmt, $ts = null ) { return date( $fmt, null === $ts ? time() : $ts ); }
