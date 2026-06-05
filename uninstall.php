<?php
/**
 * Uninstall handler — removes plugin data on deletion.
 *
 * @package WPBruteForce
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$table_name = $wpdb->prefix . 'wpbf_login_attempts';

// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );

delete_option( 'wpbf_max_attempts' );
delete_option( 'wpbf_lockout_duration' );
delete_option( 'wpbf_attempt_window' );
