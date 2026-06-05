<?php
/**
 * Database operations for login attempt logs.
 *
 * @package WPBruteForce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles custom table creation and log storage.
 */
class WPBF_Database {

	/**
	 * Get the full table name including prefix.
	 *
	 * @return string
	 */
	public static function get_table_name() {
		global $wpdb;

		return $wpdb->prefix . 'wpbf_login_attempts';
	}

	/**
	 * Plugin activation: create table and set defaults.
	 */
	public static function activate() {
		self::create_table();

		add_option( 'wpbf_max_attempts', 5 );
		add_option( 'wpbf_lockout_duration', 900 );
		add_option( 'wpbf_attempt_window', 300 );
	}

	/**
	 * Plugin deactivation.
	 */
	public static function deactivate() {
		// Table is preserved so logs remain available after reactivation.
	}

	/**
	 * Create the login attempts table.
	 */
	public static function create_table() {
		global $wpdb;

		$table_name      = self::get_table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			username varchar(255) NOT NULL DEFAULT '',
			status varchar(20) NOT NULL,
			user_agent text DEFAULT NULL,
			attempt_time datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY ip_address (ip_address),
			KEY status (status),
			KEY attempt_time (attempt_time)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Insert a login attempt log entry.
	 *
	 * @param string $ip_address Client IP.
	 * @param string $username   Attempted username.
	 * @param string $status     Attempt status: failed, success, or blocked.
	 * @param string $user_agent Client user agent.
	 * @return int|false Insert ID or false on failure.
	 */
	public static function log_attempt( $ip_address, $username, $status, $user_agent = '' ) {
		global $wpdb;

		$result = $wpdb->insert(
			self::get_table_name(),
			array(
				'ip_address'   => sanitize_text_field( $ip_address ),
				'username'     => sanitize_text_field( $username ),
				'status'       => sanitize_text_field( $status ),
				'user_agent'   => sanitize_textarea_field( $user_agent ),
				'attempt_time' => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s' )
		);

		return $result ? $wpdb->insert_id : false;
	}

	/**
	 * Count recent failed attempts for an IP within the attempt window.
	 *
	 * @param string $ip_address Client IP.
	 * @return int
	 */
	public static function count_recent_failed_attempts( $ip_address ) {
		global $wpdb;

		$window = (int) get_option( 'wpbf_attempt_window', 300 );
		$since  = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - $window );

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM " . self::get_table_name() . "
				WHERE ip_address = %s
				AND status = 'failed'
				AND attempt_time >= %s",
				$ip_address,
				$since
			)
		);
	}

	/**
	 * Check whether an IP is currently locked out.
	 *
	 * @param string $ip_address Client IP.
	 * @return bool
	 */
	public static function is_ip_locked_out( $ip_address ) {
		global $wpdb;

		$lockout_duration = (int) get_option( 'wpbf_lockout_duration', 900 );
		$since            = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - $lockout_duration );

		$blocked = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM " . self::get_table_name() . "
				WHERE ip_address = %s
				AND status = 'blocked'
				AND attempt_time >= %s",
				$ip_address,
				$since
			)
		);

		return $blocked > 0;
	}

	/**
	 * Fetch paginated log entries.
	 *
	 * @param int $per_page Items per page.
	 * @param int $page     Current page (1-based).
	 * @return array{items: array, total: int}
	 */
	public static function get_logs( $per_page = 20, $page = 1 ) {
		global $wpdb;

		$table_name = self::get_table_name();
		$per_page   = max( 1, (int) $per_page );
		$page       = max( 1, (int) $page );
		$offset     = ( $page - 1 ) * $per_page;

		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );

		$items = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table_name}
				ORDER BY attempt_time DESC
				LIMIT %d OFFSET %d",
				$per_page,
				$offset
			),
			ARRAY_A
		);

		return array(
			'items' => $items ? $items : array(),
			'total' => $total,
		);
	}

	/**
	 * Delete all log entries.
	 *
	 * @return int|false Number of rows deleted or false on failure.
	 */
	public static function clear_logs() {
		global $wpdb;

		return $wpdb->query( 'TRUNCATE TABLE ' . self::get_table_name() );
	}
}
