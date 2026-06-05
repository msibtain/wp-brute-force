<?php
/**
 * Brute force login protection.
 *
 * @package WPBruteForce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Monitors login attempts and blocks IPs that exceed the failure threshold.
 */
class WPBF_Brute_Force {

	/**
	 * Register WordPress hooks.
	 */
	public function __construct() {
		add_filter( 'authenticate', array( $this, 'check_lockout' ), 30, 3 );
		add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'handle_successful_login' ), 10, 2 );
	}

	/**
	 * Get the client IP address.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		$ip = '';

		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$forwarded = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
			$ip        = trim( $forwarded[0] );
		} elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		return $ip;
	}

	/**
	 * Get the client user agent.
	 *
	 * @return string
	 */
	private function get_user_agent() {
		if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return '';
		}

		return sanitize_textarea_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
	}

	/**
	 * Block authentication when the IP is locked out.
	 *
	 * @param WP_User|WP_Error|null $user     User object, error, or null.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return WP_User|WP_Error|null
	 */
	public function check_lockout( $user, $username, $password ) {
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		$ip = $this->get_client_ip();

		if ( empty( $ip ) ) {
			return $user;
		}

		if ( WPBF_Database::is_ip_locked_out( $ip ) ) {
			$lockout_duration = (int) get_option( 'wpbf_lockout_duration', 900 );
			$minutes          = max( 1, (int) ceil( $lockout_duration / 60 ) );

			return new WP_Error(
				'wpbf_locked_out',
				sprintf(
					/* translators: %d: lockout duration in minutes */
					__( 'Too many failed login attempts. Please try again in %d minutes.', 'wp-brute-force' ),
					$minutes
				)
			);
		}

		return $user;
	}

	/**
	 * Log failed login attempts and lock out repeat offenders.
	 *
	 * @param string   $username Attempted username.
	 * @param WP_Error $error    Login error.
	 */
	public function handle_failed_login( $username, $error ) {
		if ( is_wp_error( $error ) && 'wpbf_locked_out' === $error->get_error_code() ) {
			return;
		}

		$ip = $this->get_client_ip();

		if ( empty( $ip ) ) {
			return;
		}

		WPBF_Database::log_attempt( $ip, $username, 'failed', $this->get_user_agent() );

		$max_attempts = (int) get_option( 'wpbf_max_attempts', 5 );
		$failed_count = WPBF_Database::count_recent_failed_attempts( $ip );

		if ( $failed_count >= $max_attempts ) {
			WPBF_Database::log_attempt( $ip, $username, 'blocked', $this->get_user_agent() );
		}
	}

	/**
	 * Log successful logins.
	 *
	 * @param string  $username Username.
	 * @param WP_User $user     Authenticated user.
	 */
	public function handle_successful_login( $username, $user ) {
		$ip = $this->get_client_ip();

		if ( empty( $ip ) ) {
			return;
		}

		WPBF_Database::log_attempt( $ip, $username, 'success', $this->get_user_agent() );
	}
}
