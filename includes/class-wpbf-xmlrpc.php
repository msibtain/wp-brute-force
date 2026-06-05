<?php
/**
 * Disable XML-RPC to prevent brute force attacks via xmlrpc.php.
 *
 * @package WPBruteForce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Blocks XML-RPC requests and removes related headers/links.
 */
class WPBF_XMLRPC {

	/**
	 * Register WordPress hooks.
	 */
	public function __construct() {
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		remove_action( 'wp_head', 'rsd_link' );
		add_action( 'init', array( $this, 'block_xmlrpc_request' ), 1 );
	}

	/**
	 * Remove the X-Pingback header from HTTP responses.
	 *
	 * @param array $headers Response headers.
	 * @return array
	 */
	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );

		return $headers;
	}

	/**
	 * Reject direct requests to xmlrpc.php.
	 */
	public function block_xmlrpc_request() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			wp_die(
				esc_html__( 'XML-RPC services are disabled on this site.', 'wp-brute-force' ),
				esc_html__( 'XML-RPC Disabled', 'wp-brute-force' ),
				array( 'response' => 403 )
			);
		}

		if (
			! empty( $_SERVER['REQUEST_URI'] )
			&& false !== stripos( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), 'xmlrpc.php' )
		) {
			wp_die(
				esc_html__( 'XML-RPC services are disabled on this site.', 'wp-brute-force' ),
				esc_html__( 'XML-RPC Disabled', 'wp-brute-force' ),
				array( 'response' => 403 )
			);
		}
	}
}
