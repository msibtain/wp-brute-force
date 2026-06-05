<?php
/**
 * Plugin Name: WP Brute Force Protection
 * Plugin URI: https://github.com/msibtain/wp-brute-force
 * Description: Prevents brute force login attacks and logs all login attempts.
 * Version: 1.0.0
 * Author: msibtain
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-brute-force
 *
 * @package WPBruteForce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPBF_VERSION', '1.0.0' );
define( 'WPBF_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPBF_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require_once WPBF_PLUGIN_DIR . 'includes/class-wpbf-database.php';
require_once WPBF_PLUGIN_DIR . 'includes/class-wpbf-brute-force.php';
require_once WPBF_PLUGIN_DIR . 'includes/class-wpbf-admin.php';

register_activation_hook( __FILE__, array( 'WPBF_Database', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WPBF_Database', 'deactivate' ) );

/**
 * Bootstrap the plugin.
 */
function wpbf_init() {
	new WPBF_Brute_Force();

	if ( is_admin() ) {
		new WPBF_Admin();
	}
}
add_action( 'plugins_loaded', 'wpbf_init' );
