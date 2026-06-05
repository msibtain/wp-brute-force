<?php
/**
 * Admin UI for brute force logs and settings.
 *
 * @package WPBruteForce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers the Tools submenu page and handles log display.
 */
class WPBF_Admin {

	const PAGE_SLUG = 'wpbf-brute-force-logs';

	/**
	 * Register admin hooks.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'handle_actions' ) );
	}

	/**
	 * Register the page under Tools.
	 */
	public function register_menu() {
		add_management_page(
			__( 'Brute Force Logs', 'wp-brute-force' ),
			__( 'Brute Force Logs', 'wp-brute-force' ),
			'manage_options',
			self::PAGE_SLUG,
			array( $this, 'render_page' )
		);
	}

	/**
	 * Handle form submissions (settings save, clear logs).
	 */
	public function handle_actions() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( isset( $_POST['wpbf_save_settings'] ) ) {
			check_admin_referer( 'wpbf_save_settings' );

			update_option( 'wpbf_max_attempts', max( 1, (int) $_POST['wpbf_max_attempts'] ) );
			update_option( 'wpbf_lockout_duration', max( 60, (int) $_POST['wpbf_lockout_duration'] ) );
			update_option( 'wpbf_attempt_window', max( 60, (int) $_POST['wpbf_attempt_window'] ) );

			add_settings_error(
				'wpbf_messages',
				'wpbf_settings_saved',
				__( 'Settings saved.', 'wp-brute-force' ),
				'success'
			);
		}

		if ( isset( $_POST['wpbf_clear_logs'] ) ) {
			check_admin_referer( 'wpbf_clear_logs' );

			WPBF_Database::clear_logs();

			add_settings_error(
				'wpbf_messages',
				'wpbf_logs_cleared',
				__( 'All login attempt logs have been cleared.', 'wp-brute-force' ),
				'success'
			);
		}
	}

	/**
	 * Render the admin page.
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$per_page = 20;
		$page     = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
		$logs     = WPBF_Database::get_logs( $per_page, $page );
		$total    = $logs['total'];
		$pages    = max( 1, (int) ceil( $total / $per_page ) );

		$max_attempts     = (int) get_option( 'wpbf_max_attempts', 5 );
		$lockout_duration = (int) get_option( 'wpbf_lockout_duration', 900 );
		$attempt_window   = (int) get_option( 'wpbf_attempt_window', 300 );

		settings_errors( 'wpbf_messages' );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Brute Force Protection', 'wp-brute-force' ); ?></h1>

			<h2><?php esc_html_e( 'Settings', 'wp-brute-force' ); ?></h2>
			<form method="post" action="">
				<?php wp_nonce_field( 'wpbf_save_settings' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">
							<label for="wpbf_max_attempts"><?php esc_html_e( 'Max Failed Attempts', 'wp-brute-force' ); ?></label>
						</th>
						<td>
							<input type="number" name="wpbf_max_attempts" id="wpbf_max_attempts"
								value="<?php echo esc_attr( $max_attempts ); ?>" min="1" max="50" class="small-text" />
							<p class="description">
								<?php esc_html_e( 'Number of failed attempts before an IP is locked out.', 'wp-brute-force' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="wpbf_attempt_window"><?php esc_html_e( 'Attempt Window (seconds)', 'wp-brute-force' ); ?></label>
						</th>
						<td>
							<input type="number" name="wpbf_attempt_window" id="wpbf_attempt_window"
								value="<?php echo esc_attr( $attempt_window ); ?>" min="60" class="small-text" />
							<p class="description">
								<?php esc_html_e( 'Time period in which failed attempts are counted.', 'wp-brute-force' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="wpbf_lockout_duration"><?php esc_html_e( 'Lockout Duration (seconds)', 'wp-brute-force' ); ?></label>
						</th>
						<td>
							<input type="number" name="wpbf_lockout_duration" id="wpbf_lockout_duration"
								value="<?php echo esc_attr( $lockout_duration ); ?>" min="60" class="small-text" />
							<p class="description">
								<?php esc_html_e( 'How long a blocked IP must wait before trying again.', 'wp-brute-force' ); ?>
							</p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save Settings', 'wp-brute-force' ), 'primary', 'wpbf_save_settings' ); ?>
			</form>

			<hr />

			<h2>
				<?php esc_html_e( 'Login Attempt Logs', 'wp-brute-force' ); ?>
				<span class="subtitle"><?php echo esc_html( sprintf( __( '%d total entries', 'wp-brute-force' ), $total ) ); ?></span>
			</h2>

			<?php if ( empty( $logs['items'] ) ) : ?>
				<p><?php esc_html_e( 'No login attempts have been logged yet.', 'wp-brute-force' ); ?></p>
			<?php else : ?>
				<table class="widefat fixed striped">
					<thead>
						<tr>
							<th scope="col" style="width:60px;"><?php esc_html_e( 'ID', 'wp-brute-force' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Date / Time', 'wp-brute-force' ); ?></th>
							<th scope="col"><?php esc_html_e( 'IP Address', 'wp-brute-force' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Username', 'wp-brute-force' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Status', 'wp-brute-force' ); ?></th>
							<th scope="col"><?php esc_html_e( 'User Agent', 'wp-brute-force' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $logs['items'] as $log ) : ?>
							<tr>
								<td><?php echo esc_html( $log['id'] ); ?></td>
								<td><?php echo esc_html( $log['attempt_time'] ); ?></td>
								<td><code><?php echo esc_html( $log['ip_address'] ); ?></code></td>
								<td><?php echo esc_html( $log['username'] ); ?></td>
								<td><?php echo $this->render_status_badge( $log['status'] ); ?></td>
								<td>
									<span title="<?php echo esc_attr( $log['user_agent'] ); ?>">
										<?php echo esc_html( $this->truncate( $log['user_agent'], 60 ) ); ?>
									</span>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>

				<?php if ( $pages > 1 ) : ?>
					<div class="tablenav bottom">
						<div class="tablenav-pages">
							<span class="displaying-num">
								<?php
								echo esc_html(
									sprintf(
										/* translators: %d: total log entries */
										_n( '%d item', '%d items', $total, 'wp-brute-force' ),
										$total
									)
								);
								?>
							</span>
							<span class="pagination-links">
								<?php
								$base_url = admin_url( 'tools.php?page=' . self::PAGE_SLUG );

								if ( $page > 1 ) {
									echo '<a class="prev-page button" href="' . esc_url( add_query_arg( 'paged', $page - 1, $base_url ) ) . '">‹</a>';
								}

								echo '<span class="paging-input">';
								echo esc_html( $page ) . ' / ' . esc_html( $pages );
								echo '</span>';

								if ( $page < $pages ) {
									echo '<a class="next-page button" href="' . esc_url( add_query_arg( 'paged', $page + 1, $base_url ) ) . '">›</a>';
								}
								?>
							</span>
						</div>
					</div>
				<?php endif; ?>
			<?php endif; ?>

			<hr />

			<form method="post" action="" onsubmit="return confirm('<?php echo esc_js( __( 'Are you sure you want to delete all logs?', 'wp-brute-force' ) ); ?>');">
				<?php wp_nonce_field( 'wpbf_clear_logs' ); ?>
				<?php submit_button( __( 'Clear All Logs', 'wp-brute-force' ), 'delete', 'wpbf_clear_logs', false ); ?>
			</form>
		</div>
		<?php
	}

	/**
	 * Render a colored status badge.
	 *
	 * @param string $status Log status.
	 * @return string
	 */
	private function render_status_badge( $status ) {
		$colors = array(
			'success' => '#00a32a',
			'failed'  => '#d63638',
			'blocked' => '#996800',
		);

		$color = isset( $colors[ $status ] ) ? $colors[ $status ] : '#646970';

		return sprintf(
			'<span style="display:inline-block;padding:2px 8px;border-radius:3px;background:%1$s;color:#fff;font-size:12px;font-weight:600;text-transform:uppercase;">%2$s</span>',
			esc_attr( $color ),
			esc_html( $status )
		);
	}

	/**
	 * Truncate a string for table display.
	 *
	 * @param string $text   Text to truncate.
	 * @param int    $length Max length.
	 * @return string
	 */
	private function truncate( $text, $length ) {
		if ( strlen( $text ) <= $length ) {
			return $text;
		}

		return substr( $text, 0, $length ) . '…';
	}
}
