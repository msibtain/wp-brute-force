<?php
/**
 * Human verification challenge on the login screen.
 *
 * @package WPBruteForce
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Displays a code challenge before the login form and blocks unverified logins.
 */
class WPBF_Login_Challenge {

	const COOKIE_TOKEN = 'wpbf_ch_token';

	/**
	 * Register WordPress hooks when the feature is enabled.
	 */
	public function __construct() {
		if ( ! get_option( 'wpbf_login_challenge', false ) ) {
			return;
		}

		add_action( 'login_init', array( $this, 'handle_verification_submit' ), 1 );
		add_action( 'login_head', array( $this, 'output_visibility_styles' ) );
		add_action( 'login_footer', array( $this, 'render_challenge' ), 1 );
		add_filter( 'authenticate', array( $this, 'block_without_verification' ), 1, 3 );
	}

	/**
	 * Whether the current request is the standard login screen.
	 *
	 * @return bool
	 */
	private function is_login_screen() {
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';

		return in_array( $action, array( 'login', '' ), true );
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
	 * Get or create a per-browser challenge token stored in a cookie.
	 *
	 * @return string
	 */
	private function get_token() {
		if ( ! empty( $_COOKIE[ self::COOKIE_TOKEN ] ) ) {
			$token = sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE_TOKEN ] ) );

			if ( preg_match( '/^[a-f0-9]{32}$/', $token ) ) {
				return $token;
			}
		}

		$token = bin2hex( random_bytes( 16 ) );

		setcookie(
			self::COOKIE_TOKEN,
			$token,
			array(
				'expires'  => time() + DAY_IN_SECONDS,
				'path'     => COOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);

		$_COOKIE[ self::COOKIE_TOKEN ] = $token;

		return $token;
	}

	/**
	 * Transient key for the active challenge code hash.
	 *
	 * @param string $token Browser token.
	 * @return string
	 */
	private function challenge_transient_key( $token ) {
		return 'wpbf_ch_' . $token;
	}

	/**
	 * Transient key for a successfully verified session.
	 *
	 * @param string $token Browser token.
	 * @return string
	 */
	private function verified_transient_key( $token ) {
		return 'wpbf_ch_verified_' . $token;
	}

	/**
	 * Hash a challenge code for storage.
	 *
	 * @param string $code Plain-text code.
	 * @return string
	 */
	private function hash_code( $code ) {
		return hash_hmac( 'sha256', strtoupper( $code ), wp_salt( 'wpbf_challenge' ) );
	}

	/**
	 * Generate a readable random code and store its hash.
	 *
	 * @return string Plain-text code shown to the user.
	 */
	private function generate_code() {
		$chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
		$code  = '';

		for ( $i = 0; $i < 5; $i++ ) {
			$code .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
		}

		$token = $this->get_token();

		set_transient(
			$this->challenge_transient_key( $token ),
			array(
				'hash' => $this->hash_code( $code ),
				'code' => $code,
			),
			10 * MINUTE_IN_SECONDS
		);

		return $code;
	}

	/**
	 * Get the stored challenge data for the current browser token.
	 *
	 * @return array{hash: string, code: string}|false
	 */
	private function get_stored_challenge() {
		$token = $this->get_token();
		$data  = get_transient( $this->challenge_transient_key( $token ) );

		if ( ! is_array( $data ) || empty( $data['hash'] ) || empty( $data['code'] ) ) {
			return false;
		}

		return $data;
	}

	/**
	 * Whether the current browser has passed the challenge recently.
	 *
	 * @return bool
	 */
	private function is_verified() {
		$token = $this->get_token();

		return (bool) get_transient( $this->verified_transient_key( $token ) );
	}

	/**
	 * Mark the current browser as verified.
	 */
	private function mark_verified() {
		$token = $this->get_token();

		set_transient( $this->verified_transient_key( $token ), 1, 30 * MINUTE_IN_SECONDS );
		delete_transient( $this->challenge_transient_key( $token ) );
	}

	/**
	 * Process the challenge form submission.
	 */
	public function handle_verification_submit() {
		if ( ! $this->is_login_screen() ) {
			return;
		}

		if ( empty( $_POST['wpbf_verify_challenge'] ) ) {
			return;
		}

		check_admin_referer( 'wpbf_verify_challenge', 'wpbf_challenge_nonce' );

		$submitted = isset( $_POST['wpbf_challenge_code'] )
			? strtoupper( sanitize_text_field( wp_unslash( $_POST['wpbf_challenge_code'] ) ) )
			: '';
		$challenge = $this->get_stored_challenge();
		$stored    = is_array( $challenge ) ? $challenge['hash'] : false;

		if ( empty( $submitted ) || false === $stored ) {
			wp_safe_redirect( add_query_arg( 'wpbf_challenge', 'expired', wp_login_url( $this->get_redirect_to() ) ) );
			exit;
		}

		if ( ! hash_equals( $stored, $this->hash_code( $submitted ) ) ) {
			wp_safe_redirect( add_query_arg( 'wpbf_challenge', 'failed', wp_login_url( $this->get_redirect_to() ) ) );
			exit;
		}

		$this->mark_verified();

		wp_safe_redirect( add_query_arg( 'wpbf_challenge', 'passed', wp_login_url( $this->get_redirect_to() ) ) );
		exit;
	}

	/**
	 * Preserve redirect_to across challenge redirects.
	 *
	 * @return string
	 */
	private function get_redirect_to() {
		if ( empty( $_REQUEST['redirect_to'] ) ) {
			return '';
		}

		return wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), '' );
	}

	/**
	 * Block credential submission until the challenge is passed.
	 *
	 * @param WP_User|WP_Error|null $user     User object, error, or null.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return WP_User|WP_Error|null
	 */
	public function block_without_verification( $user, $username, $password ) {
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		if ( $this->is_verified() ) {
			return $user;
		}

		return new WP_Error(
			'wpbf_challenge_required',
			__( 'Please complete the verification challenge before logging in.', 'wp-brute-force' )
		);
	}

	/**
	 * Hide the login form or challenge depending on verification state.
	 */
	public function output_visibility_styles() {
		if ( ! $this->is_login_screen() ) {
			return;
		}

		$verified = $this->is_verified();

		if ( $verified ) {
			echo '<style>#wpbf-challenge{display:none!important;}</style>';
			return;
		}

		echo '<style>#loginform,#nav,#backtoblog,.privacy-policy-page-link{display:none!important;}</style>';
	}

	/**
	 * Output the challenge UI on the login page.
	 */
	public function render_challenge() {
		if ( ! $this->is_login_screen() ) {
			return;
		}

		$verified = $this->is_verified();
		$code     = $verified ? '' : $this->get_or_create_code();
		$status   = isset( $_GET['wpbf_challenge'] ) ? sanitize_key( wp_unslash( $_GET['wpbf_challenge'] ) ) : '';

		if ( $verified ) {
			if ( 'passed' === $status ) {
				echo '<div id="wpbf-challenge-notice" class="notice notice-success"><p>';
				esc_html_e( 'Verification successful. You may now log in.', 'wp-brute-force' );
				echo '</p></div>';
			}

			return;
		}

		$login_url = wp_login_url( $this->get_redirect_to() );
		?>
		<div id="wpbf-challenge">
			<h2><?php esc_html_e( 'Verify you are human', 'wp-brute-force' ); ?></h2>
			<p><?php esc_html_e( 'Enter the code shown below to access the login form.', 'wp-brute-force' ); ?></p>

			<?php if ( 'failed' === $status ) : ?>
				<div class="wpbf-challenge-error">
					<?php esc_html_e( 'Incorrect code. Please try again.', 'wp-brute-force' ); ?>
				</div>
			<?php elseif ( 'expired' === $status ) : ?>
				<div class="wpbf-challenge-error">
					<?php esc_html_e( 'That code has expired. A new code has been generated below.', 'wp-brute-force' ); ?>
				</div>
			<?php endif; ?>

			<div class="wpbf-challenge-code" aria-hidden="true"><?php echo esc_html( $code ); ?></div>

			<form method="post" action="<?php echo esc_url( $login_url ); ?>" id="wpbf-challenge-form">
				<?php wp_nonce_field( 'wpbf_verify_challenge', 'wpbf_challenge_nonce' ); ?>
				<input type="hidden" name="wpbf_verify_challenge" value="1" />
				<?php if ( ! empty( $_REQUEST['redirect_to'] ) ) : ?>
					<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $this->get_redirect_to() ); ?>" />
				<?php endif; ?>
				<p>
					<label for="wpbf_challenge_code"><?php esc_html_e( 'Verification code', 'wp-brute-force' ); ?></label>
					<input
						type="text"
						name="wpbf_challenge_code"
						id="wpbf_challenge_code"
						class="input"
						size="10"
						autocomplete="off"
						autocapitalize="characters"
						spellcheck="false"
						required
					/>
				</p>
				<p class="submit">
					<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Continue', 'wp-brute-force' ); ?>" />
				</p>
			</form>
		</div>
		<style>
			#wpbf-challenge {
				margin-top: 8px;
			}
			#wpbf-challenge h2 {
				font-size: 20px;
				font-weight: 400;
				margin: 0 0 12px;
				padding: 0;
				text-align: center;
			}
			#wpbf-challenge p {
				margin: 0 0 16px;
				text-align: center;
			}
			.wpbf-challenge-code {
				background: #f0f0f1;
				border: 1px solid #c3c4c7;
				border-radius: 4px;
				color: #1d2327;
				font-family: Consolas, Monaco, monospace;
				font-size: 28px;
				font-weight: 700;
				letter-spacing: 6px;
				margin: 0 auto 20px;
				padding: 16px 12px;
				text-align: center;
				user-select: none;
				width: fit-content;
			}
			.wpbf-challenge-error {
				background: #fcf0f1;
				border-left: 4px solid #d63638;
				color: #1d2327;
				margin: 0 0 16px;
				padding: 8px 12px;
			}
			#wpbf-challenge-notice {
				margin-bottom: 16px;
			}
		</style>
		<?php
	}

	/**
	 * Return the active code or create one when missing.
	 *
	 * @return string
	 */
	private function get_or_create_code() {
		$challenge = $this->get_stored_challenge();

		if ( is_array( $challenge ) ) {
			return $challenge['code'];
		}

		return $this->generate_code();
	}
}
