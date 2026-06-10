<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

class Login {
    public function register(): void {
        add_filter('wp_authenticate_user', [$this, 'maybe_challenge'], 50, 2);
        add_action('login_form_free2fa', [$this, 'render_challenge']);
        add_action('init', [$this, 'maybe_handle_challenge']);
        add_action('password_reset', [$this, 'on_password_reset'], 10, 2);
    }

    /**
     * If user has 2FA enabled, intercept authentication.
     * We allow password auth through, but issue an interim token so /wp-login.php?action=free2fa
     * can validate the second factor.
     */
    public function maybe_challenge($user, $password) {
        if (is_wp_error($user) || !($user instanceof \WP_User)) return $user;
        if (!$this->is_required_for($user)) return $user;
        if (!self::user_has_2fa($user->ID)) return $user;
        if (Rate::is_locked($user->ID)) {
            return new \WP_Error('free2fa_locked', __('Too many failed 2FA attempts. Try again later.', 'free-2fa'));
        }
        // Trusted device shortcut
        if (TrustedDevice::valid_for($user->ID)) return $user;

        // Non-interactive contexts (XML-RPC, WP-CLI, REST/JSON) cannot follow an HTTP
        // redirect — return a WP_Error so the caller fails authentication cleanly.
        if (self::is_non_interactive()) {
            return new \WP_Error(
                'free2fa_required',
                __('Two-factor authentication is required for this account; sign in via the web login.', 'free-2fa')
            );
        }

        // Issue interim token; redirect destination is bound to the token server-side.
        $redirect_to = isset($_REQUEST['redirect_to']) ? esc_url_raw($_REQUEST['redirect_to']) : admin_url();
        $rememberme  = !empty($_REQUEST['rememberme']);
        $token = self::issue_interim_token($user->ID, $redirect_to, $rememberme);
        $url = add_query_arg([
            'action' => 'free2fa',
            'token'  => $token,
        ], wp_login_url());
        wp_safe_redirect($url);
        exit;
    }

    private static function is_non_interactive(): bool {
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) return true;
        if (defined('WP_CLI') && WP_CLI) return true;
        if (function_exists('wp_is_json_request') && wp_is_json_request()) return true;
        if (defined('REST_REQUEST') && REST_REQUEST) return true;
        return false;
    }

    public function maybe_handle_challenge(): void {
        if (!isset($_POST['free2fa_submit']) && !isset($_POST['free2fa_send_email'])) return;
        if (!isset($_POST['free2fa_nonce']) || !wp_verify_nonce($_POST['free2fa_nonce'], 'free2fa_challenge')) {
            wp_die(__('Security check failed.', 'free-2fa'));
        }
        $token = sanitize_text_field($_POST['free2fa_token'] ?? '');
        $code  = sanitize_text_field($_POST['free2fa_code'] ?? '');
        $trust = !empty($_POST['free2fa_trust']);

        // Peek first; only consume on success so failed attempts can re-render with same token.
        $session = self::peek_interim_token($token);
        if (!$session) wp_die(__('Session expired. Please log in again.', 'free-2fa'));
        $user_id = (int) $session['uid'];

        // "Email me a code" — issue an OTP and re-render. Not a verification
        // attempt, so it neither consumes the token nor counts toward lockout.
        // Rate-limited inside Email::send(); the response never reveals whether
        // an email actually went out.
        if (isset($_POST['free2fa_send_email'])) {
            Email::send($user_id);
            wp_safe_redirect(add_query_arg([
                'action' => 'free2fa', 'token' => $token, 'sent' => '1',
            ], wp_login_url()));
            exit;
        }
        $redirect_to = (string) ($session['redirect_to'] ?? admin_url());
        $rememberme  = !empty($session['rememberme']);

        if (Rate::is_locked($user_id)) wp_die(__('Too many failed attempts.', 'free-2fa'));

        $ok = self::verify_any_factor($user_id, $code);
        if (!$ok) {
            Rate::record_fail($user_id);
            // Re-render with the SAME token (still valid in transient)
            wp_safe_redirect(add_query_arg([
                'action' => 'free2fa', 'token' => $token, 'error' => '1',
            ], wp_login_url()));
            exit;
        }

        // Success: burn the token, clear rate state, log in.
        self::consume_interim_token($token);
        Rate::clear($user_id);

        $user = get_userdata($user_id);
        wp_set_auth_cookie($user_id, $rememberme);

        // Recovery path: user got in with a backup code while their TOTP secret is
        // unreadable. The old secret is unrecoverable — wipe the enrollment and send
        // them straight to setup so they enroll a fresh secret under the current key.
        // No trusted-device cookie is issued in this state.
        if (get_user_meta($user_id, 'free2fa_needs_resetup', true) && self::secret_unreadable($user_id)) {
            Setup::reset_enrollment($user_id);
            do_action('wp_login', $user->user_login, $user);
            wp_safe_redirect(admin_url('users.php?page=free-2fa-setup&free2fa_resetup=1'));
            exit;
        }
        delete_user_meta($user_id, 'free2fa_needs_resetup');

        if ($trust) {
            $opts = get_option('free2fa_settings', []);
            $days = max(1, (int)($opts['trust_days'] ?? TrustedDevice::DEFAULT_DAYS));
            TrustedDevice::issue($user_id, $days);
        }
        do_action('wp_login', $user->user_login, $user);
        wp_safe_redirect($redirect_to);
        exit;
    }

    public function render_challenge(): void {
        $token = sanitize_text_field($_REQUEST['token'] ?? '');
        $session = self::peek_interim_token($token);
        if (!$session) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        $error = !empty($_GET['error']);
        $sent  = !empty($_GET['sent']);
        $uid   = (int) $session['uid'];
        $unreadable = self::secret_unreadable($uid);
        $email_ok   = Email::enabled_for($uid);

        login_header(__('Two-Factor Authentication', 'free-2fa'));
        ?>
        <form method="post" id="free2fa-form" style="margin-top:20px">
            <?php wp_nonce_field('free2fa_challenge', 'free2fa_nonce'); ?>
            <input type="hidden" name="free2fa_token" value="<?php echo esc_attr($token); ?>">
            <?php if ($unreadable): ?>
                <div class="message" style="border-left:4px solid #dba617;padding:8px 12px;margin:10px 0;background:#fcf9e8">
                    <?php esc_html_e('Authenticator codes cannot be verified right now because the site\'s security keys have changed. Enter one of your backup codes — you will then be asked to set up two-factor authentication again.', 'free-2fa'); ?>
                </div>
                <p style="font-size:13px;color:#50575e">
                    <?php esc_html_e('Enter a backup code.', 'free-2fa'); ?>
                </p>
            <?php else: ?>
            <p style="font-size:13px;color:#50575e">
                <?php esc_html_e('Enter the 6-digit code from your authenticator app, or a backup code.', 'free-2fa'); ?>
            </p>
            <?php endif; ?>
            <?php if ($error): ?>
                <div class="message error" style="border-left:4px solid #d63638;padding:8px 12px;margin:10px 0;background:#fcf0f1">
                    <?php esc_html_e('Invalid code. Try again.', 'free-2fa'); ?>
                </div>
            <?php endif; ?>
            <?php if ($sent): ?>
                <div class="message" style="border-left:4px solid #72aee6;padding:8px 12px;margin:10px 0;background:#f0f6fc">
                    <?php esc_html_e('If email codes are enabled for your account, a code is on its way. It works once and expires in 10 minutes.', 'free-2fa'); ?>
                </div>
            <?php endif; ?>
            <p>
                <label for="free2fa_code"><?php esc_html_e('Verification code', 'free-2fa'); ?></label>
                <input type="text" id="free2fa_code" name="free2fa_code"
                       inputmode="numeric" autocomplete="one-time-code"
                       autofocus required class="input" style="width:100%;font-size:22px;letter-spacing:4px;text-align:center"
                       maxlength="11">
            </p>
            <p style="margin-top:14px">
                <label>
                    <input type="checkbox" name="free2fa_trust" value="1">
                    <?php
                    $opts = get_option('free2fa_settings', []);
                    $days = (int)($opts['trust_days'] ?? 30);
                    printf(esc_html__('Trust this device for %d days', 'free-2fa'), $days);
                    ?>
                </label>
            </p>
            <p class="submit">
                <input type="submit" name="free2fa_submit" class="button button-primary button-large"
                       value="<?php esc_attr_e('Verify', 'free-2fa'); ?>" style="width:100%">
            </p>
            <?php if ($email_ok): ?>
            <p style="margin-top:10px;text-align:center">
                <button type="submit" name="free2fa_send_email" value="1" class="button-link" formnovalidate
                        style="background:none;border:none;color:#2271b1;cursor:pointer;text-decoration:underline;font-size:13px">
                    <?php esc_html_e('Email me a code instead', 'free-2fa'); ?>
                </button>
            </p>
            <?php endif; ?>
        </form>
        <p id="backtoblog"><a href="<?php echo esc_url(wp_login_url()); ?>"><?php esc_html_e('← Back to log in', 'free-2fa'); ?></a></p>
        <?php
        login_footer('free2fa_code');
        exit;
    }

    public function on_password_reset($user, $new_pass): void {
        if ($user instanceof \WP_User) {
            TrustedDevice::revoke_all($user->ID);
        }
    }

    /* helpers */

    public static function user_has_2fa(int $user_id): bool {
        return (bool) get_user_meta($user_id, 'free2fa_enabled', true);
    }

    public function is_required_for(\WP_User $user): bool {
        $opts = get_option('free2fa_settings', []);
        $mode = $opts['enforcement'] ?? 'admins';
        // IP allowlist bypass
        $allow = trim((string)($opts['ip_allowlist'] ?? ''));
        if ($allow !== '') {
            $ip = TrustedDevice::client_ip();
            foreach (preg_split('/[\s,]+/', $allow) as $cidr) {
                if ($cidr === '') continue;
                if (self::ip_in_cidr($ip, $cidr)) return false;
            }
        }
        if ($mode === 'none') return false;
        if ($mode === 'all')  return true;
        if ($mode === 'admins') {
            return user_can($user, 'manage_options');
        }
        if ($mode === 'admins_editors') {
            return user_can($user, 'edit_others_posts');
        }
        return false;
    }

    public static function issue_interim_token(int $user_id, string $redirect_to, bool $rememberme = false): string {
        $token = bin2hex(random_bytes(24));
        set_transient('free2fa_int_' . md5($token), [
            'uid'         => $user_id,
            'redirect_to' => $redirect_to,
            'rememberme'  => $rememberme,
        ], 10 * MINUTE_IN_SECONDS);
        return $token;
    }

    /** Returns ['uid' => int, 'redirect_to' => string, 'rememberme' => bool] or null. Does not delete the transient. */
    public static function peek_interim_token(string $token): ?array {
        $data = get_transient('free2fa_int_' . md5($token));
        return is_array($data) && !empty($data['uid']) ? $data : null;
    }

    /** Returns the same shape as peek_interim_token and deletes the transient. */
    public static function consume_interim_token(string $token): ?array {
        $data = self::peek_interim_token($token);
        if ($data) delete_transient('free2fa_int_' . md5($token));
        return $data;
    }

    /** True when the user's stored TOTP secret exists but cannot be decrypted
     *  (salts rotated without FREE2FA_ENCRYPTION_KEY, corruption, ...). */
    public static function secret_unreadable(int $user_id): bool {
        $enc = get_user_meta($user_id, 'free2fa_totp_secret', true);
        return $enc && Crypto::decrypt((string)$enc) === null;
    }

    public static function verify_any_factor(int $user_id, string $code): bool {
        $secret_enc = get_user_meta($user_id, 'free2fa_totp_secret', true);
        if ($secret_enc) {
            $secret = Crypto::decrypt((string)$secret_enc);
            if (!$secret) {
                // Encrypted secret can't be unwrapped (salts rotated, corruption, etc).
                // Fall through to backup codes; flag the account so a successful
                // backup-code login triggers forced re-enrollment (see maybe_handle_challenge).
                update_user_meta($user_id, 'free2fa_needs_resetup', 1);
                do_action('free2fa_totp_decrypt_failed', $user_id);
            }
            if ($secret) {
                if (Crypto::needs_rekey()) {
                    // Payload was readable only via the legacy salt key — migrate it
                    // to the current FREE2FA_ENCRYPTION_KEY transparently.
                    try {
                        update_user_meta($user_id, 'free2fa_totp_secret', Crypto::encrypt($secret));
                    } catch (\RuntimeException $e) { /* keep old payload, still readable */ }
                }
                $win = TOTP::verify($secret, $code, 1);
                if ($win >= 0) {
                    // Monotonic counter: only accept windows strictly greater than the last
                    // successful one. Prevents replay (same code reused) and replay-across-window
                    // (tolerance lets one code match in two adjacent windows). Lets fresh future
                    // codes through, so a user logging in repeatedly never gets falsely rejected.
                    $last_key = 'free2fa_last_win_' . $user_id;
                    $last = (int) get_user_meta($user_id, $last_key, true);
                    if ($win <= $last) return false;
                    update_user_meta($user_id, $last_key, $win);
                    return true;
                }
            }
        }
        // Backup code
        if (BackupCodes::consume($user_id, $code)) return true;
        // Email fallback OTP (only when site + user both opted in)
        return Email::verify($user_id, $code);
    }

    /** Supports both IPv4 and IPv6 CIDR notation. */
    public static function ip_in_cidr(string $ip, string $cidr): bool {
        if (strpos($cidr, '/') === false) {
            return hash_equals($ip, $cidr);
        }
        [$subnet, $bits] = explode('/', $cidr);
        $bits = (int)$bits;
        // inet_pton emits a warning on malformed input; we treat any parse failure as "not in CIDR".
        $ip_bin = @inet_pton($ip);
        $sn_bin = @inet_pton($subnet);
        if ($ip_bin === false || $sn_bin === false) return false;
        if (strlen($ip_bin) !== strlen($sn_bin)) return false; // version mismatch
        $bytes = intdiv($bits, 8);
        $remainder = $bits % 8;
        if ($bytes > 0 && substr($ip_bin, 0, $bytes) !== substr($sn_bin, 0, $bytes)) return false;
        if ($remainder === 0) return true;
        $mask = chr(0xFF << (8 - $remainder) & 0xFF);
        return (ord($ip_bin[$bytes]) & ord($mask)) === (ord($sn_bin[$bytes]) & ord($mask));
    }
}
