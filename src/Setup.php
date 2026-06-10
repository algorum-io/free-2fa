<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

class Setup {
    public function register(): void {
        add_action('admin_post_free2fa_setup_save', [$this, 'handle_save']);
        add_action('admin_post_free2fa_confirm_codes', [$this, 'handle_confirm_codes']);
        add_action('admin_post_free2fa_disable',    [$this, 'handle_disable']);
        add_action('admin_post_free2fa_regen_backup', [$this, 'handle_regen_backup']);
        add_action('admin_post_free2fa_revoke_device', [$this, 'handle_revoke_device']);
        add_action('admin_post_free2fa_revoke_all',    [$this, 'handle_revoke_all']);
        add_action('admin_post_free2fa_admin_reset',   [$this, 'handle_admin_reset']);
        add_action('admin_post_free2fa_email_toggle',  [$this, 'handle_email_toggle']);
    }

    /** Wipe a user's entire 2FA enrollment. Shared by admin reset and the
     *  decrypt-failure recovery flow (Login). */
    public static function reset_enrollment(int $user_id): void {
        delete_user_meta($user_id, 'free2fa_totp_secret');
        delete_user_meta($user_id, 'free2fa_enabled');
        delete_user_meta($user_id, 'free2fa_backup_codes');
        delete_user_meta($user_id, 'free2fa_last_win_' . $user_id);
        delete_user_meta($user_id, 'free2fa_needs_resetup');
        delete_user_meta($user_id, 'free2fa_pending_confirm');
        delete_user_meta($user_id, 'free2fa_email_fallback');
        TrustedDevice::revoke_all($user_id);
    }

    /** Administrator-side reset: wipe 2FA for ANOTHER user (recovery after lost device). */
    public function handle_admin_reset(): void {
        if (!current_user_can('manage_options')) wp_die(__('Permission denied.', 'free-2fa'));
        check_admin_referer('free2fa_admin_reset');
        $target_id = (int) ($_POST['user_id'] ?? 0);
        if ($target_id <= 0) wp_die(__('Invalid user.', 'free-2fa'));
        self::reset_enrollment($target_id);
        wp_safe_redirect(add_query_arg('free2fa_reset', '1', admin_url('user-edit.php?user_id=' . $target_id)));
        exit;
    }

    public function handle_save(): void {
        if (!is_user_logged_in()) wp_die(__('Login required.', 'free-2fa'));
        check_admin_referer('free2fa_setup');
        $user_id = get_current_user_id();
        $code   = sanitize_text_field($_POST['code'] ?? '');
        if (!$code) wp_die(__('Missing fields.', 'free-2fa'));

        // Secret is held server-side, encrypted, for the duration of the setup session.
        $stored = get_transient('free2fa_setup_' . $user_id);
        $secret_b32 = $stored ? Crypto::decrypt((string)$stored) : null;
        if (!$secret_b32) {
            wp_safe_redirect(add_query_arg('free2fa_setup_expired', '1', self::profile_url($user_id)));
            exit;
        }
        if (TOTP::verify($secret_b32, $code, 1) < 0) {
            wp_safe_redirect(add_query_arg('free2fa_setup_error', '1', self::profile_url($user_id)));
            exit;
        }
        try {
            $encrypted = Crypto::encrypt($secret_b32);
        } catch (\RuntimeException $e) {
            wp_safe_redirect(add_query_arg('free2fa_crypto_error', '1', self::profile_url($user_id)));
            exit;
        }
        update_user_meta($user_id, 'free2fa_totp_secret', $encrypted);
        delete_transient('free2fa_setup_' . $user_id);
        $codes = BackupCodes::generate($user_id);
        // The plaintext codes are shown once on the next page load; encrypt at rest in transit.
        set_transient('free2fa_codes_' . $user_id, Crypto::encrypt(wp_json_encode($codes)), 5 * MINUTE_IN_SECONDS);
        // 2FA does NOT activate yet: the user must confirm they saved their backup
        // codes first (handle_confirm_codes). Without saved codes, a lost phone
        // would mean a hard lockout — so saving them is part of enabling.
        // Re-enrolling users (already enabled) keep their active state.
        if (!Login::user_has_2fa($user_id)) {
            update_user_meta($user_id, 'free2fa_pending_confirm', 1);
        }
        delete_user_meta($user_id, 'free2fa_needs_resetup');
        wp_safe_redirect(add_query_arg('free2fa_show_codes', '1', self::profile_url($user_id)));
        exit;
    }

    /** Final activation step: the user confirms the backup codes are saved. */
    public function handle_confirm_codes(): void {
        if (!is_user_logged_in()) wp_die(__('Login required.', 'free-2fa'));
        check_admin_referer('free2fa_confirm_codes');
        $user_id = get_current_user_id();
        if (!get_user_meta($user_id, 'free2fa_pending_confirm', true)) {
            wp_safe_redirect(self::profile_url($user_id));
            exit;
        }
        if (empty($_POST['codes_saved'])) {
            // Checkbox not ticked — bounce back (codes transient may still be alive).
            wp_safe_redirect(add_query_arg(['free2fa_show_codes' => '1', 'free2fa_confirm_error' => '1'], self::profile_url($user_id)));
            exit;
        }
        update_user_meta($user_id, 'free2fa_enabled', 1);
        delete_user_meta($user_id, 'free2fa_pending_confirm');
        wp_safe_redirect(add_query_arg('free2fa_enabled_ok', '1', self::profile_url($user_id)));
        exit;
    }

    /** Per-user opt-in toggle for email fallback codes. */
    public function handle_email_toggle(): void {
        if (!is_user_logged_in()) wp_die(__('Login required.', 'free-2fa'));
        check_admin_referer('free2fa_email_toggle');
        $user_id = get_current_user_id();
        if (!Login::user_has_2fa($user_id)) wp_die(__('2FA not enabled.', 'free-2fa'));
        if (!empty($_POST['email_fallback'])) {
            update_user_meta($user_id, 'free2fa_email_fallback', 1);
        } else {
            delete_user_meta($user_id, 'free2fa_email_fallback');
        }
        wp_safe_redirect(self::profile_url($user_id));
        exit;
    }

    public function handle_disable(): void {
        if (!is_user_logged_in()) wp_die(__('Login required.', 'free-2fa'));
        check_admin_referer('free2fa_disable');
        $user_id = get_current_user_id();
        // Require current password
        $current = wp_check_password($_POST['current_password'] ?? '', wp_get_current_user()->user_pass, $user_id);
        if (!$current) {
            wp_safe_redirect(add_query_arg('free2fa_pw_error', '1', self::profile_url($user_id)));
            exit;
        }
        self::reset_enrollment($user_id);
        wp_safe_redirect(self::profile_url($user_id));
        exit;
    }

    public function handle_regen_backup(): void {
        if (!is_user_logged_in()) wp_die(__('Login required.', 'free-2fa'));
        check_admin_referer('free2fa_regen_backup');
        $user_id = get_current_user_id();
        if (!Login::user_has_2fa($user_id)) wp_die(__('2FA not enabled.', 'free-2fa'));
        $codes = BackupCodes::generate($user_id);
        set_transient('free2fa_codes_' . $user_id, Crypto::encrypt(wp_json_encode($codes)), 5 * MINUTE_IN_SECONDS);
        wp_safe_redirect(add_query_arg('free2fa_show_codes', '1', self::profile_url($user_id)));
        exit;
    }

    public function handle_revoke_device(): void {
        if (!is_user_logged_in()) wp_die(__('Login required.', 'free-2fa'));
        check_admin_referer('free2fa_revoke_device');
        $user_id = get_current_user_id();
        $device = sanitize_text_field($_POST['device_id'] ?? '');
        if ($device) TrustedDevice::revoke($user_id, $device);
        wp_safe_redirect(self::profile_url($user_id));
        exit;
    }

    public function handle_revoke_all(): void {
        if (!is_user_logged_in()) wp_die(__('Login required.', 'free-2fa'));
        check_admin_referer('free2fa_revoke_all');
        $user_id = get_current_user_id();
        TrustedDevice::revoke_all($user_id);
        wp_safe_redirect(self::profile_url($user_id));
        exit;
    }

    public static function profile_url(int $user_id): string {
        // Post-action landing: the standalone setup page — it is the only screen
        // that renders the free2fa_* notices, the one-time backup-codes box and
        // the codes-saved confirm form. (profile.php only shows a status summary.)
        return admin_url('users.php?page=free-2fa-setup');
    }
}
