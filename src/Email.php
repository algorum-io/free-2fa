<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

/**
 * Optional email fallback codes.
 *
 * Strictly opt-in twice: the site admin must allow it (Settings) AND the user
 * must turn it on for their own account. Email is a weaker channel than TOTP —
 * anyone who controls the mailbox controls the second factor — so it is never
 * on by default and never a silent recovery path.
 *
 * Codes: 6 digits, single use, 10 minute lifetime, stored hashed. Sending is
 * rate-limited (one email per 2 minutes) and verification allows at most 5
 * attempts per issued code.
 */
class Email {
    private const TTL         = 10 * MINUTE_IN_SECONDS;
    private const RESEND_WAIT = 2 * MINUTE_IN_SECONDS;
    private const MAX_TRIES   = 5;

    /** Both switches must be on: site-level allow + per-user opt-in. */
    public static function enabled_for(int $user_id): bool {
        $opts = get_option('free2fa_settings', []);
        if (empty($opts['email_fallback'])) return false;
        return (bool) get_user_meta($user_id, 'free2fa_email_fallback', true);
    }

    /**
     * Issue and send a fresh code. Returns true on send, false when rate-limited
     * or the user is invalid. Never discloses which to the login screen.
     */
    public static function send(int $user_id): bool {
        if (!self::enabled_for($user_id)) return false;
        $user = get_userdata($user_id);
        if (!$user || !is_email($user->user_email)) return false;

        if (get_transient('free2fa_email_rl_' . $user_id)) return false;
        set_transient('free2fa_email_rl_' . $user_id, 1, self::RESEND_WAIT);

        $code = (string) random_int(100000, 999999);
        set_transient('free2fa_email_otp_' . $user_id, [
            'hash'  => wp_hash_password($code),
            'tries' => 0,
        ], self::TTL);

        $blog = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $subject = sprintf(__('[%s] Your login code', 'free-2fa'), $blog);
        $body = sprintf(
            /* translators: 1: site name, 2: 6-digit code, 3: validity minutes */
            __("Your %1\$s login code is:\n\n    %2\$s\n\nIt is valid for %3\$d minutes and can be used once.\n\nIf you did not try to log in, someone knows your password — change it now.", 'free-2fa'),
            $blog,
            $code,
            self::TTL / MINUTE_IN_SECONDS
        );
        return (bool) wp_mail($user->user_email, $subject, $body);
    }

    /** Verify a code. Single use; at most MAX_TRIES attempts per issued code. */
    public static function verify(int $user_id, string $input): bool {
        if (!self::enabled_for($user_id)) return false;
        $input = preg_replace('/\D/', '', $input);
        if (strlen($input) !== 6) return false;

        $key = 'free2fa_email_otp_' . $user_id;
        $otp = get_transient($key);
        if (!is_array($otp) || empty($otp['hash'])) return false;

        $otp['tries'] = (int)($otp['tries'] ?? 0) + 1;
        if ($otp['tries'] > self::MAX_TRIES) {
            delete_transient($key);
            return false;
        }

        if (wp_check_password($input, $otp['hash'])) {
            delete_transient($key);
            return true;
        }
        set_transient($key, $otp, self::TTL);
        return false;
    }
}
