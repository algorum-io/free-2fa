<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

/**
 * Lockout is triggered only when BOTH the user-bucket AND the current-IP-bucket are over the threshold.
 * This prevents an attacker on one IP from DoS-locking a legit user; the legit user from a different IP
 * still gets through. Cleared on successful 2FA.
 */
class Rate {
    private static function user_key(int $user_id): string {
        return 'free2fa_fail_u_' . $user_id;
    }
    private static function ip_key(): string {
        return 'free2fa_fail_ip_' . md5(TrustedDevice::client_ip());
    }

    public static function record_fail(int $user_id): void {
        self::bump(self::user_key($user_id));
        self::bump(self::ip_key());
    }

    public static function is_locked(int $user_id): bool {
        return self::bucket_locked(self::user_key($user_id))
            && self::bucket_locked(self::ip_key());
    }

    /**
     * On a successful 2FA, only clear the per-user counter.
     * Leave the per-IP counter alone — NAT'd attackers behind the same IP
     * as the legit user must not be cleared by the legit user's success.
     */
    public static function clear(int $user_id): void {
        delete_transient(self::user_key($user_id));
    }

    private static function bump(string $key): void {
        $opts = get_option('free2fa_settings', []);
        $max  = (int)($opts['lockout_fails']   ?? 5);
        $mins = (int)($opts['lockout_minutes'] ?? 15);
        $state = get_transient($key);
        if (!is_array($state)) $state = ['count' => 0, 'first' => time()];
        $state['count']++;
        if ($state['count'] >= $max) {
            $state['locked_until'] = time() + $mins * 60;
        }
        set_transient($key, $state, $mins * 60);
    }

    private static function bucket_locked(string $key): bool {
        $state = get_transient($key);
        return is_array($state) && !empty($state['locked_until']) && $state['locked_until'] > time();
    }
}
