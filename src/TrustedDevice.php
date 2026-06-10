<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

class TrustedDevice {
    public const COOKIE = 'free2fa_trusted';
    public const DEFAULT_DAYS = 30;

    /** Issue a fresh trusted-device cookie + register in user meta. */
    public static function issue(int $user_id, int $days = self::DEFAULT_DAYS): void {
        $device_id = bin2hex(random_bytes(16));
        $expiry = time() + ($days * DAY_IN_SECONDS);
        $sig = self::sign($user_id, $device_id, $expiry);
        $value = base64_encode($user_id . '|' . $device_id . '|' . $expiry . '|' . $sig);

        // Add to user's trusted devices list
        $list = get_user_meta($user_id, 'free2fa_trusted_devices', true) ?: [];
        if (!is_array($list)) $list = [];
        $list[$device_id] = [
            'created'    => time(),
            'expiry'     => $expiry,
            'last_used'  => time(),
            'ua'         => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200),
            'ip'         => self::client_ip(),
        ];
        // Prune expired
        foreach ($list as $did => $info) {
            if (!isset($info['expiry']) || $info['expiry'] < time()) unset($list[$did]);
        }
        update_user_meta($user_id, 'free2fa_trusted_devices', $list);

        $secure = is_ssl();
        setcookie(self::COOKIE, $value, [
            'expires'  => $expiry,
            'path'     => COOKIEPATH ?: '/',
            'domain'   => COOKIE_DOMAIN,
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        $_COOKIE[self::COOKIE] = $value;
    }

    /** Check whether current request carries a valid trusted-device cookie for this user. */
    public static function valid_for(int $user_id): bool {
        if (empty($_COOKIE[self::COOKIE])) return false;
        $raw = base64_decode($_COOKIE[self::COOKIE], true);
        if (!$raw) return false;
        $parts = explode('|', $raw);
        if (count($parts) !== 4) return false;
        [$uid, $device_id, $expiry, $sig] = $parts;
        if ((int)$uid !== $user_id) return false;
        if ((int)$expiry < time()) return false;
        $expected = self::sign((int)$uid, $device_id, (int)$expiry);
        if (!hash_equals($expected, $sig)) return false;

        $list = get_user_meta($user_id, 'free2fa_trusted_devices', true) ?: [];
        if (!isset($list[$device_id])) return false;
        if (($list[$device_id]['expiry'] ?? 0) < time()) return false;

        // Anomaly hook: trusted-device cookie validated from an IP that does not match
        // the IP we issued it from. Suspicious (cookie theft / replay across machines).
        // Site owners can subscribe to this action and ship a Telegram/email alert.
        $current_ip = self::client_ip();
        $issued_ip  = (string) ($list[$device_id]['ip'] ?? '');
        if ($issued_ip !== '' && $issued_ip !== $current_ip) {
            do_action('free2fa_trusted_device_ip_changed', $user_id, $device_id, $issued_ip, $current_ip);
        }

        $list[$device_id]['last_used'] = time();
        $list[$device_id]['last_ip']   = $current_ip;
        update_user_meta($user_id, 'free2fa_trusted_devices', $list);
        return true;
    }

    public static function revoke(int $user_id, string $device_id): void {
        $list = get_user_meta($user_id, 'free2fa_trusted_devices', true) ?: [];
        if (isset($list[$device_id])) unset($list[$device_id]);
        update_user_meta($user_id, 'free2fa_trusted_devices', $list);
    }

    public static function revoke_all(int $user_id): void {
        delete_user_meta($user_id, 'free2fa_trusted_devices');
    }

    public static function clear_cookie(): void {
        if (isset($_COOKIE[self::COOKIE])) {
            setcookie(self::COOKIE, '', [
                'expires'  => time() - 3600,
                'path'     => COOKIEPATH ?: '/',
                'domain'   => COOKIE_DOMAIN,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            unset($_COOKIE[self::COOKIE]);
        }
    }

    public static function list_for(int $user_id): array {
        $list = get_user_meta($user_id, 'free2fa_trusted_devices', true) ?: [];
        return is_array($list) ? $list : [];
    }

    private static function sign(int $user_id, string $device_id, int $expiry): string {
        $user = get_userdata($user_id);
        $pass_frag = $user ? substr($user->user_pass, 8, 12) : '';
        $key = (defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : '') .
               (defined('SECURE_AUTH_SALT') ? SECURE_AUTH_SALT : '');
        return hash_hmac('sha256', $user_id . '|' . $device_id . '|' . $expiry . '|' . $pass_frag, $key);
    }

    /**
     * Defaults to REMOTE_ADDR. Forwarded-IP headers are honoured ONLY when the
     * request comes from a trusted proxy IP configured in the plugin settings
     * (CIDR allowed). Without trusted proxies, attacker-controlled CF/XFF
     * headers cannot influence rate limiting or the IP allowlist.
     */
    public static function client_ip(): string {
        $remote = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!filter_var($remote, FILTER_VALIDATE_IP)) {
            return '0.0.0.0';
        }
        $opts = get_option('free2fa_settings', []);
        $trusted = trim((string)($opts['trusted_proxies'] ?? ''));
        if ($trusted === '') {
            return $remote;
        }
        $is_trusted = false;
        foreach (preg_split('/[\s,]+/', $trusted) as $cidr) {
            if ($cidr === '') continue;
            if (Login::ip_in_cidr($remote, $cidr)) { $is_trusted = true; break; }
        }
        if (!$is_trusted) return $remote;
        // Trusted proxy: prefer CF, fall back to XFF (first hop).
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR'] as $k) {
            if (!empty($_SERVER[$k])) {
                $ip = trim(explode(',', $_SERVER[$k])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
            }
        }
        return $remote;
    }
}
