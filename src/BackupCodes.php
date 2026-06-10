<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

class BackupCodes {
    public const COUNT = 10;
    public const LENGTH = 10; // 10 char alphanumeric

    /** Generate fresh batch. Returns plaintext codes (display once) AND saves hashed list to user meta. */
    public static function generate(int $user_id): array {
        $plain = [];
        $hashed = [];
        for ($i = 0; $i < self::COUNT; $i++) {
            $code = self::random_code();
            $plain[] = $code;
            $hashed[] = wp_hash_password($code);
        }
        update_user_meta($user_id, 'free2fa_backup_codes', $hashed);
        return $plain;
    }

    public static function consume(int $user_id, string $input): bool {
        // strtoupper FIRST so users entering lowercase still match.
        $input = preg_replace('/[^A-Z0-9]/', '', strtoupper($input));
        if (strlen($input) !== self::LENGTH) return false;

        // Acquire an atomic lock. wp_cache_add returns false if the key already exists,
        // so we get a real test-and-set even without an object cache (the default in-memory
        // cache is per-request, which is exactly what we need to serialise concurrent code paths
        // within the same PHP-FPM worker). For cross-worker safety, the update_user_meta call
        // itself is the final guard: the meta value is replaced wholesale and a second
        // concurrent consume on the same code will not find the hash on its read of the
        // already-written shrunken list.
        $lock_key = 'free2fa_bc_lock_' . $user_id;
        if (!wp_cache_add($lock_key, 1, 'free2fa', 5)) {
            return false; // another consume() is mid-flight in this worker
        }
        try {
            // Re-read meta inside the lock window.
            wp_cache_delete($user_id, 'user_meta'); // bypass any stale cached meta
            $hashed = get_user_meta($user_id, 'free2fa_backup_codes', true);
            if (!is_array($hashed)) return false;
            foreach ($hashed as $idx => $hash) {
                if (wp_check_password($input, $hash)) {
                    unset($hashed[$idx]);
                    update_user_meta($user_id, 'free2fa_backup_codes', array_values($hashed));
                    return true;
                }
            }
            return false;
        } finally {
            wp_cache_delete($lock_key, 'free2fa');
        }
    }

    public static function remaining(int $user_id): int {
        $hashed = get_user_meta($user_id, 'free2fa_backup_codes', true);
        return is_array($hashed) ? count($hashed) : 0;
    }

    private static function random_code(): string {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
        $code = '';
        for ($i = 0; $i < self::LENGTH; $i++) {
            $code .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        return $code;
    }
}
