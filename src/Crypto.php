<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

/**
 * Encrypt-at-rest helper. AES-256-GCM.
 *
 * Key source (in order):
 *   1. FREE2FA_ENCRYPTION_KEY constant (wp-config.php) — recommended. Survives
 *      WP salt rotation, so incident-response salt changes don't break 2FA.
 *   2. SECURE_AUTH_KEY + SECURE_AUTH_SALT — default, zero-config.
 *
 * Migration: payloads encrypted under the salt-derived key remain readable after
 * the admin defines FREE2FA_ENCRYPTION_KEY — decrypt() falls back to the legacy
 * key and flags the payload for re-encryption (see needs_rekey()).
 */
class Crypto {

    /** Set by decrypt(): true when the payload was unwrapped with a legacy key
     *  and should be re-encrypted under the current primary key. */
    private static $needs_rekey = false;

    private static function derive(string $material): string {
        return hash('sha256', $material . 'free2fa-totp-v1', true);
    }

    /** Primary key. */
    private static function key(): string {
        if (defined('FREE2FA_ENCRYPTION_KEY') && is_string(FREE2FA_ENCRYPTION_KEY) && FREE2FA_ENCRYPTION_KEY !== '') {
            return self::derive(FREE2FA_ENCRYPTION_KEY);
        }
        return self::salt_key();
    }

    /** Legacy/default key derived from WP salts (byte-identical to pre-1.1 key()). */
    private static function salt_key(): string {
        $material = (defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : 'free2fa-fallback-key')
                  . (defined('SECURE_AUTH_SALT') ? SECURE_AUTH_SALT : 'free2fa-fallback-salt');
        return self::derive($material);
    }

    public static function encrypt(string $plaintext): string {
        $iv = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($plaintext, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag);
        if ($ct === false) {
            throw new \RuntimeException('Free2FA: openssl_encrypt failed');
        }
        return 'v1:' . base64_encode($iv . $tag . $ct);
    }

    public static function decrypt(string $payload): ?string {
        self::$needs_rekey = false;
        if (strpos($payload, 'v1:') !== 0) return null;
        $raw = base64_decode(substr($payload, 3), true);
        if ($raw === false || strlen($raw) < 28) return null;
        $iv  = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ct  = substr($raw, 28);

        $pt = openssl_decrypt($ct, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag);
        if ($pt !== false) return $pt;

        // Fallback: payload may predate FREE2FA_ENCRYPTION_KEY — try the salt key.
        if (defined('FREE2FA_ENCRYPTION_KEY') && FREE2FA_ENCRYPTION_KEY !== '') {
            $pt = openssl_decrypt($ct, 'aes-256-gcm', self::salt_key(), OPENSSL_RAW_DATA, $iv, $tag);
            if ($pt !== false) {
                self::$needs_rekey = true;
                return $pt;
            }
        }
        return null;
    }

    /** Whether the last successful decrypt() used a legacy key — caller should
     *  re-encrypt the plaintext and store the fresh payload. */
    public static function needs_rekey(): bool {
        return self::$needs_rekey;
    }
}
