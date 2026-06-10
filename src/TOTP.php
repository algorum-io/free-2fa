<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

/**
 * TOTP implementation per RFC 6238 / RFC 4226 (HOTP base).
 * SHA-1, 30 second window, 6 digit codes.
 * Compatible with standard TOTP authenticator apps.
 */
class TOTP {
    public const DIGITS = 6;
    public const PERIOD = 30;
    public const ALGO   = 'sha1';

    /** Generate 20 random bytes for new TOTP secret. */
    public static function generate_secret(): string {
        return self::base32_encode(random_bytes(20));
    }

    /** Verify code with ±1 window tolerance. Returns timestamp window used on match, -1 on fail. */
    public static function verify(string $secret, string $code, int $tolerance = 1, ?int $time = null): int {
        $code = preg_replace('/\D/', '', $code);
        if (strlen($code) !== self::DIGITS) return -1;
        $time = $time ?? time();
        $current = intdiv($time, self::PERIOD);
        for ($i = -$tolerance; $i <= $tolerance; $i++) {
            $expected = self::at($secret, $current + $i);
            if (hash_equals($expected, $code)) return $current + $i;
        }
        return -1;
    }

    /** Generate code at given counter (window). */
    public static function at(string $secret, int $counter): string {
        $key = self::base32_decode($secret);
        $bin = pack('N*', 0) . pack('N*', $counter);
        $hmac = hash_hmac(self::ALGO, $bin, $key, true);
        $offset = ord($hmac[strlen($hmac) - 1]) & 0x0F;
        $part = substr($hmac, $offset, 4);
        $value = unpack('N', $part)[1] & 0x7FFFFFFF;
        $code = $value % (10 ** self::DIGITS);
        return str_pad((string)$code, self::DIGITS, '0', STR_PAD_LEFT);
    }

    /** Build otpauth:// URI for QR code. */
    public static function uri(string $secret, string $account, string $issuer): string {
        $account = rawurlencode($account);
        $issuer  = rawurlencode($issuer);
        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
            $issuer, $account, $secret, $issuer, self::DIGITS, self::PERIOD
        );
    }

    public static function base32_encode(string $bin): string {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $out = '';
        $buffer = 0;
        $bits = 0;
        for ($i = 0; $i < strlen($bin); $i++) {
            $buffer = ($buffer << 8) | ord($bin[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= $alphabet[($buffer >> $bits) & 0x1F];
            }
        }
        if ($bits > 0) {
            $out .= $alphabet[($buffer << (5 - $bits)) & 0x1F];
        }
        return $out;
    }

    public static function base32_decode(string $b32): string {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $b32 = strtoupper(preg_replace('/[^A-Z2-7]/', '', $b32));
        $out = '';
        $buffer = 0;
        $bits = 0;
        for ($i = 0; $i < strlen($b32); $i++) {
            $pos = strpos($alphabet, $b32[$i]);
            if ($pos === false) continue;
            $buffer = ($buffer << 5) | $pos;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($buffer >> $bits) & 0xFF);
            }
        }
        return $out;
    }
}
