<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

class Activator {
    public static function activate(): void {
        $defaults = [
            'enforcement'   => 'admins',      // all|admins|admins_editors|none
            'trust_days'    => 30,
            'grace_days'    => 7,
            'ip_allowlist'  => '',
            'lockout_fails' => 5,
            'lockout_minutes' => 15,
        ];
        if (get_option('free2fa_settings', false) === false) {
            update_option('free2fa_settings', $defaults);
        }
    }
    public static function deactivate(): void {
        // No destructive action on deactivate. Uninstall.php handles full cleanup.
    }
}
