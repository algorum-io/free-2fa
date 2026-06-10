<?php
/**
 * Plugin Name: Free 2FA
 * Plugin URI: https://github.com/algorum/free-2fa
 * Description: Free two-factor authentication with trusted devices. Works with any TOTP authenticator app (Authy, 1Password, Microsoft Authenticator, and others). No paywall, no upsell.
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Aytun Çelebi
 * Author URI: https://github.com/algorum
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: free-2fa
 * Domain Path: /languages
 * Network: true
 */

if (!defined('ABSPATH')) {
    exit;
}

define('FREE2FA_VERSION', '1.0.0');
define('FREE2FA_FILE', __FILE__);
define('FREE2FA_DIR', plugin_dir_path(__FILE__));
define('FREE2FA_URL', plugin_dir_url(__FILE__));

// PSR-4 autoloader
spl_autoload_register(function ($class) {
    $prefix = 'Free2FA\\';
    $base_dir = FREE2FA_DIR . 'src/';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    $relative_class = substr($class, $len);
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});

register_activation_hook(__FILE__, ['Free2FA\\Activator', 'activate']);
register_deactivation_hook(__FILE__, ['Free2FA\\Activator', 'deactivate']);

add_action('plugins_loaded', function () {
    (new Free2FA\Plugin())->boot();
});
