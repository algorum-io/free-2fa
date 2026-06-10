<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

class Plugin {
    public function boot(): void {
        load_plugin_textdomain('free-2fa', false, dirname(plugin_basename(FREE2FA_FILE)) . '/languages');

        (new Login())->register();
        (new Setup())->register();
        (new Admin())->register();
        (new Settings())->register();
    }
}
