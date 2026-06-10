<?php
if (!defined('WP_UNINSTALL_PLUGIN')) exit;

global $wpdb;

// Remove option
delete_option('free2fa_settings');
if (is_multisite()) {
    foreach (get_sites(['fields' => 'ids']) as $blog_id) {
        switch_to_blog($blog_id);
        delete_option('free2fa_settings');
        restore_current_blog();
    }
    delete_site_option('free2fa_settings');
}

// Remove user meta
$meta_keys = [
    'free2fa_enabled', 'free2fa_totp_secret', 'free2fa_backup_codes',
    'free2fa_trusted_devices', 'free2fa_needs_resetup',
    'free2fa_pending_confirm', 'free2fa_email_fallback',
];
foreach ($meta_keys as $key) {
    $wpdb->delete($wpdb->usermeta, ['meta_key' => $key]);
}
// Per-user monotonic counters (dynamic key names)
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'free2fa\\_last\\_win\\_%'");
