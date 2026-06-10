<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

class Admin {
    public function register(): void {
        add_action('show_user_profile', [$this, 'render_profile_section']);
        add_action('edit_user_profile', [$this, 'render_profile_section']);
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue']);
    }

    public function menu(): void {
        // Hidden submenu (no parent slug) — accessible via direct URL only.
        add_users_page(
            __('Two-Factor Setup', 'free-2fa'),
            __('Two-Factor Setup', 'free-2fa'),
            'read',
            'free-2fa-setup',
            [$this, 'render_setup_page']
        );
    }

    public function enqueue($hook): void {
        if (!in_array($hook, ['profile.php', 'user-edit.php', 'users_page_free-2fa-setup'], true)) return;
        wp_register_script('free2fa-qrcode', FREE2FA_URL . 'assets/js/qrcode.min.js', [], FREE2FA_VERSION, true);
        wp_register_script('free2fa-setup', FREE2FA_URL . 'assets/js/setup.js', ['free2fa-qrcode'], FREE2FA_VERSION, true);
        wp_enqueue_script('free2fa-setup');
        wp_enqueue_style('free2fa-admin', FREE2FA_URL . 'assets/css/admin.css', [], FREE2FA_VERSION);
    }

    /** Brief status section inside the WP user profile page. Links out to the setup page (which has its own form). */
    public function render_profile_section(\WP_User $user): void {
        $user_id = $user->ID;
        $is_self = ($user_id === get_current_user_id());
        if (!$is_self && !current_user_can('manage_options')) return;

        $enabled = Login::user_has_2fa($user_id);
        $setup_url = admin_url('users.php?page=free-2fa-setup');
        $reset_just_done = !empty($_GET['free2fa_reset']);
        ?>
        <h2 id="free2fa"><?php esc_html_e('Two-Factor Authentication', 'free-2fa'); ?></h2>
        <?php if ($reset_just_done): ?>
            <div class="notice notice-success inline"><p><?php esc_html_e('2FA has been reset for this user. They will be prompted to enrol again on next login.', 'free-2fa'); ?></p></div>
        <?php endif; ?>
        <table class="form-table" role="presentation"><tbody>
        <tr>
            <th><?php esc_html_e('Status', 'free-2fa'); ?></th>
            <td>
                <?php if ($enabled): ?>
                    <span style="color:#00a32a;font-weight:600">●</span>
                    <?php esc_html_e('Active', 'free-2fa'); ?>
                    &mdash;
                    <?php printf(esc_html__('%d backup codes remaining', 'free-2fa'), BackupCodes::remaining($user_id)); ?>
                    <?php if ($is_self): ?>
                        &nbsp;&nbsp;<a class="button" href="<?php echo esc_url($setup_url); ?>"><?php esc_html_e('Manage', 'free-2fa'); ?></a>
                    <?php endif; ?>
                <?php else: ?>
                    <span style="color:#d63638;font-weight:600">●</span>
                    <?php esc_html_e('Inactive', 'free-2fa'); ?>
                    <?php if ($is_self): ?>
                        &nbsp;&nbsp;<a class="button button-primary" href="<?php echo esc_url($setup_url); ?>"><?php esc_html_e('Set up now', 'free-2fa'); ?></a>
                    <?php endif; ?>
                <?php endif; ?>
            </td>
        </tr>
        <?php if (!$is_self && current_user_can('manage_options') && $enabled): ?>
        <tr>
            <th><?php esc_html_e('Recovery', 'free-2fa'); ?></th>
            <td>
                <p style="margin-top:0"><?php esc_html_e('If this user has lost access to their authenticator and backup codes, reset their 2FA to let them enrol a new device.', 'free-2fa'); ?></p>
                <button type="button" class="button button-link-delete" onclick="document.getElementById('free2fa-reset-modal-<?php echo (int)$user_id; ?>').style.display='block'">
                    <?php esc_html_e('Reset 2FA for this user', 'free-2fa'); ?>
                </button>
                <div id="free2fa-reset-modal-<?php echo (int)$user_id; ?>" style="display:none;margin-top:10px;border:1px solid #c3c4c7;background:#fffbe5;padding:12px;max-width:520px">
                    <p style="margin-top:0"><?php esc_html_e('This will remove the TOTP secret, all backup codes, and all trusted devices for this user. They will be required to enrol again. Are you sure?', 'free-2fa'); ?></p>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <?php wp_nonce_field('free2fa_admin_reset'); ?>
                        <input type="hidden" name="action" value="free2fa_admin_reset">
                        <input type="hidden" name="user_id" value="<?php echo (int)$user_id; ?>">
                        <button class="button button-link-delete"><?php esc_html_e('Yes, reset 2FA', 'free-2fa'); ?></button>
                    </form>
                </div>
            </td>
        </tr>
        <?php endif; ?>
        </tbody></table>
        <?php
    }

    /** Dedicated standalone setup page. Forms here are NOT nested in any other form. */
    public function render_setup_page(): void {
        if (!is_user_logged_in()) {
            wp_die(__('Login required.', 'free-2fa'));
        }
        $user = wp_get_current_user();
        $user_id = $user->ID;
        $enabled = Login::user_has_2fa($user_id);
        // Activation is held until the user confirms their backup codes are saved.
        $pending_confirm = (bool) get_user_meta($user_id, 'free2fa_pending_confirm', true);
        // Show backup codes exactly once: only on the immediate post-generate redirect.
        $just_codes = null;
        if (!empty($_GET['free2fa_show_codes'])) {
            $stored = get_transient('free2fa_codes_' . $user_id);
            if ($stored) {
                $decoded = Crypto::decrypt((string)$stored);
                if ($decoded) $just_codes = json_decode($decoded, true);
                // Pending users may bounce back here on confirm_error — keep the
                // transient alive until they confirm, so codes stay visible.
                if (!$pending_confirm) delete_transient('free2fa_codes_' . $user_id);
            }
        }
        ?>
        <div class="wrap" style="max-width:760px">
            <h1><?php esc_html_e('Two-Factor Authentication', 'free-2fa'); ?></h1>

            <?php if ($just_codes && is_array($just_codes)): ?>
                <div class="free2fa-codes-box" style="border:2px solid #00a32a;background:#f0fdf4;padding:18px;margin:18px 0">
                    <p style="font-weight:600;margin-top:0;font-size:15px"><?php esc_html_e('Your backup codes — save them now', 'free-2fa'); ?></p>
                    <p style="font-size:12px;color:#50575e">
                        <?php esc_html_e('Each code works once. Use them if you lose your authenticator device. We cannot show them again.', 'free-2fa'); ?>
                    </p>
                    <pre style="font-family:Menlo,Consolas,monospace;background:#fff;padding:12px;border:1px solid #c3c4c7;font-size:15px;letter-spacing:2px"><?php
                        foreach ($just_codes as $c) echo esc_html(chunk_split($c, 5, ' ')) . "\n";
                    ?></pre>
                    <p>
                        <button type="button" class="button" onclick="free2faDownloadCodes()">
                            <?php esc_html_e('Download as .txt', 'free-2fa'); ?>
                        </button>
                        <button type="button" class="button" onclick="window.print()">
                            <?php esc_html_e('Print', 'free-2fa'); ?>
                        </button>
                    </p>
                    <?php if ($pending_confirm): ?>
                    <?php // Activation gate: 2FA turns on only after this confirm (Setup::handle_confirm_codes). ?>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"
                          style="margin-bottom:0;padding-top:10px;border-top:1px solid #c3c4c7">
                        <?php wp_nonce_field('free2fa_confirm_codes'); ?>
                        <input type="hidden" name="action" value="free2fa_confirm_codes">
                        <?php if (!empty($_GET['free2fa_confirm_error'])): ?>
                            <p style="color:#d63638;font-weight:600"><?php esc_html_e('Please confirm you saved the codes before continuing.', 'free-2fa'); ?></p>
                        <?php endif; ?>
                        <label>
                            <input type="checkbox" id="free2fa-codes-saved" name="codes_saved" value="1">
                            <strong><?php esc_html_e('I have saved these backup codes in a safe place', 'free-2fa'); ?></strong>
                        </label>
                        <span style="display:block;font-size:12px;color:#50575e;margin-top:4px">
                            <?php esc_html_e('Backup codes are your only way back in if you lose your authenticator — without them an administrator or hosting-level access is required.', 'free-2fa'); ?>
                        </span>
                        <p style="margin-bottom:0">
                            <button type="submit" class="button button-primary" id="free2fa-confirm-btn" disabled>
                                <?php esc_html_e('Enable two-factor authentication', 'free-2fa'); ?>
                            </button>
                        </p>
                    </form>
                    <?php else: ?>
                    <p style="margin-bottom:0;padding-top:10px;border-top:1px solid #c3c4c7">
                        <label>
                            <input type="checkbox" id="free2fa-codes-saved">
                            <strong><?php esc_html_e('I have saved these backup codes in a safe place', 'free-2fa'); ?></strong>
                        </label>
                    </p>
                    <?php endif; ?>
                    <script>
                    function free2faDownloadCodes(){
                        const codes = <?php echo wp_json_encode($just_codes); ?>;
                        const blob = new Blob([codes.join("\n") + "\n"], {type:'text/plain'});
                        const a = document.createElement('a');
                        a.href = URL.createObjectURL(blob);
                        a.download = 'free-2fa-backup-codes-<?php echo esc_js(date('Ymd')); ?>.txt';
                        document.body.appendChild(a); a.click(); a.remove();
                    }
                    (function(){
                        const box = document.getElementById('free2fa-codes-saved');
                        const btn = document.getElementById('free2fa-confirm-btn');
                        const warn = function(e){ e.preventDefault(); e.returnValue = ''; };
                        window.addEventListener('beforeunload', warn);
                        box.addEventListener('change', function(){
                            if (btn) btn.disabled = !box.checked;
                            if (box.checked) window.removeEventListener('beforeunload', warn);
                            else window.addEventListener('beforeunload', warn);
                        });
                        // The confirm submit itself must not trigger the leave-warning.
                        const form = box.closest('form');
                        if (form) form.addEventListener('submit', function(){ window.removeEventListener('beforeunload', warn); });
                    })();
                    </script>
                </div>
            <?php endif; ?>

            <?php if (!empty($_GET['free2fa_enabled_ok'])): ?>
                <div class="notice notice-success"><p><?php esc_html_e('Two-factor authentication is now enabled for your account.', 'free-2fa'); ?></p></div>
            <?php endif; ?>
            <?php if (!empty($_GET['free2fa_resetup'])): ?>
                <div class="notice notice-warning"><p><?php esc_html_e('Your two-factor authentication was reset because the site\'s security keys changed and your old authenticator secret could no longer be verified. Please set it up again now — your previous authenticator entry and backup codes no longer work.', 'free-2fa'); ?></p></div>
            <?php endif; ?>
            <?php if (!empty($_GET['free2fa_setup_error'])): ?>
                <div class="notice notice-error"><p><?php esc_html_e('Code did not match. Please scan the QR again and try.', 'free-2fa'); ?></p></div>
            <?php endif; ?>
            <?php if (!empty($_GET['free2fa_setup_expired'])): ?>
                <div class="notice notice-error"><p><?php esc_html_e('Setup session expired. Please start again.', 'free-2fa'); ?></p></div>
            <?php endif; ?>
            <?php if (!empty($_GET['free2fa_crypto_error'])): ?>
                <div class="notice notice-error"><p><?php esc_html_e('Could not store the secret securely. Please try again.', 'free-2fa'); ?></p></div>
            <?php endif; ?>
            <?php if (!empty($_GET['free2fa_pw_error'])): ?>
                <div class="notice notice-error"><p><?php esc_html_e('Current password was incorrect.', 'free-2fa'); ?></p></div>
            <?php endif; ?>

            <?php if (!$enabled): ?>
                <?php $this->render_setup_wizard($user); ?>
            <?php else: ?>
                <?php $this->render_management($user); ?>
            <?php endif; ?>
        </div>
        <?php
    }

    private function render_setup_wizard(\WP_User $user): void {
        // Generate the secret once per setup session and keep it server-side, encrypted.
        // The QR/URI is derived from this transient on each render, so a page refresh
        // doesn't rotate the secret; the hidden POST field is gone.
        $stored = get_transient('free2fa_setup_' . $user->ID);
        $secret = $stored ? Crypto::decrypt((string)$stored) : null;
        if (!$secret) {
            $secret = TOTP::generate_secret();
            set_transient('free2fa_setup_' . $user->ID, Crypto::encrypt($secret), 15 * MINUTE_IN_SECONDS);
        }
        $issuer = get_bloginfo('name');
        $uri = TOTP::uri($secret, $user->user_login, $issuer);
        ?>
        <h2><?php esc_html_e('Set up two-factor authentication', 'free-2fa'); ?></h2>
        <div style="background:#fff;border:1px solid #c3c4c7;padding:24px;margin-top:14px">
            <ol style="line-height:1.8;font-size:14px">
                <li>
                    <?php esc_html_e('Install any TOTP authenticator app on your phone (Authy, 1Password, Microsoft Authenticator, etc.)', 'free-2fa'); ?>
                </li>
                <li>
                    <?php esc_html_e('Scan this QR code with the app:', 'free-2fa'); ?>
                    <div id="free2fa-qr" data-uri="<?php echo esc_attr($uri); ?>" style="margin:14px 0;padding:14px;background:#fff;display:inline-block;border:1px solid #c3c4c7"></div>
                    <p style="font-size:12px;color:#50575e">
                        <?php esc_html_e('Can\'t scan? Enter this code manually:', 'free-2fa'); ?><br>
                        <code style="font-size:14px;letter-spacing:2px;padding:6px 10px;background:#f6f7f7;display:inline-block;margin-top:6px"><?php
                            echo esc_html(chunk_split($secret, 4, ' '));
                        ?></code>
                    </p>
                </li>
                <li><?php esc_html_e('Enter the 6-digit code from the app:', 'free-2fa'); ?></li>
            </ol>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top:6px;padding-left:32px">
                <?php wp_nonce_field('free2fa_setup'); ?>
                <input type="hidden" name="action" value="free2fa_setup_save">
                <input type="text" name="code" required maxlength="6" inputmode="numeric" autocomplete="one-time-code"
                       style="font-size:22px;letter-spacing:6px;width:200px;text-align:center;padding:10px">
                <button type="submit" class="button button-primary button-large" style="vertical-align:middle">
                    <?php esc_html_e('Verify & continue', 'free-2fa'); ?>
                </button>
            </form>
        </div>
        <?php
    }

    private function render_management(\WP_User $user): void {
        $devices = TrustedDevice::list_for($user->ID);
        ?>
        <h2><?php esc_html_e('Trusted devices', 'free-2fa'); ?></h2>
        <?php if (empty($devices)): ?>
            <p style="color:#50575e"><?php esc_html_e('No trusted devices. After a successful 2FA login you can mark the current device as trusted to skip the prompt for up to 30 days.', 'free-2fa'); ?></p>
        <?php else: ?>
            <table class="widefat striped" style="max-width:720px">
                <thead><tr>
                    <th><?php esc_html_e('First seen', 'free-2fa'); ?></th>
                    <th><?php esc_html_e('Last used', 'free-2fa'); ?></th>
                    <th><?php esc_html_e('Expires', 'free-2fa'); ?></th>
                    <th><?php esc_html_e('IP', 'free-2fa'); ?></th>
                    <th><?php esc_html_e('Browser', 'free-2fa'); ?></th>
                    <th></th>
                </tr></thead>
                <tbody>
                <?php foreach ($devices as $device_id => $info): ?>
                    <tr>
                        <td><?php echo esc_html(date_i18n('Y-m-d', $info['created'] ?? 0)); ?></td>
                        <td><?php echo esc_html(human_time_diff($info['last_used'] ?? 0) . ' ago'); ?></td>
                        <td><?php echo esc_html(date_i18n('Y-m-d', $info['expiry'] ?? 0)); ?></td>
                        <td><code><?php echo esc_html($info['ip'] ?? ''); ?></code></td>
                        <td style="font-size:11px"><?php echo esc_html(substr($info['ua'] ?? '', 0, 80)); ?></td>
                        <td>
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline">
                                <?php wp_nonce_field('free2fa_revoke_device'); ?>
                                <input type="hidden" name="action" value="free2fa_revoke_device">
                                <input type="hidden" name="device_id" value="<?php echo esc_attr($device_id); ?>">
                                <button class="button button-small"><?php esc_html_e('Revoke', 'free-2fa'); ?></button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top:10px">
                <?php wp_nonce_field('free2fa_revoke_all'); ?>
                <input type="hidden" name="action" value="free2fa_revoke_all">
                <button class="button button-link-delete"><?php esc_html_e('Revoke all trusted devices', 'free-2fa'); ?></button>
            </form>
        <?php endif; ?>

        <h2><?php esc_html_e('Backup codes', 'free-2fa'); ?></h2>
        <p><?php printf(esc_html__('%d unused backup codes.', 'free-2fa'), BackupCodes::remaining($user->ID)); ?></p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <?php wp_nonce_field('free2fa_regen_backup'); ?>
            <input type="hidden" name="action" value="free2fa_regen_backup">
            <button class="button"><?php esc_html_e('Regenerate backup codes', 'free-2fa'); ?></button>
        </form>

        <?php
        // Email fallback: only offered when the site admin allows it in Settings.
        $site_opts = get_option('free2fa_settings', []);
        if (!empty($site_opts['email_fallback'])):
            $email_on = (bool) get_user_meta($user->ID, 'free2fa_email_fallback', true);
        ?>
        <h2><?php esc_html_e('Email fallback', 'free-2fa'); ?></h2>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="max-width:560px">
            <?php wp_nonce_field('free2fa_email_toggle'); ?>
            <input type="hidden" name="action" value="free2fa_email_toggle">
            <p>
                <label>
                    <input type="checkbox" name="email_fallback" value="1" <?php checked($email_on); ?>>
                    <?php esc_html_e('Allow one-time login codes sent to my email as a fallback', 'free-2fa'); ?>
                </label>
            </p>
            <p class="description" style="margin-top:0">
                <?php esc_html_e('Use this if you might lose access to both your authenticator and your backup codes. Note: anyone who controls your mailbox could then complete your second factor — keep that account well protected.', 'free-2fa'); ?>
            </p>
            <p><button class="button"><?php esc_html_e('Save', 'free-2fa'); ?></button></p>
        </form>
        <?php endif; ?>

        <h2><?php esc_html_e('Disable 2FA', 'free-2fa'); ?></h2>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="max-width:480px">
            <?php wp_nonce_field('free2fa_disable'); ?>
            <input type="hidden" name="action" value="free2fa_disable">
            <p>
                <label><?php esc_html_e('Confirm with your current password:', 'free-2fa'); ?><br>
                    <input type="password" name="current_password" required class="regular-text">
                </label>
            </p>
            <button class="button button-link-delete"><?php esc_html_e('Turn off 2FA', 'free-2fa'); ?></button>
        </form>
        <?php
    }
}
