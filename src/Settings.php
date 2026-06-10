<?php
namespace Free2FA;

if (!defined('ABSPATH')) exit;

class Settings {
    public function register(): void {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_init', [$this, 'register_settings']);
    }

    public function menu(): void {
        add_options_page(
            __('Free 2FA', 'free-2fa'),
            __('Free 2FA', 'free-2fa'),
            'manage_options',
            'free-2fa',
            [$this, 'render']
        );
    }

    public function register_settings(): void {
        register_setting('free2fa_settings_group', 'free2fa_settings', [$this, 'sanitize']);
    }

    public function sanitize($input): array {
        $valid_modes = ['none', 'admins', 'admins_editors', 'all'];
        return [
            'enforcement'     => in_array($input['enforcement'] ?? '', $valid_modes, true) ? $input['enforcement'] : 'admins',
            'trust_days'      => max(1, min(90, (int)($input['trust_days'] ?? 30))),
            'ip_allowlist'    => sanitize_textarea_field($input['ip_allowlist'] ?? ''),
            'trusted_proxies' => sanitize_textarea_field($input['trusted_proxies'] ?? ''),
            'lockout_fails'   => max(3, min(20, (int)($input['lockout_fails'] ?? 5))),
            'lockout_minutes' => max(5, min(120, (int)($input['lockout_minutes'] ?? 15))),
            'email_fallback'  => empty($input['email_fallback']) ? 0 : 1,
        ];
    }

    public function render(): void {
        if (!current_user_can('manage_options')) return;
        $opts = get_option('free2fa_settings', []);
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Free 2FA Settings', 'free-2fa'); ?></h1>
            <form method="post" action="options.php">
                <?php settings_fields('free2fa_settings_group'); ?>
                <table class="form-table" role="presentation"><tbody>
                <tr>
                    <th><label for="enforcement"><?php esc_html_e('Required for', 'free-2fa'); ?></label></th>
                    <td>
                        <select name="free2fa_settings[enforcement]" id="enforcement">
                            <?php
                            $cur = $opts['enforcement'] ?? 'admins';
                            $options = [
                                'none' => __('No one (off)', 'free-2fa'),
                                'admins' => __('Administrators only', 'free-2fa'),
                                'admins_editors' => __('Administrators + Editors', 'free-2fa'),
                                'all' => __('All users (every role)', 'free-2fa'),
                            ];
                            foreach ($options as $k => $label) {
                                printf('<option value="%s" %s>%s</option>',
                                    esc_attr($k), selected($cur, $k, false), esc_html($label));
                            }
                            ?>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th><label for="trust_days"><?php esc_html_e('Trust device for', 'free-2fa'); ?></label></th>
                    <td>
                        <input type="number" name="free2fa_settings[trust_days]" id="trust_days" min="1" max="90" value="<?php echo esc_attr($opts['trust_days'] ?? 30); ?>" class="small-text"> <?php esc_html_e('days', 'free-2fa'); ?>
                    </td>
                </tr>
                <tr>
                    <th><label for="lockout_fails"><?php esc_html_e('Lockout after', 'free-2fa'); ?></label></th>
                    <td>
                        <input type="number" name="free2fa_settings[lockout_fails]" id="lockout_fails" min="3" max="20" value="<?php echo esc_attr($opts['lockout_fails'] ?? 5); ?>" class="small-text">
                        <?php esc_html_e('failed attempts, for', 'free-2fa'); ?>
                        <input type="number" name="free2fa_settings[lockout_minutes]" min="5" max="120" value="<?php echo esc_attr($opts['lockout_minutes'] ?? 15); ?>" class="small-text">
                        <?php esc_html_e('minutes', 'free-2fa'); ?>
                    </td>
                </tr>
                <tr>
                    <th><label for="email_fallback"><?php esc_html_e('Email fallback codes', 'free-2fa'); ?></label></th>
                    <td>
                        <label>
                            <input type="checkbox" name="free2fa_settings[email_fallback]" id="email_fallback" value="1" <?php checked(!empty($opts['email_fallback'])); ?>>
                            <?php esc_html_e('Let users opt in to one-time login codes sent to their email', 'free-2fa'); ?>
                        </label>
                        <p class="description"><?php esc_html_e('Off by default. Email is a weaker second factor than an authenticator app — a compromised mailbox can complete the login. Each user must additionally enable it for their own account.', 'free-2fa'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label for="ip_allowlist"><?php esc_html_e('IP allowlist (skip 2FA)', 'free-2fa'); ?></label></th>
                    <td>
                        <textarea name="free2fa_settings[ip_allowlist]" id="ip_allowlist" rows="4" cols="40" placeholder="192.168.1.0/24&#10;10.0.0.5"><?php echo esc_textarea($opts['ip_allowlist'] ?? ''); ?></textarea>
                        <p class="description"><?php esc_html_e('One IP or CIDR per line. Logins from these IPs skip 2FA entirely.', 'free-2fa'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><label for="trusted_proxies"><?php esc_html_e('Trusted proxies', 'free-2fa'); ?></label></th>
                    <td>
                        <textarea name="free2fa_settings[trusted_proxies]" id="trusted_proxies" rows="4" cols="40" placeholder="173.245.48.0/20&#10;103.21.244.0/22"><?php echo esc_textarea($opts['trusted_proxies'] ?? ''); ?></textarea>
                        <p class="description"><?php esc_html_e('One IP or CIDR per line. The CF-Connecting-IP / X-Forwarded-For headers are honoured ONLY for requests coming from these proxies. Leave empty if your site is not behind Cloudflare / a load balancer.', 'free-2fa'); ?></p>
                    </td>
                </tr>
                </tbody></table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}
