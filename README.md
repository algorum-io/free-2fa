# Free 2FA

Free WordPress two-factor authentication with **30-day trusted devices**. Works with any standard TOTP authenticator app (Authy, 1Password, Bitwarden, Microsoft Authenticator, and others).

No paywall. No upsell. No external services.

[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2+-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
![WordPress 6.0+](https://img.shields.io/badge/WordPress-6.0+-21759b)
![PHP 7.4+](https://img.shields.io/badge/PHP-7.4+-777BB4)

## Why this exists

Every other free WordPress 2FA plugin gates the "remember this device" feature behind a paid upgrade. Result: you either pay a subscription, or you type a 6-digit code every single time you log in.

Free 2FA does what those plugins do — TOTP, backup codes, role-based enforcement — *and* the trusted-device skip cookie, all in the free version.

## Features

- **TOTP (RFC 6238)** — compatible with any standard authenticator app
- **Trusted devices** — 30-day (configurable 1-90 day) skip cookie, HMAC-signed
- **Backup codes** — 10 single-use, hashed at rest; 2FA activates only after the user confirms the codes are saved
- **Role-based enforcement** — off / admins / admins + editors / all admin-area users
- **IP allowlist** — IPv4 and IPv6 CIDR, skip 2FA from trusted networks
- **Brute-force lockout** — per user *and* per IP combined (so an attacker can't DoS a real admin)
- **Replay-resistant** — monotonic time-window counter; a code can never be accepted twice
- **AES-256-GCM encryption at rest** for TOTP secrets — keyed off an optional dedicated `FREE2FA_ENCRYPTION_KEY` constant (survives salt rotation) with WordPress salts as the zero-config default
- **Salt-rotation recovery built in** — if stored secrets ever become undecryptable, users sign in with a backup code and are walked through re-enrollment; no lockout, no database surgery
- **Optional email fallback codes** — double opt-in (site setting + per-user), single-use, short-lived, rate-limited
- **Anomaly hook** — `do_action('free2fa_trusted_device_ip_changed', …)` fires when a trusted cookie validates from a new IP
- **REST API / App Passwords stay accessible** — automations don't break
- **Multisite-aware** — works under network-activate
- **Zero external HTTP calls** — QR rendered client-side from bundled qrcode.js

## Install

1. Upload `/free-2fa/` to `/wp-content/plugins/`
2. Activate via **Plugins**
3. Each user opens **Users → Profile** and clicks **Set up now** under Two-Factor Authentication
4. Admins tune enforcement under **Settings → Free 2FA**

## Architecture

```
src/
├── Plugin.php          ← bootstrap, hooks
├── TOTP.php            ← RFC 6238 (SHA-1, 30s, 6 digit)
├── Crypto.php          ← AES-256-GCM; FREE2FA_ENCRYPTION_KEY or WP-salt key, auto-migration
├── BackupCodes.php     ← generate / consume (mutex-protected)
├── Email.php           ← opt-in email fallback codes (hashed, single-use, rate-limited)
├── TrustedDevice.php   ← HMAC cookie, IP-anomaly hook
├── Rate.php            ← user+IP combined lockout
├── Login.php           ← wp_authenticate_user intercept + challenge + recovery
├── Setup.php           ← admin-post handlers (save/confirm/disable/regen/revoke)
├── Settings.php        ← Options > Free 2FA page
├── Admin.php           ← user profile section + standalone setup page
└── Activator.php       ← plugin activation defaults
```

## Security model

- TOTP secrets are encrypted with AES-256-GCM before storage. Define `FREE2FA_ENCRYPTION_KEY` in wp-config.php and the key survives WordPress salt rotation (secrets stored under the salt-derived key migrate automatically on the next login); without the constant, `SECURE_AUTH_KEY` + `SECURE_AUTH_SALT` are used
- If secrets do become undecryptable (salts rotated without the constant), backup codes — hashed independently of the salts — remain valid: the login screen tells the user what happened, accepts a backup code, wipes the dead enrollment, and sends them straight to re-enrollment. Recovery never opens a password-only door
- Email fallback codes are off unless both the site admin and the user enable them; codes are 6-digit, single-use, expire in 10 minutes, are stored hashed, and sending is rate-limited to one email per 2 minutes
- Backup codes are hashed with `wp_hash_password()` (bcrypt) and verified with `wp_check_password()`
- Trusted-device cookie is HMAC-SHA256 signed with WP salts plus a 12-byte fragment of the user's password hash — changing the password automatically invalidates every trusted device for that user
- Cookie is HttpOnly + Secure (under HTTPS) + SameSite=Lax
- All HMAC comparisons use `hash_equals()` for timing safety
- Replay protection keeps a per-user monotonic window counter: only codes from a strictly newer time window are accepted, so no code — including one seen in transit — can ever be used twice
- Failed-attempt lockout requires *both* user-bucket *and* IP-bucket over threshold, so an attacker on one IP cannot DoS a legitimate user from another IP

## What this plugin does NOT do

- It does not phone home, ever
- It does not require a Google account or any third-party API
- It does not store TOTP secrets in plain text
- It does not interfere with REST API or WP-CLI
- It does not lock you out if your authenticator dies — that's what backup codes are for

## Why "compatible with Google Authenticator" without the word "Google" in the name

WordPress.org plugin guidelines do not allow trademarked names in plugin titles. The TOTP standard (RFC 6238) is open, and every modern authenticator app — Authy, 1Password, Bitwarden, Microsoft Authenticator, Google Authenticator — implements the same standard. This plugin works with all of them. The Google brand reference belongs in documentation, not in the name.

## Contributing

Issues and PRs welcome. Before opening a PR, please:

1. Run `php -l` on every file you touched
2. Confirm `defined('ABSPATH') || exit;` guard at the top of every PHP file
3. Use `esc_html()` / `esc_attr()` / `esc_url()` / `wp_kses_post()` on every output, no exceptions
4. Use `$wpdb->prepare()` if you touch SQL
5. Use `hash_equals()` for any secret comparison

## License

GPL v2 or later — see [LICENSE](LICENSE).
