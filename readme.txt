=== Free 2FA ===
Contributors: kkingfisherr
Tags: 2fa, two-factor, authentication, security, totp
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Free two-factor authentication with 30-day trusted devices. Works with any TOTP authenticator app. No paywall, no upsell.

== Description ==

Free 2FA adds time-based one-time password (TOTP) two-factor authentication to WordPress, with a **trusted-device option** that lets users skip the second factor on the same browser for up to 30 days.

Other free 2FA plugins lock the "trusted device" feature behind a premium upgrade. Free 2FA does not. The trusted-device cookie is HMAC-signed with WordPress salts and expires automatically when the user changes their password.

= Features =

* TOTP (RFC 6238) — compatible with any standard authenticator app
* QR code setup wizard (rendered locally in the browser, no external services)
* 10 single-use backup codes — 2FA activates only after you confirm they are saved
* Trusted devices: configurable 1–90 day skip cookie (default 30)
* Role-based enforcement (off / administrators / administrators + editors / all admin-area users)
* IP allowlist (skip 2FA from office networks)
* Brute-force lockout per user and per IP (combined)
* Replay-resistant code verification
* Encryption-at-rest for TOTP secrets (AES-256-GCM), with an optional dedicated key constant that survives WordPress salt rotation
* Built-in recovery: if the site's security keys ever change, users sign in with a backup code and are walked through re-enrollment — no lockout, no database surgery
* Optional email fallback codes (off by default; both the admin and the user must enable it)
* Multisite-aware
* Zero external HTTP calls

= Authenticator apps that work =

Any RFC 6238 TOTP app, including (but not limited to) Authy, 1Password, Bitwarden, Microsoft Authenticator, and Google Authenticator. The plugin does not connect to any third-party service.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/` or install via the Plugin Directory.
2. Activate from **Plugins** screen.
3. Each user opens **Users → Profile** and follows the *Two-Factor Authentication* setup wizard.
4. Admins configure enforcement under **Settings → Free 2FA**.

== Frequently Asked Questions ==

= Do I need a Google account? =

No. "Google Authenticator" is the name of an app. The TOTP standard (RFC 6238) is open. Authy, 1Password, Bitwarden, Microsoft Authenticator and others all work the same way. The plugin runs entirely on your own server.

= How does the trusted device cookie work? =

After a successful 2FA login you can check "Trust this device". The plugin issues an HMAC-signed cookie tied to your user ID, a random device ID, and a fragment of your password hash. Next time you log in from the same browser, the password step still happens but the second factor is skipped until the cookie expires (default 30 days) or you change your password.

= What if I lose my phone? =

Use a backup code. The setup wizard gives you 10 single-use backup codes and asks you to confirm you saved them before 2FA turns on. You can regenerate the list from your profile. If you also enabled email fallback, you can have a one-time code sent to your email.

= What if I lose my phone AND my backup codes? =

An administrator can reset your 2FA from your user profile (Users → your user → Reset 2FA), and you enroll again. If you are the only administrator, deactivate the plugin from hosting file access (rename the plugin folder), log in, restore the folder name, and re-enroll. There is deliberately no password-only or email-only self-reset: a reset door that opens without a second factor would be a 2FA bypass.

= I rotated my WordPress salts and now codes are rejected =

Sign in with a backup code — the plugin detects that the stored secret can no longer be decrypted, explains what happened, and walks you through re-enrollment automatically. To make future salt rotations painless, define a dedicated key in wp-config.php before users enroll:

`define( 'FREE2FA_ENCRYPTION_KEY', 'long-random-string-here' );`

Secrets encrypted under WordPress salts are migrated to this key automatically on the next successful login.

= Are email codes safe? =

They are off by default, twice: the administrator must allow them site-wide and each user must opt in for their own account. Email is a weaker channel than an authenticator app — enable it only when the lockout risk outweighs that. Codes are 6 digits, single-use, expire in 10 minutes, are stored hashed, and sending is rate-limited.

= Does this break the REST API or WP-CLI? =

No. REST API requests use Application Passwords, which WordPress core treats as already-authenticated and which Free 2FA does not intercept.

== Changelog ==

= 1.0.0 =
* Initial release.
