# Changelog

All notable changes to Free 2FA are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-06-10

### Added
- TOTP (RFC 6238) compatible with any standard authenticator app
- 30-day trusted-device cookie (configurable 1–90 days), HMAC-SHA256 signed with WP salts + password-hash fragment
- 10 single-use backup codes, hashed with `wp_hash_password()`; activation waits until the user confirms the codes are saved
- Role-based enforcement: off / admins only / admins + editors / all admin-area users
- IPv4 + IPv6 CIDR allowlist
- Per-user *and* per-IP combined brute-force lockout
- Replay protection via a per-user monotonic time-window counter — no code is ever accepted twice
- AES-256-GCM encryption-at-rest for TOTP secrets, with optional `FREE2FA_ENCRYPTION_KEY` wp-config constant; secrets encrypted under WordPress salts migrate to the dedicated key automatically
- Salt-rotation recovery: when a stored secret can no longer be decrypted, the login screen switches to backup-code mode and the user is walked through re-enrollment after signing in
- Optional email fallback codes — double opt-in (site setting + per-user), 6-digit, single-use, 10-minute expiry, hashed at rest, rate-limited sending
- Anomaly action hook `free2fa_trusted_device_ip_changed` for site owners to alert on cookie replay from a new IP
- Standalone setup page at **Users → Two-Factor Setup** (kept out of the WordPress profile form to avoid nested-form issues)
- Backup code regeneration and per-device revoke UI
- Settings page under **Settings → Free 2FA**
- Multisite-aware activation
- Uninstall cleanup of every option and user meta key the plugin creates
