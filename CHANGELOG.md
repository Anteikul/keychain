# Changelog

All notable changes to Keychain are documented in this file. Releases follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-08-17

### Added

- Private and shared encrypted password and TOTP entries.
- Folders, tags, search, card view, and compact list view.
- Password generation and encrypted credential history.
- Shared icon library with upload deduplication.
- Administrator user management, password resets, session management, trash restore, and audit logging.
- Automatic SQLite and device-key backups with configurable retention.
- Docker Compose, systemd, and backup timer deployment files.
- Optional native HTTPS using PEM certificate and private-key paths, with TLS 1.2 as the minimum version.
- TLS-aware Docker health checks and automatic `Secure` cookie attributes when native HTTPS is enabled.

### Security

- User passwords are hashed with scrypt and unique random salts.
- Vault secrets and password history are encrypted with AES-256-GCM.
- State-changing requests require CSRF tokens.
- Sessions expire after 15 minutes of inactivity and can be revoked by users or administrators.
- Restrictive Content Security Policy, frame, referrer, and content-type headers are enabled.

### Changed

- Standardized the website, client-side messages, server errors, and audit events in English.

[1.0.0]: https://github.com/Anteikul/keychain/releases/tag/v1.0.0
