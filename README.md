# Keychain

Keychain is a small self-hosted, multi-user password and TOTP vault designed for trusted private networks. It uses Python's standard HTTP server, SQLite, and AES-256-GCM encryption, with no external database or application framework.

Current release: **1.0.0**. See [CHANGELOG.md](CHANGELOG.md) for release notes.

> [!WARNING]
> This project has not received an independent security audit. Do not expose it directly to the public internet. Run it behind a properly configured HTTPS reverse proxy and protect the host, database, encryption key, and backups.

## Features

- Private and shared credentials
- Passwords and TOTP codes in one entry
- Folders, tags, search, card view, and compact list view
- Shared icon library with upload deduplication
- Password generator and encrypted password history
- Soft deletion with administrator restore
- Light and dark themes
- Fifteen-minute inactivity timeout
- User-managed and administrator-managed active sessions
- First-user administrator bootstrap
- Administrator user management, password resets, and audit log
- Consistent automatic backups with retention

## Security model

- User passwords are hashed with `scrypt` and a unique random salt.
- Vault secrets and historical passwords are encrypted with AES-256-GCM.
- The device key is generated locally at first start and stored separately from the database.
- Sessions are revocable and stored as hashes in SQLite.
- State-changing requests use CSRF protection.
- The application emits restrictive browser security headers.

The SQLite database is encrypted at the field level, not as a whole file. Metadata such as usernames, item titles, URLs, folders, tags, audit records, and timestamps may remain readable to someone who obtains the database. Anyone who obtains both the database and `.device-key` can decrypt vault secrets.

## Quick start with Docker Compose

Requirements: Docker Engine with the Compose plugin.

```bash
git clone <repository-url> keychain
cd keychain
docker compose up -d --build
```

Open `http://localhost:8080`. The first account created becomes the administrator. Persistent data is stored in the `keychain-data` Docker volume.

To stop the application:

```bash
docker compose down
```

Do not add `-v` unless you intentionally want to delete the persistent Docker volume.

## Run directly with Python

Requirements: Python 3.11 or newer.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
KEYCHAIN_HOST=127.0.0.1 KEYCHAIN_PORT=8080 python3 app.py
```

The application creates `keychain.db` and `.device-key` in the project directory by default. Both are excluded from Git.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `KEYCHAIN_HOST` | `0.0.0.0` | Listening address |
| `KEYCHAIN_PORT` | `80` | Listening port |
| `KEYCHAIN_DB` | `./keychain.db` | SQLite database path |
| `KEYCHAIN_KEY` | `./.device-key` | AES encryption key path |
| `KEYCHAIN_TLS_CERT` | unset | PEM TLS certificate or full-chain path |
| `KEYCHAIN_TLS_KEY` | unset | PEM TLS private-key path |
| `KEYCHAIN_BACKUP_DIR` | `./backups` | Backup destination |
| `KEYCHAIN_BACKUP_KEEP` | `14` | Number of backup archives retained |

The Docker image overrides the listening port to `8080` and stores persistent files under `/data`.

## HTTPS with TLS certificates

Set both TLS variables to terminate HTTPS directly in Keychain. The application rejects incomplete TLS configuration. The certificate file may include the server certificate and intermediate certificates; protect the private key and make it readable by the service account.

```bash
KEYCHAIN_HOST=0.0.0.0 \
KEYCHAIN_PORT=8443 \
KEYCHAIN_TLS_CERT=/etc/keychain/fullchain.pem \
KEYCHAIN_TLS_KEY=/etc/keychain/privkey.pem \
python3 app.py
```

Native HTTPS requires TLS 1.2 or newer and automatically adds `Secure` to every application cookie.

With Docker Compose, mount the certificates read-only and configure their container paths:

```yaml
services:
  keychain:
    ports:
      - "8443:8080"
    environment:
      KEYCHAIN_TLS_CERT: /certs/fullchain.pem
      KEYCHAIN_TLS_KEY: /certs/privkey.pem
    volumes:
      - keychain-data:/data
      - ./certs:/certs:ro
```

Restart the service after renewing a certificate. For automatic certificate management, use an HTTPS reverse proxy and leave these variables unset.

## Backups and recovery

Create a consistent backup manually:

```bash
python3 backup.py
```

Each archive contains both `keychain.db` and `.device-key`. Store it as sensitive data: possession of both files permits decryption of vault contents. Keep at least one protected off-host backup and test recovery regularly.

To recover, stop the application, extract both files into the configured data directory, confirm restrictive file permissions, and start the application again.

## systemd installation

The included unit files expect the application at `/opt/keychain`:

```bash
sudo cp keychain.service keychain-backup.service keychain-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now keychain.service keychain-backup.timer
```

Inspect the service and backup timer with:

```bash
systemctl status keychain.service
systemctl list-timers keychain-backup.timer
journalctl -u keychain.service
```

Adjust paths, permissions, the service account, and listening port for your environment before installation. Binding directly to a privileged port such as `80` normally requires additional service privileges or a reverse proxy.

## CI

The GitLab CI pipeline checks Python syntax and core cryptographic operations, then verifies that the Docker image can be built. It does not publish the image to a container registry.

## Repository hygiene

The `.gitignore` and `.dockerignore` files exclude the live database, device key, backups, TLS private material, environment files, and Python cache files. Before making a fork public, review the entire Git history as well as the current working tree.

## License

No license has been selected yet. Without an explicit license, copyright law reserves all rights to the author. Add a license before inviting third-party reuse or contributions.
