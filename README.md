# Keychain

Keychain is a small self-hosted, multi-user password and TOTP vault for trusted
private networks. It uses Python's standard HTTP server, SQLite, and AES-256-GCM
encryption, with no external database or application framework.

> [!WARNING]
> Keychain has not received an independent security audit. Never expose its
> application port directly to the public internet and never use plain HTTP
> across an untrusted network. The production setup below includes HTTPS.

## Features

- Private and shared credentials
- Passwords and TOTP codes in one entry
- Folders, tags, search, card view, and compact list view
- Password generator and encrypted password history
- Soft deletion with administrator restore
- User and session administration with an audit log
- Fifteen-minute inactivity timeout
- Consistent automatic-backup support

## Choose an installation

| Goal | Command | Address |
| --- | --- | --- |
| Try it on one computer | `docker compose up -d --build` | `http://127.0.0.1:8080` |
| Run it with a public domain | `docker compose -f compose.prod.yaml up -d --build` | `https://your-domain` |

The local setup binds only to `127.0.0.1`; other computers cannot reach it.
The production setup runs Caddy in front of Keychain, obtains and renews TLS
certificates automatically, and does not publish the Keychain container port.

## Local quick start

Requirements: Docker Engine with the Compose plugin.

```bash
git clone https://github.com/Anteikul/keychain.git
cd keychain
docker compose up -d --build
```

Open <http://127.0.0.1:8080>. The first account created becomes the
administrator. Persistent data is stored in the `keychain-data` Docker volume.

Stop the application without deleting its data:

```bash
docker compose down
```

Do not add `-v` unless you intentionally want to delete the vault volume.

This HTTP mode is only for access from the same computer. Use the production
setup for LAN or internet access.

## Production deployment with automatic HTTPS

You need:

- a Linux server with Docker and Docker Compose;
- a domain whose `A`/`AAAA` record points to the server;
- inbound TCP ports 80 and 443 open (and optionally UDP 443 for HTTP/3).

Create the configuration file:

```bash
git clone https://github.com/Anteikul/keychain.git
cd keychain
cp .env.example .env
nano .env
```

Set both required values:

```dotenv
KEYCHAIN_DOMAIN=passwords.example.com
KEYCHAIN_EMAIL=admin@example.com
```

`KEYCHAIN_DOMAIN` must contain only the hostname—no `https://`, port, or path.
Compose refuses to start if either required value is missing.

Start the production stack:

```bash
docker compose -f compose.prod.yaml up -d --build
docker compose -f compose.prod.yaml ps
docker compose -f compose.prod.yaml logs --tail=100
```

Open `https://passwords.example.com` and create the first administrator.
Caddy redirects HTTP to HTTPS and manages certificate renewal. Keychain is only
reachable through Caddy on the private Docker network.

If certificate issuance fails, verify DNS, ports 80/443, and the Caddy logs:

```bash
docker compose -f compose.prod.yaml logs caddy
```

## Backups

Every backup contains both the SQLite database and `.device-key`. Treat an
archive like the entire vault: possession of both files permits decryption.

Create a consistent backup while production is running:

```bash
docker compose -f compose.prod.yaml exec keychain python3 backup.py
mkdir -p backups-export
docker compose -f compose.prod.yaml cp keychain:/data/backups/. ./backups-export/
```

The container retains the newest 14 archives by default. Copy backups off the
server to protected storage and test recovery regularly.

### Restore

Extract the chosen archive on the host:

```bash
mkdir -p restore
tar -xzf backups-export/keychain-YYYYMMDD-HHMMSS.tar.gz -C restore
```

Stop Keychain, copy both files into its persistent volume, and start it again:

```bash
docker compose -f compose.prod.yaml stop keychain
docker compose -f compose.prod.yaml cp restore/keychain.db keychain:/data/keychain.db
docker compose -f compose.prod.yaml cp restore/.device-key keychain:/data/.device-key
docker compose -f compose.prod.yaml run --rm --no-deps --user root --entrypoint sh keychain \
  -c 'chown keychain:keychain /data/keychain.db /data/.device-key && chmod 600 /data/keychain.db /data/.device-key'
docker compose -f compose.prod.yaml start keychain
docker compose -f compose.prod.yaml logs --tail=100 keychain
```

Then sign in and verify that several entries decrypt correctly. Remove the
temporary `restore` directory after successful verification.

## Updates

Create and export a backup first, then rebuild from the new source:

```bash
git pull
docker compose -f compose.prod.yaml up -d --build
```

## Run directly with Python

Requirements: Python 3.11 or newer.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
KEYCHAIN_HOST=127.0.0.1 KEYCHAIN_PORT=8080 python3 app.py
```

Direct HTTP is suitable only for localhost. For native HTTPS, configure both
certificate paths:

```bash
KEYCHAIN_HOST=0.0.0.0 \
KEYCHAIN_PORT=8443 \
KEYCHAIN_TLS_CERT=/etc/keychain/fullchain.pem \
KEYCHAIN_TLS_KEY=/etc/keychain/privkey.pem \
python3 app.py
```

When a different reverse proxy terminates HTTPS, leave the native TLS variables
unset and set `KEYCHAIN_SECURE_COOKIES=true`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `KEYCHAIN_HOST` | `0.0.0.0` | Listening address |
| `KEYCHAIN_PORT` | `80` | Listening port |
| `KEYCHAIN_DB` | `./keychain.db` | SQLite database path |
| `KEYCHAIN_KEY` | `./.device-key` | AES encryption-key path |
| `KEYCHAIN_TLS_CERT` | unset | Native TLS certificate/full chain |
| `KEYCHAIN_TLS_KEY` | unset | Native TLS private key |
| `KEYCHAIN_SECURE_COOKIES` | unset | Use secure cookies behind an HTTPS proxy |
| `KEYCHAIN_BACKUP_DIR` | `./backups` | Backup destination |
| `KEYCHAIN_BACKUP_KEEP` | `14` | Number of retained backup archives |

## Security model

- Passwords are hashed with `scrypt` and unique random salts.
- Vault secrets and historical passwords are encrypted with AES-256-GCM.
- The device key is generated locally and stored separately from the database.
- Session tokens are stored as hashes and can be revoked.
- State-changing requests use CSRF protection.
- Restrictive browser security headers are emitted.

SQLite is encrypted at field level, not as a whole file. Usernames, item titles,
URLs, notes, folders, tags, audit records, and timestamps remain readable to
someone who obtains the database. Anyone with both the database and device key
can decrypt the vault.

## Repository and release files

`Dockerfile`, Compose files, and `Caddyfile` intentionally live in the repository
so their exact configuration is reviewable and versioned with the application.
A release may additionally publish a prebuilt container image, but it should not
be the only place where deployment definitions exist.

## License

Keychain is available under the [MIT License](LICENSE).
