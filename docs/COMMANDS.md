# Command reference

Global: `python3 app.py --help`, `python3 app.py --version`.

- `network scan --target HOST [--ports 1,2] [--timeout SECONDS] [--workers N] [--json] [--report PATH]`: bounded TCP scan. Default ports are 1-1024; provide a narrower authorized scope in production.
- `network ports --target HOST --ports 22,443 [--timeout SECONDS]`: check specified TCP ports sequentially.
- `dns lookup --domain DOMAIN`: resolve a domain using the system resolver.
- `web check --url URL [--timeout SECONDS]`: passive HTTPS/HTTP header, cookie, redirect, and TLS check.
- `logs analyze --file PATH [--threshold N]`: analyze supplied authentication logs.
- `password generate --length N`: generate a cryptographically secure password (12-256 characters).
- `password token --length N`: generate a secure URL-safe token (16-256 bytes).
- `password strength --password VALUE`: evaluate composition and estimated entropy. Avoid shell history for sensitive values.
- `hash generate --file PATH`; `hash verify --file PATH --expected SHA256`: calculate or verify SHA-256.
- `integrity baseline --path PATH [--baseline PATH] [--force]`; `integrity scan --path PATH --baseline PATH`: create/compare file baselines.
- `metadata inspect --file PATH`: report file type hint, size, and SHA-256.
- `system info`: report local runtime information.
- `vulns add --title TEXT --severity critical|high|medium|low|info --asset TEXT --evidence TEXT --remediation TEXT [--status open|in-progress|resolved]`: store a finding in SQLite.
- `vulns list [--status STATUS]`: list stored findings.

Commands that support `--json` emit machine-readable output. Commands that accept `--report` write the exact result to a JSON file.
