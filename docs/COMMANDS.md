# Command reference

Global: `python3 app.py --help`, `python3 app.py --version`.

## Short operator commands

After `python3 -m pip install -e .`, the `firebox` command is available. These shortcuts print readable text by default:

- `firebox scan HOST --ports 22,80,443`: bounded TCP scan.
- `firebox ports HOST --ports 22,80,443`: check selected ports.
- `firebox dns DOMAIN`: resolve a domain.
- `firebox web URL`: perform a passive web check.
- `firebox vuln-scan URL`: perform a bounded passive assessment of the URL.
- `firebox logs PATH`: analyze an authentication log.
- `firebox hash PATH`: calculate a SHA-256 hash.
- `firebox wifi status`: list local wireless interfaces only.
- `firebox wifi audit --interface wlan0`: read-only audit of one local wireless interface.
- `firebox wifi pcap --file authorized-capture.pcap`: inspect PCAP metadata and record lengths without decoding payloads.
- `firebox phishing analyze --file suspicious-email.eml`: statically analyze a supplied email for phishing indicators.
- `firebox phishing template --scenario account-alert [--output PATH]`: create clearly labeled synthetic awareness material.
- `firebox api discover --url https://authorized.example`: check standard API documentation paths without crawling.
- `firebox web enumerate --url https://authorized.example --wordlist approved-paths.txt --confirm-authorized`: sequentially check an approved path list with hard caps.

Append `--json` for machine-readable output or `--report PATH` to save a JSON report.

- `network scan --target HOST [--ports 1,2] [--timeout SECONDS] [--workers N] [--json] [--report PATH]`: bounded TCP scan. Default ports are 1-1024; provide a narrower authorized scope in production.
- `network ports --target HOST --ports 22,443 [--timeout SECONDS]`: check specified TCP ports sequentially.
- `dns lookup --domain DOMAIN`: resolve a domain using the system resolver.
- `web check --url URL [--timeout SECONDS]`: passive HTTPS/HTTP header, cookie, redirect, and TLS check.
- `web audit --url URL [--paths /,/health] [--timeout SECONDS]`: assess the base URL and up to 8 explicitly supplied paths for observable TLS, header, cookie, and server-response issues. It never crawls, fuzzes, authenticates, exploits, or submits destructive payloads.
- `logs analyze --file PATH [--threshold N]`: analyze supplied authentication logs.
- `password generate --length N`: generate a cryptographically secure password (12-256 characters).
- `password token --length N`: generate a secure URL-safe token (16-256 bytes).
- `password strength --password VALUE`: evaluate composition and estimated entropy. Avoid shell history for sensitive values.
- `hash generate --file PATH`; `hash verify --file PATH --expected SHA256`: calculate or verify SHA-256.
- `integrity baseline --path PATH [--baseline PATH] [--force]`; `integrity scan --path PATH --baseline PATH`: create/compare file baselines.
- `metadata inspect --file PATH`: report file type hint, size, and SHA-256.
- `system info`: report local runtime information.
- `wifi status`: report local wireless interfaces; no nearby-network scan is performed.
- `wifi audit --interface IFACE`: report local interface state and read-only `iw` link information.
- `wifi pcap --file PATH`: report classic PCAP metadata and packet counts, with a 256 MiB input limit.
- `phishing analyze --file PATH`: inspect headers, links, urgency language, and attachments without opening links or sending mail.
- `phishing template --scenario suspicious-invoice|account-alert|delivery-notice`: generate non-deliverable training text with no live links or credential collection.
- `api discover --url URL [--paths /openapi.json,/docs]`: perform bounded read-only GET requests for explicitly selected or standard API documentation paths; maximum 8 paths.
- `plugins list`: validate and list trusted Python plugins in `plugins/` or `FIREBOX_PLUGIN_DIR`.
- `web enumerate --url URL --wordlist PATH --confirm-authorized [--max-requests N] [--delay SECONDS]`: perform sequential read-only HEAD checks; maximum 500 requests and minimum 0.1-second delay. This is path enumeration only, not credential brute force.
- `vulns add --title TEXT --severity critical|high|medium|low|info --asset TEXT --evidence TEXT --remediation TEXT [--status open|in-progress|resolved]`: store a finding in SQLite.
- `vulns list [--status STATUS]`: list stored findings.

Commands that support `--json` emit machine-readable output. Commands that accept `--report` write the exact result to a JSON file.
