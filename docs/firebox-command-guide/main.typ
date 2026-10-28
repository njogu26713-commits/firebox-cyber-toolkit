#import "report-theme.typ": report-accent, report-theme

#show: report-theme.with(
  title: "Firebox Cyber Toolkit Command Guide",
  author: "Firebox Cyber Toolkit",
  rhythm: "report",
  running-header: true,
)

#page(margin: (top: 30%, x: 2.2cm), numbering: none, header: none)[
  #set par(first-line-indent: 0em)
  #align(center)[
    #text(size: 26pt, weight: "bold", fill: report-accent)[Firebox Cyber Toolkit]
    #v(0.5em)
    #text(size: 18pt, weight: "bold")[Complete Command Guide]
    #v(0.8em)
    #text(size: 13pt, fill: luma(80))[Commands, copyable examples, usage, and safety limits]
    #v(2em)
    #line(length: 40%, stroke: 0.5pt + luma(160))
    #v(2em)
    #text(size: 11pt)[Production CLI reference]
    #v(0.5em)
    #text(size: 10pt, fill: luma(90))[Version 0.1.0 • Generated 28 October 2026]
  ]
]

#page(numbering: none, header: none)[
  #outline(title: [Contents], indent: 1.5em)
]

#counter(page).update(1)

= Read this first

Firebox is a lightweight defensive security toolkit for systems and websites that you own or are explicitly authorized to assess. The normal output is readable terminal text. Add `--json` when another program needs machine-readable output, and add `--report PATH` when a JSON report file is required.

The toolkit does not perform credential theft, password cracking, Wi-Fi key attacks, phishing delivery, exploit payloads, destructive requests, unrestricted crawling, or state-changing API calls. The bounded web enumerator is path enumeration only and requires an explicit authorization flag.

== Install and update

```bash
# Install on Ubuntu 24.04
sudo apt-get update && sudo apt-get install -y git python3 python3-venv
git clone https://github.com/njogu26713-commits/firebox-cyber-toolkit.git
cd firebox-cyber-toolkit
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
firebox --help
```

If the environment already exists:

```bash
cd ~/firebox-cyber-toolkit
git pull --ff-only
source .venv/bin/activate
python3 -m pip install -e .
hash -r
```

If `.venv/bin/activate` does not exist:

```bash
sudo apt-get update
sudo apt-get install -y python3-venv
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
```

== Global commands

=== Help

Show all top-level modules and options:

```bash
firebox --help
```

Show help for a module or command:

```bash
firebox network --help
firebox web audit --help
firebox web enumerate --help
```

=== Version

```bash
firebox --version
```

== Short operator aliases

These aliases are designed for quick, readable terminal use. The longer forms remain available.

#table(
  columns: (1fr, 2fr),
  stroke: 0.4pt + luma(190),
  inset: 6pt,
  [*Short command*], [*Equivalent operation*],
  [`firebox scan HOST`], [`network scan --target HOST`],
  [`firebox ports HOST --ports 22,443`], [`network ports --target HOST --ports 22,443`],
  [`firebox dns DOMAIN`], [`dns lookup --domain DOMAIN`],
  [`firebox web URL`], [`web check --url URL`],
  [`firebox vuln-scan URL`], [`web audit --url URL`],
  [`firebox logs FILE`], [`logs analyze --file FILE`],
  [`firebox hash FILE`], [`hash generate --file FILE`],
)

```bash
firebox scan 127.0.0.1
firebox dns example.com
firebox web https://your-authorized-domain.example
firebox vuln-scan https://your-authorized-domain.example
```

= Network and DNS

== TCP scan

`network scan` checks TCP connectivity against an explicitly supplied host. Without `--ports`, it checks ports 1–1024. It uses bounded concurrency and a timeout. Closed ports are summarized in normal output; JSON and reports preserve the detailed result.

```bash
# Localhost, default bounded range 1-1024
firebox scan 127.0.0.1

# Explicit authorized scope
firebox scan chukanest.co.ke --ports 22,80,443

# Tune timeout and concurrency
firebox scan 127.0.0.1 --ports 22,80,443 --timeout 2 --workers 4

# Save a complete JSON report
firebox scan 127.0.0.1 --report reports/localhost-scan.json

# Machine-readable output
firebox scan 127.0.0.1 --json
```

Long form:

```bash
firebox network scan --target 127.0.0.1 --ports 22,80,443
```

== Specific TCP ports

Use `network ports` when you want to check only a small list sequentially.

```bash
firebox ports 127.0.0.1 --ports 22,80,443
firebox network ports --target chukanest.co.ke --ports 80,443 --timeout 3
```

== DNS lookup

```bash
firebox dns chukanest.co.ke
firebox dns chukanest.co.ke --json
firebox dns lookup --domain chukanest.co.ke --report reports/dns.json
```

DNS resolution uses the server's system resolver. It does not claim ownership or geolocation.

= Web security commands

== Passive web check

`web check` sends a safe `HEAD` request and reports the response status, headers, cookies, redirects, TLS validation, and certificate expiry. It does not submit form data or exploit anything.

```bash
firebox web https://chukanest.co.ke
firebox web https://chukanest.co.ke --report reports/chukanest-web-check.json
firebox web check --url https://chukanest.co.ke --json
```

== Bounded passive web audit

`web audit` checks one base URL or up to eight explicitly supplied paths. Findings are evidence-based from live responses. It is not a complete penetration test.

```bash
firebox vuln-scan https://chukanest.co.ke

firebox web audit \
  --url https://chukanest.co.ke \
  --paths /,/login,/health,/api,/openapi.json \
  --report reports/chukanest-web-audit.json
```

It checks TLS, certificate expiry, HTTP status, server errors, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, cookie attributes, and redirect information.

== Authorized read-only path enumeration

This is the only command in this guide that accepts a wordlist. It requires `--confirm-authorized`, a user-supplied wordlist, sequential requests, a maximum of 500 requests, and a minimum delay of 0.1 seconds. It uses `HEAD` only. It is path enumeration, not password or credential brute force.

Create a reviewed wordlist:

```bash
cat > approved-paths.txt <<'EOF'
/
/login
/health
/api
/openapi.json
/swagger.json
EOF
```

Run it:

```bash
firebox web enumerate \
  --url https://chukanest.co.ke \
  --wordlist approved-paths.txt \
  --confirm-authorized \
  --max-requests 100 \
  --delay 0.5
```

Save a report:

```bash
firebox web enumerate \
  --url https://chukanest.co.ke \
  --wordlist approved-paths.txt \
  --confirm-authorized \
  --max-requests 100 \
  --delay 0.5 \
  --report reports/path-enumeration.json
```

= API documentation discovery

`api discover` checks standard OpenAPI and Swagger documentation paths, or up to eight paths you explicitly provide. It performs bounded read-only `GET` requests. It does not crawl, authenticate, brute-force endpoints, or call state-changing methods.

```bash
firebox api discover --url https://chukanest.co.ke

firebox api discover \
  --url https://chukanest.co.ke \
  --paths /openapi.json,/swagger.json,/api/docs \
  --report reports/chukanest-api-discovery.json

firebox api discover --url https://chukanest.co.ke --json
```

= Authentication log analysis

Analyze a supplied Linux authentication log for repeated failures, targeted usernames, suspicious sources, and successful logins following failures.

```bash
# Included synthetic fixture
firebox logs samples/sample-auth.log

# Custom threshold
firebox logs samples/sample-auth.log --threshold 3

# Authorized system log, if readable by the current user
firebox logs /var/log/auth.log --report reports/auth-analysis.json
```

No root access is required for a readable supplied file. Do not weaken permissions on protected logs.

= Password, token, and hash commands

== Secure password generation

Generated secrets are printed to stdout only. They are not written to application logs.

```bash
firebox password generate --length 20
firebox password generate --length 32
```

Supported length: 12–256 characters.

== Password strength

Use test values rather than real production passwords in shell history.

```bash
firebox password strength --password 'Example-Test-Password-2026!'
firebox password strength --password 'Use-a-test-value-only'
```

== Secure token generation

```bash
firebox password token --length 32
firebox password token --length 64
```

Supported length: 16–256 bytes.

== SHA-256 hash generation

```bash
firebox hash README.md
firebox hash generate --file README.md
firebox hash README.md --report reports/readme-hash.json
```

== SHA-256 verification

```bash
firebox hash verify \
  --file README.md \
  --expected YOUR_EXPECTED_SHA256_HASH

firebox hash verify \
  --file README.md \
  --expected "$(sha256sum README.md | awk '{print $1}')"
```

= File integrity monitoring

== Create a baseline

Baselines are not overwritten unless `--force` is provided.

```bash
firebox integrity baseline \
  --path samples \
  --baseline data/samples-baseline.json

firebox integrity baseline \
  --path /path/to/monitored-directory \
  --baseline /secure/path/firebox-baseline.json
```

== Compare against a baseline

```bash
firebox integrity scan \
  --path samples \
  --baseline data/samples-baseline.json

firebox integrity scan \
  --path /path/to/monitored-directory \
  --baseline /secure/path/firebox-baseline.json \
  --json
```

Reports identify modified, added, missing, and unreadable-file conditions where applicable.

= Metadata and system commands

== File metadata

```bash
firebox metadata inspect --file README.md
firebox metadata inspect --file /path/to/authorized/document.pdf
firebox metadata inspect --file /path/to/image.jpg --json
```

The current metadata command reports existence, size, a type hint, and SHA-256. It does not claim to extract all PDF or image EXIF fields.

== System information

```bash
firebox system info
firebox system info --json
```

= Wi-Fi and PCAP commands

These are local defensive diagnostics only. They do not scan nearby networks, crack keys, capture credentials, inject frames, or deauthenticate clients. Azure cloud VMs commonly have no wireless adapter.

== Wireless interface status

```bash
firebox wifi status
firebox wifi status --json
```

If no local wireless interface is present, the result explains that the host may be a wired-only or cloud VM.

== Read-only interface audit

Use the actual local wireless interface name, if one exists.

```bash
firebox wifi audit --interface wlan0
firebox wifi audit --interface wlan0 --json
```

The command reads local interface state and, when available, read-only `iw` link information.

== PCAP metadata

Use a real authorized classic PCAP file. The example filename must exist.

```bash
find ~ -type f \( -name '*.pcap' -o -name '*.pcapng' \) -print
firebox wifi pcap --file /actual/path/to/capture.pcap
firebox wifi pcap --file /actual/path/to/capture.pcap --json
```

The current parser reports classic PCAP metadata and packet record lengths. It does not decode payloads or extract credentials and limits input to 256 MiB.

= Phishing-awareness commands

These commands are defensive. Analysis is static and never opens links. Templates are synthetic and non-deliverable.

== Analyze an email file

The repository includes a safe synthetic sample.

```bash
firebox phishing analyze --file samples/suspicious-email.eml
firebox phishing analyze \
  --file samples/suspicious-email.eml \
  --report reports/phishing-analysis.json
firebox phishing analyze --file suspicious-email.eml --json
```

The analyzer checks From/Reply-To differences, authentication-result headers, urgency language, non-HTTPS links, non-ASCII hostnames, and attachments.

== Generate a synthetic training template

```bash
firebox phishing template --scenario account-alert
firebox phishing template --scenario suspicious-invoice --output reports/training-template.txt
firebox phishing template --scenario delivery-notice --output reports/delivery-training.txt
```

Allowed scenarios are `suspicious-invoice`, `account-alert`, and `delivery-notice`. Output contains no real-brand impersonation, live links, tracking, credential collection, or delivery mechanism.

= Vulnerability records

The vulnerability database is local SQLite at `data/firebox.db` by default.

== Add a finding

```bash
firebox vulns add \
  --title 'Missing security header' \
  --severity medium \
  --asset 'https://your-authorized-domain.example' \
  --evidence 'The authorized passive assessment did not observe CSP' \
  --remediation 'Configure and test an appropriate CSP policy'
```

Allowed severity values: `critical`, `high`, `medium`, `low`, `info`.

Add a status explicitly:

```bash
firebox vulns add \
  --title 'Outdated package' \
  --severity high \
  --asset 'authorized-server' \
  --evidence 'Installed version is below the approved baseline' \
  --remediation 'Upgrade and verify dependent services' \
  --status in-progress
```

Allowed statuses: `open`, `in-progress`, `resolved`.

== List findings

```bash
firebox vulns list
firebox vulns list --status open
firebox vulns list --status in-progress
firebox vulns list --status resolved
firebox vulns list --json
```

= Safe defensive replacement tools

These commands provide defensive alternatives to tracking, cracking, stealth, exploitation, and data-theft tools. They are intentionally limited to format validation, passive inspection, or local user-supplied files.

== Phone-number format validation

This checks formatting only. It does not identify a person, locate a phone, query a carrier, or perform surveillance.

```bash
firebox phone validate --number '+254700000000'
firebox phone validate --number '+254700000000' --json
```

== Passive CMS and technology inspection

This uses observable response headers only. It does not crawl or exploit the site and does not claim positive identification when evidence is inconclusive.

```bash
firebox cms inspect --url https://your-authorized-domain.example
firebox cms inspect --url https://your-authorized-domain.example --json
```

== PDF information

Inspect a user-supplied PDF signature, version, size, and SHA-256 hash.

```bash
firebox document pdf-info --file report.pdf
firebox document pdf-info --file report.pdf --json
```

== Optional local OCR

OCR uses the locally installed Tesseract executable when available. If it is missing, Firebox reports that clearly instead of pretending extraction occurred.

```bash
firebox document ocr --file image.png
firebox document ocr --file scanned-document.jpg --json
```

== Local process inventory

This reports local process names, PIDs, and UIDs. It does not automatically label a process malicious or terminate anything.

```bash
firebox system processes
firebox system processes --json
```

== Read-only VPN configuration check

Review an authorized VPN configuration without modifying it or printing credentials.

```bash
firebox config vpn-check --file vpn.conf
firebox config vpn-check --file vpn.conf --json
```

= Manual Python plugins

Trusted Python files placed in `plugins/` are loaded automatically at startup. The plugin directory contains the full contract in `plugins/README.md`.

Create a plugin:

```python
# plugins/system_check.py

def register(subparsers):
    parser = subparsers.add_parser("system-check", help="Run a custom system check")
    parser.add_argument("--path", default="/etc/os-release")
    parser.set_defaults(_plugin_handler=run)


def run(args):
    with open(args.path, "r", encoding="utf-8") as file:
        content = file.read(4096)
    return {"plugin": "system-check", "path": args.path, "readable": True, "preview": content}
```

Use it:

```bash
firebox plugins list
firebox system-check --help
firebox system-check --path /etc/hostname
```

Use a separate plugin directory:

```bash
FIREBOX_PLUGIN_DIR=/secure/path/plugins firebox plugins list
```

Plugins execute with the same operating-system permissions as the current user. Review source before use. A plugin can read files, make network connections, modify data, or execute arbitrary Python code. Built-in commands do not depend on plugins.

= Output, reports, and colors

Readable text is the default. Use JSON for automation:

```bash
firebox scan 127.0.0.1 --json
firebox web audit --url https://your-authorized-domain.example --json
```

Use `--report PATH` where the command supports it:

```bash
firebox web audit --url https://your-authorized-domain.example --report reports/audit.json
firebox api discover --url https://your-authorized-domain.example --report reports/api.json
```

Colors are enabled in interactive terminals. They are disabled for redirected output, JSON, and `NO_COLOR=1`:

```bash
NO_COLOR=1 firebox scan 127.0.0.1
```

= Production safety checklist

Before any network or web operation:

- Confirm written authorization and the exact target scope.
- Prefer a staging environment with synthetic data.
- Use narrow paths, small port lists, and conservative timeouts.
- Preserve reports securely; do not commit private logs or scan results.
- Do not expose a dashboard or plugin directory publicly.
- Never put production passwords, tokens, or API keys in command history or reports.
- Treat every manually added plugin as executable code and review it first.

This guide describes the implemented Firebox behavior. It does not claim that passive checks prove exploitability or replace a full authorized penetration test.
