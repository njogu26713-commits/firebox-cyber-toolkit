# Firebox Cyber Toolkit

Firebox is a lightweight, production-oriented Python CLI for authorized defensive security work. It performs real local file, log, hash, integrity, DNS, TCP connectivity, HTTPS, metadata, system-information, and vulnerability-record operations. It does not exploit vulnerabilities, crack credentials, change firewall/SSH settings, or scan arbitrary targets without an operator explicitly providing a target.

## Install on Ubuntu 24.04

```bash
sudo apt-get update && sudo apt-get install -y git python3 python3-venv
git clone https://github.com/njogu26713-commits/firebox-cyber-toolkit.git
cd firebox-cyber-toolkit
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
firebox --help
```

No external runtime dependency is required. The optional dashboard and OCR integration are intentionally not enabled in this initial production CLI release. Run commands only against assets you own or are authorized to assess.

### If `.venv/bin/activate` does not exist

The virtual environment is local to each server and is intentionally not stored in Git. From the repository directory, create it before activating it:

```bash
sudo apt-get update
sudo apt-get install -y python3-venv
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

If `.venv` is present but incomplete, remove only that local environment and recreate it; this does not remove repository files:

```bash
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
```

## First operations

```bash
firebox scan 127.0.0.1 --ports 22,80,443
firebox ports 127.0.0.1 --ports 22,80,443
firebox dns example.com
firebox web https://your-authorized-site.example
firebox vuln-scan https://your-authorized-site.example
firebox logs samples/sample-auth.log
firebox hash README.md
firebox system info
firebox wifi status
firebox wifi audit --interface wlan0
firebox wifi pcap --file authorized-capture.pcap
firebox phishing analyze --file samples/suspicious-email.eml
firebox phishing template --scenario account-alert --output reports/training-template.txt
firebox api discover --url https://your-authorized-domain.example
firebox plugins list
firebox web enumerate --url https://your-authorized-domain.example --wordlist approved-paths.txt --confirm-authorized
```

Results are human-readable by default. Add `--json` only when another program needs machine-readable output, and add `--report PATH` when a JSON report file is required. The longer forms such as `firebox network scan --target HOST` remain supported.

`firebox vuln-scan URL` is a bounded passive web assessment. It checks the base URL and, only when explicitly supplied, up to eight known paths for TLS, security headers, cookie attributes, server errors, and certificate expiry. It does not crawl, fuzz, brute-force, authenticate, exploit, or submit destructive payloads. It must not be described as a complete penetration test or a full vulnerability scanner.

Wi-Fi commands are intentionally defensive and local-only. They do not scan nearby networks, capture credentials, crack keys, inject frames, deauthenticate clients, or perform wireless attack actions. PCAP analysis reads only capture metadata and record lengths.

Phishing commands are defensive only. Email analysis is static and does not open links or send mail. Templates are clearly marked synthetic awareness material and contain no real-brand impersonation, credential collection, tracking, delivery mechanism, or active phishing links.

API discovery checks standard API documentation paths such as `/openapi.json` and `/swagger.json`, or up to eight paths explicitly supplied with `--paths`. It uses bounded read-only requests and does not crawl, brute-force endpoints, authenticate, or make state-changing API calls.

For an authorized, read-only path enumeration, provide your own approved wordlist and explicit confirmation:

```bash
firebox web enumerate \
  --url https://your-authorized-domain.example \
  --wordlist approved-paths.txt \
  --confirm-authorized \
  --max-requests 100 \
  --delay 0.5
```

This command is sequential, capped at 500 requests, requires at least 0.1 seconds between requests, and uses only `HEAD`. It does not perform credential/password brute force, Wi-Fi attacks, API mutations, payload injection, crawling, or destructive actions.

## Manual Python plugins

Add trusted Python files to the repository’s `plugins/` directory. Each file must define `register(subparsers)`, add its command parser, and set `_plugin_handler` to a function that accepts parsed arguments and returns a JSON-serializable result. See [plugins/README.md](plugins/README.md) for the exact contract. Then run:

```bash
firebox plugins list
firebox your-command --help
```

Plugins execute with the same operating-system permissions as the current user. Review plugin source before using it; a plugin can read files, make network connections, and execute arbitrary Python code. Built-in commands do not depend on plugins.

Human-readable output is colored automatically in an interactive terminal. Color is disabled when output is redirected, when using `--json`, or when the standard `NO_COLOR=1` environment variable is set:

```bash
NO_COLOR=1 firebox scan 127.0.0.1 --ports 22,80,443
```

Generated passwords and tokens are written only to stdout and are never logged by the application. Store them securely.

## Commands

See [docs/COMMANDS.md](docs/COMMANDS.md) for the complete command reference. Reports are JSON and can be written with `--report PATH`. Network scans have bounded concurrency and a maximum of 1,024 explicitly supplied ports. HTTPS checks use certificate validation and safe HEAD requests; they do not submit payloads. Integrity baselines refuse to overwrite existing files unless `--force` is provided.

## Security scope and limitations

The operator is responsible for authorization, target scope, rate limits, and applicable law. DNS and TCP operations may produce network traffic. Web checks are passive and limited to response headers, cookies, redirects, and TLS connection validation. Technology identification and OSINT enrichment are not included unless evidence-backed implementations are added and tested. Do not expose a dashboard publicly without authentication. Never commit secrets, private logs, or scan results.

## Development

The test suite uses synthetic logs, temporary files, and a local TCP server; it does not require external websites or internet access. Contributions must include tests and documentation for any new advertised feature.
