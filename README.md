# Firebox Cyber Toolkit

Firebox is a lightweight, production-oriented Python CLI for authorized defensive security work. It performs real local file, log, hash, integrity, DNS, TCP connectivity, HTTPS, metadata, system-information, and vulnerability-record operations. It does not exploit vulnerabilities, crack credentials, change firewall/SSH settings, or scan arbitrary targets without an operator explicitly providing a target.

## Install on Ubuntu 24.04

```bash
sudo apt-get update && sudo apt-get install -y git python3 python3-venv
 git clone https://github.com/njogu26713-commits/firebox-cyber-toolkit.git
cd firebox-cyber-toolkit
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
python3 app.py --help
```

No external runtime dependency is required. The optional dashboard and OCR integration are intentionally not enabled in this initial production CLI release. Run commands only against assets you own or are authorized to assess.

## First operations

```bash
python3 app.py password generate --length 20
python3 app.py hash generate --file README.md --json
python3 app.py network scan --target 127.0.0.1 --ports 22,80,443 --json --report reports/localhost.json
python3 app.py logs analyze --file samples/sample-auth.log --threshold 5 --json
python3 app.py integrity baseline --path samples --baseline data/samples-baseline.json
python3 app.py integrity scan --path samples --baseline data/samples-baseline.json --json
python3 app.py system info --json
```

Generated passwords and tokens are written only to stdout and are never logged by the application. Store them securely.

## Commands

See [docs/COMMANDS.md](docs/COMMANDS.md) for the complete command reference. Reports are JSON and can be written with `--report PATH`. Network scans have bounded concurrency and a maximum of 1,024 explicitly supplied ports. HTTPS checks use certificate validation and safe HEAD requests; they do not submit payloads. Integrity baselines refuse to overwrite existing files unless `--force` is provided.

## Security scope and limitations

The operator is responsible for authorization, target scope, rate limits, and applicable law. DNS and TCP operations may produce network traffic. Web checks are passive and limited to response headers, cookies, redirects, and TLS connection validation. Technology identification and OSINT enrichment are not included unless evidence-backed implementations are added and tested. Do not expose a dashboard publicly without authentication. Never commit secrets, private logs, or scan results.

## Development

The test suite uses synthetic logs, temporary files, and a local TCP server; it does not require external websites or internet access. Contributions must include tests and documentation for any new advertised feature.
