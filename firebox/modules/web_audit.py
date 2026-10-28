from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from firebox.core import utc_now
from firebox.modules.web_security import check

DEFAULT_PATHS = ["/"]


def _paths(value: str | None) -> list[str]:
    values = DEFAULT_PATHS if not value else [item.strip() for item in value.split(",") if item.strip()]
    if not values or len(values) > 8:
        raise ValueError("provide between 1 and 8 explicit paths")
    result = []
    for path in values:
        if not path.startswith("/") or ".." in path or len(path) > 200:
            raise ValueError("paths must be absolute URL paths without '..'")
        result.append(path)
    return result


def _url_for_path(url: str, path: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _finding(severity: str, title: str, url: str, evidence: str, remediation: str) -> dict:
    return {"severity": severity, "title": title, "url": url, "evidence": evidence, "remediation": remediation}


def audit(url: str, paths: str | None = None, timeout: float = 8.0) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include http:// or https:// and a hostname")
    requested_paths = _paths(paths)
    checks = []
    findings = []
    for path in requested_paths:
        target = _url_for_path(url, path)
        result = check(target, timeout)
        checks.append(result)
        if result.get("error"):
            continue
        if result.get("status", 0) >= 500:
            findings.append(_finding("medium", "Server error response", target, f"HTTP status {result['status']}", "Review server logs and application error handling."))
        if result.get("https"):
            missing = result.get("security_headers", {}).get("missing", [])
            for header in missing:
                severity = "medium" if header in {"HSTS", "CSP"} else "low"
                findings.append(_finding(severity, f"Missing {header} header", target, f"The response did not include {header}.", f"Configure and test an appropriate {header} policy for this application."))
            certificate = result.get("tls_certificate", {})
            days = certificate.get("days_until_expiry")
            if days is not None and days < 30:
                findings.append(_finding("high", "TLS certificate expires soon", target, f"Certificate expires in {days} days.", "Renew the certificate and verify automated renewal."))
            elif days is not None and days < 90:
                findings.append(_finding("medium", "TLS certificate renewal due soon", target, f"Certificate expires in {days} days.", "Schedule certificate renewal before expiration."))
        for cookie in result.get("cookies", []):
            lower = cookie.lower()
            name = cookie.split("=", 1)[0]
            if result.get("https") and "secure" not in lower:
                findings.append(_finding("medium", "Cookie missing Secure attribute", target, f"Cookie {name} was set without Secure.", "Set Secure on cookies that must only travel over HTTPS."))
            if "httponly" not in lower:
                findings.append(_finding("low", "Cookie missing HttpOnly attribute", target, f"Cookie {name} was set without HttpOnly.", "Set HttpOnly where client-side JavaScript does not need cookie access."))
            if "samesite" not in lower:
                findings.append(_finding("low", "Cookie missing SameSite attribute", target, f"Cookie {name} was set without SameSite.", "Set an intentional SameSite policy and test application flows."))
    counts = {severity: sum(1 for item in findings if item["severity"] == severity) for severity in ("critical", "high", "medium", "low")}
    return {
        "assessed_at": utc_now(),
        "target": url,
        "paths_assessed": requested_paths,
        "requests_made": len(checks),
        "findings": findings,
        "summary": counts,
        "checks": checks,
        "scope": "Passive, bounded assessment of explicitly supplied paths; no crawling, fuzzing, authentication attacks, exploit payloads, or destructive requests.",
    }
