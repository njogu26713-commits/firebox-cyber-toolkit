from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from firebox.modules.web_security import check as web_check


def phone_validate(number: str) -> dict:
    normalized = re.sub(r"[\s().-]", "", number)
    valid = bool(re.fullmatch(r"\+?[1-9]\d{7,14}", normalized))
    return {"input": number, "normalized": normalized, "valid_format": valid, "scope": "format validation only; no identity, location, or carrier lookup"}


def cms_inspect(url: str) -> dict:
    result = web_check(url)
    if result.get("error"):
        return {"url": url, "error": result["error"], "technologies": [], "scope": "passive response-header inspection only"}
    headers = result.get("headers", {})
    evidence = []
    technologies = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    for value, label in ((server, "server"), (powered, "x-powered-by")):
        if value:
            evidence.append({"source": label, "value": value})
            technologies.append({"technology": value, "confidence": "observed", "evidence": label})
    indicators = {"x-drupal-cache": "Drupal indicator", "x-generator": "Generator indicator", "x-wp-total": "WordPress REST indicator"}
    for header, label in indicators.items():
        if header in headers:
            evidence.append({"source": header, "value": headers[header]})
            technologies.append({"technology": label, "confidence": "possible", "evidence": header})
    return {"url": url, "status": result.get("status"), "technologies": technologies, "evidence": evidence, "scope": "passive response-header inspection only; no crawling or exploitation"}


def pdf_info(file: str) -> dict:
    path = Path(file).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")
    with path.open("rb") as handle:
        header = handle.read(8)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"file": str(path), "is_pdf": header.startswith(b"%PDF-"), "pdf_version": header[5:8].decode("ascii", errors="replace") if header.startswith(b"%PDF-") else None, "size_bytes": path.stat().st_size, "sha256": digest, "scope": "file signature and hash inspection"}


def ocr_extract(file: str) -> dict:
    path = Path(file).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"file not found: {path}")
    executable = shutil.which("tesseract")
    if not executable:
        return {"file": str(path), "available": False, "text": None, "message": "Optional OCR dependency 'tesseract' is not installed.", "scope": "local user-supplied file only"}
    try:
        completed = subprocess.run([executable, str(path), "stdout"], capture_output=True, text=True, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        return {"file": str(path), "available": True, "text": None, "error": "OCR timed out", "scope": "local user-supplied file only"}
    return {"file": str(path), "available": True, "text": completed.stdout if completed.returncode == 0 else None, "error": completed.stderr.strip() if completed.returncode else None, "scope": "local user-supplied file only"}


def process_audit() -> dict:
    processes = []
    proc = Path("/proc")
    for entry in sorted(proc.iterdir(), key=lambda item: item.name):
        if not entry.name.isdigit():
            continue
        try:
            command = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
            state = (entry / "status").read_text(encoding="utf-8", errors="replace")
            user = next((line.split(":", 1)[1].strip() for line in state.splitlines() if line.startswith("Uid:")), None)
            processes.append({"pid": int(entry.name), "command": command, "uid": user})
        except OSError:
            continue
    return {"process_count": len(processes), "processes": processes, "scope": "local process inventory; no process is labeled malicious automatically"}


def vpn_audit(file: str) -> dict:
    path = Path(file).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"VPN configuration not found: {path}")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    lowered = [line.strip().lower() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    findings = []
    if any(line.startswith("auth-user-pass") and len(line.split()) > 1 for line in lowered):
        findings.append({"severity": "high", "title": "Inline VPN credential reference", "evidence": "auth-user-pass includes a filename or inline value", "remediation": "Use a protected credential mechanism and never commit secrets."})
    if not any(line.startswith("remote ") for line in lowered):
        findings.append({"severity": "medium", "title": "No remote endpoint observed", "evidence": "The configuration has no remote directive", "remediation": "Verify the profile is complete before deployment."})
    if any(line.startswith("cipher ") and any(old in line for old in ("des", "3des", "bf-cbc")) for line in lowered):
        findings.append({"severity": "high", "title": "Legacy cipher directive", "evidence": "A legacy cipher name was observed", "remediation": "Use the VPN provider's current authenticated encryption profile."})
    return {"file": str(path), "lines_reviewed": len(lines), "findings": findings, "secrets_printed": False, "scope": "read-only configuration review; configuration was not modified"}
