from __future__ import annotations

import re
from email import policy
from email.parser import Parser
from pathlib import Path
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
URGENCY_TERMS = ("urgent", "immediately", "within 24 hours", "suspended", "verify now", "final notice", "act now")


def _finding(severity: str, title: str, evidence: str, recommendation: str) -> dict:
    return {"severity": severity, "title": title, "evidence": evidence, "recommendation": recommendation}


def analyze(path: str) -> dict:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"email file not found: {source}")
    raw = source.read_text(encoding="utf-8", errors="replace")
    message = Parser(policy=policy.default).parsestr(raw)
    findings = []
    sender = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    if sender and reply_to and sender.lower() != reply_to.lower():
        findings.append(_finding("medium", "From and Reply-To differ", f"From: {sender}; Reply-To: {reply_to}", "Verify the sender through an independent trusted channel."))
    auth = message.get("Authentication-Results", "")
    if not auth:
        findings.append(_finding("info", "Authentication results not supplied", "No Authentication-Results header was present in the supplied message.", "Review SPF, DKIM, and DMARC results in the receiving mail system."))
    subject = message.get("Subject", "")
    body = message.get_body(preferencelist=("plain", "html"))
    body_text = body.get_content() if body else raw
    combined = f"{subject}\n{body_text}"
    matches = [term for term in URGENCY_TERMS if term in combined.lower()]
    if matches:
        findings.append(_finding("low", "Urgency language detected", ", ".join(sorted(set(matches))), "Do not bypass normal verification procedures because of urgency."))
    urls = URL_RE.findall(combined)
    domains = sorted({urlparse(url.rstrip(".,);" )).hostname for url in urls if urlparse(url.rstrip(".,);" )).hostname})
    for url in urls:
        parsed = urlparse(url.rstrip(".,);"))
        if parsed.scheme != "https":
            findings.append(_finding("medium", "Link is not HTTPS", url, "Avoid entering information on an unencrypted link; navigate using a trusted bookmark instead."))
        if parsed.hostname and any(ord(char) > 127 for char in parsed.hostname):
            findings.append(_finding("high", "Link contains non-ASCII hostname characters", url, "Treat possible lookalike or homograph domains as suspicious."))
    attachments = [part.get_filename() for part in message.walk() if part.get_filename()]
    if attachments:
        findings.append(_finding("medium", "Attachment present", ", ".join(attachments), "Verify the sender and scan attachments through approved security controls before opening."))
    return {"file": str(source), "subject": subject, "from": sender, "reply_to": reply_to, "urls": urls, "domains": domains, "attachments": attachments, "findings": findings, "scope": "Static analysis only; no links were opened and no messages were sent."}


def template(scenario: str) -> str:
    allowed = {"suspicious-invoice", "account-alert", "delivery-notice"}
    if scenario not in allowed:
        raise ValueError(f"scenario must be one of: {', '.join(sorted(allowed))}")
    titles = {"suspicious-invoice": "Synthetic Training Example: Invoice Review", "account-alert": "Synthetic Training Example: Account Alert", "delivery-notice": "Synthetic Training Example: Delivery Notice"}
    return (f"TRAINING ONLY — SYNTHETIC PHISHING-AWARENESS EXAMPLE\n"
            f"Scenario: {scenario}\n\n"
            f"Subject: {titles[scenario]}\n\n"
            "This message is a non-deliverable awareness exercise. It contains no real brand, sender, credential form, tracking pixel, or active URL.\n\n"
            "Review questions:\n"
            "1. Is the sender expected and independently verifiable?\n"
            "2. Does the message create unusual urgency?\n"
            "3. Are links or attachments expected and approved?\n"
            "4. What trusted channel should be used to verify the request?\n")
