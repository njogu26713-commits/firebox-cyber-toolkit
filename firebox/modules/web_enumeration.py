from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from firebox.core import utc_now
from firebox.modules.web_security import check


def _load_paths(wordlist: str, maximum: int) -> list[str]:
    source = Path(wordlist).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"wordlist not found: {source}")
    paths = []
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if not value.startswith("/"):
            value = "/" + value
        if ".." in value or "?" in value or "#" in value or len(value) > 200:
            raise ValueError(f"unsafe wordlist path: {value}")
        if value not in paths:
            paths.append(value)
        if len(paths) >= maximum:
            break
    return paths


def enumerate_paths(base_url: str, wordlist: str, max_requests: int = 100, delay: float = 0.5, confirm_authorized: bool = False, timeout: float = 5.0) -> dict:
    if not confirm_authorized:
        raise ValueError("refusing enumeration without --confirm-authorized")
    if not 1 <= max_requests <= 500:
        raise ValueError("max-requests must be between 1 and 500")
    if delay < 0.1:
        raise ValueError("delay must be at least 0.1 seconds")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include http:// or https:// and a hostname")
    paths = _load_paths(wordlist, max_requests)
    results = []
    for index, path in enumerate(paths):
        if index:
            time.sleep(delay)
        target = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
        result = check(target, timeout)
        result["path"] = path
        results.append(result)
    interesting = [item for item in results if item.get("status") not in {None, 404} or item.get("error")]
    return {"enumerated_at": utc_now(), "base_url": base_url, "wordlist": str(Path(wordlist).expanduser().resolve()), "requests_made": len(results), "interesting_results": interesting, "all_results": results, "scope": "Authorized, sequential, bounded read-only HEAD requests; no credentials, payloads, crawling, or state-changing methods.", "authorization_confirmed": True}
