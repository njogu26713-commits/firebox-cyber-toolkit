from __future__ import annotations

import http.client
import json
import ssl
from urllib.parse import urlparse, urlunparse

from firebox.core import utc_now

DEFAULT_PATHS = ["/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/v1/openapi.json"]


def _path_list(value: str | None) -> list[str]:
    paths = DEFAULT_PATHS if not value else [item.strip() for item in value.split(",") if item.strip()]
    if not paths or len(paths) > 8:
        raise ValueError("provide between 1 and 8 API documentation paths")
    for path in paths:
        if not path.startswith("/") or ".." in path or len(path) > 200:
            raise ValueError("API paths must be absolute paths without '..'")
    return paths


def _check(url: str, timeout: float) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host or parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must include http:// or https:// and a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection = None
    try:
        if parsed.scheme == "https":
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request("GET", parsed.path or "/", headers={"User-Agent": "FireboxCyberToolkit/0.1", "Accept": "application/json, text/yaml, text/plain;q=0.8"})
        response = connection.getresponse()
        body = response.read(128 * 1024)
        content_type = response.getheader("Content-Type", "")
        text = body.decode("utf-8", errors="replace")
        markers = []
        if '"openapi"' in text or "openapi:" in text:
            markers.append("OpenAPI")
        if '"swagger"' in text or "swagger:" in text:
            markers.append("Swagger")
        valid_json = False
        if "json" in content_type.lower():
            try:
                json.loads(text)
                valid_json = True
            except json.JSONDecodeError:
                pass
        return {"url": url, "status": response.status, "reason": response.reason, "content_type": content_type, "content_length_bytes": len(body), "documentation_markers": markers, "valid_json": valid_json, "error": None}
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return {"url": url, "status": None, "error": str(exc)}
    finally:
        if connection:
            connection.close()


def discover(base_url: str, paths: str | None = None, timeout: float = 5.0) -> dict:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include http:// or https:// and a hostname")
    selected = _path_list(paths)
    results = []
    for path in selected:
        target = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
        results.append(_check(target, timeout))
    found = [item for item in results if item.get("status") == 200]
    return {"checked_at": utc_now(), "base_url": base_url, "paths_checked": selected, "requests_made": len(results), "documents_found": found, "results": results, "scope": "Read-only bounded checks of API documentation paths; no crawling, endpoint brute force, authentication, or state-changing requests."}
