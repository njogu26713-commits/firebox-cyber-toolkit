from __future__ import annotations
import datetime, http.client, socket, ssl, urllib.parse
from firebox.core import utc_now

REQUIRED = {"strict-transport-security":"HSTS", "content-security-policy":"CSP", "x-content-type-options":"X-Content-Type-Options", "referrer-policy":"Referrer-Policy"}

def check(url: str, timeout: float = 8.0) -> dict:
    parsed=urllib.parse.urlparse(url)
    if parsed.scheme not in {"http","https"} or not parsed.hostname: raise ValueError("URL must include http:// or https:// and a hostname")
    host=parsed.hostname; port=parsed.port or (443 if parsed.scheme=="https" else 80); path=parsed.path or "/"; conn=None
    try:
        if parsed.scheme == "https": conn=http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context())
        else: conn=http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("HEAD", path, headers={"User-Agent":"FireboxCyberToolkit/0.1", "Accept":"*/*"}); response=conn.getresponse(); headers={k.lower():v for k,v in response.getheaders()}
        certificate = {"validated": parsed.scheme == "https", "expires_at": None, "days_until_expiry": None}
        if parsed.scheme == "https" and conn.sock:
            peer = conn.sock.getpeercert()
            if peer.get("notAfter"):
                expiry = datetime.datetime.strptime(peer["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                certificate["expires_at"] = expiry.isoformat()
                certificate["days_until_expiry"] = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
        location = headers.get("location")
        return {"checked_at":utc_now(),"url":url,"status":response.status,"reason":response.reason,"headers":headers,"https":parsed.scheme=="https","tls_certificate":certificate,"http_to_https_redirect":parsed.scheme=="http" and bool(location and location.lower().startswith("https://")),"security_headers":{"present":[REQUIRED[k] for k in REQUIRED if k in headers],"missing":[v for k,v in REQUIRED.items() if k not in headers]},"redirect_location":location,"cookies":[v for k,v in response.getheaders() if k.lower()=="set-cookie"],"error":None}
    except (OSError, ssl.SSLError, socket.timeout, http.client.HTTPException) as exc: return {"checked_at":utc_now(),"url":url,"error":str(exc)}
    finally:
        if conn: conn.close()
