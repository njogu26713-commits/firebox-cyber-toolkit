from __future__ import annotations
import hashlib, json, struct
from pathlib import Path

def inspect(path: str) -> dict:
    p=Path(path).expanduser().resolve(); data={"path":str(p),"exists":p.exists()}
    if not p.is_file(): return data
    data["size_bytes"]=p.stat().st_size; h=hashlib.sha256();
    with p.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    data["sha256"]=h.hexdigest(); data["type_hint"]="PDF" if p.read_bytes()[:5]==b"%PDF-" else "image" if p.suffix.lower() in {".jpg",".jpeg",".png",".gif",".webp"} else "unknown"
    return data
