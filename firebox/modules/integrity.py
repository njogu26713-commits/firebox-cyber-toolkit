from __future__ import annotations
import hashlib, json
from pathlib import Path
from firebox.core import utc_now

def hashes(root: str) -> dict[str, str]:
    base = Path(root).expanduser().resolve()
    if not base.exists(): raise FileNotFoundError(root)
    files = [base] if base.is_file() else sorted(p for p in base.rglob('*') if p.is_file() and not p.is_symlink())
    result = {}
    for path in files:
        try:
            h = hashlib.sha256()
            with path.open('rb') as f:
                for chunk in iter(lambda: f.read(1024*1024), b''): h.update(chunk)
            result[str(path.relative_to(base.parent if base.is_file() else base))] = h.hexdigest()
        except OSError: continue
    return result

def create_baseline(path: str, baseline: str, force: bool = False) -> dict:
    dest = Path(baseline).expanduser().resolve()
    if dest.exists() and not force: raise FileExistsError(f"baseline exists: {dest}; pass --force to replace")
    data = {"created_at": utc_now(), "path": str(Path(path).expanduser().resolve()), "files": hashes(path)}
    dest.parent.mkdir(parents=True, exist_ok=True); dest.write_text(json.dumps(data, indent=2) + '\n')
    return data

def compare(path: str, baseline: str) -> dict:
    data = json.loads(Path(baseline).read_text()); current = hashes(path); old = data.get('files', {})
    return {"path": str(Path(path).expanduser().resolve()), "modified": sorted(k for k in current.keys() & old.keys() if current[k] != old[k]), "added": sorted(current.keys() - old.keys()), "missing": sorted(old.keys() - current.keys())}
