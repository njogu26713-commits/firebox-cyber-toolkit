from __future__ import annotations
import json, sqlite3
from pathlib import Path
from firebox.core import utc_now

class VulnerabilityDB:
    def __init__(self, path: str = "data/firebox.db"):
        self.path = Path(path).expanduser(); self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, asset TEXT NOT NULL, evidence TEXT NOT NULL, remediation TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)")
    def add(self, title, severity, asset, evidence, remediation, status="open"):
        if severity not in {"critical","high","medium","low","info"}: raise ValueError("invalid severity")
        if status not in {"open","in-progress","resolved"}: raise ValueError("invalid status")
        with sqlite3.connect(self.path) as db: cur = db.execute("INSERT INTO findings(title,severity,asset,evidence,remediation,status,created_at) VALUES(?,?,?,?,?,?,?)", (title,severity,asset,evidence,remediation,status,utc_now())); return cur.lastrowid
    def list(self, status=None):
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
            q="SELECT * FROM findings"; args=()
            if status: q += " WHERE status=?"; args=(status,)
            q += " ORDER BY id DESC"; return [dict(x) for x in db.execute(q,args)]
