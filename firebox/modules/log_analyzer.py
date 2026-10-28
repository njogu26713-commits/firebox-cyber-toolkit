from __future__ import annotations
import re
from collections import Counter, defaultdict
from pathlib import Path

FAILED = re.compile(r"(?P<date>\w+\s+\d+\s+[\d:]+).*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")
SUCCESS = re.compile(r"(?P<date>\w+\s+\d+\s+[\d:]+).*Accepted \S+ for (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")

def analyze(path: str, threshold: int = 5) -> dict:
    if threshold < 1: raise ValueError("threshold must be positive")
    failed_by_ip, failed_by_user, successes = Counter(), Counter(), []
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines:
        if m := FAILED.search(line): failed_by_ip[m["ip"]] += 1; failed_by_user[m["user"]] += 1
        if m := SUCCESS.search(line): successes.append({"user": m["user"], "ip": m["ip"], "timestamp": m["date"]})
    suspicious = [{"ip": ip, "failed_attempts": count} for ip, count in failed_by_ip.items() if count >= threshold]
    return {"file": str(Path(path).resolve()), "lines": len(lines), "failed_attempts": sum(failed_by_ip.values()), "successful_logins": len(successes), "failed_by_ip": dict(failed_by_ip), "failed_by_username": dict(failed_by_user), "suspicious_sources": suspicious, "successful_logins_after_threshold": [s for s in successes if failed_by_ip[s["ip"]] >= threshold]}
