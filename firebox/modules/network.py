from __future__ import annotations
import concurrent.futures, ipaddress, socket
from dataclasses import asdict, dataclass
from typing import Iterable

@dataclass
class PortResult:
    host: str
    port: int
    open: bool
    service: str | None
    error: str | None = None

def resolve(domain: str) -> dict:
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in infos})
        return {"domain": domain, "addresses": addresses, "error": None}
    except socket.gaierror as exc:
        return {"domain": domain, "addresses": [], "error": str(exc)}

def validate_target(target: str) -> None:
    if not target or len(target) > 253 or any(c.isspace() for c in target):
        raise ValueError("target must be a hostname or IP address")

def check_port(target: str, port: int, timeout: float = 2.0) -> PortResult:
    validate_target(target)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    try:
        with socket.create_connection((target, port), timeout=timeout):
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = None
            return PortResult(target, port, True, service)
    except (OSError, ValueError) as exc:
        return PortResult(target, port, False, None, str(exc))

def scan(target: str, ports: Iterable[int], timeout: float = 2.0, workers: int = 8) -> dict:
    validate_target(target)
    ports = list(ports)
    if len(ports) > 1024:
        raise ValueError("refusing scans larger than 1024 ports")
    workers = max(1, min(int(workers), 32))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda p: check_port(target, p, timeout), ports))
    return {"target": target, "ports": [asdict(r) for r in results], "open_ports": [r.port for r in results if r.open], "timeout_seconds": timeout}
