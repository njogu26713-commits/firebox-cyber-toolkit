from __future__ import annotations

import os
import struct
import subprocess
from pathlib import Path


def _interfaces() -> list[dict]:
    result = []
    for path in sorted(Path("/sys/class/net").glob("*")):
        wireless = (path / "wireless").exists()
        if not wireless:
            continue
        def read(name: str) -> str | None:
            try:
                return (path / name).read_text(encoding="utf-8").strip()
            except OSError:
                return None
        result.append({
            "interface": path.name,
            "state": read("operstate"),
            "mac_address": read("address"),
            "wireless": True,
        })
    return result


def status() -> dict:
    """Return local wireless interfaces only; no nearby-network scan is performed."""
    interfaces = _interfaces()
    result = {"interfaces": interfaces, "scan_performed": False, "scope": "local interface inventory only"}
    if not interfaces:
        result["message"] = "No local wireless interfaces found; this host may be a wired-only or cloud VM."
    return result


def _run_iw(args: list[str]) -> str | None:
    try:
        completed = subprocess.run(["iw", *args], capture_output=True, text=True, timeout=4, check=False)
        if completed.returncode == 0:
            return completed.stdout.strip()
        return completed.stderr.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def audit(interface: str) -> dict:
    if not interface or "/" in interface or any(char.isspace() for char in interface):
        raise ValueError("interface must be a local interface name")
    path = Path("/sys/class/net") / interface
    if not path.exists() or not (path / "wireless").exists():
        raise ValueError(f"wireless interface not found: {interface}")
    info = next(item for item in _interfaces() if item["interface"] == interface)
    link_output = _run_iw(["dev", interface, "link"])
    info.update({
        "connected": bool(link_output and "Not connected" not in link_output),
        "iw_available": link_output is not None,
        "link_details": link_output,
        "attack_actions_performed": False,
        "scope": "read-only local interface audit",
    })
    return info


def pcap_metadata(file: str) -> dict:
    """Read only the capture header and record lengths; never decodes payloads."""
    path = Path(file).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"capture file not found: {path}")
    if path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("refusing packet captures larger than 256 MiB")
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24:
            raise ValueError("file is not a complete classic PCAP file")
        magic = header[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }
        if magic not in formats:
            raise ValueError("unsupported capture format; expected classic PCAP")
        endian = formats[magic]
        version_major, version_minor, _zone, _sigfigs, snaplen, network = struct.unpack(endian + "HHiiii", header[4:24])
        packets = 0
        captured_bytes = 0
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("truncated packet header")
            _sec, _usec, included, _original = struct.unpack(endian + "IIII", packet_header)
            handle.seek(included, os.SEEK_CUR)
            packets += 1
            captured_bytes += included
        return {
            "file": str(path),
            "format": "classic-pcap",
            "version": f"{version_major}.{version_minor}",
            "snaplen": snaplen,
            "link_type": network,
            "packet_count": packets,
            "captured_bytes": captured_bytes,
            "payloads_decoded": False,
            "scope": "metadata and record lengths only; no credential or payload extraction",
        }
