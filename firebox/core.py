from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def emit(data: Any, as_json: bool = False, _level: int = 0) -> None:
    """Print JSON for integrations or indented text for operators."""
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
        return
    if isinstance(data, dict):
        for key, value in data.items():
            label = str(key).replace('_', ' ').title()
            if isinstance(value, (dict, list)):
                print(f"{'  ' * _level}{label}:")
                emit(value, False, _level + 1)
            else:
                print(f"{'  ' * _level}{label}: {value}")
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, (dict, list)):
                print(f"{'  ' * _level}-")
                emit(value, False, _level + 1)
            else:
                print(f"{'  ' * _level}- {value}")
    else:
        print(data)

def write_report(data: Any, path: str | None) -> None:
    if not path:
        return
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
