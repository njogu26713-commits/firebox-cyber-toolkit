from __future__ import annotations
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _color_enabled() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _paint(value: object, code: str, enabled: bool) -> str:
    return f"\033[{code}m{value}\033[0m" if enabled else str(value)


def emit(data: Any, as_json: bool = False, _level: int = 0, _colors: bool | None = None) -> None:
    """Print JSON for integrations or indented text for operators."""
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
        return
    if _colors is None:
        _colors = _color_enabled()
    if isinstance(data, dict):
        for key, value in data.items():
            label = str(key).replace('_', ' ').title()
            if isinstance(value, (dict, list)):
                print(f"{'  ' * _level}{_paint(label, '36', _colors)}:")
                emit(value, False, _level + 1, _colors)
            else:
                if isinstance(value, bool):
                    rendered = _paint(value, '32' if value else '31', _colors)
                elif key in {'error', 'missing'} and value:
                    rendered = _paint(value, '31', _colors)
                else:
                    rendered = str(value)
                print(f"{'  ' * _level}{_paint(label, '36', _colors)}: {rendered}")
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, (dict, list)):
                print(f"{'  ' * _level}{_paint('-', '33', _colors)}")
                emit(value, False, _level + 1, _colors)
            else:
                print(f"{'  ' * _level}{_paint('-', '33', _colors)} {value}")
    else:
        print(data)

def write_report(data: Any, path: str | None) -> None:
    if not path:
        return
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
