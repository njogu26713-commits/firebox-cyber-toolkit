from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType
from typing import Any


def plugin_directory() -> Path:
    configured = os.environ.get("FIREBOX_PLUGIN_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    local = Path.cwd() / "plugins"
    if local.is_dir():
        return local.resolve()
    return (Path(__file__).resolve().parents[1] / "plugins").resolve()


def _files() -> list[Path]:
    directory = plugin_directory()
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.glob("*.py") if path.name != "__init__.py" and not path.name.startswith("_"))


def load_plugin(path: Path) -> ModuleType:
    module_name = f"firebox_user_plugin_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if not spec or not spec.loader:
        raise ImportError(f"unable to load plugin: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    register = getattr(module, "register", None)
    if not callable(register):
        raise TypeError("plugin must define register(subparsers)")
    return module


def load_into(subparsers: Any) -> list[dict]:
    loaded = []
    for path in _files():
        try:
            module = load_plugin(path)
            module.register(subparsers)
            loaded.append({"name": path.stem, "file": str(path), "status": "loaded"})
        except Exception as exc:
            loaded.append({"name": path.stem, "file": str(path), "status": "error", "error": str(exc)})
    return loaded


def inventory() -> dict:
    plugins = []
    for path in _files():
        try:
            load_plugin(path)
            plugins.append({"name": path.stem, "file": str(path), "status": "valid"})
        except Exception as exc:
            plugins.append({"name": path.stem, "file": str(path), "status": "error", "error": str(exc)})
    return {"directory": str(plugin_directory()), "plugins": plugins}
