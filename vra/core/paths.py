"""Path utilities for VRA."""

from __future__ import annotations

import os
import platform
from pathlib import Path


def get_home_dir() -> Path:
    return Path.home()


def get_config_dir() -> Path:
    if platform.system() == "Linux":
        return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "vra"
    elif platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "vra"
    else:
        return Path.home() / ".vra"


def get_cache_dir() -> Path:
    if platform.system() == "Linux":
        return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "vra"
    elif platform.system() == "Darwin":
        return Path.home() / "Library" / "Caches" / "vra"
    else:
        return Path.home() / ".vra" / "cache"


def get_default_workspace() -> Path:
    return Path.cwd() / ".vra-workspace"


def get_reports_dir(workspace: Path) -> Path:
    return workspace / "reports"


def get_runs_dir(workspace: Path) -> Path:
    return workspace / "runs"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_path_join(base: Path, *parts: str) -> Path:
    result = base
    for part in parts:
        result = result / part
    resolved = result.resolve()
    if not str(resolved).startswith(str(base.resolve())):
        raise ValueError(f"Path traversal detected: {result} is outside {base}")
    return resolved
