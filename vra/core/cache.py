"""Caching layer for VRA."""

from __future__ import annotations

import hashlib
import json
import pickle  # noqa: S403 - safe for internal cache only
from pathlib import Path

from vra.core.logging import get_logger

log = get_logger("core.cache")


class RunCache:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = cache_dir / "index.json"
        self._index: dict[str, dict] = self._load_index()

    def _load_index(self) -> dict[str, dict]:
        if self._index_path.exists():
            try:
                return json.loads(self._index_path.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_index(self) -> None:
        try:
            self._index_path.write_text(json.dumps(self._index, indent=2))
        except OSError:
            pass

    @staticmethod
    def compute_key(commit_hash: str, tool_version: str, config_hash: str) -> str:
        raw = "|".join([commit_hash, tool_version, config_hash])
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

    @staticmethod
    def config_hash(config) -> str:
        from dataclasses import asdict

        try:
            data = asdict(config)
            return hashlib.sha256(json.dumps(data, default=str).encode()).hexdigest()[:16]
        except (TypeError, ValueError):
            return "unknown"

    def get(self, key: str) -> object | None:
        entry = self._index.get(key)
        if not entry:
            return None
        cache_file = self.cache_dir / f"{key}.pkl"
        if not cache_file.exists():
            return None
        try:
            with open(cache_file, "rb") as f:
                return pickle.load(f)  # noqa: S301
        except (OSError, pickle.PickleError, EOFError) as e:
            log.debug("Cache load failed for %s: %s", key, e)
            return None

    def put(self, key: str, value: object) -> None:
        cache_file = self.cache_dir / f"{key}.pkl"
        try:
            with open(cache_file, "wb") as f:
                pickle.dump(value, f)
            self._index[key] = {"file": cache_file.name}
            self._save_index()
        except (OSError, pickle.PickleError) as e:
            log.debug("Cache save failed for %s: %s", key, e)

    def clear(self) -> None:
        for f in self.cache_dir.glob("*.pkl"):
            f.unlink(missing_ok=True)
        self._index = {}
        self._save_index()
