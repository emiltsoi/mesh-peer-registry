"""Persistence layer for the mesh peer registry."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import PeerInfo


class FileStore:
    """Atomic JSON file storage for peer records."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(data, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)

    def get(self, name: str) -> PeerInfo | None:
        data = self._load()
        if name not in data:
            return None
        return PeerInfo(**data[name])

    def list(self) -> list[PeerInfo]:
        data = self._load()
        return [PeerInfo(**v) for _, v in sorted(data.items())]

    def put(self, peer: PeerInfo) -> None:
        data = self._load()
        data[peer.name] = peer.__dict__
        self._save(data)

    def delete(self, name: str) -> bool:
        data = self._load()
        if name not in data:
            return False
        del data[name]
        self._save(data)
        return True
