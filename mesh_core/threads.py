"""Closed-thread anchor registry for mesh terminal replies."""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX-only feature
    fcntl = None  # type: ignore[assignment]

from mesh_core.envelope import validate_envelope_token

logger = logging.getLogger(__name__)

# In-memory locked-flag store. Fail-open: missing/corrupt registry disables enforcement.
_LOCKED: set[str] = set()
_LOADED: bool = False
_MTIME: int | float | None = None
_WRITE_LOCK = threading.Lock()

_DEFAULT_REGISTRY_NAME = "closed-threads.json"


def _registry_path(vault_path: str | Path | None = None) -> Path:
    env = os.getenv("MESH_CLOSED_THREADS")
    if env:
        return Path(env)
    if vault_path:
        root = Path(vault_path).expanduser().resolve()
    else:
        env = os.getenv("MESH_VAULT_PATH")
        root = Path(env) if env else Path.home() / ".mesh"
    return root / "mesh" / _DEFAULT_REGISTRY_NAME


def _registry_lock_path(path: Path) -> Path:
    return Path(f"{path}.lock")


def _registry_mtime(path: Path) -> int | float | None:
    try:
        st = path.stat()
    except OSError:
        return None
    ns = getattr(st, "st_mtime_ns", None)
    return ns if ns is not None else st.st_mtime


@contextmanager
def _registry_lock(path: Path):
    lock_path = _registry_lock_path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
    with _WRITE_LOCK:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _hydrate(entries: list[dict], path: Path) -> None:
    global _LOCKED, _LOADED, _MTIME
    _LOCKED = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        anchor = entry.get("anchor_task_id")
        if anchor:
            try:
                _LOCKED.add(validate_envelope_token(anchor, "anchor"))
            except ValueError:
                pass
    _LOADED = True
    _MTIME = _registry_mtime(path)


def _load(path: Path) -> None:
    if not path.exists():
        _hydrate([], path)
        return
    try:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            _hydrate([], path)
            return
        data = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "[mesh] closed-threads registry UNAVAILABLE — enforcement disabled: %s", exc
        )
        _LOADED = False
        return
    if not isinstance(data, list):
        logger.warning(
            "[mesh] closed-threads registry UNAVAILABLE — enforcement disabled: not a list"
        )
        _LOADED = False
        return
    _hydrate(data, path)


def _maybe_reload(path: Path) -> None:
    if not _LOADED:
        _load(path)
        return
    mtime = _registry_mtime(path)
    if mtime is None:
        # Registry disappeared; keep in-memory set and log.
        logger.warning("[mesh] closed-threads registry file disappeared; keeping in-memory set")
        return
    if _MTIME is not None and mtime == _MTIME:
        return
    _load(path)


def is_closed(anchor: str, *, vault_path: str | Path | None = None) -> bool:
    """Return True if `anchor` is a closed thread."""
    path = _registry_path(vault_path)
    _maybe_reload(path)
    return not _LOADED or anchor in _LOCKED


def record(anchor: str, closed_by: str, *, vault_path: str | Path | None = None) -> None:
    """Record a terminal anchor as closed."""
    anchor = validate_envelope_token(anchor, "anchor")
    closed_by = validate_envelope_token(closed_by, "closed_by")
    path = _registry_path(vault_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with _registry_lock(path):
        _load(path)
        entries: list[dict] = []
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8")
                if text.strip():
                    data = json.loads(text)
                    if isinstance(data, list):
                        entries = data
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("[mesh] failed to read closed-threads registry: %s", exc)

        if anchor not in {e.get("anchor_task_id") for e in entries if isinstance(e, dict)}:
            entries.append(
                {
                    "anchor_task_id": anchor,
                    "closed_at": time.time(),
                    "closed_by": closed_by,
                }
            )

        try:
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".closed-threads-")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)
            shutil.move(tmp, path)
        except OSError as exc:
            logger.warning("[mesh] failed to write closed-threads registry: %s", exc)

    _hydrate(entries, path)


def list_closed(*, vault_path: str | Path | None = None) -> list[str]:
    path = _registry_path(vault_path)
    _maybe_reload(path)
    return sorted(_LOCKED)


def clear(*, vault_path: str | Path | None = None) -> None:
    path = _registry_path(vault_path)
    with _registry_lock(path):
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass
    global _LOCKED, _LOADED, _MTIME  # noqa: PLW0602
    _LOCKED.clear()
    _LOADED = False
    _MTIME = None
