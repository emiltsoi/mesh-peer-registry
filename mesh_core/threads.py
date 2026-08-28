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
    global _LOADED, _MTIME
    _LOCKED.clear()
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


def _read_entries_strict(path: Path) -> tuple[list[dict], bool]:
    """Read registry entries, reporting corrupt/unreadable state.

    Returns ``(entries, failed)``. ``failed`` is True when the file exists but
    could not be read as a valid JSON list.
    """
    if not path.exists():
        return [], False
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return [], True
    if not text.strip():
        return [], False
    try:
        data = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return [], True
    if not isinstance(data, list):
        return [], True
    return [entry for entry in data if isinstance(entry, dict)], False


def _read_entries(path: Path) -> list[dict]:
    """Read registry entries; tolerate a missing or corrupt file."""
    entries, _ = _read_entries_strict(path)
    return entries


def _write_entries(entries: list[dict], path: Path) -> None:
    """Atomically write registry entries (tmp file + os.replace + parent fsync)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent), prefix="closed-threads-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(entries, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        # Durability: fsync the parent directory so the rename itself is
        # persisted across power loss, not just the file contents.
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:  # pragma: no cover - dir fsync unsupported on this FS
            pass
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _backup_corrupt(path: Path) -> Path | None:
    """Back up a corrupt registry file to ``<path>.corrupt-<ts>``.

    Best-effort: returns the backup path on success, None on failure.
    """
    if not path.exists():
        return None
    backup = Path(f"{path}.corrupt-{time.time()}")
    try:
        shutil.copy2(path, backup)
    except OSError:
        return None
    return backup


def _load(path: Path) -> None:
    if not path.exists():
        _hydrate([], path)
        return
    entries, failed = _read_entries_strict(path)
    if failed:
        logger.warning(
            "[mesh] closed-threads registry UNAVAILABLE — enforcement disabled: %s", path
        )
    _hydrate(entries, path)


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
    try:
        with _registry_lock(path):
            _maybe_reload(path)
            return _LOADED and anchor in _LOCKED
    except (PermissionError, OSError) as exc:
        logger.warning(
            "[mesh] closed-threads registry UNAVAILABLE — enforcement disabled: %s (%s)",
            path,
            exc,
        )
        return False


def record(anchor: str, closed_by: str, *, vault_path: str | Path | None = None) -> None:
    """Record a terminal anchor as closed."""
    anchor = validate_envelope_token(anchor, "anchor")
    closed_by = validate_envelope_token(closed_by, "closed_by")
    path = _registry_path(vault_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with _registry_lock(path):
        entries, failed = _read_entries_strict(path)
        if failed:
            backup = _backup_corrupt(path)
            if backup:
                logger.warning(
                    "[mesh] corrupt closed-threads registry %s backed up to %s",
                    path,
                    backup,
                )
            else:
                logger.warning(
                    "[mesh] failed to back up corrupt closed-threads registry %s", path
                )

        if anchor not in {e.get("anchor_task_id") for e in entries if isinstance(e, dict)}:
            entries.append(
                {
                    "anchor_task_id": anchor,
                    "closed_at": time.time(),
                    "closed_by": closed_by,
                }
            )
            _write_entries(entries, path)

        _hydrate(entries, path)

    logger.info("[mesh] thread closed %s (closed_by=%s)", anchor, closed_by)


def load(*, vault_path: str | Path | None = None) -> list[dict]:
    """Load registry entries from disk."""
    path = _registry_path(vault_path)
    entries = _read_entries(path)
    _hydrate(entries, path)
    return entries


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
    _LOCKED.clear()
    global _LOADED, _MTIME
    _LOADED = False
    _MTIME = None
