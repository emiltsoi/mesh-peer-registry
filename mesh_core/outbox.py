"""Durable outbox for mesh delivery and injection failures."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from mesh_core.envelope import MeshEnvelope

logger = logging.getLogger(__name__)

DEFAULT_OUTBOX_DIR = Path.home() / ".mesh" / "outbox"


@dataclass
class OutboxEntry:
    direction: str
    ts: float
    peer: str | None = None
    text: str | None = None
    envelope: dict | None = None
    error: str | None = None
    status: int | None = None
    attempts: int = 0


def _today() -> str:
    t = time.gmtime()
    return f"{t.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d}.jsonl"


def _outbox_dir(outbox_dir: str | Path | None = None) -> Path:
    if outbox_dir:
        return Path(outbox_dir).expanduser()
    env = os.getenv("MESH_OUTBOX_DIR")
    if env:
        return Path(env)
    return DEFAULT_OUTBOX_DIR


def append(
    entry: OutboxEntry,
    outbox_dir: str | Path | None = None,
) -> None:
    """Append a failed delivery/receive event to the durable outbox."""
    d = _outbox_dir(outbox_dir)
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    file = d / _today()
    line = json.dumps(
        {
            "direction": entry.direction,
            "ts": entry.ts or time.time(),
            "peer": entry.peer,
            "text": entry.text,
            "envelope": entry.envelope,
            "error": entry.error,
            "status": entry.status,
            "attempts": entry.attempts,
        },
        default=str,
    )
    try:
        with open(file, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        file.chmod(0o600)
    except OSError as exc:
        logger.warning("[mesh] failed to append to outbox %s: %s", file, exc)


def list_entries(
    outbox_dir: str | Path | None = None,
    max_entries: int = 100,
    older_than: float | None = None,
) -> list[OutboxEntry]:
    """Read recent outbox entries, optionally filtering by age."""
    d = _outbox_dir(outbox_dir)
    if not d.is_dir():
        return []

    now = time.time()
    entries: list[OutboxEntry] = []
    files = sorted(d.glob("*.jsonl"), reverse=True)
    for file in files:
        try:
            text = file.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if older_than is not None and (now - data.get("ts", now)) <= older_than:
                continue
            entries.append(
                OutboxEntry(
                    direction=data.get("direction", "send"),
                    ts=data.get("ts", 0),
                    peer=data.get("peer"),
                    text=data.get("text"),
                    envelope=data.get("envelope"),
                    error=data.get("error"),
                    status=data.get("status"),
                    attempts=data.get("attempts", 0),
                )
            )
            if len(entries) >= max_entries:
                return entries
    return entries


def clean(older_than_seconds: float, outbox_dir: str | Path | None = None) -> int:
    """Remove outbox files whose mtime is older than `older_than_seconds`."""
    d = _outbox_dir(outbox_dir)
    if not d.is_dir():
        return 0
    now = time.time()
    removed = 0
    for file in d.glob("*.jsonl"):
        try:
            stat = file.stat()
        except OSError:
            continue
        if now - stat.st_mtime > older_than_seconds:
            try:
                file.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def append_send_failure(
    envelope: MeshEnvelope,
    error: str,
    status: int | None,
    attempts: int,
    outbox_dir: str | Path | None = None,
) -> None:
    """Convenience helper for outbound send failures."""
    append(
        OutboxEntry(
            direction="send",
            ts=time.time(),
            peer=envelope.recipient,
            text=envelope.body,
            envelope={
                "sender": envelope.sender,
                "recipient": envelope.recipient,
                "msg_id": envelope.msg_id,
                "action": envelope.action,
                "reply": envelope.reply,
                "ref": envelope.ref,
                "version": envelope.version,
            },
            error=error,
            status=status,
            attempts=attempts,
        ),
        outbox_dir=outbox_dir,
    )
