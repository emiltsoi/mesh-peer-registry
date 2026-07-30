"""Persistence layer for the mesh peer registry."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from .models import PeerInfo


class SqliteStore:
    """SQLite-backed storage for peer records with TTL support."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS peers (
                    name TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'agent',
                    description TEXT NOT NULL DEFAULT '',
                    ttl INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL DEFAULT 0,
                    last_seen REAL NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_peers_role ON peers(role)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers(last_seen)"
            )

    @staticmethod
    def _row_to_peer(row: sqlite3.Row) -> PeerInfo:
        return PeerInfo(
            name=row["name"],
            url=row["url"],
            public_key=row["public_key"],
            role=row["role"],
            description=row["description"],
            ttl=row["ttl"],
            created_at=row["created_at"],
            last_seen=row["last_seen"],
        )

    def get(self, name: str) -> PeerInfo | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM peers WHERE name = ?", (name,)
            ).fetchone()
        return self._row_to_peer(row) if row else None

    def list(
        self,
        role: str | None = None,
        limit: int = 0,
        offset: int = 0,
    ) -> list[PeerInfo]:
        query = "SELECT * FROM peers"
        params: list[Any] = []
        if role:
            query += " WHERE role = ?"
            params.append(role)
        query += " ORDER BY name"
        if limit > 0:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_peer(r) for r in rows]

    def count(self, role: str | None = None) -> int:
        query = "SELECT COUNT(*) FROM peers"
        params: list[Any] = []
        if role:
            query += " WHERE role = ?"
            params.append(role)
        with self._conn() as conn:
            row = conn.execute(query, params).fetchone()
        return row[0] if row else 0

    def put(self, peer: PeerInfo) -> None:
        now = time.time()
        if not peer.created_at:
            peer.created_at = now
        if not peer.last_seen:
            peer.last_seen = now
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO peers (name, url, public_key, role, description, ttl, created_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    url=excluded.url,
                    public_key=excluded.public_key,
                    role=excluded.role,
                    description=excluded.description,
                    ttl=excluded.ttl,
                    last_seen=excluded.last_seen
                """,
                (
                    peer.name,
                    peer.url,
                    peer.public_key,
                    peer.role,
                    peer.description,
                    peer.ttl,
                    peer.created_at,
                    peer.last_seen,
                ),
            )

    def touch(self, name: str) -> bool:
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE peers SET last_seen = ? WHERE name = ?",
                (now, name),
            )
            return cur.rowcount > 0

    def delete(self, name: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM peers WHERE name = ?", (name,))
            return cur.rowcount > 0

    def reap_expired(self) -> int:
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM peers WHERE ttl > 0 AND last_seen + ttl < ?",
                (now,),
            )
            return cur.rowcount

    def metrics(self) -> dict:
        now = time.time()
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM peers WHERE ttl > 0 AND last_seen + ttl < ?",
                (now,),
            ).fetchone()[0]
            roles = conn.execute(
                "SELECT role, COUNT(*) FROM peers GROUP BY role"
            ).fetchall()
        return {
            "total": total,
            "expired": expired,
            "roles": {r[0]: r[1] for r in roles},
        }


# Backwards compatibility for existing imports/tests.
FileStore = SqliteStore
