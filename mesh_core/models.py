"""Shared data models for mesh_core."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PeerInfo:
    """Public peer record held by the mesh peer registry."""

    name: str
    url: str
    public_key: str
    role: str = "agent"
    description: str = ""
    ttl: int = 0
    created_at: float = 0.0
    last_seen: float = 0.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "url": self.url,
            "public_key": self.public_key,
            "role": self.role,
            "description": self.description,
            "ttl": self.ttl,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
        }
