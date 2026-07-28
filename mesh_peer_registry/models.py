"""Data models for the mesh peer registry."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PeerInfo:
    """Public peer record held by the registry."""

    name: str
    url: str
    public_key: str
    role: str = "agent"
    description: str = ""
