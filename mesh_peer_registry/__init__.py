"""Shared peer registry package for hermes-mesh and openclaw-mesh."""
from __future__ import annotations

from .client import RegistryClient
from .crypto import (
    canonicalize_payload,
    generate_keypair,
    sign_json,
    sign_message,
    verify_json,
    verify_message,
)
from .models import PeerInfo
from .server import create_app

__all__ = [
    "PeerInfo",
    "RegistryClient",
    "canonicalize_payload",
    "create_app",
    "generate_keypair",
    "sign_json",
    "sign_message",
    "verify_json",
    "verify_message",
]
