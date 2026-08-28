"""Ed25519 signature primitives for the mesh peer registry.

This module is a thin re-export from mesh_core for backward compatibility.
The canonical implementations live in mesh_core.crypto.
"""

from __future__ import annotations

from mesh_core.crypto import (
    canonicalize_json,
    generate_keypair,
    sign_json,
    sign_message,
    spki_hash_from_cert,
    verify_json,
    verify_message,
)

canonicalize_payload = canonicalize_json

__all__ = [
    "canonicalize_payload",
    "generate_keypair",
    "sign_json",
    "sign_message",
    "spki_hash_from_cert",
    "verify_json",
    "verify_message",
]
