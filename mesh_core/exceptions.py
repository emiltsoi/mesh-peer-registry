"""Exceptions raised by mesh_core."""

from __future__ import annotations


class MeshError(Exception):
    """Base class for mesh protocol errors."""


class EnvelopeError(MeshError):
    """Raised when an envelope cannot be parsed or is invalid."""


class IdentityNotFound(MeshError):
    """Raised when a mesh peer identity is not found in the vault or registry."""


class DeliveryFailed(MeshError):
    """Raised when a mesh message cannot be delivered."""

    def __init__(self, message: str, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason


class ThreadClosed(MeshError):
    """Raised when a reply references a closed thread."""


class SignatureError(MeshError):
    """Raised when Ed25519 signature verification fails."""
