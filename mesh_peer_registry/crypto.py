"""Ed25519 signature primitives for the mesh peer registry."""
from __future__ import annotations

import base64
import json
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "generate_keypair",
    "sign_message",
    "verify_message",
    "canonicalize_payload",
    "sign_json",
    "verify_json",
]


def generate_keypair() -> tuple[str, str]:
    """Generate a new Ed25519 keypair and return (private_key_pem, public_key_pem)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _load_private_key(private_key_pem: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )


def _load_public_key(public_key_pem: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(public_key_pem.encode("utf-8"))


def sign_message(private_key_pem: str, message: Union[str, bytes]) -> str:
    """Sign a message and return a base64-encoded signature."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    private_key = _load_private_key(private_key_pem)
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("utf-8")


def verify_message(
    public_key_pem: str, message: Union[str, bytes], signature_b64: str
) -> bool:
    """Verify a base64-encoded signature against a message and public key."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    public_key = _load_public_key(public_key_pem)
    signature = base64.b64decode(signature_b64.encode("utf-8"))
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def canonicalize_payload(payload: dict) -> bytes:
    """Return a deterministic JSON encoding of a payload for signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_json(private_key_pem: str, payload: dict) -> str:
    """Sign a JSON-serializable payload and return a base64-encoded signature."""
    return sign_message(private_key_pem, canonicalize_payload(payload))


def verify_json(public_key_pem: str, payload: dict, signature_b64: str) -> bool:
    """Verify a signature over a JSON-serializable payload."""
    return verify_message(public_key_pem, canonicalize_payload(payload), signature_b64)
