"""Ed25519 key management, signing, and verification for mesh peers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "canonicalize_json",
    "generate_keypair",
    "load_or_generate_keypair",
    "public_from_private",
    "sign_json",
    "sign_message",
    "spki_hash_from_cert",
    "verify_json",
    "verify_message",
]

logger = logging.getLogger(__name__)

DEFAULT_KEY_DIR = Path.home() / ".mesh" / "keys"


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


def private_key_path(name: str, override: str | Path | None = None) -> Path:
    """Return the private key path for an agent."""
    if override:
        return Path(os.path.expanduser(override))
    return DEFAULT_KEY_DIR / f"{name}.pem"


def load_or_generate_keypair(
    name: str, *, private_key_path_override: str | Path | None = None
) -> tuple[str, str]:
    """Load or generate the local Ed25519 keypair for `name`.

    Returns `(private_pem, public_pem)`. The private key is written to
    `~/.mesh/keys/<name>.pem` (or `private_key_path_override`) with 0600
    permissions.
    """
    path = private_key_path(name, private_key_path_override)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass

    if path.exists():
        private_pem = path.read_text(encoding="utf-8")
        return private_pem, public_from_private(private_pem)

    private_pem, public_pem = generate_keypair()
    path.write_text(private_pem, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return private_pem, public_pem


def public_from_private(private_pem: str) -> str:
    """Derive the public key PEM from an Ed25519 private key PEM."""
    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"), password=None
    )
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _load_public_key(public_key_input: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM or raw base64 SPKI.

    Tolerates two key framings:
    - PEM SPKI (input containing "BEGIN PUBLIC KEY"): strict PEM only.
    - Raw base64 SPKI (no PEM marker): stripped, strict base64-decoded,
      must be exactly 32 bytes of Ed25519 raw public key or 44 bytes SPKI DER.
      X25519 SPKI has the same 44-byte DER shape but a different OID; we
      reject it via isinstance check.
    """
    raw = public_key_input.strip()

    if "BEGIN PUBLIC KEY" in raw:
        public_key = serialization.load_pem_public_key(raw.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("PEM key is not Ed25519")
        return public_key

    # Raw base64 SPKI (possibly with whitespace from YAML block scalars).
    raw_b64 = "".join(raw.split())
    try:
        der = base64.b64decode(raw_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"Invalid base64 public key: {exc}") from exc

    if len(der) == 32:
        return Ed25519PublicKey.from_public_bytes(der)

    if len(der) == 44:
        public_key = serialization.load_der_public_key(der)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("44-byte DER key is not Ed25519 (possible X25519)")
        return public_key

    raise ValueError(
        f"Invalid public key length: {len(der)} bytes; expected 32 (raw) or 44 (SPKI DER)"
    )


def sign_message(private_key_pem: str, message: str | bytes) -> str:
    """Sign a message with the private key and return a base64 signature."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode("utf-8")


def verify_message(public_key_input: str, message: str | bytes, signature_b64: str) -> bool:
    """Verify an Ed25519 signature.

    Returns False on any failure (invalid key, bad signature, etc.).
    Never raises.
    """
    if not public_key_input or not signature_b64:
        return False
    if isinstance(message, str):
        message = message.encode("utf-8")
    try:
        public_key = _load_public_key(public_key_input)
        signature = base64.b64decode(signature_b64.encode("utf-8"), validate=True)
    except (ValueError, binascii.Error):
        return False
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def canonicalize_json(payload: dict) -> bytes:
    """Return a deterministic JSON encoding of a payload for signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_json(private_key_pem: str, payload: dict) -> str:
    """Sign a JSON-serializable payload and return a base64-encoded signature."""
    return sign_message(private_key_pem, canonicalize_json(payload))


def verify_json(public_key_input: str, payload: dict, signature_b64: str) -> bool:
    """Verify a signature over a JSON-serializable payload."""
    return verify_message(public_key_input, canonicalize_json(payload), signature_b64)


def spki_hash_from_cert(der_cert: bytes) -> str:
    """Return the SHA-256 hex digest of a certificate's Subject Public Key Info (SPKI)."""
    cert = x509.load_der_x509_certificate(der_cert)
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()
