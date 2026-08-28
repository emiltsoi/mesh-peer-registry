"""mesh_core — shared protocol primitives for the mesh family."""

from __future__ import annotations

from mesh_core.config import MeshConfig
from mesh_core.crypto import (
    generate_keypair,
    load_or_generate_keypair,
    public_from_private,
    sign_json,
    sign_message,
    spki_hash_from_cert,
    verify_json,
    verify_message,
)
from mesh_core.delivery import DeliveryClient, DeliveryResult
from mesh_core.envelope import (
    MeshEnvelope,
    is_envelope,
    parse_envelope,
    parse_envelope_safe,
    strip_envelope,
    validate_envelope_token,
)
from mesh_core.exceptions import (
    DeliveryFailed,
    EnvelopeError,
    IdentityNotFound,
    MeshError,
    SignatureError,
    ThreadClosed,
)
from mesh_core.identity import IdentityVault, MeshIdentity
from mesh_core.models import PeerInfo
from mesh_core.outbox import (
    OutboxEntry,
    append,
    append_send_failure,
    clean,
    list_entries,
)
from mesh_core.registry import RegistryClient, RegistryClientError
from mesh_core.replay import ReplayWindow
from mesh_core.threads import clear, is_closed, list_closed, record

__version__ = "0.1.0"

__all__ = [
    "DeliveryClient",
    "DeliveryFailed",
    "DeliveryResult",
    "EnvelopeError",
    "IdentityNotFound",
    "IdentityVault",
    "MeshConfig",
    "MeshEnvelope",
    "MeshError",
    "MeshIdentity",
    "OutboxEntry",
    "PeerInfo",
    "RegistryClient",
    "RegistryClientError",
    "ReplayWindow",
    "SignatureError",
    "ThreadClosed",
    "append",
    "append_send_failure",
    "clean",
    "clear",
    "generate_keypair",
    "is_closed",
    "is_envelope",
    "list_closed",
    "list_entries",
    "load_or_generate_keypair",
    "parse_envelope",
    "parse_envelope_safe",
    "public_from_private",
    "record",
    "sign_json",
    "sign_message",
    "spki_hash_from_cert",
    "strip_envelope",
    "validate_envelope_token",
    "verify_json",
    "verify_message",
]
