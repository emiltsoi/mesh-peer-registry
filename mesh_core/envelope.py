"""Mesh envelope parsing, building, and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from mesh_core.exceptions import EnvelopeError

# Tokens appear inside bracket envelope fields and in logs.
_ENVELOPE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

# Tolerant receive: action/reply groups are OPTIONAL in the pattern so a
# receiver can default to conservative values (info/no). Senders MUST include
# both fields.
_MESH_ENVELOPE_RE = re.compile(
    r"^\s*\[mesh\](?:\[v:([^\]]+)\])?\[from:([^\]]+)\]\[to:([^\]]+)\]\[id:([^\]]+)\]"
    r"(?:\[action:([^\]]+)\])?(?:\[reply:([^\]]+)\])?"
    r"(?:\[ref:([^\]]+)\])?\s*"
)

# Strict pattern for outgoing envelopes: action and reply are required.
_MESH_ENVELOPE_STRICT_RE = re.compile(
    r"^\s*\[mesh\](?:\[v:([^\]]+)\])?\[from:([^\]]+)\]\[to:([^\]]+)\]\[id:([^\]]+)\]"
    r"\[action:([^\]]+)\]\[reply:([^\]]+)\]"
    r"(?:\[ref:([^\]]+)\])?\s*"
)


def validate_envelope_token(token: object, field: str = "token") -> str:
    """Validate a message id, ref, or agent name.

    Envelope tokens appear inside the bracket mesh header and in logs, so
    they must be short and free of injection/whitespace characters.
    """
    if not isinstance(token, str):
        raise EnvelopeError(f"{field} must be a string: {token!r}")
    value = token.strip()
    if not value:
        raise EnvelopeError(f"{field} must not be empty")
    if not _ENVELOPE_TOKEN_RE.match(value):
        raise EnvelopeError(
            f"Invalid {field}: {value!r}. "
            "Allowed: 1-128 characters from A-Z, a-z, 0-9, _, ., -, :"
        )
    return value


@dataclass(frozen=True)
class MeshEnvelope:
    """Structured representation of a [mesh] envelope header."""

    sender: str
    recipient: str
    msg_id: str
    action: Literal["do", "info"]
    reply: Literal["yes", "no", "end"]
    ref: str | None = None
    version: str | None = None
    body: str = ""

    def build(self) -> str:
        """Build the bracketed [mesh] header for this envelope."""
        header = "[mesh]"
        if self.version:
            header += f"[v:{validate_envelope_token(self.version, 'version')}]"
        header += (
            f"[from:{self.sender}]"
            f"[to:{self.recipient}]"
            f"[id:{self.msg_id}]"
            f"[action:{self.action}]"
            f"[reply:{self.reply}]"
        )
        if self.ref:
            header += f"[ref:{validate_envelope_token(self.ref, 'ref')}]"
        return f"{header} {self.body}"


def parse_envelope(text: str) -> MeshEnvelope:
    """Parse a bracketed [mesh] envelope.

    Missing action/reply default to the conservative values info/no.
    Raises EnvelopeError for malformed envelopes.
    """
    m = _MESH_ENVELOPE_RE.match(text)
    if not m:
        raise EnvelopeError("Malformed mesh envelope header")

    version, sender, recipient, msg_id, action, reply, ref = m.groups()
    body_text = text[m.end() :].lstrip()

    sender = validate_envelope_token(sender, "sender")
    recipient = validate_envelope_token(recipient, "recipient")
    msg_id = validate_envelope_token(msg_id, "msg_id")

    action = validate_envelope_token(action or "info", "action")
    if action not in {"do", "info"}:
        raise EnvelopeError(f"Invalid action: {action!r}; must be 'do' or 'info'")

    reply = validate_envelope_token(reply or "no", "reply")
    if reply not in {"yes", "no", "end"}:
        raise EnvelopeError(f"Invalid reply: {reply!r}; must be 'yes', 'no', or 'end'")

    if ref:
        ref = validate_envelope_token(ref, "ref")
    else:
        ref = None

    if version:
        version = validate_envelope_token(version, "version")
    else:
        version = None

    return MeshEnvelope(
        sender=sender,
        recipient=recipient,
        msg_id=msg_id,
        action=action,  # type: ignore[arg-type]
        reply=reply,  # type: ignore[arg-type]
        ref=ref,
        version=version,
        body=body_text,
    )


def parse_envelope_safe(text: str) -> MeshEnvelope | None:
    """Parse a [mesh] envelope, returning None if the text is not a valid envelope."""
    try:
        return parse_envelope(text)
    except EnvelopeError:
        return None


def strip_envelope(text: str) -> str:
    """Return the body text with the [mesh] header removed."""
    m = _MESH_ENVELOPE_RE.match(text)
    if not m:
        return text
    return text[m.end() :].lstrip()


def is_envelope(text: str) -> bool:
    """Return True if text starts with a valid [mesh] envelope header."""
    return _MESH_ENVELOPE_RE.match(text) is not None
