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
    r"(?:\[session:([^\]]+)\])?"
    r"(?:\[from_session:([^\]]+)\])?"
    r"(?:\[action:([^\]]+)\])?(?:\[reply:([^\]]+)\])?"
    r"(?:\[ref:([^\]]+)\])?\s*"
)

# Strict pattern for outgoing envelopes: action and reply are required.
_MESH_ENVELOPE_STRICT_RE = re.compile(
    r"^\s*\[mesh\](?:\[v:([^\]]+)\])?\[from:([^\]]+)\]\[to:([^\]]+)\]\[id:([^\]]+)\]"
    r"(?:\[session:([^\]]+)\])?"
    r"(?:\[from_session:([^\]]+)\])?"
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


# Token-loop parser: accept any field order (robust receivers). The canonical
# builder order is [from][to][id][session?][from_session?][action][reply][ref],
# but receivers MUST NOT depend on order — this loop collects every token.
_FIELD_LOOP_RE = re.compile(
    r"\[(v|from|to|id|session|from_session|action|reply|ref):([^\]]+)\]"
)


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
    session: str | None = None
    from_session: str | None = None
    body: str = ""

    def build(self) -> str:
        """Build the bracketed [mesh] header for this envelope.

        Canonical token order (normative for build()):
        [from][to][id][session?][from_session?][action][reply][ref]
        """
        header = "[mesh]"
        if self.version:
            header += f"[v:{validate_envelope_token(self.version, 'version')}]"
        header += (
            f"[from:{self.sender}]"
            f"[to:{self.recipient}]"
            f"[id:{self.msg_id}]"
        )
        if self.session:
            header += f"[session:{validate_envelope_token(self.session, 'session')}]"
        if self.from_session:
            header += f"[from_session:{validate_envelope_token(self.from_session, 'from_session')}]"
        header += (
            f"[action:{self.action}]"
            f"[reply:{self.reply}]"
        )
        if self.ref:
            header += f"[ref:{validate_envelope_token(self.ref, 'ref')}]"
        return f"{header} {self.body}"


def _parse_token_loop(text: str) -> tuple[dict[str, str], str]:
    """Parse the bracketed header with a token loop (order-independent).

    Returns (fields dict, remaining body text). The [mesh] marker is
    required; every other field is optional and order-free.
    """
    if not text.startswith("[mesh]"):
        raise EnvelopeError("Malformed mesh envelope header")

    # Walk the tokens after the [mesh] marker.
    fields: dict[str, str] = {}
    pos = len("[mesh]")
    while True:
        token_match = _FIELD_LOOP_RE.match(text, pos)
        if not token_match:
            break
        key, value = token_match.groups()
        if key == "v":
            key = "version"
        fields[key] = value
        pos = token_match.end()
    return fields, text[pos:].lstrip()


def parse_envelope(text: str) -> MeshEnvelope:
    """Parse a bracketed [mesh] envelope.

    Missing action/reply default to the conservative values info/no.
    Raises EnvelopeError for malformed envelopes.
    Accepts tokens in ANY order (token-loop parser, 0.1.8).
    """
    # Token-loop parser is the primary path (order-independent, 0.1.8).
    # The regex fast-path would partially match a prefix of a non-canonical
    # header and treat remaining tokens as body — so we always walk the loop.
    try:
        fields, body_text = _parse_token_loop(text)
    except EnvelopeError:
        raise
    if not fields.get("from") or not fields.get("to") or not fields.get("id"):
        raise EnvelopeError("Malformed mesh envelope header")
    sender = validate_envelope_token(fields["from"], "sender")
    recipient = validate_envelope_token(fields["to"], "recipient")
    msg_id = validate_envelope_token(fields["id"], "msg_id")
    action_raw = fields.get("action", "info")
    reply_raw = fields.get("reply", "no")
    ref_raw = fields.get("ref")
    version_raw = fields.get("version")
    session_raw = fields.get("session")
    from_session_raw = fields.get("from_session")

    action_val = validate_envelope_token(action_raw or "info", "action")
    if action_val not in {"do", "info"}:
        raise EnvelopeError(f"Invalid action: {action_val!r}; must be 'do' or 'info'")

    reply_val = validate_envelope_token(reply_raw or "no", "reply")
    if reply_val not in {"yes", "no", "end"}:
        raise EnvelopeError(f"Invalid reply: {reply_val!r}; must be 'yes', 'no', or 'end'")

    ref = validate_envelope_token(ref_raw, "ref") if ref_raw else None
    version = validate_envelope_token(version_raw, "version") if version_raw else None
    session = validate_envelope_token(session_raw, "session") if session_raw else None
    from_session = (
        validate_envelope_token(from_session_raw, "from_session")
        if from_session_raw
        else None
    )

    return MeshEnvelope(
        sender=sender,
        recipient=recipient,
        msg_id=msg_id,
        action=action_val,  # type: ignore[arg-type]
        reply=reply_val,  # type: ignore[arg-type]
        ref=ref,
        version=version,
        session=session,
        from_session=from_session,
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
