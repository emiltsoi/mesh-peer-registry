"""Tests for the mesh_core protocol library."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mesh_core import (
    DeliveryClient,
    EnvelopeError,
    IdentityVault,
    MeshEnvelope,
    MeshIdentity,
    ReplayWindow,
    generate_keypair,
    is_closed,
    is_envelope,
    list_closed,
    load_or_generate_keypair,
    parse_envelope,
    parse_envelope_safe,
    record,
    sign_message,
    strip_envelope,
    validate_envelope_token,
    verify_message,
)


def test_validate_envelope_token_accepts_valid() -> None:
    assert validate_envelope_token("hermes-0", "sender") == "hermes-0"
    assert validate_envelope_token("a.b-c:1_2", "token") == "a.b-c:1_2"


def test_validate_envelope_token_rejects_invalid() -> None:
    with pytest.raises(EnvelopeError):
        validate_envelope_token("", "sender")
    with pytest.raises(EnvelopeError):
        validate_envelope_token("hermes 0", "sender")
    with pytest.raises(EnvelopeError):
        validate_envelope_token("hermes/0", "sender")
    with pytest.raises(EnvelopeError):
        validate_envelope_token("a" * 129, "sender")


def _load_vectors() -> tuple[list[dict], list[dict]]:
    spec_dir = Path(__file__).parent.parent / "spec" / "test-vectors"
    with open(spec_dir / "valid.json") as f:
        valid = json.load(f)
    with open(spec_dir / "invalid.json") as f:
        invalid = json.load(f)
    return valid, invalid


def test_envelope_vectors() -> None:
    valid, invalid = _load_vectors()
    for case in valid:
        envelope = parse_envelope(case["text"])
        expected = case["expected"]
        assert envelope.sender == expected["sender"]
        assert envelope.recipient == expected["recipient"]
        assert envelope.msg_id == expected["msg_id"]
        assert envelope.action == expected["action"]
        assert envelope.reply == expected["reply"]
        assert envelope.ref == expected["ref"]
        assert envelope.version == expected.get("version")
        assert envelope.body == expected["body"]

    for case in invalid:
        assert parse_envelope_safe(case["text"]) is None
        with pytest.raises(EnvelopeError):
            parse_envelope(case["text"])


def test_envelope_body_override_is_not_parsed() -> None:
    # The body may contain [key:value] tokens, but they must not override header fields.
    text = "[mesh][from:hermes-0][to:diploid-0][id:msg-1][action:do][reply:yes] [from:attacker][to:victim] body"
    env = parse_envelope(text)
    assert env.sender == "hermes-0"
    assert env.recipient == "diploid-0"
    assert env.body == "[from:attacker][to:victim] body"


def test_build_and_round_trip() -> None:
    env = MeshEnvelope(
        sender="hermes-0",
        recipient="diploid-0",
        msg_id="msg-1",
        action="do",
        reply="yes",
        ref="ref-1",
        version="1",
        body="Hello",
    )
    text = env.build()
    assert is_envelope(text)
    parsed = parse_envelope(text)
    assert parsed == env


def test_strip_envelope() -> None:
    text = "[mesh][from:hermes-0][to:diploid-0][id:msg-1][action:do][reply:yes] Hello"
    assert strip_envelope(text) == "Hello"
    assert strip_envelope("Hello") == "Hello"


def test_crypto_generate_and_verify() -> None:
    private, public = generate_keypair()
    message = "hello mesh"
    sig = sign_message(private, message)
    assert verify_message(public, message, sig) is True
    assert verify_message(public, message + "!", sig) is False


def test_crypto_load_or_generate(tmp_path: Path) -> None:
    from mesh_core.crypto import public_from_private

    key_path = tmp_path / "agent.pem"
    private, public = load_or_generate_keypair(
        "test-agent", private_key_path_override=key_path
    )
    assert key_path.exists()
    assert public == public_from_private(private)
    # Second call returns same key.
    private2, public2 = load_or_generate_keypair(
        "test-agent", private_key_path_override=key_path
    )
    assert private == private2
    assert public == public2


def test_crypto_tolerates_raw_base64_public() -> None:
    import base64

    private, public = generate_keypair()
    from cryptography.hazmat.primitives import serialization

    public_key = serialization.load_pem_public_key(public.encode())
    raw_b64 = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    raw_public = base64.b64encode(raw_b64).decode("utf-8")
    message = "hello"
    sig = sign_message(private, message)
    assert verify_message(raw_public, message, sig) is True


def test_identity_vault(tmp_path: Path) -> None:
    vault = IdentityVault(root=tmp_path)
    identity = MeshIdentity(
        id="diploid-0",
        name="diploid-0",
        role="worker",
        description="diploid agent",
        url="http://127.0.0.1:4003/mesh/receive",
        a2a_url="http://127.0.0.1:4003/",
        public_key="fake-key",
        platform="diploid",
    )
    vault.save("diploid-0", identity)

    loaded = vault.get("diploid-0")
    assert loaded is not None
    assert loaded.name == "diploid-0"
    assert loaded.url == "http://127.0.0.1:4003/mesh/receive"
    assert loaded.a2a_url == "http://127.0.0.1:4003/"
    assert loaded.platform == "diploid"

    assert vault.get_public_key("diploid-0") == "fake-key"
    assert vault.get_webhook_url("diploid-0") == "http://127.0.0.1:4003/mesh/receive"
    assert vault.list() == [loaded]

    vault.remove("diploid-0")
    assert vault.get("diploid-0") is None


def test_identity_vault_resolves_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MESH_SECRET", "s3cr3t")
    vault = IdentityVault(root=tmp_path)
    identity = MeshIdentity(
        id="diploid-0",
        name="diploid-0",
        role="worker",
        description="diploid agent",
        url="http://127.0.0.1:4003/mesh/receive",
        public_key="pk",
    )
    vault.save("diploid-0", identity)
    file = vault._identity_file("diploid-0")
    raw = file.read_text()
    raw = raw.replace('public_key: pk', 'token: "${MESH_SECRET}"')
    file.write_text(raw)
    # Add the token key to the auth dict manually for this test.
    loaded = vault._load_with_cache(file)
    assert loaded is not None
    # The token should be resolved.
    assert loaded.get("transports", {}).get("hermes_webhook", {}).get("auth", {}).get("token") == "s3cr3t"


def test_replay_window() -> None:
    window = ReplayWindow(ttl=1.0, max_size=2)
    assert window.has("msg-1") is False
    window.add("msg-1")
    assert window.has("msg-1") is True
    window.add("msg-2")
    window.add("msg-3")
    # msg-1 should be evicted by max_size.
    assert window.has("msg-1") is False
    assert window.has("msg-2") is True
    assert window.has("msg-3") is True


def test_threads_record_and_check(tmp_path: Path) -> None:
    record("anchor-1", "hermes-0", vault_path=tmp_path)
    assert is_closed("anchor-1", vault_path=tmp_path) is True
    assert is_closed("anchor-2", vault_path=tmp_path) is False
    assert list_closed(vault_path=tmp_path) == ["anchor-1"]


def test_delivery_ssrf_blocks_loopback() -> None:
    private, _ = generate_keypair()
    client = DeliveryClient(
        private_key_pem=private,
        retries=1,
        timeout=1.0,
    )
    env = MeshEnvelope(
        sender="hermes-0",
        recipient="diploid-0",
        msg_id="msg-1",
        action="do",
        reply="yes",
        body="Hello",
    )
    # CGNAT is always blocked even in loopback-allowed mode.
    result = client.send(env, "http://100.64.0.1:9999/mesh/receive")
    assert result.error == "loopback-blocked"
