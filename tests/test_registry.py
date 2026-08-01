"""Tests for mesh-peer-registry crypto, store, client, and server."""
from __future__ import annotations

import asyncio
import datetime
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aiohttp.test_utils import AioHTTPTestCase

from mesh_peer_registry.client import RegistryClient, RegistryClientError
from mesh_peer_registry.crypto import (
    canonicalize_payload,
    generate_keypair,
    sign_json,
    sign_message,
    spki_hash_from_cert,
    verify_json,
    verify_message,
)
from mesh_peer_registry.models import PeerInfo
from mesh_peer_registry.server import create_app
from mesh_peer_registry.store import FileStore


class TestCrypto(unittest.TestCase):
    def test_generate_keypair(self):
        private, public = generate_keypair()
        assert "BEGIN PRIVATE KEY" in private
        assert "BEGIN PUBLIC KEY" in public

    def test_sign_and_verify(self):
        private, public = generate_keypair()
        sig = sign_message(private, "hello mesh")
        assert verify_message(public, "hello mesh", sig)

    def test_verify_fails_with_wrong_key(self):
        private, _public = generate_keypair()
        _, wrong_public = generate_keypair()
        sig = sign_message(private, "hello")
        assert not verify_message(wrong_public, "hello", sig)

    def test_verify_fails_with_tampered_message(self):
        private, public = generate_keypair()
        sig = sign_message(private, "hello")
        assert not verify_message(public, "tampered", sig)

    def test_sign_and_verify_json(self):
        private, public = generate_keypair()
        payload = {"from": "linda", "to": "britney", "id": "msg-123"}
        sig = sign_json(private, payload)
        assert verify_json(public, payload, sig)
        assert not verify_json(public, {"from": "linda"}, sig)

    def test_canonicalize_is_deterministic(self):
        a = canonicalize_payload({"b": 2, "a": 1})
        b = canonicalize_payload({"a": 1, "b": 2})
        assert a == b

    def test_verify_message_rejects_invalid_base64(self):
        _private, public = generate_keypair()
        assert not verify_message(public, "hello", "not-base64!!!")

    def test_verify_message_rejects_invalid_public_key(self):
        private, _public = generate_keypair()
        sig = sign_message(private, "hello")
        assert not verify_message("not-a-public-key", "hello", sig)

    def test_spki_hash_from_cert_matches_public_key(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        private, public = generate_keypair()

        from cryptography.hazmat.primitives import serialization as ser

        sk = ser.load_pem_private_key(private.encode(), password=None)
        pk = ser.load_pem_public_key(public.encode())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(pk)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(sk, None)
        )
        der = cert.public_bytes(ser.Encoding.DER)

        # SPKI of the cert must equal SPKI of the standalone public key.
        got = spki_hash_from_cert(der)
        expected = ser.load_pem_public_key(public.encode()).public_bytes(
            encoding=ser.Encoding.DER,
            format=ser.PublicFormat.SubjectPublicKeyInfo,
        )
        assert got == __import__("hashlib").sha256(expected).hexdigest()


class TestStore(unittest.TestCase):
    def test_put_get_list_delete(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileStore(Path(tmpdir) / "registry.json")
            peer = PeerInfo(
                name="britney",
                url="http://127.0.0.1:8645",
                public_key="pk",
                role="swe",
            )
            store.put(peer)
            fetched = store.get("britney")
            assert fetched is not None
            assert fetched.name == "britney"
            assert store.list()[0].name == "britney"
            assert store.delete("britney")
            assert store.get("britney") is None

    def test_delete_missing_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FileStore(Path(tmpdir) / "registry.json")
            assert not store.delete("nobody")


class TestRegistryClientSecurity(unittest.TestCase):
    def test_client_rejects_http(self):
        with self.assertRaises(RegistryClientError):
            RegistryClient("http://example.com", "pk", "pub")

    def test_client_allows_http_with_env(self):
        with patch.dict(os.environ, {"MESH_REGISTRY_ALLOW_INSECURE": "1"}):
            client = RegistryClient("http://example.com", "pk", "pub")
            self.assertEqual(client.registry_url, "http://example.com")


class TestRegistryServer(AioHTTPTestCase):
    async def get_application(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self._old_allow_insecure = os.environ.get("MESH_REGISTRY_ALLOW_INSECURE")
        os.environ["MESH_REGISTRY_ALLOW_INSECURE"] = "1"
        return create_app(str(Path(self.tmpdir.name) / "registry.json"))

    def tearDown(self):
        super().tearDown()
        if hasattr(self, "tmpdir"):
            self.tmpdir.cleanup()
        if hasattr(self, "_old_allow_insecure"):
            if self._old_allow_insecure is None:
                os.environ.pop("MESH_REGISTRY_ALLOW_INSECURE", None)
            else:
                os.environ["MESH_REGISTRY_ALLOW_INSECURE"] = self._old_allow_insecure

    async def test_list_empty(self):
        resp = await self.client.request("GET", "/peers")
        assert resp.status == 200
        body = await resp.json()
        assert body["peers"] == []

    async def test_register_and_get(self):
        private, public = generate_keypair()
        client = RegistryClient(
            f"http://127.0.0.1:{self.server.port}",
            private,
            public,
            allow_insecure=True,
        )

        result = await asyncio.to_thread(
            client.register,
            name="britney",
            url="http://127.0.0.1:8645",
            role="swe",
            description="Principal",
        )
        assert result["ok"]

        peer = await asyncio.to_thread(client.get_peer, "britney")
        assert peer is not None
        assert peer.name == "britney"
        assert peer.role == "swe"

    async def test_register_without_signature_rejected(self):
        resp = await self.client.request(
            "POST",
            "/register",
            data=json.dumps(
                {
                    "name": "britney",
                    "url": "http://127.0.0.1:8645",
                    "public_key": "pk",
                }
            ),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status == 400

    async def test_register_rejects_bad_name(self):
        resp = await self.client.request(
            "POST",
            "/register",
            data=json.dumps({"name": "bad name!", "url": "http://127.0.0.1:8645", "public_key": "pk"}),
            headers={"Content-Type": "application/json", "X-Mesh-Signature": "sig"},
        )
        assert resp.status == 400

    async def test_register_rejects_bad_url(self):
        resp = await self.client.request(
            "POST",
            "/register",
            data=json.dumps({"name": "good", "url": "ftp://example.com", "public_key": "pk"}),
            headers={"Content-Type": "application/json", "X-Mesh-Signature": "sig"},
        )
        assert resp.status == 400

    async def test_register_rate_limit(self):
        with patch.dict(os.environ, {"MESH_REGISTRY_RATE_LIMIT": "2"}):
            private, public = generate_keypair()
            client = RegistryClient(f"http://127.0.0.1:{self.server.port}", private, public, allow_insecure=True)
            await asyncio.to_thread(client.register, "one", "http://127.0.0.1:8645", role="agent")
            await asyncio.to_thread(client.register, "two", "http://127.0.0.1:8646", role="agent")
            with self.assertRaises(RegistryClientError) as ctx:
                await asyncio.to_thread(client.register, "three", "http://127.0.0.1:8647", role="agent")
            assert "429" in str(ctx.exception) or "rate" in str(ctx.exception).lower()

    async def test_deregister(self):
        private, public = generate_keypair()
        client = RegistryClient(
            f"http://127.0.0.1:{self.server.port}",
            private,
            public,
            allow_insecure=True,
        )

        await asyncio.to_thread(
            client.register,
            name="daji",
            url="http://127.0.0.1:8646",
            role="agent",
        )
        assert (await asyncio.to_thread(client.get_peer, "daji")) is not None

        await asyncio.to_thread(client.deregister, "daji")
        assert (await asyncio.to_thread(client.get_peer, "daji")) is None

    async def test_get_missing_returns_404(self):
        resp = await self.client.request("GET", "/peers/nobody")
        assert resp.status == 404

    async def test_hsts_header_emitted_when_enabled_and_secure(self):
        with patch.dict(
            os.environ,
            {
                "MESH_REGISTRY_HSTS": "1",
                "MESH_REGISTRY_BEHIND_PROXY": "1",
                "MESH_REGISTRY_ALLOW_INSECURE": "1",
            },
        ):
            resp = await self.client.request(
                "GET",
                "/peers",
                headers={"X-Forwarded-Proto": "https"},
            )
            assert resp.status == 200
            assert "Strict-Transport-Security" in resp.headers
            assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]

    async def test_hsts_header_not_emitted_when_disabled(self):
        with patch.dict(
            os.environ,
            {
                "MESH_REGISTRY_HSTS": "",
                "MESH_REGISTRY_BEHIND_PROXY": "1",
                "MESH_REGISTRY_ALLOW_INSECURE": "1",
            },
        ):
            resp = await self.client.request(
                "GET",
                "/peers",
                headers={"X-Forwarded-Proto": "https"},
            )
            assert resp.status == 200
            assert "Strict-Transport-Security" not in resp.headers
