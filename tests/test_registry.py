"""Tests for mesh-peer-registry crypto, store, and server."""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from aiohttp.test_utils import AioHTTPTestCase

from mesh_peer_registry.client import RegistryClient, RegistryClientError
from mesh_peer_registry.crypto import (
    canonicalize_payload,
    generate_keypair,
    sign_json,
    sign_message,
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
        private, public = generate_keypair()
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


class TestRegistryServer(AioHTTPTestCase):
    async def get_application(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        return create_app(str(Path(self.tmpdir.name) / "registry.json"))

    def tearDown(self):
        super().tearDown()
        if hasattr(self, "tmpdir"):
            self.tmpdir.cleanup()

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

    async def test_deregister(self):
        private, public = generate_keypair()
        client = RegistryClient(
            f"http://127.0.0.1:{self.server.port}",
            private,
            public,
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
