"""HTTP registry server for mesh peers."""
from __future__ import annotations

import json
import os
from pathlib import Path

from aiohttp import web

from .crypto import verify_json
from .models import PeerInfo
from .store import FileStore

__all__ = ["create_app"]

AppKeyStore = web.AppKey("store", FileStore)

REGISTRY_FIELDS = {"name", "url", "public_key", "role", "description"}
REQUIRED_FIELDS = {"name", "url", "public_key"}


async def _json_body(request: web.Request) -> dict:
    try:
        return await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(text='{"error": "invalid json"}')


async def register(request: web.Request) -> web.Response:
    body = await _json_body(request)
    missing = REQUIRED_FIELDS - set(body)
    if missing:
        return web.json_response(
            {"error": f"missing fields: {sorted(missing)}"}, status=400
        )

    sig = request.headers.get("X-Mesh-Signature", "")
    if not sig:
        return web.json_response(
            {"error": "missing X-Mesh-Signature header"}, status=400
        )

    payload = {k: body[k] for k in REGISTRY_FIELDS if k in body}
    public_key = body["public_key"]
    if not verify_json(public_key, payload, sig):
        return web.json_response({"error": "invalid signature"}, status=401)

    store: FileStore = request.app[AppKeyStore]
    store.put(PeerInfo(**payload))
    return web.json_response({"ok": True, "peer": payload})


async def list_peers(request: web.Request) -> web.Response:
    store: FileStore = request.app[AppKeyStore]
    peers = store.list()
    return web.json_response({"peers": [p.__dict__ for p in peers]})


async def get_peer(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    store: FileStore = request.app[AppKeyStore]
    peer = store.get(name)
    if not peer:
        return web.json_response({"error": "not found"}, status=404)
    return web.json_response(peer.__dict__)


async def delete_peer(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    sig = request.headers.get("X-Mesh-Signature", "")
    if not sig:
        return web.json_response(
            {"error": "missing X-Mesh-Signature header"}, status=400
        )

    store: FileStore = request.app[AppKeyStore]
    peer = store.get(name)
    if not peer:
        return web.json_response({"error": "not found"}, status=404)

    sig_payload = {"name": name, "action": "deregister"}
    if not verify_json(peer.public_key, sig_payload, sig):
        return web.json_response({"error": "invalid signature"}, status=401)

    store.delete(name)
    return web.json_response({"ok": True})


def create_app(store_path: str | None = None) -> web.Application:
    store_path = store_path or os.path.expanduser("~/.mesh/registry.json")
    app = web.Application()
    app[AppKeyStore] = FileStore(Path(store_path))
    app.router.add_post("/register", register)
    app.router.add_get("/peers", list_peers)
    app.router.add_get("/peers/{name}", get_peer)
    app.router.add_delete("/peers/{name}", delete_peer)
    return app
