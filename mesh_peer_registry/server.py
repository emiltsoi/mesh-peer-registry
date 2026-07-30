"""HTTP registry server for mesh peers."""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from aiohttp import web

from .crypto import verify_json
from .models import PeerInfo
from .store import SqliteStore

__all__ = ["create_app"]

AppKeyStore = web.AppKey("store", SqliteStore)

REGISTRY_FIELDS = {"name", "url", "public_key", "role", "description", "ttl"}
REQUIRED_FIELDS = {"name", "url", "public_key"}


def _admin_token() -> str:
    return os.getenv("MESH_REGISTRY_ADMIN_TOKEN", "")


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

    store: SqliteStore = request.app[AppKeyStore]
    store.put(PeerInfo(**payload))
    return web.json_response({"ok": True, "peer": payload})


async def list_peers(request: web.Request) -> web.Response:
    store: SqliteStore = request.app[AppKeyStore]
    try:
        limit = max(0, int(request.query.get("limit", 0)))
        offset = max(0, int(request.query.get("offset", 0)))
    except ValueError:
        limit, offset = 0, 0
    role = request.query.get("role") or None
    peers = store.list(role=role, limit=limit, offset=offset)
    total = store.count(role=role)
    return web.json_response({
        "peers": [p.to_dict() for p in peers],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


async def get_peer(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    store: SqliteStore = request.app[AppKeyStore]
    peer = store.get(name)
    if not peer:
        return web.json_response({"error": "not found"}, status=404)
    return web.json_response(peer.to_dict())


async def delete_peer(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    sig = request.headers.get("X-Mesh-Signature", "")
    if not sig:
        return web.json_response(
            {"error": "missing X-Mesh-Signature header"}, status=400
        )

    store: SqliteStore = request.app[AppKeyStore]
    peer = store.get(name)
    if not peer:
        return web.json_response({"error": "not found"}, status=404)

    sig_payload = {"name": name, "action": "deregister"}
    if not verify_json(peer.public_key, sig_payload, sig):
        return web.json_response({"error": "invalid signature"}, status=401)

    store.delete(name)
    return web.json_response({"ok": True})


async def refresh_peer(request: web.Request) -> web.Response:
    """Refresh last_seen for a peer (prevents TTL expiry)."""
    name = request.match_info["name"]
    sig = request.headers.get("X-Mesh-Signature", "")
    if not sig:
        return web.json_response(
            {"error": "missing X-Mesh-Signature header"}, status=400
        )

    store: SqliteStore = request.app[AppKeyStore]
    peer = store.get(name)
    if not peer:
        return web.json_response({"error": "not found"}, status=404)

    sig_payload = {"name": name, "action": "refresh"}
    if not verify_json(peer.public_key, sig_payload, sig):
        return web.json_response({"error": "invalid signature"}, status=401)

    store.touch(name)
    return web.json_response({"ok": True})


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "healthy"})


async def metrics(request: web.Request) -> web.Response:
    store: SqliteStore = request.app[AppKeyStore]
    return web.json_response({"registry": store.metrics()})


async def _reaper_task(app: web.Application) -> None:
    store: SqliteStore = app[AppKeyStore]
    interval = float(os.getenv("MESH_REGISTRY_REAPER_INTERVAL", "60"))
    while True:
        await asyncio.sleep(interval)
        try:
            store.reap_expired()
        except Exception:
            pass


async def _reaper_context(app: web.Application):
    """Start the reaper on startup and cancel it on cleanup."""
    task = asyncio.create_task(_reaper_task(app))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@web.middleware
async def admin_token_middleware(request: web.Request, handler):
    if request.path in ("/health", "/metrics"):
        token = request.headers.get("X-Admin-Token", "")
        expected = _admin_token()
        if expected and token != expected:
            return web.json_response({"error": "unauthorized"}, status=401)
    return await handler(request)


def create_app(store_path: str | None = None) -> web.Application:
    store_path = store_path or os.path.expanduser("~/.mesh/registry.sqlite")
    app = web.Application(middlewares=[admin_token_middleware])
    app[AppKeyStore] = SqliteStore(Path(store_path))
    app.router.add_post("/register", register)
    app.router.add_get("/peers", list_peers)
    app.router.add_get("/peers/{name}", get_peer)
    app.router.add_post("/peers/{name}/refresh", refresh_peer)
    app.router.add_delete("/peers/{name}", delete_peer)
    app.router.add_get("/health", health)
    app.router.add_get("/metrics", metrics)
    app.cleanup_ctx.append(_reaper_context)
    return app
