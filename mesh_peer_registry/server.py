"""HTTP registry server for mesh peers."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlparse

from aiohttp import web

from .crypto import verify_json
from .models import PeerInfo
from .store import SqliteStore

__all__ = ["create_app"]

logger = logging.getLogger(__name__)

AppKeyStore = web.AppKey("store", SqliteStore)

REGISTRY_FIELDS = {"name", "url", "public_key", "role", "description", "ttl"}
REQUIRED_FIELDS = {"name", "url", "public_key"}

_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

_rate_limit_state: dict[str, tuple[int, float]] = {}


def _admin_token() -> str:
    return os.getenv("MESH_REGISTRY_ADMIN_TOKEN", "")


def _validate_name(name: str) -> bool:
    return bool(name and _NAME_RE.match(name))


def _validate_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _validate_public_key(public_key: str) -> bool:
    return isinstance(public_key, str) and "BEGIN PUBLIC KEY" in public_key and "END PUBLIC KEY" in public_key


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

    if not _validate_name(body.get("name", "")):
        return web.json_response({"error": "invalid name"}, status=400)
    if not _validate_url(body.get("url", "")):
        return web.json_response({"error": "invalid url"}, status=400)
    if not _validate_public_key(body.get("public_key", "")):
        return web.json_response({"error": "invalid public_key"}, status=400)

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
    logger.info("registered peer name=%s url=%s", payload["name"], payload["url"])
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
    logger.info("deregistered peer name=%s", name)
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
    logger.info("refreshed peer name=%s", name)
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
        except sqlite3.Error:
            logger.exception("reaper failed")


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


@web.middleware
async def secure_middleware(request: web.Request, handler):
    allow_insecure = os.getenv("MESH_REGISTRY_ALLOW_INSECURE", "").lower() in ("1", "true", "yes")
    behind_proxy = os.getenv("MESH_REGISTRY_BEHIND_PROXY", "").lower() in ("1", "true", "yes")
    if not allow_insecure:
        is_secure = request.secure
        if behind_proxy:
            is_secure = is_secure or request.headers.get("X-Forwarded-Proto") == "https"
        if not is_secure:
            return web.json_response({"error": "https required"}, status=400)
    response = await handler(request)
    hsts_enabled = os.getenv("MESH_REGISTRY_HSTS", "").lower() in ("1", "true", "yes")
    if hsts_enabled and (request.secure or (behind_proxy and request.headers.get("X-Forwarded-Proto") == "https")):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def _rate_limit_key(request: web.Request) -> str | None:
    behind_proxy = os.getenv("MESH_REGISTRY_BEHIND_PROXY", "").lower() in ("1", "true", "yes")
    if behind_proxy:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote


@web.middleware
async def rate_limit_middleware(request: web.Request, handler):
    raw = os.getenv("MESH_REGISTRY_RATE_LIMIT", "0")
    limit = int(raw) if raw.isdigit() else 0
    if limit > 0 and request.path == "/register":
        key = _rate_limit_key(request)
        if key:
            now = time.time()
            count, window = _rate_limit_state.get(key, (0, 0))
            if now - window > 60:
                count, window = 0, now
            count += 1
            _rate_limit_state[key] = (count, window)
            if count > limit:
                return web.json_response({"error": "rate limited"}, status=429)
    return await handler(request)


def create_app(store_path: str | None = None) -> web.Application:
    store_path = store_path or os.path.expanduser("~/.mesh/registry.sqlite")
    app = web.Application(middlewares=[secure_middleware, admin_token_middleware, rate_limit_middleware])
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
