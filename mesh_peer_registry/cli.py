"""CLI entry point for the mesh peer registry server."""
from __future__ import annotations

import argparse
import os

from aiohttp import web

from .server import create_app

__all__ = ["main"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the mesh peer registry")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8646)
    parser.add_argument(
        "--store",
        default="~/.mesh/registry.sqlite",
        help="Path to the SQLite store file",
    )
    parser.add_argument(
        "--ssl-cert",
        default=None,
        help="Path to TLS certificate for HTTPS",
    )
    parser.add_argument(
        "--ssl-key",
        default=None,
        help="Path to TLS private key for HTTPS",
    )
    parser.add_argument(
        "--admin-token",
        default=None,
        help="Admin token for /health and /metrics endpoints",
    )
    parser.add_argument(
        "--reaper-interval",
        type=float,
        default=60.0,
        help="Interval in seconds to reap expired peers",
    )
    parser.add_argument(
        "--behind-proxy",
        action="store_true",
        help="Trust X-Forwarded-Proto and X-Forwarded-For headers",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=0,
        help="Max /register requests per IP per minute (0 = unlimited)",
    )
    parser.add_argument(
        "--hsts",
        action="store_true",
        help="Emit Strict-Transport-Security headers for HTTPS responses",
    )
    args = parser.parse_args()

    if args.admin_token:
        os.environ["MESH_REGISTRY_ADMIN_TOKEN"] = args.admin_token
    if args.reaper_interval:
        os.environ["MESH_REGISTRY_REAPER_INTERVAL"] = str(args.reaper_interval)
    if args.behind_proxy:
        os.environ["MESH_REGISTRY_BEHIND_PROXY"] = "1"
    if args.rate_limit:
        os.environ["MESH_REGISTRY_RATE_LIMIT"] = str(args.rate_limit)
    if args.hsts:
        os.environ["MESH_REGISTRY_HSTS"] = "1"

    app = create_app(os.path.expanduser(args.store))
    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        import ssl
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(args.ssl_cert, args.ssl_key)
    web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_context)
