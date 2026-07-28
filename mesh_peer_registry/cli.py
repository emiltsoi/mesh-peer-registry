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
        default="~/.mesh/registry.json",
        help="Path to the JSON store file",
    )
    args = parser.parse_args()

    app = create_app(os.path.expanduser(args.store))
    web.run_app(app, host=args.host, port=args.port)
