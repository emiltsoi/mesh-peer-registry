"""Loopback and local-address classification for binding vs target hosts."""

from __future__ import annotations

import ipaddress


def _strip_brackets(host: str) -> str:
    """Remove surrounding ``[`` ``]`` from bracketed IPv6 literals."""
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def is_loopback_bind_host(host: str | None) -> bool:
    """Return True when `host` binds only to the local machine.

    ``0.0.0.0`` and ``::`` are *not* loopback; they mean every interface.
    """
    if not host:
        return False
    return host.strip().lower() in {"127.0.0.1", "localhost", "::1"}


def is_local_target_host(host: str) -> bool:
    """Return True when `host` is a known local/loopback/private endpoint."""
    host = (host or "").lower().strip()
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}:
        return True
    host = _strip_brackets(host)
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local)
