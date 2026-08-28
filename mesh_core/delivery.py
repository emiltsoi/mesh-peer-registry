"""Ed25519-signed mesh webhook delivery with SSRF protection and retries."""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import socket
import ssl
import time
import urllib.error
from dataclasses import dataclass
from urllib.parse import urlparse

from mesh_core.crypto import sign_message
from mesh_core.dsn import send_delivery_error
from mesh_core.envelope import MeshEnvelope
from mesh_core.network import is_local_target_host

logger = logging.getLogger(__name__)

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_BENCHMARK = ipaddress.ip_network("198.18.0.0/15")


@dataclass
class DeliveryResult:
    """Result of a mesh_send delivery attempt."""

    delivery_id: str | None = None
    error: str | None = None


def _is_ip_blocked(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_loopback: bool
) -> bool:
    """Return True when `ip_obj` must be rejected for the given policy."""
    if ip_obj in _CGNAT or ip_obj in _BENCHMARK:
        return True
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return True
    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
        return not allow_loopback
    return False


def _resolve_host(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname and validate all returned addresses."""
    if not host:
        raise ValueError("Empty host")
    try:
        addrinfo = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve host {host}: {exc}") from exc
    if not addrinfo:
        raise ValueError(f"No addresses for host {host}")

    ip_objs: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for _, _, _, _, sockaddr in addrinfo:
        try:
            ip_objs.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    if not ip_objs:
        raise ValueError(f"No valid IP addresses for host {host}")
    return ip_objs


def _resolve_target_url(
    url: str, *, allow_loopback: bool = False
) -> tuple[str, list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    """Resolve a target URL once for SSRF protection.

    Returns the cleaned URL and the list of allowed IP addresses.
    """
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"URL must use http/https: {url}")

    parsed = urlparse(url)
    host = parsed.hostname or ""
    ip_objs = _resolve_host(host)
    allowed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for ip_obj in ip_objs:
        if _is_ip_blocked(ip_obj, allow_loopback=allow_loopback):
            if allow_loopback:
                continue
            scope = "Loopback" if ip_obj.is_loopback else "Private/reserved"
            raise ValueError(f"{scope} address blocked: {ip_obj}")
        allowed.append(ip_obj)
    if not allowed:
        raise ValueError(f"No valid IP addresses for host {host}")
    return url, allowed


def _pinned_request(
    url: str,
    body: bytes,
    headers: dict,
    timeout: float,
    allow_loopback: bool,
    resolved_ip_objs: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> bytes:
    """Make a single POST to a resolved IP while preserving SNI/Host."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL must use http/https: {url}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Empty host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    host_header = host if parsed.port is None else f"{host}:{port}"
    req_headers = dict(headers)
    req_headers.setdefault("Host", host_header)

    last_exc: Exception | None = None
    for ip_obj in resolved_ip_objs:
        if _is_ip_blocked(ip_obj, allow_loopback=allow_loopback):
            if allow_loopback:
                continue
            scope = "Loopback" if ip_obj.is_loopback else "Private/reserved"
            raise ValueError(f"{scope} address blocked: {ip_obj}")

        resolved_ip = str(ip_obj)
        if parsed.scheme == "https":
            if allow_loopback:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context = ssl.create_default_context()
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                resolved_ip, port, timeout=timeout, context=context, server_hostname=host
            )
        else:
            conn = http.client.HTTPConnection(resolved_ip, port, timeout=timeout)

        try:
            conn.request("POST", path, body=body, headers=req_headers)
            resp = conn.getresponse()
            data = resp.read()
            if resp.status >= 400:
                raise urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, resp)
            return data
        except (TimeoutError, OSError, http.client.HTTPException) as exc:
            last_exc = exc
            continue
        finally:
            conn.close()

    if last_exc is not None:
        raise last_exc
    raise ValueError(f"Could not connect to any resolved IP for {host}")


def _exception_to_reason(exc: Exception) -> str:
    """Map a delivery exception to a short, stable reason code."""
    if isinstance(exc, urllib.error.HTTPError):
        code = exc.code
        if code in (401, 403):
            return "unauthorized"
        if code == 404:
            return "not-found"
        if code == 400:
            return "bad-request"
        if code == 429:
            return "rate-limited"
        if code == 503:
            return "busy"
        if code >= 500:
            return "internal-error"
    msg = str(exc).lower()
    if "blocked" in msg or "private" in msg or "loopback" in msg:
        return "loopback-blocked"
    if "timeout" in msg:
        return "unreachable"
    return "unreachable"


class DeliveryClient:
    """Send Ed25519-signed mesh webhook POSTs with SSRF protection."""

    def __init__(
        self,
        *,
        private_key_pem: str,
        sign_timestamp: bool = True,
        allow_loopback: bool = False,
        retries: int = 3,
        backoff: float = 1.0,
        timeout: float = 10.0,
        dsn_enabled: bool = True,
        agent_name: str = "",
    ) -> None:
        self.private_key_pem = private_key_pem
        self.sign_timestamp = sign_timestamp
        self.allow_loopback = allow_loopback
        self.retries = max(1, retries)
        self.backoff = max(0.0, backoff)
        self.timeout = max(1.0, timeout)
        self.dsn_enabled = dsn_enabled
        self.agent_name = agent_name

    def send(
        self,
        envelope: MeshEnvelope,
        target_url: str,
        *,
        dsn_from: str | None = None,
        dsn_to: str | None = None,
        is_dsn: bool = False,
        allow_loopback: bool | None = None,
    ) -> DeliveryResult:
        """Deliver a signed mesh message to `target_url`.

        Returns DeliveryResult with delivery_id or error reason.
        """
        # Respect allow_loopback override in the target URL if present.
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        if allow_loopback is None:
            allow_loopback = self.allow_loopback or is_local_target_host(parsed.hostname or "")

        try:
            url, resolved_ip_objs = _resolve_target_url(target_url, allow_loopback=allow_loopback)
        except ValueError as exc:
            reason = "loopback-blocked" if "blocked" in str(exc).lower() else "unreachable"
            return self._fail(
                envelope,
                reason,
                dsn_from=dsn_from,
                dsn_to=dsn_to,
                is_dsn=is_dsn,
            )

        timestamp = str(time.time())
        body_text = envelope.build()
        body = json.dumps({"from": envelope.sender, "text": body_text}, sort_keys=True)

        headers = {
            "Content-Type": "application/json",
            "X-Mesh-Timestamp": timestamp,
        }
        if is_dsn:
            headers["X-Mesh-DSN"] = "1"

        signed_body = f"{timestamp}\n{body}".encode() if self.sign_timestamp else body.encode()
        signature = sign_message(self.private_key_pem, signed_body)
        headers["X-Mesh-Signature"] = signature

        deadline = time.monotonic() + self.timeout
        last_exc: Exception | None = None

        for attempt in range(self.retries):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            attempt_timeout = max(1.0, remaining / (self.retries - attempt))
            try:
                data = _pinned_request(
                    url,
                    body.encode(),
                    headers,
                    attempt_timeout,
                    allow_loopback=allow_loopback,
                    resolved_ip_objs=resolved_ip_objs,
                )
                result = json.loads(data.decode())
                delivery_id = result.get("delivery_id", "unknown")
                return DeliveryResult(delivery_id=delivery_id)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt < self.retries - 1:
                    sleep_time = min(self.backoff * (2 ** attempt), max(0.0, remaining - 1.0))
                    if sleep_time > 1e-3:
                        logger.warning(
                            "Mesh delivery attempt %d/%d failed: %s",
                            attempt + 1,
                            self.retries,
                            exc,
                        )
                        time.sleep(sleep_time)

        reason = _exception_to_reason(last_exc) if last_exc else "unreachable"
        return self._fail(
            envelope,
            reason,
            dsn_from=dsn_from,
            dsn_to=dsn_to,
            is_dsn=is_dsn,
        )

    def _fail(
        self,
        envelope: MeshEnvelope,
        reason: str,
        *,
        dsn_from: str | None = None,
        dsn_to: str | None = None,
        is_dsn: bool = False,
    ) -> DeliveryResult:
        if self.dsn_enabled and not is_dsn and dsn_from and dsn_to:
            send_delivery_error(
                dsn_from=dsn_from,
                dsn_to=dsn_to,
                original_id=envelope.msg_id,
                reason=reason,
                original_from=envelope.sender,
                original_to=envelope.recipient,
                private_key_pem=self.private_key_pem,
                agent_name=self.agent_name,
            )
        return DeliveryResult(error=reason)
