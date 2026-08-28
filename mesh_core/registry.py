"""Synchronous HTTP client for the mesh peer registry."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

from .crypto import sign_json, spki_hash_from_cert
from .models import PeerInfo

__all__ = ["RegistryClient", "RegistryClientError"]


class _PinningSSLContext(ssl.SSLContext):
    """SSL context that optionally pins the server certificate's SPKI."""

    def __init__(self, pin: str | None = None):
        super().__init__(ssl.PROTOCOL_TLS_CLIENT)
        self._pin = (pin or "").lower().strip()
        if self._pin:
            self.load_default_certs()

    def wrap_socket(self, *args, **kwargs):
        sock = super().wrap_socket(*args, **kwargs)
        if self._pin:
            cert = sock.getpeercert(binary_form=True)
            if not cert:
                raise ssl.SSLError("no peer certificate for pinning")
            got = spki_hash_from_cert(cert)
            if got != self._pin:
                raise ssl.SSLError(
                    f"certificate pinning mismatch: expected {self._pin[:16]}..., got {got[:16]}..."
                )
        return sock


class RegistryClientError(Exception):
    """Registry client error with HTTP status and server message."""

    def __init__(self, status: int, message: object):
        self.status = status
        self.message = message
        super().__init__(f"Registry HTTP {status}: {message}")


class RegistryClient:
    """Synchronous client for a mesh-peer-registry server."""

    def __init__(
        self,
        registry_url: str,
        private_key_pem: str,
        public_key_pem: str,
        timeout: float = 10.0,
        pin: str | None = None,
        allow_insecure: bool = False,
    ) -> None:
        url = registry_url.strip()
        if url.lower().startswith("http://"):
            env_allow = os.getenv("MESH_REGISTRY_ALLOW_INSECURE", "").lower()
            if not allow_insecure and env_allow not in ("1", "true", "yes"):
                raise RegistryClientError(
                    0,
                    "insecure http registry URL; set MESH_REGISTRY_ALLOW_INSECURE=1 or allow_insecure=True",
                )
        self.registry_url = url.rstrip("/")
        self.private_key_pem = private_key_pem
        self.public_key_pem = public_key_pem
        self.timeout = timeout
        self._pin = (pin or os.getenv("MESH_REGISTRY_PIN", "")).lower().strip()
        self._context: ssl.SSLContext | None = None
        if self.registry_url.lower().startswith("https://"):
            self._context = _PinningSSLContext(self._pin) if self._pin else ssl.create_default_context()

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        signature_payload: dict | None = None,
    ) -> dict:
        url = f"{self.registry_url}{path}"
        headers: dict[str, str] = {}
        data: bytes | None = None

        if payload is not None:
            data = json.dumps(payload, sort_keys=True).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if signature_payload is not None:
            sig = sign_json(self.private_key_pem, signature_payload)
            headers["X-Mesh-Signature"] = sig

        req = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        kwargs: dict[str, object] = {"timeout": self.timeout}
        if self._context is not None:
            kwargs["context"] = self._context
        try:
            with urllib.request.urlopen(req, **kwargs) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8")
            try:
                detail = json.loads(body)
            except json.JSONDecodeError:
                detail = body
            raise RegistryClientError(status=exc.code, message=detail) from exc

    def register(
        self,
        name: str,
        url: str,
        role: str = "agent",
        description: str = "",
        ttl: int | None = None,
    ) -> dict:
        payload: dict[str, object] = {
            "name": name,
            "url": url,
            "public_key": self.public_key_pem,
            "role": role,
            "description": description,
        }
        if ttl is not None:
            payload["ttl"] = ttl
        result = self._request("POST", "/register", payload, payload)
        # Refresh last_seen after registration so a peer with short TTL stays alive.
        self.refresh(name)
        return result

    def list_peers(
        self,
        role: str | None = None,
        limit: int = 0,
        offset: int = 0,
    ) -> list[PeerInfo]:
        qs = []
        if role:
            qs.append(f"role={role}")
        if limit:
            qs.append(f"limit={limit}")
        if offset:
            qs.append(f"offset={offset}")
        path = "/peers"
        if qs:
            path += "?" + "&".join(qs)
        data = self._request("GET", path)
        return [PeerInfo(**p) for p in data.get("peers", [])]

    def refresh(self, name: str) -> dict:
        sig_payload = {"name": name, "action": "refresh"}
        return self._request(
            "POST", f"/peers/{name}/refresh", signature_payload=sig_payload
        )

    def get_peer(self, name: str) -> PeerInfo | None:
        try:
            data = self._request("GET", f"/peers/{name}")
            return PeerInfo(**data)
        except RegistryClientError as exc:
            if exc.status == 404:
                return None
            raise

    def deregister(self, name: str) -> dict:
        sig_payload = {"name": name, "action": "deregister"}
        return self._request(
            "DELETE", f"/peers/{name}", signature_payload=sig_payload
        )
