"""Synchronous HTTP client for the mesh peer registry."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .crypto import sign_json
from .models import PeerInfo

__all__ = ["RegistryClient"]


class RegistryClient:
    """Synchronous client for a mesh-peer-registry server."""

    def __init__(
        self,
        registry_url: str,
        private_key_pem: str,
        public_key_pem: str,
        timeout: float = 10.0,
    ) -> None:
        self.registry_url = registry_url.rstrip("/")
        self.private_key_pem = private_key_pem
        self.public_key_pem = public_key_pem
        self.timeout = timeout

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
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8")
            try:
                detail = json.loads(body)
            except json.JSONDecodeError:
                detail = body
            raise RegistryClientError(
                status=exc.code, message=detail
            ) from exc

    def register(
        self,
        name: str,
        url: str,
        role: str = "agent",
        description: str = "",
    ) -> dict:
        payload = {
            "name": name,
            "url": url,
            "public_key": self.public_key_pem,
            "role": role,
            "description": description,
        }
        return self._request("POST", "/register", payload, payload)

    def list_peers(self) -> list[PeerInfo]:
        data = self._request("GET", "/peers")
        return [PeerInfo(**p) for p in data.get("peers", [])]

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


class RegistryClientError(Exception):
    """Registry client error with HTTP status and server message."""

    def __init__(self, status: int, message: object):
        self.status = status
        self.message = message
        super().__init__(f"Registry HTTP {status}: {message}")
