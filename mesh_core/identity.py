"""Fleet identity resolution for the mesh vault."""

from __future__ import annotations

import logging
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

import yaml

from mesh_core.envelope import validate_envelope_token

logger = logging.getLogger(__name__)

DEFAULT_VAULT_PATH = Path.home() / ".mesh"


@dataclass
class MeshIdentity:
    """Public view of a mesh peer identity."""

    id: str
    name: str
    role: str
    description: str
    url: str
    a2a_url: str | None = None
    public_key: str = ""
    allow_loopback: bool = False
    platform: str = "hermes"


class IdentityVault:
    """Read and write mesh agent identities from a local vault.

    The vault root is the directory that contains `mesh/agents/<name>/identity.yaml`.
    """

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        cache_ttl: float = 1.0,
        cache_maxsize: int = 256,
    ) -> None:
        if root is None:
            env = os.getenv("MESH_VAULT_PATH")
            if env:
                root = Path(env)
            else:
                root = DEFAULT_VAULT_PATH
        self.root = Path(root).expanduser().resolve()
        self.agents_root = self.root / "mesh" / "agents"
        self._cache_ttl = max(0.0, cache_ttl)
        self._cache_maxsize = max(1, cache_maxsize)
        self._cache: OrderedDict[Path, tuple[float, float | None, dict | None]] = OrderedDict()

    def _identity_file(self, name: str) -> Path:
        name = name.lower().strip()
        if not name:
            raise ValueError("Agent name must not be empty")
        if ".." in name or "/" in name or "\\" in name:
            raise ValueError(f"Invalid agent name: {name!r}")
        return self.agents_root / name / "identity.yaml"

    def _file_mtime(self, path: Path) -> float | None:
        try:
            return path.stat().st_mtime
        except FileNotFoundError:
            return None

    def _resolve_env(self, value: object) -> str:
        """Resolve ${ENV_VAR} interpolations and coerce values to strings."""
        if not isinstance(value, str):
            return str(value)
        match = re.fullmatch(r"^\$\{([^}]+)\}$", value.strip())
        if match:
            env_key = match.group(1)
            resolved = os.environ.get(env_key)
            if resolved is None:
                raise RuntimeError(
                    f"Vault env var ${env_key} is not set — refusing to use "
                    f"template string as a secret. Set {env_key} in the environment."
                )
            return resolved
        return value

    def _load_yaml(self, path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("Mesh identity: failed to load %s: %s", path, exc)
            return None
        if not isinstance(raw, dict):
            return None

        # Resolve env vars in auth secrets.
        for transport in raw.get("transports", {}).values():
            if not isinstance(transport, dict):
                continue
            auth = transport.get("auth")
            if isinstance(auth, dict):
                for key in ("token", "public_key", "value"):
                    if key in auth:
                        try:
                            auth[key] = self._resolve_env(auth[key])
                        except RuntimeError as exc:
                            logger.warning("Mesh identity: %s", exc)
        return raw

    def _load_with_cache(self, path: Path) -> dict | None:
        if self._cache_ttl == 0:
            return self._load_yaml(path)

        now = time.monotonic()
        mtime = self._file_mtime(path)
        cached = self._cache.get(path)

        if cached is not None:
            cached_time, cached_mtime, cached_data = cached
            if (now - cached_time) < self._cache_ttl and cached_mtime == mtime:
                self._cache.move_to_end(path)
                return cached_data

        data = self._load_yaml(path)
        self._cache[path] = (now, mtime, data)
        self._cache.move_to_end(path)

        while len(self._cache) > self._cache_maxsize:
            self._cache.popitem(last=False)

        return data

    def _webhook_url(self, identity: dict) -> str:
        if not isinstance(identity, dict):
            return ""
        transports = identity.get("transports", {}) or {}
        hermes = transports.get("hermes_webhook", {}) or {}
        return hermes.get("url", "")

    def _public_key(self, identity: dict) -> str:
        if not isinstance(identity, dict):
            return ""
        transports = identity.get("transports", {}) or {}
        hermes = transports.get("hermes_webhook", {}) or {}
        auth = hermes.get("auth", {}) or {}
        return auth.get("public_key", "")

    def get(self, name: str) -> MeshIdentity | None:
        """Look up a public identity by name."""
        identity_file = self._identity_file(name)
        identity = self._load_with_cache(identity_file)
        if not identity:
            return None

        key = name.lower()
        return MeshIdentity(
            id=identity.get("id") or identity.get("name", key),
            name=identity.get("name", key).lower(),
            role=identity.get("role", ""),
            description=identity.get("description", ""),
            url=self._webhook_url(identity),
            a2a_url=identity.get("a2a_url", ""),
            public_key=self._public_key(identity),
            allow_loopback=bool(identity.get("allow_loopback", False)),
            platform=identity.get("platform", "hermes"),
        )

    def get_public_key(self, name: str) -> str | None:
        identity = self.get(name)
        if identity is None:
            return None
        return identity.public_key or None

    def get_webhook_url(self, name: str) -> str | None:
        identity = self.get(name)
        if identity is None:
            return None
        return identity.url or None

    def list(self) -> list[MeshIdentity]:
        """Return all public identities in the vault."""
        agents: list[MeshIdentity] = []
        if not self.agents_root.is_dir():
            return agents
        for agent_dir in self.agents_root.iterdir():
            if not agent_dir.is_dir():
                continue
            identity = self.get(agent_dir.name)
            if identity:
                agents.append(identity)
        return agents

    def _save_yaml(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True)
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def save(self, name: str, identity: MeshIdentity) -> Path:
        """Write an identity.yaml for an agent."""
        name = validate_envelope_token(name, "agent name").lower()
        path = self._identity_file(name)

        data: dict[str, object] = {
            "id": identity.id or name,
            "name": name,
            "description": identity.description,
            "role": identity.role,
        }
        if identity.a2a_url:
            data["a2a_url"] = identity.a2a_url
        if identity.allow_loopback:
            data["allow_loopback"] = True
        if identity.platform:
            data["platform"] = identity.platform

        public_key = identity.public_key or ""
        data["transports"] = {
            "hermes_webhook": {
                "protocol": "hermes-webhook",
                "url": identity.url,
                "auth": {
                    "public_key": public_key,
                },
            }
        }

        self._save_yaml(path, data)
        self._cache.pop(path, None)
        return path

    def remove(self, name: str) -> None:
        """Remove an identity from the vault."""
        path = self._identity_file(name)
        if path.exists():
            path.unlink()
        self._cache.pop(path, None)

    def clear_cache(self) -> None:
        """Clear the identity cache."""
        self._cache.clear()
