"""Configuration dataclass for mesh peers."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

DEFAULT_VAULT_PATH = Path.home() / ".mesh"
DEFAULT_KEY_DIR = Path.home() / ".mesh" / "keys"
DEFAULT_REGISTRY_URL = "http://127.0.0.1:8646"


@dataclass
class MeshConfig:
    """Runtime configuration for a mesh peer."""

    agent_name: str
    private_key_path: Path | None = None
    vault_path: Path | None = None
    registry_url: str | None = None
    registry_pin: str | None = None
    allow_insecure_registry: bool = False
    sign_timestamp: bool = True
    allow_loopback: bool = False
    delivery_retries: int = 3
    delivery_backoff: float = 1.0
    delivery_timeout: float = 10.0
    replay_window_ttl: float = 300.0
    replay_window_size: int = 10000
    rate_limit_per_minute: int = 0
    outbox_enabled: bool = False
    outbox_max_attempts: int = 5
    outbox_backoff: float = 5.0
    dsn_enabled: bool = True
    dsn_rate_limit: int = 10
    dsn_auth_failure_rate_limit: int = 0
    chat_mapping: Literal["per_sender", "single"] = "per_sender"
    fallback_chat_id: str = "mesh:inbox"
    chat_map: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.agent_name or not isinstance(self.agent_name, str):
            raise ValueError("agent_name must be a non-empty string")
        self.agent_name = self.agent_name.strip().lower()

        if self.vault_path is None:
            env = os.getenv("MESH_VAULT_PATH")
            self.vault_path = Path(env) if env else DEFAULT_VAULT_PATH
        self.vault_path = Path(self.vault_path).expanduser().resolve()

        if self.private_key_path is None:
            self.private_key_path = DEFAULT_KEY_DIR / f"{self.agent_name}.pem"
        self.private_key_path = Path(self.private_key_path).expanduser()

        if self.registry_url:
            self.registry_url = self.registry_url.rstrip("/")
