"""Thin re-export of the mesh peer registry client.

The full client will move into `mesh_core.registry` in Phase 6; for now we
re-export `mesh_peer_registry.client` so downstream packages can depend on a
stable `mesh_core.registry.RegistryClient` import.
"""

from __future__ import annotations

from mesh_peer_registry.client import RegistryClient, RegistryClientError

__all__ = ["RegistryClient", "RegistryClientError"]
