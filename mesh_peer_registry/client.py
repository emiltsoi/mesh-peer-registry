"""Synchronous HTTP client for the mesh peer registry.

This module is a thin re-export from mesh_core for backward compatibility.
The canonical implementation lives in mesh_core.registry.
"""

from __future__ import annotations

from mesh_core.registry import RegistryClient, RegistryClientError

__all__ = ["RegistryClient", "RegistryClientError"]
