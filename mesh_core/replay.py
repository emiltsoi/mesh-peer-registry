"""Inbound mesh message replay window."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class ReplayWindow:
    """TTL + capped in-memory replay window for seen message IDs."""

    ttl: float = 300.0
    max_size: int = 10000

    def __post_init__(self) -> None:
        self._seen: OrderedDict[str, float] = OrderedDict()

    def _expire(self) -> None:
        now = time.time()
        expired = [mid for mid, ts in self._seen.items() if now - ts > self.ttl]
        for mid in expired:
            del self._seen[mid]
        while len(self._seen) > self.max_size:
            self._seen.popitem(last=False)

    def has(self, msg_id: str) -> bool:
        """Return True if the message id has been seen within the replay window."""
        if not msg_id:
            return False
        self._expire()
        return msg_id in self._seen

    def add(self, msg_id: str) -> None:
        """Record a message id in the replay window."""
        if not msg_id:
            return
        self._expire()
        self._seen[msg_id] = time.time()
        self._seen.move_to_end(msg_id)

    def clear(self) -> None:
        """Clear the replay window."""
        self._seen.clear()
