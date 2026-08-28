"""Delivery-Status Notifications (DSN) for mesh delivery failures."""

from __future__ import annotations

import logging
import os
import re
import time
import uuid

from mesh_core.envelope import MeshEnvelope, validate_envelope_token

logger = logging.getLogger(__name__)

_DSN_RATE_BUCKETS: dict[str, tuple[int, float]] = {}


def _dsn_enabled() -> bool:
    return os.getenv("MESH_DSN_ENABLED", "1").lower() in ("1", "true", "yes")


def _dsn_rate_limit(auth_failure: bool = False) -> int:
    env = "MESH_DSN_AUTH_FAILURE_RATE_LIMIT" if auth_failure else "MESH_DSN_RATE_LIMIT"
    default = "0" if auth_failure else "10"
    raw = os.getenv(env, default)
    try:
        return int(raw)
    except ValueError:
        return int(default)


def _check_dsn_rate_limit(to_agent: str, auth_failure: bool = False) -> bool:
    limit = _dsn_rate_limit(auth_failure=auth_failure)
    if auth_failure and limit <= 0:
        return False
    if limit <= 0:
        return True
    now = time.time()
    bucket = _DSN_RATE_BUCKETS.get(to_agent)
    if bucket is None or now - bucket[1] > 60:
        _DSN_RATE_BUCKETS[to_agent] = (1, now)
        return True
    count, window_start = bucket
    count += 1
    _DSN_RATE_BUCKETS[to_agent] = (count, window_start)
    return count <= limit


def _safe_reason(reason: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", reason)[:32]


def make_dsn_envelope(
    dsn_from: str,
    dsn_to: str,
    original_id: str,
    reason: str,
    original_from: str,
    original_to: str,
) -> MeshEnvelope:
    """Build a DSN envelope for a failed delivery."""
    dsn_id = str(uuid.uuid4())
    safe_reason = _safe_reason(reason)
    body = (
        f"[mesh-dsn][status:failed][reason:{safe_reason}] "
        f"Delivery of message {original_id} from {original_from} to {original_to} "
        f"failed: {safe_reason}."
    )
    return MeshEnvelope(
        sender=validate_envelope_token(dsn_from, "dsn_from"),
        recipient=validate_envelope_token(dsn_to, "dsn_to"),
        msg_id=dsn_id,
        action="info",
        reply="no",
        ref=validate_envelope_token(original_id, "original_id"),
        body=body,
    )


def send_delivery_error(
    dsn_from: str,
    dsn_to: str,
    original_id: str,
    reason: str,
    original_from: str,
    original_to: str,
    *,
    private_key_pem: str,
    agent_name: str,
    target_url: str | None = None,
    is_dsn: bool = False,
) -> None:
    """Best-effort delivery of a DSN to the interested party."""
    if not _dsn_enabled():
        return
    if is_dsn:
        logger.debug("[mesh] not sending DSN for a DSN message %s", original_id)
        return
    if not _check_dsn_rate_limit(dsn_to, auth_failure=False):
        logger.warning("[mesh] DSN rate limit exceeded for %s", dsn_to)
        return

    try:
        dsn_from = validate_envelope_token(dsn_from, "dsn_from").lower()
        dsn_to = validate_envelope_token(dsn_to, "dsn_to").lower()
        original_id = validate_envelope_token(original_id, "original_id")
    except ValueError as exc:
        logger.warning("[mesh] DSN invalid envelope token: %s", exc)
        return

    if not target_url:
        from mesh_core.identity import IdentityVault

        vault = IdentityVault()
        target_url = vault.get_webhook_url(dsn_to)
        if not target_url:
            logger.warning("[mesh] DSN target %s has no webhook URL", dsn_to)
            return

    envelope = make_dsn_envelope(dsn_from, dsn_to, original_id, reason, original_from, original_to)
    from mesh_core.delivery import DeliveryClient

    client = DeliveryClient(
        private_key_pem=private_key_pem,
        agent_name=agent_name,
    )
    result = client.send(
        envelope,
        target_url,
        dsn_from=dsn_from,
        dsn_to=dsn_to,
        is_dsn=True,
    )
    if result.error:
        logger.warning("[mesh] DSN delivery to %s failed: %s", dsn_to, result.error)
    else:
        logger.info("[mesh] DSN delivered to %s: %s", dsn_to, result.delivery_id)
